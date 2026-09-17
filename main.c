/**
 * @file main.c
 * @brief Magma (GOST R 34.12-2018) hardware accelerator workbench.
 *
 * Measures cipher latency and throughput via GPIO timing markers, and
 * cross-checks a plain-C software reference implementation of Magma
 * against the same hardware so the two can be compared on-scope.
 * Connect an oscilloscope to GPIOB pin 0 (PROBE_PIN).
 *
 * Six back-to-back pulses are emitted in each iteration:
 *   Pulse 1 — single ECB block, hardware (one cipher latency)
 *   Pulse 2 — burst of BENCH_BLOCK_COUNT ECB blocks, hardware, CPU-polled (throughput window)
 *   Pulse 3 — key schedule only, hardware (UPDATE_KEY latency)
 *   Pulse 4 — single block, software reference (directly comparable to Pulse 1)
 *   Pulse 5 — burst of BENCH_BLOCK_COUNT blocks, software reference (comparable to Pulse 2)
 *   Pulse 6 — burst of BENCH_BLOCK_COUNT blocks, hardware, via CRYPTO's OWN descriptor-driven
 *             streaming engine instead of CPU polling (directly comparable to Pulse 2)
 *
 * The software pulses (4, 5) are expected to be orders of magnitude wider
 * than their hardware counterparts — that gap *is* the measurement.
 * Re-time the scope per pulse group rather than expecting one timebase to
 * frame all six usefully.
 *
 * Pulse 6 uses CRYPTO's OWN internal descriptor-chain DMA engine (datasheet
 * §16.4, "поточный режим" / streaming mode; CRYPTO->BASE_DESCRIPTOR /
 * DMA_CONTROL / STATUS.DMA_ACTIVE) -- NOT the chip-wide 24-channel DMA
 * controller (datasheet §10), whose hardware-request-source table (§10.1)
 * has no entry for CRYPTO at all (only HASH, among the crypto blocks, gets
 * a wired channel there). CRYPTO's own engine walks a linked list of
 * {control word, source address, destination address, next-descriptor
 * address} descriptors in RAM, reading TEXT_IN and writing TEXT_OUT without
 * CPU involvement per block. Pulse 6 exercises this engine for the same
 * burst Pulse 2 runs CPU-polled, isolating how much of Pulse 2's per-block
 * time is STATUS-polling overhead vs. the ~9-cycle silicon minimum the
 * datasheet's §16.6 performance table gives for one Magma block.
 *
 * Before the loop starts, both the software cipher and the CRYPTO
 * streaming burst are checked once against a trusted reference (the
 * hardware single-block engine's own output, and the software reference
 * per block, respectively — see "cross-checks" below); on a mismatch the
 * probe pin is driven into a fast, unmistakable blink instead of reporting
 * misleading comparison data.
 *
 * Each pulse's wall-clock duration is also measured directly, via the
 * RISC-V `cycle` CSR (rdcycle(), csr.h) read immediately around the call,
 * independent of the oscilloscope. Every sample updates that pulse's own
 * exponential moving average (PULSE_AVG_ALPHA_PCT sets the weight); once
 * every PRINT_INTERVAL_CYCLES (~3 s), the six running averages are printed
 * as a table over UART0 (default pins, 115200 8N1 -- see prvUartInit()).
 *
 * A long idle gap follows so the scope can frame one full iteration.
 *
 * Core clock: 50 MHz (PLL0, HSECLK=24 MHz × FBDIV=100 / REFDIV=2 / PD0A+1=6 / PD0B+1=4).
 *
 * @version 0.1
 * @date 2026-06-25
 * @copyright Sova Lab (c) 2026
 */

#include "K1921VG015.h"
#include <system_k1921vg015.h>
#include <stdint.h>

/* ---- board configuration ----------------------------------------------- */

/** Probe GPIO port.  Connect oscilloscope to this pin. */
#define PROBE_PORT         GPIOB
#define PROBE_PORT_CLK_Msk RCU_CGCFGAHB_GPIOBEN_Msk
#define PROBE_PORT_RST_Msk RCU_RSTDISAHB_GPIOBEN_Msk
#define PROBE_PIN          0u                     /**< GPIOB[0] */
#define PROBE_PIN_Msk      (1u << PROBE_PIN)

/** Number of 64-bit blocks in the throughput burst (Pulse 2). */
#define BENCH_BLOCK_COUNT  256u

/** Short busy-wait gap inserted between consecutive test pulses (cycles). */
#define INTER_PULSE_GAP    400u

/** Long idle gap between full iterations — adjust until scope shows ~1 ms idle. */
#define ITER_IDLE_GAP      50000u   /* ~1 ms at 50 MHz */

/** Core clock this file's SystemInit() PLL config produces -- see top doc comment. */
#define CORE_CLK_HZ        50000000u

/**
 * UART0 default pins (SovaHub's app/core/debug_uart.c: PA0=RX/AF1,
 * PA1=TX/AF1) -- only TX is wired up here, this file has no use for RX.
 */
#define UART_TX_PORT        GPIOA
#define UART_TX_PORT_CLK_Msk RCU_CGCFGAHB_GPIOAEN_Msk
#define UART_TX_PORT_RST_Msk RCU_RSTDISAHB_GPIOAEN_Msk
#define UART_TX_PIN          1u   /**< PA1 = UART0_TX, AF1 */
#define UART_BAUD             115200u

/**
 * EMA smoothing weight applied to each new per-pulse duration sample, as a
 * percentage (10 = ALPHA 0.10): avg += (ALPHA/100) * (sample - avg).
 * Smaller = smoother/slower to react to a real change; larger = noisier.
 */
#define PULSE_AVG_ALPHA_PCT   10u

/** How often the pulse-average table is printed over UART0 (~3 s). */
#define PRINT_INTERVAL_CYCLES (CORE_CLK_HZ * 3u)

/* ---- test vectors ------------------------------------------------------- */

/**
 * GOST R 34.12-2018 / GOST R 34.11-2018 standard test key (256 bit).
 * KEY[0] = bits 255..224 (most-significant word first).
 */
static const uint32_t k_key[8] = {
    0xFF070605u, 0x04030201u, 0x0F0E0D0Cu, 0x0B0A0908u,
    0x17161514u, 0x13121110u, 0x1F1E1D1Cu, 0x1B1A1918u,
};

/**
 * 64-bit test plaintext block.
 * TEXT_IN[0] = bits 63..32, TEXT_IN[1] = bits 31..0.
 */
static const uint32_t k_pt[2] = { 0xFEDCBA98u, 0x76543210u };

/* ---- private helpers ---------------------------------------------------- */

/**
 * @defgroup Private helpers
 * @brief Low-level inline accessors and wait loops.
 * @{
 */

/** @name Probe control */
/** @{ */
static inline void probe_high(void) { PROBE_PORT->DATAOUTSET = PROBE_PIN_Msk; }
static inline void probe_low(void)  { PROBE_PORT->DATAOUTCLR = PROBE_PIN_Msk; }
/** @} */

/** @name CRYPTO status polls */
/** @{ */

/**
 * @brief Spin until the engine accepts a new command (STATUS.READY = 1).
 */
static inline void prvWaitReady(void)
{
    while (!(CRYPTO->STATUS & CRYPTO_STATUS_READY_Msk)) {}
}

/**
 * @brief Spin until round-key expansion is done (STATUS.KEYS_READY = 1).
 */
static inline void prvWaitKeysReady(void)
{
    while (!(CRYPTO->STATUS & CRYPTO_STATUS_KEYS_READY_Msk)) {}
}

/** @} */
/** @} */

/* ---- software Magma reference implementation ---------------------------- */

/**
 * @defgroup SoftwareMagma Software Magma reference
 * @brief Plain-C Magma encryption (RFC 8891 / GOST R 34.12-2018), timed
 *        against the CRYPTO peripheral's hardware acceleration of the
 *        same block. Deliberately unoptimised (a naive per-nibble
 *        substitution loop, no combined byte-wide S-box tables) — the
 *        point of this workbench is the hardware/software gap, not a fast
 *        software cipher.
 * @{
 */

/** @name Fixed S-box and round-key schedule */
/** @{ */

/**
 * @brief Magma round substitution tables Pi'_0..Pi'_7.
 *
 * The fixed S-box mandated by GOST R 34.12-2018 ("id-tc26-gost-28147-
 * param-Z", RFC 8891 §5.2) — unlike the older GOST 28147-89, this set is
 * no longer negotiable. k_sbox[i] is Pi'_i, applied to nibble i of the
 * round function's input where nibble 0 is the least-significant 4 bits
 * (RFC 8891: a = a_7||...||a_0, t(a) = Pi_7(a_7)||...||Pi_0(a_0)).
 */
static const uint8_t k_sbox[8][16] = {
    { 12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1 },
    { 6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15 },
    { 11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0 },
    { 12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11 },
    { 7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12 },
    { 5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0 },
    { 8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7 },
    { 1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2 },
};

/**
 * @brief Round-key selection order for all 32 Magma rounds (RFC 8891 §5.1).
 *
 * Rounds 1-24 cycle K_1..K_8 three times; rounds 25-32 use K_8..K_1
 * (reversed). Values are 0-based indices into k_key[], so
 * k_round_key_order[0] selects K_1 = k_key[0] — the same K_1 = KEY[0]
 * convention prvMagmaKeyLoad() uses for the hardware engine.
 */
static const uint8_t k_round_key_order[32] = {
    0, 1, 2, 3, 4, 5, 6, 7,
    0, 1, 2, 3, 4, 5, 6, 7,
    0, 1, 2, 3, 4, 5, 6, 7,
    7, 6, 5, 4, 3, 2, 1, 0,
};

/** @} */

/** @name Reference encryption */
/** @{ */

/**
 * @brief Magma round function g[k](a) = (t(a [+] k)) <<< 11.
 *
 * @param k  32-bit round key.
 * @param a  32-bit round input.
 * @return   Substituted and rotated result.
 */
static inline uint32_t prvMagmaG(uint32_t k, uint32_t a)
{
    uint32_t t = a + k; /* Int_32 addition mod 2^32 — wraps for free in uint32_t. */
    uint32_t sub = 0u;

    for (uint32_t nibble = 0u; nibble < 8u; nibble++) {
        uint32_t in = (t >> (nibble * 4u)) & 0xFu;
        sub |= (uint32_t)k_sbox[nibble][in] << (nibble * 4u);
    }

    return (sub << 11) | (sub >> (32u - 11u));
}

/**
 * @brief Software-only encryption of one 64-bit Magma block.
 *
 * Feistel network per RFC 8891 §4/§5.1: 32 rounds of g[K_i], with the
 * final round omitting the half-swap.
 *
 * @param key     8-word round key array (key[0] = K_1, ..., key[7] = K_8).
 * @param in_hi   Input block bits 63..32 (matches CRYPTO->TEXT_IN[0]).
 * @param in_lo   Input block bits 31..0  (matches CRYPTO->TEXT_IN[1]).
 * @param out_hi  Output block bits 63..32 (matches CRYPTO->TEXT_OUT[0]).
 * @param out_lo  Output block bits 31..0  (matches CRYPTO->TEXT_OUT[1]).
 */
static void prvMagmaEncryptBlock(const uint32_t key[8], uint32_t in_hi, uint32_t in_lo,
                                  uint32_t *out_hi, uint32_t *out_lo)
{
    uint32_t a1 = in_hi;
    uint32_t a0 = in_lo;

    for (uint32_t round = 0u; round < 31u; round++) {
        uint32_t next_a0 = prvMagmaG(key[k_round_key_order[round]], a0) ^ a1;
        a1 = a0;
        a0 = next_a0;
    }

    /* Final round: no half-swap. */
    *out_hi = prvMagmaG(key[k_round_key_order[31]], a0) ^ a1;
    *out_lo = a0;
}

/** @} */
/** @} */

/* ---- CRYPTO descriptor-driven streaming burst ---------------------------- */

/**
 * @defgroup CryptoDmaStream CRYPTO streaming mode
 * @brief Exercises CRYPTO's own descriptor-chain DMA engine (datasheet
 *        §16.4, "поточный режим") -- see this file's top doc comment for
 *        why this is NOT the chip's generic 24-channel DMA controller.
 *        Modelled on SovaHub's crypto_crypt_with_dma() (platform/
 *        middleware/mbedtls/alt_k1921vg015/crypto_util.c), the one place in
 *        SovaHub that actually drives this engine, and on
 *        CRYPTO_InitDMADescriptor()/CRPYTO_ProcessData() (platform/plib015/
 *        src/plib015_crypto.c) for the register write order. The
 *        CRYPTO_DMA_DESCR_TypeDef struct itself is a base-chip type
 *        (K1921VG015.h), not a plib015-only one, so no plib015 files are
 *        pulled in here.
 * @{
 */

/** @name Descriptor and buffers */
/** @{ */

/**
 * @brief Single DMA descriptor for the whole BENCH_BLOCK_COUNT-block burst.
 *
 * Must be aligned to a 4-word (16-byte) boundary (datasheet §16.4 and
 * table 16.6/16.7) -- CRYPTO->BASE_DESCRIPTOR's low 4 bits are read-only.
 * One descriptor with LAST_DESCRIPTOR set covers the whole burst; no chain
 * needed.
 */
static CRYPTO_DMA_DESCR_TypeDef crypto_dma_descr __attribute__((aligned(16)));

static uint32_t crypto_dma_src_buf[BENCH_BLOCK_COUNT * 2u]; /**< Plaintext: same k_pt[]^i pattern as prvBenchBurst()/prvBenchSoftBurst(). */
static uint32_t crypto_dma_dst_buf[BENCH_BLOCK_COUNT * 2u]; /**< Ciphertext, written directly by the CRYPTO engine, one whole burst at a time. */

/** @} */

/** @name Streaming driver */
/** @{ */

/**
 * @brief One-time fill of the plaintext buffer the streaming burst reads.
 *
 * Same layout convention as CRYPTO->TEXT_IN[0]/[1] (hi word then lo word
 * per block) with DMA_CONTROL.WORDS_SWAP left at 0, so the first word DMA
 * reads from a block lands in TEXT_IN_0 exactly like the CPU-driven
 * benchmarks -- see prvCryptoDmaBurst()'s own doc.
 */
static void prvCryptoDmaInit(void)
{
    for (uint32_t i = 0u; i < BENCH_BLOCK_COUNT; i++) {
        crypto_dma_src_buf[2u * i]      = k_pt[0] ^ i;
        crypto_dma_src_buf[2u * i + 1u] = k_pt[1] ^ i;
    }
}

/**
 * @brief Blocking BENCH_BLOCK_COUNT-block Magma/ECB/Encrypt burst, driven
 *        entirely by CRYPTO's descriptor engine -- one CPU write starts
 *        the whole burst, vs. prvBenchBurst()'s per-block register writes.
 *
 * UPDATE_KEY is left clear: prvMagmaKeyLoad() already stored Magma's round
 * keys, and datasheet §16.4 only forces a recompute when none are stored.
 * WORDS_SWAP/BYTES_SWAP are left at 0 (natural order), matching
 * crypto_dma_src_buf's hi-word-then-lo-word layout. DIRECTION/ALGORITHM/
 * MODE/GCM_PHASE are read from the descriptor by the state machine and
 * overwrite CRYPTO->CONTROL's own copies of those fields as a side effect
 * (datasheet §16.4) -- no separate CONTROL setup needed here.
 */
static void prvCryptoDmaBurst(void)
{
    prvWaitReady();

    crypto_dma_descr.CONTROL = 0u;
    crypto_dma_descr.CONTROL_bit.UPDATE_KEY      = 0u;
    crypto_dma_descr.CONTROL_bit.LAST_DESCRIPTOR = 1u;
    crypto_dma_descr.CONTROL_bit.DIRECTION       = CRYPTO_CONTROL_DIRECTION_Encrypt;
    crypto_dma_descr.CONTROL_bit.ALGORITHM       = CRYPTO_CONTROL_ALGORITHM_Magma;
    crypto_dma_descr.CONTROL_bit.MODE            = CRYPTO_CONTROL_MODE_ECB;
    crypto_dma_descr.CONTROL_bit.GCM_PHASE       = 0u;
    crypto_dma_descr.CONTROL_bit.INTERRUPT_ENABLE = 0u;
    crypto_dma_descr.CONTROL_bit.BLOCKS_COUNT    = BENCH_BLOCK_COUNT - 1u; /* datasheet: COUNT + 1 blocks processed. */

    crypto_dma_descr.SRC_ADDR   = (uint32_t)crypto_dma_src_buf;
    crypto_dma_descr.DST_ADDR   = (uint32_t)crypto_dma_dst_buf;
    crypto_dma_descr.NEXT_DESCR = 0u; /* LAST_DESCRIPTOR set -- not read by the state machine. */

    CRYPTO->BASE_DESCRIPTOR = (uint32_t)&crypto_dma_descr;
    CRYPTO->DMA_CONTROL = CRYPTO_DMA_CONTROL_START_Msk; /* WORDS_SWAP=0, BYTES_SWAP=0, START=1, one write. */

    while (CRYPTO->STATUS & CRYPTO_STATUS_DMA_ACTIVE_Msk) {}
    prvWaitReady();
}

/** @} */
/** @} */

/* ---- UART0 pulse-average reporting ---------------------------------------- */

/**
 * @defgroup UartReport UART0 pulse-average reporting
 * @brief Polled, TX-only UART0 driver plus an exponential-moving-average
 *        table printed every PRINT_INTERVAL_CYCLES. Register setup and the
 *        16x-oversampled baud divisor are modelled on SovaHub's
 *        debug_uart_init() (app/core/debug_uart.c), adapted to this file's
 *        own HSECLK_VAL (UART0's baud clock is routed straight from HSE,
 *        independent of the core's PLL -- see datasheet's UARTCLKCFG).
 *        No printf/retarget pulled in: decimal formatting is hand-rolled,
 *        matching this project's self-contained, register-level style.
 * @{
 */

/** @name UART0 driver */
/** @{ */

/**
 * @brief Bring up UART0 TX at UART_BAUD 8N1 on UART_TX_PIN.
 */
static void prvUartInit(void)
{
    RCU->CGCFGAHB  |= UART_TX_PORT_CLK_Msk;
    RCU->RSTDISAHB |= UART_TX_PORT_RST_Msk;
    RCU->CGCFGAPB  |= RCU_CGCFGAPB_UART0EN_Msk;
    RCU->RSTDISAPB |= RCU_RSTDISAPB_UART0EN_Msk;

    RCU->UARTCLKCFG[0].UARTCLKCFG = ((uint32_t)RCU_UARTCLKCFG_CLKSEL_HSE << RCU_UARTCLKCFG_CLKSEL_Pos) |
                                     RCU_UARTCLKCFG_CLKEN_Msk |
                                     RCU_UARTCLKCFG_RSTDIS_Msk;

    UART_TX_PORT->ALTFUNCNUM_bit.PIN1 = 1u; /* PA1 = UART0_TX, AF1 */
    UART_TX_PORT->ALTFUNCSET = (1u << UART_TX_PIN);

    /* IBRD.FBRD = HSECLK_VAL / (16 * baud); FBRD is the fractional part in 1/64ths. */
    float divisor  = (float)HSECLK_VAL / (16.0f * (float)UART_BAUD);
    uint32_t int_div  = (uint32_t)divisor;
    uint32_t frac_div = (uint32_t)((divisor - (float)int_div) * 64.0f + 0.5f);

    UART0->IBRD = int_div;
    UART0->FBRD = frac_div;
    UART0->LCRH = UART_LCRH_FEN_Msk | ((uint32_t)UART_LCRH_WLEN_8bit << UART_LCRH_WLEN_Pos);
    UART0->CR   = UART_CR_TXE_Msk | UART_CR_UARTEN_Msk;
}

/**
 * @brief Blocking single-character UART0 TX.
 * @param c  Character to send.
 */
static void prvUartPutc(char c)
{
    while (UART0->FR & UART_FR_TXFF_Msk) {}
    UART0->DR = (uint32_t)(uint8_t)c;
}

/**
 * @brief Blocking NUL-terminated string UART0 TX.
 * @param s  String to send.
 */
static void prvUartPuts(const char *s)
{
    while (*s != '\0') {
        prvUartPutc(*s++);
    }
}

/**
 * @brief Blocking string UART0 TX, right-padded with spaces to @p width.
 * @param s      String to send.
 * @param width  Minimum total characters to emit (no truncation if longer).
 */
static void prvUartPutsPadded(const char *s, uint32_t width)
{
    uint32_t len = 0u;
    const char *p = s;

    while (*p != '\0') {
        p++;
        len++;
    }

    prvUartPuts(s);
    for (uint32_t pad = len; pad < width; pad++) {
        prvUartPutc(' ');
    }
}

/** @} */

/** @name Decimal formatting */
/** @{ */

/**
 * @brief Format an unsigned decimal integer into @p buf, most-significant
 *        digit first. No NUL terminator, no leading zeros.
 *
 * @param v    Value to format.
 * @param buf  Destination buffer; at least 10 bytes (max uint32_t digits).
 * @return     Number of characters written.
 */
static uint32_t prvUDecToStr(uint32_t v, char *buf)
{
    char tmp[10];
    uint32_t n = 0u;

    do {
        tmp[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    } while (v != 0u);

    for (uint32_t i = 0u; i < n; i++) {
        buf[i] = tmp[n - 1u - i];
    }
    return n;
}

/**
 * @brief Print an unsigned decimal integer, no padding.
 * @param v  Value to print.
 */
static void prvUartPrintUDec(uint32_t v)
{
    char buf[10];
    uint32_t n = prvUDecToStr(v, buf);

    for (uint32_t i = 0u; i < n; i++) {
        prvUartPutc(buf[i]);
    }
}

/**
 * @brief Print a non-negative value with one decimal digit (e.g. "275.1"),
 *        right-justified in a field of @p width characters.
 *
 * @param value_us  Value to print (this file only ever passes microseconds).
 * @param width     Minimum field width; longer values are not truncated.
 */
static void prvUartPrintFixed1(float value_us, uint32_t width)
{
    uint32_t tenths = (uint32_t)(value_us * 10.0f + 0.5f);
    char buf[16];
    uint32_t n = prvUDecToStr(tenths / 10u, buf);

    buf[n++] = '.';
    buf[n++] = (char)('0' + (tenths % 10u));

    for (uint32_t pad = n; pad < width; pad++) {
        prvUartPutc(' ');
    }
    for (uint32_t i = 0u; i < n; i++) {
        prvUartPutc(buf[i]);
    }
}

/** @} */

/** @name Pulse averages */
/** @{ */

#define PULSE_COUNT  6u

static float   pulse_avg_us[PULSE_COUNT];     /**< Running EMA, in microseconds, one slot per Pulse 1..6. */
static uint8_t pulse_avg_primed[PULSE_COUNT]; /**< 0 until each slot's first sample seeds it directly (no ramp-up bias). */

/** Column labels, in Pulse 1..6 order -- kept short; prvUartPrintTable() pads them to a common width. */
static const char * const k_pulse_label[PULSE_COUNT] = {
    "Pulse 1 HW single",
    "Pulse 2 HW burst/256",
    "Pulse 3 HW key sched",
    "Pulse 4 SW single",
    "Pulse 5 SW burst/256",
    "Pulse 6 HW stream/256",
};

/**
 * @brief Feed one new duration sample into pulse @p idx's running average.
 *
 * @param idx     Pulse index, 0..PULSE_COUNT-1 (Pulse (idx+1) in this
 *                file's own numbering).
 * @param cycles  Duration of this sample, in CPU cycles (an rdcycle() delta).
 */
static void prvPulseAvgUpdate(uint32_t idx, uint32_t cycles)
{
    float sample_us = (float)cycles / ((float)CORE_CLK_HZ / 1000000.0f);

    if (pulse_avg_primed[idx] != 0u) {
        pulse_avg_us[idx] += ((float)PULSE_AVG_ALPHA_PCT / 100.0f) * (sample_us - pulse_avg_us[idx]);
    } else {
        pulse_avg_us[idx] = sample_us;
        pulse_avg_primed[idx] = 1u;
    }
}

/**
 * @brief Print the current pulse-average table over UART0.
 *
 * A pulse whose slot isn't primed yet (main() hasn't run it since reset)
 * prints "n/a" rather than a misleading 0.0.
 */
static void prvUartPrintTable(void)
{
    prvUartPuts("\r\n---- magma_workbench pulse averages (EMA alpha=");
    prvUartPrintUDec(PULSE_AVG_ALPHA_PCT);
    prvUartPuts("%) ----\r\n");

    for (uint32_t i = 0u; i < PULSE_COUNT; i++) {
        prvUartPutsPadded(k_pulse_label[i], 22u);
        prvUartPuts(": ");
        if (pulse_avg_primed[i] != 0u) {
            prvUartPrintFixed1(pulse_avg_us[i], 8u);
            prvUartPuts(" us\r\n");
        } else {
            prvUartPuts("     n/a\r\n");
        }
    }
}

/** @} */
/** @} */

/* ---- initialisation ----------------------------------------------------- */

/**
 * @defgroup Init
 * @brief Peripheral clock and GPIO initialisation.
 * @{
 */

/** @name Init functions */
/** @{ */

/**
 * @brief Enable AHB clocks and release resets for CRYPTO and GPIOB.
 */
static void prvClocksInit(void)
{
    RCU->CGCFGAHB |= RCU_CGCFGAHB_CRYPTOEN_Msk | PROBE_PORT_CLK_Msk;
    RCU->RSTDISAHB |= RCU_RSTDISAHB_CRYPTOEN_Msk | PROBE_PORT_RST_Msk;
}

/**
 * @brief Configure probe pin as push-pull output, initially low.
 */
static void prvProbeInit(void)
{
    /* Push-pull = 0x0 at bits[2*pin+1 : 2*pin] — explicit for clarity. */
    PROBE_PORT->OUTMODE &= ~(0x3u << (PROBE_PIN * 2u));
    PROBE_PORT->OUTENSET  = PROBE_PIN_Msk;
    PROBE_PORT->DATAOUTCLR = PROBE_PIN_Msk;
}

/**
 * @brief Load test key and run Magma key schedule.
 *
 * Configures CONTROL (Magma / ECB / Encrypt) and issues UPDATE_KEY.
 * After this call STATUS.KEYS_STORED[Magma] is set, so bench loops
 * can issue START without a repeated key schedule.
 */
static void prvMagmaKeyLoad(void)
{
    prvWaitReady();

    CRYPTO->CONTROL = ((uint32_t)CRYPTO_CONTROL_ALGORITHM_Magma  << CRYPTO_CONTROL_ALGORITHM_Pos)  |
                      ((uint32_t)CRYPTO_CONTROL_MODE_ECB          << CRYPTO_CONTROL_MODE_Pos)       |
                      ((uint32_t)CRYPTO_CONTROL_DIRECTION_Encrypt << CRYPTO_CONTROL_DIRECTION_Pos);

    for (uint32_t i = 0u; i < 8u; i++) {
        CRYPTO->KEY[i] = k_key[i];
    }

    /* Trigger key schedule; wait until round keys are computed and engine is idle. */
    CRYPTO->CONTROL |= CRYPTO_CONTROL_UPDATE_KEY_Msk;
    prvWaitKeysReady();
    prvWaitReady();

    /* Clear UPDATE_KEY so subsequent |= START writes don't re-trigger it. */
    CRYPTO->CONTROL &= ~CRYPTO_CONTROL_UPDATE_KEY_Msk;
}

/** @} */
/** @} */

/* ---- benchmark functions ------------------------------------------------ */

/**
 * @defgroup Benchmark
 * @brief Timing measurement functions.
 * @{
 */

/** @name ECB encryption benchmarks */
/** @{ */

/**
 * @brief Pulse 1 — one 64-bit ECB block; GPIO high only during acceleration.
 *
 * Measures raw single-block cipher latency.
 *
 * @return XOR of output words (prevents dead-code elimination by compiler).
 */
static uint32_t prvBenchSingleBlock(void)
{
    prvWaitReady();

    CRYPTO->TEXT_IN[0] = k_pt[0];
    CRYPTO->TEXT_IN[1] = k_pt[1];

    probe_high();
    CRYPTO->CONTROL |= CRYPTO_CONTROL_START_Msk;
    prvWaitReady();
    probe_low();

    return CRYPTO->TEXT_OUT[0] ^ CRYPTO->TEXT_OUT[1];
}

/**
 * @brief Pulse 2 — BENCH_BLOCK_COUNT blocks back-to-back; GPIO spans the batch.
 *
 * GPIO pulse width / BENCH_BLOCK_COUNT = per-block time including polling overhead.
 *
 * @return XOR accumulator across all output words (prevents dead-code elimination).
 */
static uint32_t prvBenchBurst(void)
{
    volatile uint32_t acc = 0u;

    prvWaitReady();

    probe_high();
    for (uint32_t i = 0u; i < BENCH_BLOCK_COUNT; i++) {
        CRYPTO->TEXT_IN[0] = k_pt[0] ^ i;
        CRYPTO->TEXT_IN[1] = k_pt[1] ^ i;

        CRYPTO->CONTROL |= CRYPTO_CONTROL_START_Msk;
        prvWaitReady();

        acc ^= CRYPTO->TEXT_OUT[0] ^ CRYPTO->TEXT_OUT[1];
    }
    probe_low();

    return acc;
}

/** @} */

/** @name Key schedule benchmark */
/** @{ */

/**
 * @brief Pulse 3 — key schedule only; GPIO high from UPDATE_KEY to KEYS_READY.
 *
 * Measures round-key expansion latency in isolation.
 * Reloads the same test key so subsequent bench loops remain valid.
 */
static void prvBenchKeySchedule(void)
{
    prvWaitReady();

    for (uint32_t i = 0u; i < 8u; i++) {
        CRYPTO->KEY[i] = k_key[i];
    }

    probe_high();
    CRYPTO->CONTROL |= CRYPTO_CONTROL_UPDATE_KEY_Msk;
    prvWaitKeysReady();
    probe_low();

    CRYPTO->CONTROL &= ~CRYPTO_CONTROL_UPDATE_KEY_Msk;
    prvWaitReady();
}

/** @} */

/** @name Software Magma benchmarks */
/** @{ */

/**
 * @brief Pulse 4 — one 64-bit block, software reference; GPIO high only
 *        during prvMagmaEncryptBlock(). Directly comparable to Pulse 1
 *        (hardware single-block latency) on the same test vector.
 *
 * @return XOR of output words (prevents dead-code elimination by compiler).
 */
static uint32_t prvBenchSoftSingleBlock(void)
{
    uint32_t out_hi, out_lo;

    probe_high();
    prvMagmaEncryptBlock(k_key, k_pt[0], k_pt[1], &out_hi, &out_lo);
    probe_low();

    return out_hi ^ out_lo;
}

/**
 * @brief Pulse 5 — BENCH_BLOCK_COUNT blocks, software reference; GPIO spans
 *        the batch. Directly comparable to Pulse 2 (hardware throughput).
 *
 * @return XOR accumulator across all output words (prevents dead-code elimination).
 */
static uint32_t prvBenchSoftBurst(void)
{
    volatile uint32_t acc = 0u;
    uint32_t out_hi, out_lo;

    probe_high();
    for (uint32_t i = 0u; i < BENCH_BLOCK_COUNT; i++) {
        prvMagmaEncryptBlock(k_key, k_pt[0] ^ i, k_pt[1] ^ i, &out_hi, &out_lo);
        acc ^= out_hi ^ out_lo;
    }
    probe_low();

    return acc;
}

/** @} */

/** @name CRYPTO streaming-mode benchmark */
/** @{ */

/**
 * @brief Pulse 6 — BENCH_BLOCK_COUNT-block burst via CRYPTO's own streaming
 *        engine; GPIO spans the whole descriptor-driven transfer.
 *
 * Directly comparable to Pulse 2 — same algorithm, mode, key, block count,
 * and plaintext pattern, the only difference being who feeds TEXT_IN/reads
 * TEXT_OUT between blocks (CRYPTO's descriptor engine here, the CPU in
 * Pulse 2). The gap between the two isolates STATUS-polling overhead from
 * actual cipher compute time.
 */
static void prvBenchCryptoDmaBurst(void)
{
    probe_high();
    prvCryptoDmaBurst();
    probe_low();
}

/** @} */
/** @} */

/* ---- fatal error signalling ---------------------------------------------- */

/**
 * @brief Park forever, blinking the probe pin fast and steadily.
 *
 * Used by the startup cross-checks below when a comparison can't be
 * trusted (software cipher vs. hardware, or CRYPTO streaming burst vs.
 * software reference). Deliberately never returns: better an obviously
 * wrong scope trace than silently emitting benchmark pulses that compare
 * two different results.
 */
static void prvFatalBlink(void)
{
    for (;;) {
        probe_high();
        for (volatile uint32_t d = 0u; d < 20000u; d++) {}
        probe_low();
        for (volatile uint32_t d = 0u; d < 20000u; d++) {}
    }
}

/* ---- main --------------------------------------------------------------- */

int main(void)
{
    SystemInit();       /* configure PLL → 50 MHz */
    prvClocksInit();
    prvProbeInit();
    prvMagmaKeyLoad();
    prvCryptoDmaInit();
    prvUartInit();

    /* software/hardware cross-check -------------------------------------
     * Encrypt the same test block with both engines once, before trusting
     * either for comparison timing. The key in this file is a NIIET demo
     * vector, not RFC 8891's published test key, so there is no literal
     * "known-good" ciphertext to check against here — the hardware engine
     * itself is the reference. On a mismatch, don't run the benchmark loop
     * at all. */
    {
        uint32_t hw_hi, hw_lo, sw_hi, sw_lo;

        prvWaitReady();
        CRYPTO->TEXT_IN[0] = k_pt[0];
        CRYPTO->TEXT_IN[1] = k_pt[1];
        CRYPTO->CONTROL |= CRYPTO_CONTROL_START_Msk;
        prvWaitReady();
        hw_hi = CRYPTO->TEXT_OUT[0];
        hw_lo = CRYPTO->TEXT_OUT[1];

        prvMagmaEncryptBlock(k_key, k_pt[0], k_pt[1], &sw_hi, &sw_lo);

        if ((hw_hi != sw_hi) || (hw_lo != sw_lo)) {
            prvFatalBlink();
        }
    }

    /* CRYPTO streaming-mode cross-check --------------------------------
     * Run the whole burst once via the descriptor engine and compare every
     * block against the (already-trusted, per the check above) software
     * reference before Pulse 6's timing means anything. */
    {
        prvCryptoDmaBurst();

        for (uint32_t i = 0u; i < BENCH_BLOCK_COUNT; i++) {
            uint32_t exp_hi, exp_lo;

            prvMagmaEncryptBlock(k_key, k_pt[0] ^ i, k_pt[1] ^ i, &exp_hi, &exp_lo);

            if ((crypto_dma_dst_buf[2u * i] != exp_hi) || (crypto_dma_dst_buf[2u * i + 1u] != exp_lo)) {
                prvFatalBlink();
            }
        }
    }

    /* sink prevents the return values of bench functions from being optimised away. */
    volatile uint32_t sink = 0u;

    /* rdcycle() reference point for the ~3 s UART table print, below. */
    uint32_t last_print_cycle = rdcycle();

    for (;;)
    {
        uint32_t t0;

        /* Pulse 1: single ECB block — narrow pulse = one cipher latency. */
        t0 = rdcycle();
        sink ^= prvBenchSingleBlock();
        prvPulseAvgUpdate(0u, rdcycle() - t0);

        for (volatile uint32_t d = 0u; d < INTER_PULSE_GAP; d++) {}

        /* Pulse 2: burst of BENCH_BLOCK_COUNT blocks — wide pulse = N × latency. */
        t0 = rdcycle();
        sink ^= prvBenchBurst();
        prvPulseAvgUpdate(1u, rdcycle() - t0);

        for (volatile uint32_t d = 0u; d < INTER_PULSE_GAP; d++) {}

        /* Pulse 3: key schedule — time for Magma round-key expansion. */
        t0 = rdcycle();
        prvBenchKeySchedule();
        prvPulseAvgUpdate(2u, rdcycle() - t0);

        for (volatile uint32_t d = 0u; d < INTER_PULSE_GAP; d++) {}

        /* Pulse 4: single block, software reference — compare width to Pulse 1. */
        t0 = rdcycle();
        sink ^= prvBenchSoftSingleBlock();
        prvPulseAvgUpdate(3u, rdcycle() - t0);

        for (volatile uint32_t d = 0u; d < INTER_PULSE_GAP; d++) {}

        /* Pulse 5: burst of BENCH_BLOCK_COUNT blocks, software reference —
         * compare width to Pulse 2. Expect this pulse to dwarf every other
         * one on the trace; that gap is the hardware acceleration factor. */
        t0 = rdcycle();
        sink ^= prvBenchSoftBurst();
        prvPulseAvgUpdate(4u, rdcycle() - t0);

        for (volatile uint32_t d = 0u; d < INTER_PULSE_GAP; d++) {}

        /* Pulse 6: burst of BENCH_BLOCK_COUNT blocks via CRYPTO's own
         * streaming engine — compare width to Pulse 2; the gap between them
         * is STATUS-polling overhead, not cipher compute. */
        t0 = rdcycle();
        prvBenchCryptoDmaBurst();
        prvPulseAvgUpdate(5u, rdcycle() - t0);

        /* Long idle — lets the oscilloscope frame one complete iteration. */
        for (volatile uint32_t d = 0u; d < ITER_IDLE_GAP; d++) {}

        /* Unsigned subtraction wraps correctly across the 32-bit rdcycle()
         * rollover (~85 s at CORE_CLK_HZ); PRINT_INTERVAL_CYCLES (~3 s) is
         * far under that, so this is safe every time through the loop. */
        if ((rdcycle() - last_print_cycle) >= PRINT_INTERVAL_CYCLES) {
            prvUartPrintTable();
            last_print_cycle = rdcycle();
        }
    }
}

/* Weak stub — resolves plic.c's debug_uart_log() reference in exception paths. */
__attribute__((weak)) void debug_uart_log(const char *fmt, ...) { (void)fmt; }
