/**
 * @file main.c
 * @brief Magma (GOST R 34.12-2018) hardware accelerator workbench.
 *
 * Measures cipher latency and throughput via GPIO timing markers, and
 * cross-checks a plain-C software reference implementation of Magma
 * against the same hardware so the two can be compared on-scope.
 * Connect an oscilloscope to GPIOB pin 0 (PROBE_PIN).
 *
 * Five back-to-back pulses are emitted in each iteration:
 *   Pulse 1 — single ECB block, hardware (one cipher latency)
 *   Pulse 2 — burst of BENCH_BLOCK_COUNT ECB blocks, hardware (throughput window)
 *   Pulse 3 — key schedule only, hardware (UPDATE_KEY latency)
 *   Pulse 4 — single block, software reference (directly comparable to Pulse 1)
 *   Pulse 5 — burst of BENCH_BLOCK_COUNT blocks, software reference (comparable to Pulse 2)
 *
 * The software pulses are expected to be orders of magnitude wider than
 * their hardware counterparts — that gap *is* the measurement. Re-time the
 * scope per pulse pair rather than expecting one timebase to frame all five
 * usefully.
 *
 * Before the loop starts, the software implementation's output is checked
 * once against the hardware engine's output for the same test block (see
 * "software/hardware cross-check" below); on a mismatch the probe pin is
 * driven into a fast, unmistakable blink instead of reporting misleading
 * comparison data.
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
/** @} */

/* ---- main --------------------------------------------------------------- */

int main(void)
{
    SystemInit();       /* configure PLL → 50 MHz */
    prvClocksInit();
    prvProbeInit();
    prvMagmaKeyLoad();

    /* software/hardware cross-check -------------------------------------
     * Encrypt the same test block with both engines once, before trusting
     * either for comparison timing. The key in this file is a NIIET demo
     * vector, not RFC 8891's published test key, so there is no literal
     * "known-good" ciphertext to check against here — the hardware engine
     * itself is the reference. On a mismatch, don't run the benchmark loop
     * at all: park in a fast, unmistakable blink instead of emitting
     * pulses that would silently compare two different ciphers. */
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
            for (;;) {
                probe_high();
                for (volatile uint32_t d = 0u; d < 20000u; d++) {}
                probe_low();
                for (volatile uint32_t d = 0u; d < 20000u; d++) {}
            }
        }
    }

    /* sink prevents the return values of bench functions from being optimised away. */
    volatile uint32_t sink = 0u;

    for (;;)
    {
        /* Pulse 1: single ECB block — narrow pulse = one cipher latency. */
        sink ^= prvBenchSingleBlock();

        for (volatile uint32_t d = 0u; d < INTER_PULSE_GAP; d++) {}

        /* Pulse 2: burst of BENCH_BLOCK_COUNT blocks — wide pulse = N × latency. */
        sink ^= prvBenchBurst();

        for (volatile uint32_t d = 0u; d < INTER_PULSE_GAP; d++) {}

        /* Pulse 3: key schedule — time for Magma round-key expansion. */
        prvBenchKeySchedule();

        for (volatile uint32_t d = 0u; d < INTER_PULSE_GAP; d++) {}

        /* Pulse 4: single block, software reference — compare width to Pulse 1. */
        sink ^= prvBenchSoftSingleBlock();

        for (volatile uint32_t d = 0u; d < INTER_PULSE_GAP; d++) {}

        /* Pulse 5: burst of BENCH_BLOCK_COUNT blocks, software reference —
         * compare width to Pulse 2. Expect this pulse to dwarf every other
         * one on the trace; that gap is the hardware acceleration factor. */
        sink ^= prvBenchSoftBurst();

        /* Long idle — lets the oscilloscope frame one complete iteration. */
        for (volatile uint32_t d = 0u; d < ITER_IDLE_GAP; d++) {}
    }
}

/* Weak stub — resolves plic.c's debug_uart_log() reference in exception paths. */
__attribute__((weak)) void debug_uart_log(const char *fmt, ...) { (void)fmt; }
