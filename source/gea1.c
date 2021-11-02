#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "exploit.h"
#include "bitops.h"
#include "gea1.h"
#include "transform.h"

uint8_t f_table[128];

// Unfortunately the penalty will be the bit extraction time.
void setup_f_table(void)
{
    int i, res;
    uint32_t x0, x1, x2, x3, x4, x5, x6;
    for(i=0; i<128; i++) {
        x0 = GET_BIT(i,0);
        x1 = GET_BIT(i,1);
        x2 = GET_BIT(i,2);
        x3 = GET_BIT(i,3);
        x4 = GET_BIT(i,4);
        x5 = GET_BIT(i,5);
        x6 = GET_BIT(i,6);
        res = f(x0, x1, x2, x3, x4, x5, x6);
        f_table[i] = res;
    }
}

uint32_t apply_f_2_S_fwd(uint8_t *S)
{
    return f(S[3], S[12], S[22], S[38], S[42], S[55], S[63]);
}

uint32_t apply_f_2_S_bwd(uint8_t *S)
{
    return f(S[2], S[11], S[21], S[37], S[41], S[54], S[62]);
}

void clock_S_backward(uint8_t *S_out, uint8_t *S_in, uint8_t *F, int F_len)
{
    int i=0, j=0;
    uint32_t old_fb, old_b0;

    ASSERT(F_len > 0);

    memcpy(S_out, S_in, 64); 
    for(i=0; i<F_len; i++) {
        old_fb = apply_f_2_S_bwd(S_out);
        old_b0 = (old_fb + F[F_len-1-i] + S_out[63])&1;
        for(j=0; j<63; j++) {
            S_out[63-j] = S_out[63-j-1];
        }
        S_out[0] = old_b0;
    }
    return;
}

void clock_S_forward(uint8_t *S_out, uint8_t *S_in, uint8_t *F, int F_len)
{
    uint32_t fb;
    int i, j;

    ASSERT(F_len > 0);

    memcpy(S_out, S_in, 64); 
    for(i=0; i<F_len; i++) {
        fb = apply_f_2_S_fwd(S_out) ^ S_out[0] ^ F[i];
        for(j=0; j<63; j++) {
            S_out[j] = S_out[j+1];
        }
        S_out[63] = fb;
    }
    return;
}

void init_S(uint8_t *S, uint8_t *K, uint8_t *IV, int dir)
{
    /*
     * Initialization of the S register and extraction of its content
     * once feeded with IV, K, dir
     */

    uint8_t F[225];
    uint8_t bit = dir&1;

    memcpy(&F[0], IV, 32);
    memcpy(&F[32], &bit, 1);
    memcpy(&F[33], K, 64);
    memset(&F[97], 0, 128);

    memset(S, 0, 64);

    clock_S_forward(S, S, F, 225);
}

// 31 bits register
uint64_t lfsr_galois_A(uint64_t state, int nr_bits)
{
    uint64_t lfsr = state;
    uint64_t res = 0;
    int lsb, period = 0;

    ASSERT(nr_bits <= 64);

    for(period=0; period<nr_bits; period++) {

        lsb = lfsr & 1;
        lfsr >>= 1;
        lfsr &= ((1UL << REG_A_SIZE)-1);
        if (lsb) {
            res |= (1UL<<period);
            lfsr ^= (0x5dd89b8d); // aka 0x58ec8ddd reversed
        }
    }
    return res;
}

uint64_t lfsr_galois_B(uint64_t state, int nr_bits)
{
    uint64_t lfsr = state;
    uint64_t res = 0;
    int lsb, period = 0;

    ASSERT(nr_bits <= 64);

    for(period=0; period<nr_bits; period++) {

        lsb = lfsr & 1;
        lfsr >>= 1;
        lfsr &= ((1UL << REG_B_SIZE)-1);
        if (lsb) {
            res |= (1UL<<period);
            lfsr ^= (0xf1c0f045); // aka a20f038f reversed
        }
    }
    return res;
}

uint64_t lfsr_galois_C(uint64_t state, int nr_bits)
{
    uint64_t lfsr = state;
    uint64_t res = 0;
    int lsb, period = 0;

    ASSERT(nr_bits <= 64);

    for(period=0; period<nr_bits; period++) {

        lsb = lfsr & 1;
        lfsr >>= 1;
        lfsr &= ((1UL << REG_C_SIZE)-1);

        if (lsb) {
            res |= (1UL<<period);
            lfsr ^= (0x150e6fa24UL); // aka 0x48bece15 reversed
        }
    }
    return res;
}

uint64_t RegisterA(uint64_t state, int nr_bits)
{
    uint64_t lfsr = state;
    uint64_t res = 0;
    uint64_t b;
    int lsb, period = 0;

    ASSERT(nr_bits <= 64);

    for(period=0; period<nr_bits; period++) {

         b = f(GET_BIT(lfsr, 22),
               GET_BIT(lfsr, 0),
               GET_BIT(lfsr, 13),
               GET_BIT(lfsr, 21),
               GET_BIT(lfsr, 25),
               GET_BIT(lfsr, 2),
               GET_BIT(lfsr, 7));

        res |= (b<<period);
        lsb = lfsr&1;
        lfsr >>= 1;
        if (lsb) {
            lfsr ^= (0x5dd89b8d); // aka 0x58ec8ddd reversed
        }
    }
    return res;
}

// TODO: nr_bits vs 32 bits
uint64_t RegisterB(uint32_t state, int nr_bits)
{
    uint32_t lfsr = state;
    uint64_t res = 0;
    uint64_t b;
    int lsb, period = 0;

    ASSERT(nr_bits <= 64);

    for(period=0; period<nr_bits; period++) {

        b = f(GET_BIT(lfsr, 12), // b1  4
              GET_BIT(lfsr, 27), // b3  3
              GET_BIT(lfsr, 0),  // b0  0
              GET_BIT(lfsr, 1),  // b0  1
              GET_BIT(lfsr, 29), // b3  5
              GET_BIT(lfsr, 21), // b2  5
              GET_BIT(lfsr, 5)); // b0  5

        res |= (b<<period);
        lsb = lfsr&1;
        lfsr >>= 1;
        if (lsb) {
            lfsr ^= (0xf1c0f045); // aka a20f038f reversed
        }
    }
    return res;
}

uint64_t RegisterC(uint64_t state, int nr_bits)
{
    uint64_t lfsr = state;
    uint64_t res = 0;
    uint64_t b;
    int lsb, period = 0;

    ASSERT(nr_bits <= 64);

    for(period=0; period<nr_bits; period++) {

         b = f(GET_BIT(lfsr, 10),
               GET_BIT(lfsr, 30),
               GET_BIT(lfsr, 32),
               GET_BIT(lfsr, 3),
               GET_BIT(lfsr, 19),
               GET_BIT(lfsr, 0),
               GET_BIT(lfsr, 4));

        res |= (b<<period);
        lsb = lfsr&1;
        lfsr >>= 1;
        if (lsb) {
            lfsr ^= (0x150e6fa24UL); // aka 0x48bece15 reversed
        }
    }
    return res;
}

uint64_t init_A(uint64_t S)
{
    uint64_t lfsr = 0;
    uint64_t m0, m1, lsb;
    uint64_t state;
    int period = 0;

    state = rotate_right(S, 64, SHIFT_A);
    for(period=0; period<64; period++) {

        m0 = lfsr & 1;
        m1 = state & 1;
        lsb = m0 ^ m1;
        lfsr >>= 1;
        lfsr &= ((1UL << REG_A_SIZE)-1);
        if (lsb) {
            lfsr ^= (0x5dd89b8d); // aka 0x58ec8ddd reversed
        }
        state = rotate_right(state, 64, 1);

    }
    return lfsr;
}

uint64_t init_B(uint64_t S)
{
    uint64_t lfsr = 0;
    uint64_t m0, m1, lsb;
    uint64_t state;
    int period = 0;

    state = rotate_right(S, 64, SHIFT_B);
    for(period=0; period<64; period++) {
        m0 = lfsr & 1;
        m1 = state & 1;
        lsb = m0 ^ m1;
        lfsr >>= 1;
        lfsr &= ((1UL << REG_B_SIZE)-1);
        if (lsb) {
            lfsr ^= (0xf1c0f045); // aka 0xa20f038f reversed
        }
        state = rotate_right(state, 64, 1);
    }
    return lfsr;
}

uint64_t init_C(uint64_t S)
{
    uint64_t lfsr = 0;
    uint64_t m0, m1, lsb;
    uint64_t state;
    int period = 0;

    state = rotate_right(S, 64, SHIFT_C);
    for(period=0; period<64; period++) {
        m0 = lfsr & 1;
        m1 = state & 1;
        lsb = m0 ^ m1;
        lfsr >>= 1;
        lfsr &= ((1UL << REG_C_SIZE)-1);
        if (lsb) {
            lfsr ^= (0x150e6fa24UL); // aka 0x48bece15 reversed
        }
        state = rotate_right(state, 64, 1);
    }
    return lfsr;
}

// It is not optimized at all but we do not use it anyway.
// The function is just meant to verify the correctness of the
// implementation.

#define __GEA1_DBG__ 0

int GEA1(uint64_t K, uint32_t IV, int dir, uint64_t *bitstream)
{
    uint8_t S[64];
    uint8_t K_array[64];
    uint8_t IV_array[32];
    uint64_t  qSA, qSB, qSC;
    uint64_t qS = 0;
    uint64_t LA, LB, LC;

    ASSERT(bitstream);

    transform_dword_2_list(IV, IV_array, 32);
    transform_qword_2_list(K, K_array, 64);
    init_S(S, K_array, IV_array, dir);
    transform_list_2_qword(S, 64, &qS);

#if __GEA1_DBG__
    printf("K = %lx, IV = %x, dir=%d\n", K, IV, dir);
    printf("S = %lx\n", qS);
#endif

    qSA = init_A(qS);
    qSB = init_B(qS);
    qSC = init_C(qS);

#if __GEA1_DBG__
    printf("A = %lx\n", qSA);
    printf("B = %lx\n", qSB);
    printf("C = %lx\n", qSC);
#endif

    if(!qSA) {
        qSA |= 1;
    }

    if(!qSB) {
        qSB |= 1;
    }

    if(!qSC) {
        qSC |= 1;
    }

    LA = RegisterA2(qSA, 64);
    LB = RegisterB2(qSB, 64);
    LC = RegisterC2(qSC, 64);

    *bitstream = LA ^ LB ^ LC;
#if __GEA1_DBG__
    printf("Bitstream = %lx\n", *bitstream);
#endif
    return 0;
}
