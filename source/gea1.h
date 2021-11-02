#ifndef __GEA1_H__
#define __GEA1_H__

#include "bitops.h"

// The original function which is slow as hell from an assembly point of
// view. Should absolutely not be used as if during bf stages.

static __inline__
uint32_t f(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t x4, uint32_t x5, uint32_t x6)
{
    uint32_t r;

    r  = x0*x2*x5*x6 + x0*x3*x5*x6 + x0*x1*x5*x6;
    r += x1*x2*x5*x6 + x0*x2*x3*x6 + x1*x3*x4*x6;
    r += x1*x3*x5*x6 + x0*x2*x4 + x0*x2*x3 + x0*x1*x3;
    r += x0*x2*x6 + x0*x1*x4 + x0*x1*x6;
    r += x1*x2*x6 + x2*x5*x6 + x0*x3*x5 + x1*x4*x6;
    r += x1*x2*x5 + x0*x3 + x0*x5 + x1*x3;
    r += x1*x5 + x1*x6 + x0*x2 + x1 + x2*x3 + x2*x5 + x2*x6 + x4*x5 + x5*x6 + x2 + x3 + x5;
    return r&1;
}

// First optimization for f computation.
extern uint8_t f_table[128];

static __inline__
uint64_t RegisterA2(uint64_t state, int nr_bits)
{
    uint64_t lfsr = state;
    uint64_t res = 0;
    uint64_t b;
    int lsb, period = 0;

    ASSERT(nr_bits <= 64);

    uint8_t x00;
    for(period=0; period<nr_bits; period++) {

        x00 = 0;
        SET_BIT(x00, 0, GET_BIT(lfsr, 22));
        SET_BIT(x00, 1, GET_BIT(lfsr, 0));
        SET_BIT(x00, 2, GET_BIT(lfsr, 13));
        SET_BIT(x00, 3, GET_BIT(lfsr, 21));
        SET_BIT(x00, 4, GET_BIT(lfsr, 25));
        SET_BIT(x00, 5, GET_BIT(lfsr, 2));
        SET_BIT(x00, 6, GET_BIT(lfsr, 7));
        b = f_table[x00];

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
static __inline__
uint64_t RegisterB2(uint32_t state, int nr_bits)
{
    uint32_t lfsr = state;
    uint64_t res = 0;
    uint64_t b;
    int lsb, period = 0;

    ASSERT(nr_bits <= 64);

    uint8_t x00;
    for(period=0; period<nr_bits; period++) {

        x00 = 0;
        SET_BIT(x00, 0, GET_BIT(lfsr, 12));
        SET_BIT(x00, 1, GET_BIT(lfsr, 27));
        SET_BIT(x00, 2, GET_BIT(lfsr, 0));
        SET_BIT(x00, 3, GET_BIT(lfsr, 1));
        SET_BIT(x00, 4, GET_BIT(lfsr, 29));
        SET_BIT(x00, 5, GET_BIT(lfsr, 21));
        SET_BIT(x00, 6, GET_BIT(lfsr, 5));
        b = f_table[x00];

        res |= (b<<period);
        lsb = lfsr&1;
        lfsr >>= 1;
        if (lsb) {
            lfsr ^= (0xf1c0f045); // aka a20f038f reversed
        }
    }
    return res;
}

static __inline__
uint64_t RegisterC2(uint64_t state, int nr_bits)
{
    uint64_t lfsr = state;
    uint64_t res = 0;
    uint64_t b;
    int lsb, period = 0;

    ASSERT(nr_bits <= 64);

    uint8_t x00;
    for(period=0; period<nr_bits; period++) {

        x00 = 0;
        SET_BIT(x00, 0, GET_BIT(lfsr, 10));
        SET_BIT(x00, 1, GET_BIT(lfsr, 30));
        SET_BIT(x00, 2, GET_BIT(lfsr, 32));
        SET_BIT(x00, 3, GET_BIT(lfsr, 3));
        SET_BIT(x00, 4, GET_BIT(lfsr, 19));
        SET_BIT(x00, 5, GET_BIT(lfsr, 0));
        SET_BIT(x00, 6, GET_BIT(lfsr, 4));
        b = f_table[x00];

        res |= (b<<period);
        lsb = lfsr&1;
        lfsr >>= 1;
        if (lsb) {
            lfsr ^= (0x150e6fa24UL); // aka 0x48bece15 reversed
        }
    }
    return res;
}

#endif /* __GEA1_H__ */
