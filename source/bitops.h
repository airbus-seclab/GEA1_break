#ifndef __BITOPS_H__
#define __BITOPS_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Macros
#define GET_BIT(x, i)       (((x)>>(i))&1)
#define SET_BIT(x, i, b)    ((x) |= ((b)<<(i)))

// Inlined routines

#if 0
static __inline__
uint64_t invert_bits_qword(uint64_t a)
{
    uint64_t b = 0;
    uint64_t x;
    int i;

    for(i=0; i<64; i++) {
        x = GET_BIT(a, i);
        b |= (x<<(63-i));
    }
    return b;
}

static __inline__
uint64_t invert_bits_dword(uint32_t a)
{
    uint64_t b = 0;
    uint32_t x;
    int i;

    for(i=0; i<32; i++) {
        x = GET_BIT(a, i);
        b |= (x<<(31-i));
    }
    return b;
}
#endif

static __inline__
uint64_t rotate_left(uint64_t val, int n, int shift)
{
    return ((val >> (n-shift)) | ((val << shift) & ((1UL<<n)-1)));
}

static __inline__
uint64_t rotate_right(uint64_t x, int n, int shift)
{
    return ((uint64_t)(x & ((1UL << shift)-1)) << (n-shift) | (x >> shift));
}

#endif /* __BITOPS_H__ */
