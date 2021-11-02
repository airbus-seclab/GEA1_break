#ifndef __TRANSFORM_H__
#define __TRANSFORM_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// TODO: nrows
static __inline__
void transform_vect_2_dword(mzd_t *C, uint32_t *d)
{
    uint32_t tmp = 0;
    int i, nr_bits = C->nrows;

    ASSERT(nr_bits <= 32);

    for(i=0; i<nr_bits; i++) {
        int b = mzd_read_bit(C, i, 0);
        if(b)
            tmp |= (1U<<i);
    }
    *d = tmp;
}

static __inline__
void transform_vect_2_qword(mzd_t *C, uint64_t *q)
{
    uint64_t tmp = 0;
    int i, nr_bits = C->nrows;

    ASSERT(nr_bits <= 64);

    for(i=0; i<nr_bits; i++) {
        int b = mzd_read_bit(C, i, 0);
        if(b)
            tmp |= (1UL<<i);
    }
    *q = tmp;
}

static __inline__
void transform_dword_2_vect(uint32_t d, mzd_t *x)
{
    int i, b;

    ASSERT(x->nrows <= 32);

    for(i=0; i<x->nrows; i++) {
        b = (d >> i) & 0x1;
        mzd_write_bit(x, i, 0, b);
    }
}

static __inline__
void transform_qword_2_vect(uint64_t q, mzd_t *x)
{
    int i, b;

    ASSERT(x->nrows <= 64);

    for(i=0; i<x->nrows; i++) {
        b = (q >> i) & 0x1;
        mzd_write_bit(x, i, 0, b);
    }
}

static __inline__
void transform_list_2_qword(uint8_t *L, int nr_bits, uint64_t *q)
{
    uint64_t tmp = 0;
    int i;

    ASSERT(nr_bits <= 64);

    for(i=0; i<nr_bits; i++) {
        int b = L[i];
        if(b)
            tmp |= (1UL<<i);
    }
    *q = tmp;
}

static __inline__
void transform_qword_2_list(uint64_t q, uint8_t *L, int nr_bits)
{
    int i, b;

    ASSERT(nr_bits <= 64);

    for(i=0; i<nr_bits; i++) {
        b = (q >> i) & 0x1;
        L[i] = b;
    }
}

static __inline__
void transform_dword_2_list(uint32_t d, uint8_t *L, int nr_bits)
{
    int i, b;

    ASSERT(nr_bits <= 32);

    for(i=0; i<nr_bits; i++) {
        b = (d >> i) & 0x1;
        L[i] = b;
    }
}

#endif /* __TRANSFORM_H__ */
