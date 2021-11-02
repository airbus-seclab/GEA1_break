#include <stdio.h>
#include <stdlib.h>
#include <x86intrin.h>

#include "exploit.h"
#include "bitops.h"
#include "gea1.h"
#include "transform.h"

static __inline__
void __test_cpu_load(uint32_t nr_cores, uint32_t nr_rounds, uint64_t nr_elements)
{
    uint64_t lower_bound, lower_bound_0, last_upper_bound = 0;
    uint64_t upper_bound, upper_bound_0;

    lower_bound_0 = 0;
    upper_bound_0 = nr_elements-1;

    for(uint32_t i=0; i<nr_cores; i++) {
        for(uint32_t j=0; j<nr_rounds; j++) {

            cpu_get_work(&lower_bound, &upper_bound, i, j, nr_cores, nr_rounds, nr_elements);
            assert(upper_bound >= lower_bound);
            if(i==0 && j==0) {
                last_upper_bound = upper_bound;
                assert(lower_bound == lower_bound_0);
            } else {
                assert(lower_bound == (last_upper_bound+1));
                last_upper_bound = upper_bound;
            }
        }
    }
    assert(upper_bound == upper_bound_0);
}

void test_cpu_load()
{
    uint64_t array_nr_elements[3] = { NR_V_ELEMENTS_MAX, NR_TAC_ELEMENTS_MAX, NR_UB_ELEMENTS_MAX };

    for(int i=1; i<201; i++) {
        for(int j=2; j<=8; j+=2) {
            for(int k=0; k<3; k++) {
                if((uint64_t)(i*j) > array_nr_elements[k])
                    continue;
                __test_cpu_load(i, j, array_nr_elements[k]);
            }
        }
    }
}

void test_hw()
{
    uint64_t i;
    int nr_w_1 = 0;

    for(i=0; i<64; i++) {
        int w = hamming_weight(1UL<<i);
        assert(w == 1);
    }

    for(int k=0; k<=25; k++) {
        nr_w_1 = 0;
        for(i=0; i<(1UL<<k); i++) {
            if(hamming_weight(i) == 1) {
                nr_w_1++;
            }
        }
        assert(nr_w_1 == k);
    }
}

void test_rotate()
{
    uint64_t x, y, z;
    int i,n;

    for(i=0; i<0xFFF; i++) {
        // Pick x
        x = random();
        x <<= 32;
        x |= random();
        
        // Pick n
        n = random() % 64;
        
        // rotate & check
        y = rotate_left(x, 64, n);
        assert((x!=y) || (x==y && n==0));
        z = rotate_right(y, 64, n);
        assert(x == z);
    }
}

void test_init_S()
{
    uint8_t S[64];
    uint8_t IV[GEA1_IV_LENGTH];
    uint8_t K[GEA1_KEY_LENGTH];
    int ret;
    uint8_t S0[64] = { 0, 0, 0, 0, 0, 1, 1, 0,
                       0, 1, 1, 1, 0, 1, 0, 1,
                       1, 0, 0, 1, 0, 0, 1, 0,
                       1, 1, 1, 0, 0, 0, 0, 0,
                       1, 0, 0, 1, 1, 1, 0, 0,
                       0, 0, 1, 1, 1, 1, 1, 1,
                       0, 1, 1, 0, 0, 1, 1, 0,
                       0, 0, 1, 0, 1, 1, 1, 1 };
    
    uint8_t S1[64] = { 1, 0, 0, 0, 0, 0, 1, 0,
                       1, 0, 1, 1, 1, 1, 0, 1,
                       1, 1, 1, 1, 1, 0, 0, 0,
                       1, 1, 0, 0, 1, 0, 0, 0,
                       1, 1, 1, 0, 0, 0, 0, 0,
                       1, 1, 1, 1, 1, 0, 1, 0,
                       1, 0, 0, 1, 0, 0, 0, 1,
                       1, 1, 0, 1, 1, 0, 0, 0 };
    
    // Test #1
    
    memset(IV, 0, sizeof(IV));
    memset(K, 1, sizeof(K));
    
    init_S(S, K, IV, 0);
    ret = memcmp(S, S0, 64);
    assert(ret == 0);
    
    // Test #2

    memset(IV, 1, sizeof(IV));
    memset(K, 0, sizeof(K));

    IV[3] = 0;
    IV[9] = 0;
    IV[17] = 0;

    K[2] = 1;
    K[12] = 1;
    K[27] = 1;

    init_S(S, K, IV, 1);    
    ret = memcmp(S, S1, 64);
    assert(ret == 0);
}

// test_deciphering_stage2.sage
void test_retrieve_K()
{
    uint8_t IV0[GEA1_IV_LENGTH] = {
          1, 1, 1, 1, 0, 0, 0, 0,
          1, 1, 1, 1, 0, 0, 0, 0,
          1, 1, 1, 1, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0
    };

    uint8_t K0[GEA1_KEY_LENGTH] = {
          0, 0, 0, 0, 1, 1, 1, 1,
          0, 0, 0, 0, 1, 1, 1, 1,
          0, 0, 0, 0, 1, 1, 1, 1,
          0, 0, 0, 0, 1, 1, 1, 1,
          0, 0, 0, 0, 1, 1, 1, 1,
          0, 0, 0, 0, 1, 1, 1, 1,
          0, 0, 0, 0, 1, 1, 1, 1,
          0, 0, 0, 0, 1, 1, 1, 1
    };

    uint8_t S_test0[64] = {
          0, 1, 0, 1, 0, 0, 0, 1,
          1, 1, 1, 0, 0, 0, 0, 1,
          1, 1, 1, 0, 1, 1, 0, 1,
          1, 1, 0, 0, 0, 1, 0, 1,
          0, 1, 0, 1, 0, 1, 1, 0,
          1, 1, 0, 1, 1, 0, 1, 0,
          1, 1, 1, 1, 0, 1, 1, 1,
          0, 1, 1, 0, 1, 0, 1, 0
    };

    uint8_t S[64];
    uint8_t K[GEA1_KEY_LENGTH];
    int ret;

    memset(S, 0, sizeof(S));
    init_S(S, K0, IV0, 1);

    ret = memcmp(S, S_test0, sizeof(S));
    assert(ret == 0);

    retrieve_K(K, S, IV0, 1);
    ret = memcmp(K, K0, sizeof(K0));
    assert(ret == 0);
}

int cmp_bitstream_with_array(uint64_t z, int z_len, uint8_t *array)
{
    int i;

    for(i=0; i<z_len; i++) {
        if(array[i] != ((z >> i)&1)) {
            return 1;
        }
    }
    return 0;
}

int cmp_vectors(mzd_t *a, mzd_t *b, int len)
{
    int i, b1, b2;

    for(i=0; i<len; i++) {
        b1 = mzd_read_bit(a, i, 0);
        b2 = mzd_read_bit(b, i, 0);
        if(b1 != b2)
            return 1;
    }
    return 0;
}

/* Some routine to check the consistency between:
 * transform_vect_2_dword()
 * transform_dword_2_vect()
 */

void test_transform_state1()
{
    uint32_t d=0, ret, i, j;
    mzd_t *C1 = mzd_init(32,1);
    mzd_t *C2 = mzd_init(32,1);

    for(i=0; i<256; i++) {

        for(j=0; j<32; j++) {

            d = 0;
            if(rand()%1) {
                mzd_write_bit(C1, j, 0, 1);
            } else {
                mzd_write_bit(C1, j, 0, 0);
            }

            transform_vect_2_dword(C1, &d);
            transform_dword_2_vect(d, C2);

            ret = cmp_vectors(C1, C2, 32);
            assert(ret == 0);
        }
    }

    mzd_free(C1);
    mzd_free(C2);
    return;
}

void test_transform_state2()
{
    uint64_t q=0, ret, i, j;
    mzd_t *C1 = mzd_init(64,1);
    mzd_t *C2 = mzd_init(64,1);

    for(i=0; i<256; i++) {

        for(j=0; j<64; j++) {

            q = 0;
            if(rand()%1) {
                mzd_write_bit(C1, j, 0, 1);
            } else {
                mzd_write_bit(C1, j, 0, 0);
            }

            transform_vect_2_qword(C1, &q);
            transform_qword_2_vect(q, C2);

            ret = cmp_vectors(C1, C2, 64);
            assert(ret == 0);
        }
    }

    mzd_free(C1);
    mzd_free(C2);
    return;
}

void test_registerC()
{
    // state = 0x1ffffffff
    uint8_t bitstream_LFSR_C[64] = { 1, 1, 1, 0, 0, 0, 0, 0,
                                     0, 1, 0, 0, 0, 1, 0, 1,
                                     1, 1, 0, 0, 0, 0, 0, 0,
                                     1, 0, 0, 0, 1, 0, 0, 1,
                                     0, 1, 0, 0, 0, 0, 1, 1,
                                     1, 0, 1, 1, 1, 1, 1, 0,
                                     1, 0, 0, 0, 1, 0, 1, 1,
                                     1, 0, 0, 1, 0, 1, 0, 1 };

    // state = 0x1ffffffff
    uint8_t bitstream_regC[64] =   { 1, 1, 0, 0, 1, 0, 1, 0,
                                     0, 0, 1, 0, 1, 1, 1, 0,
                                     1, 0, 0, 1, 1, 1, 0, 0,
                                     1, 1, 0, 1, 1, 0, 0, 1,
                                     0, 0, 0, 0, 0, 0, 1, 0,
                                     0, 1, 0, 0, 1, 0, 1, 0,
                                     1, 1, 0, 1, 1, 1, 0, 0,
                                     0, 0, 0, 1, 1, 1, 1, 0 };

    uint64_t bitstream;
    int i, ret;

    for(i=1; i<=64; i++) {
        bitstream = lfsr_galois_C(0x1ffffffff, i);
        ret = cmp_bitstream_with_array(bitstream, i, bitstream_LFSR_C);
        assert(ret == 0);
        if(i==64)
            assert(bitstream == 0xa9d17dc29103a207);
    }

    for(i=1; i<=64; i++) {
        bitstream = RegisterC(0x1ffffffff, i);
        ret = cmp_bitstream_with_array(bitstream, i, bitstream_regC);
        assert(ret == 0);
        if(i==64)
            assert(bitstream == 0x783b52409b397453);
    }

    for(i=1; i<=64; i++) {
        bitstream = RegisterC2(0x1ffffffff, i);
        ret = cmp_bitstream_with_array(bitstream, i, bitstream_regC);
        assert(ret == 0);
        if(i==64)
            assert(bitstream == 0x783b52409b397453);
    }

}

void test_registerA()
{
    // state = 0x7ffffff1
    uint8_t bitstream_LFSR_A[64] = { 1, 1, 1, 0, 1, 0, 0, 0,
                                     1, 0, 0, 0, 1, 1, 1, 0,
                                     0, 0, 0, 1, 0, 0, 1, 1,
                                     0, 0, 1, 0, 1, 0, 0, 0,
                                     0, 0, 0, 0, 0, 1, 0, 0,
                                     1, 0, 1, 1, 0, 0, 1, 1,
                                     1, 1, 0, 0, 1, 0, 0, 1,
                                     0, 0, 0, 0, 1, 0, 1, 1 };

    // state = 0xeadbeef
    uint8_t bitstream_regA[64] =   { 1, 0, 0, 0, 1, 1, 1, 1,
                                     1, 1, 0, 0, 0, 1, 1, 0,
                                     1, 0, 0, 0, 1, 1, 1, 1,
                                     0, 1, 1, 1, 1, 0, 1, 0,
                                     1, 0, 1, 0, 0, 0, 0, 1,
                                     1, 0, 0, 1, 0, 1, 1, 0,
                                     1, 0, 0, 1, 1, 0, 1, 0,
                                     0, 0, 1, 1, 1, 1, 0, 1 };

    uint64_t bitstream;
    int i, ret;

    for(i=1; i<=64; i++) {
        bitstream = lfsr_galois_A(0x7ffffff1, i);
        ret = cmp_bitstream_with_array(bitstream, i, bitstream_LFSR_A);
        assert(ret == 0);
        if(i==64)
            assert(bitstream == 0xd093cd2014c87117);
    }

    for(i=1; i<=64; i++) {
        bitstream = RegisterA(0xeadbeef, i);
        ret = cmp_bitstream_with_array(bitstream, i, bitstream_regA);
        assert(ret == 0);
        if(i==64)
            assert(bitstream == 0xbc5969855ef163f1);
    }

    for(i=1; i<=64; i++) {
        bitstream = RegisterA2(0xeadbeef, i);
        ret = cmp_bitstream_with_array(bitstream, i, bitstream_regA);
        assert(ret == 0);
        if(i==64)
            assert(bitstream == 0xbc5969855ef163f1);
    }
}

void test_registerB()
{
    // state = 0xffffffff
    uint8_t bitstream_LFSR_B_0[64] = { 1, 0, 1, 1, 0, 0, 0, 0,
                                       1, 1, 1, 1, 1, 0, 1, 0,
                                       1, 0, 0, 0, 1, 0, 1, 0,
                                       0, 0, 0, 1, 1, 0, 1, 1,
                                       1, 0, 0, 0, 0, 1, 0, 0,
                                       1, 0, 1, 1, 0, 0, 1, 0,
                                       0, 1, 1, 0, 0, 1, 1, 0,
                                       0, 1, 1, 0, 1, 0, 0, 0 };

    // state = 0xfffffffe
    uint8_t bitstream_LFSR_B_1[64] = { 0, 1, 0, 1, 1, 0, 0, 0,
                                       0, 1, 1, 1, 1, 1, 0, 1,
                                       0, 1, 0, 0, 0, 1, 0, 1,
                                       0, 0, 0, 0, 1, 1, 0, 1,
                                       0, 0, 1, 0, 1, 0, 1, 0,
                                       1, 1, 0, 1, 1, 1, 1, 0,
                                       1, 1, 1, 1, 1, 1, 0, 0,
                                       0, 0, 1, 0, 0, 0, 1, 0 };

    // state = 0xffffffff
    uint8_t bitstream_regB_0[16] = { 1, 0, 1, 1, 1, 0, 0, 1,
                                     1, 1, 1, 0, 0, 0, 0, 0 };

    // state = 0xc0000000
    uint8_t bitstream_regB_3[64] = { 0, 0, 0, 1, 1, 0, 0, 0,
                                     0, 1, 1, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 1, 1, 0,
                                     1, 1, 1, 0, 0, 1, 0, 0,
                                     0, 0, 0, 0, 1, 1, 0, 1,
                                     0, 0, 1, 1, 0, 1, 1, 1,
                                     1, 1, 1, 0, 0, 1, 0, 0 };

    uint64_t bitstream;
    int nr_bits;
    int ret;

    setup_f_table();

    // lfsr_galois_B
    nr_bits = 64;
    bitstream = lfsr_galois_B(0xffffffff, nr_bits);
    ret = cmp_bitstream_with_array(bitstream, nr_bits, bitstream_LFSR_B_0);
    assert(ret == 0);

    nr_bits = 64;
    bitstream = lfsr_galois_B(0xfffffffe, nr_bits);
    ret = cmp_bitstream_with_array(bitstream, nr_bits, bitstream_LFSR_B_1);
    assert(ret == 0);

    // RegisterB
    nr_bits = 13;
    bitstream = RegisterB(0xffffffff, nr_bits);
    ret = cmp_bitstream_with_array(bitstream, nr_bits, bitstream_regB_0);
    assert(ret == 0);

    // RegisterB2
    nr_bits = 9;
    bitstream = RegisterB(0xffffffff, nr_bits);
    ret = cmp_bitstream_with_array(bitstream, nr_bits, bitstream_regB_0);
    assert(ret == 0);

    // RegisterB
    nr_bits = 64;
    bitstream = RegisterB(0xc0000000, nr_bits);
    ret = cmp_bitstream_with_array(bitstream, nr_bits, bitstream_regB_3);
    assert(ret == 0);
}

void test_initA()
{
    uint64_t state;

    uint8_t S[64];
    uint8_t IV[GEA1_IV_LENGTH];
    uint8_t K[GEA1_KEY_LENGTH];

    uint8_t S0[64];
    uint8_t S1[64] = { 0, 1, 1, 0, 1, 0, 0, 1,
                       1, 0, 1, 1, 0, 0, 1, 0,
                       0, 0, 0, 1, 0, 1, 1, 1,
                       0, 1, 1, 0, 0, 0, 1, 0,
                       1, 0, 1, 1, 0, 0, 0, 1,
                       0, 1, 0, 0, 1, 1, 0, 0,
                       1, 1, 0, 0, 1, 0, 0, 0,
                       0, 1, 1, 0, 1, 0, 1, 1  };

    uint64_t stateA_0 = 0;
    uint64_t stateA_1 = 0x298b4553;

    uint64_t q0;
    int ret;

    // 1. All 0 including dir
    memset(IV, 0, sizeof(IV));
    memset(K, 0, sizeof(K));
    memset(S, 0, sizeof(S));
    memset(S0, 0, sizeof(S0));

    init_S(S, K, IV, 0);
    ret = memcmp(S, S0, sizeof(S0));
    assert(ret == 0);

    q0 = 0;
    transform_list_2_qword(S, 64, &q0);
    state = init_A(q0);
    assert(state == stateA_0);

    // 2. All 0 but dir
    memset(IV, 0, sizeof(IV));
    memset(K, 0, sizeof(K));
    memset(S, 0, sizeof(S));

    init_S(S, K, IV, 1);
    ret = memcmp(S, S1, sizeof(S1));
    assert(ret == 0);

    q0 = 0;
    transform_list_2_qword(S, 64, &q0);
    state = init_A(q0);
    assert(state == stateA_1);
}

void test_initB()
{
    uint64_t state;

    uint8_t S[64];
    uint8_t IV[GEA1_IV_LENGTH];
    uint8_t K[GEA1_KEY_LENGTH];

    uint8_t S0[64];
    uint8_t S1[64] = { 0, 1, 1, 0, 1, 0, 0, 1,
                       1, 0, 1, 1, 0, 0, 1, 0,
                       0, 0, 0, 1, 0, 1, 1, 1,
                       0, 1, 1, 0, 0, 0, 1, 0,
                       1, 0, 1, 1, 0, 0, 0, 1,
                       0, 1, 0, 0, 1, 1, 0, 0,
                       1, 1, 0, 0, 1, 0, 0, 0,
                       0, 1, 1, 0, 1, 0, 1, 1  };

    uint64_t stateB_0 = 0;
    uint64_t stateB_1 = 0x77613c05;
    uint64_t q0;
    int ret;

    // 1. All 0 including dir
    memset(IV, 0, sizeof(IV));
    memset(K, 0, sizeof(K));
    memset(S, 0, sizeof(S));
    memset(S0, 0, sizeof(S0));

    init_S(S, K, IV, 0);
    ret = memcmp(S, S0, sizeof(S0));
    assert(ret == 0);

    q0 = 0;
    transform_list_2_qword(S, 64, &q0);
    state = init_B(q0);
    assert(state == stateB_0);

    // 2. All 0 but dir
    memset(S, 0, sizeof(S));
    memset(IV, 0, sizeof(IV));
    memset(K, 0, sizeof(K));

    init_S(S, K, IV, 1);
    ret = memcmp(S, S1, sizeof(S1));
    assert(ret == 0);

    q0 = 0;
    transform_list_2_qword(S, 64, &q0);
    state = init_B(q0);
    assert(state == stateB_1);
}

void test_initC()
{
    uint64_t state;

    uint8_t S[64];
    uint8_t IV[GEA1_IV_LENGTH];
    uint8_t K[GEA1_KEY_LENGTH];

    uint8_t S0[64];
    uint8_t S1[64] = { 0, 1, 1, 0, 1, 0, 0, 1,
                       1, 0, 1, 1, 0, 0, 1, 0,
                       0, 0, 0, 1, 0, 1, 1, 1,
                       0, 1, 1, 0, 0, 0, 1, 0,
                       1, 0, 1, 1, 0, 0, 0, 1,
                       0, 1, 0, 0, 1, 1, 0, 0,
                       1, 1, 0, 0, 1, 0, 0, 0,
                       0, 1, 1, 0, 1, 0, 1, 1  };

    uint64_t stateC_0 = 0;
    uint64_t stateC_1 = 0x87792855;
    uint64_t q0;
    int ret;

    // 1. All 0 including dir
    memset(IV, 0, sizeof(IV));
    memset(K, 0, sizeof(K));
    memset(S, 0, sizeof(S));
    memset(S0, 0, sizeof(S0));

    init_S(S, K, IV, 0);
    ret = memcmp(S, S0, sizeof(S0));
    assert(ret == 0);

    q0 = 0;
    transform_list_2_qword(S, 64, &q0);
    state = init_C(q0);
    assert(state == stateC_0);

    // 2. All 0 but dir
    memset(S, 0, sizeof(S));
    memset(IV, 0, sizeof(IV));
    memset(K, 0, sizeof(K));

    init_S(S, K, IV, 1);
    ret = memcmp(S, S1, sizeof(S1));
    assert(ret == 0);

    q0 = 0;
    transform_list_2_qword(S, 64, &q0);
    state = init_C(q0);
    assert(state == stateC_1);
}

static __inline__
void extract_params(uint64_t *K, uint32_t *IV, int *dir, uint16_t gcu_key[7])
{
    uint16_t tmp;

    memcpy(K, &gcu_key[0], 8);
    memcpy(IV, &gcu_key[4], 4);
    memcpy(&tmp, &gcu_key[6], 2);

    assert(tmp == 0x001c || tmp == 0x001e);
    if(tmp == 0x001c)
        *dir = 0;
    else
        *dir = 1;
}

static __inline__
int memcmp_bitstream(uint64_t z0, uint8_t *p, uint8_t *c)
{
    uint8_t b0, b1;
    for(int i=0; i<8; i++) {
        b0 = (z0 >> (8*i)) & 0xff;
        b1 = p[i] ^ c[i];
        if(b0 != b1)
            return 1;
    }
    return 0;
}


void test_GEA1()
{
    uint8_t gcu_plaintext_1[18]  = { 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00 };

    uint8_t gcu_ciphertext_1[18] = { 0x1F, 0xA1, 0x98, 0xAB,
                                     0x21, 0x14, 0xC3, 0x8A,
                                     0x9E, 0xBC, 0xCB, 0x63,
                                     0xAD, 0x48, 0x13, 0xA7,
                                     0x40, 0xC1 };

    uint8_t gcu_plaintext_2[18]  = { 0x91, 0xE1, 0xDB, 0x43,
                                     0x0B, 0x86, 0x40, 0x18,
                                     0xED, 0x59, 0x63, 0x9B,
                                     0xAB, 0x9A, 0x73, 0xC3,
                                     0xCD, 0xE6 };

    uint8_t gcu_ciphertext_2[18] = { 0x2A, 0x26, 0xD8, 0xFB,
                                     0x64, 0xEC, 0xF3, 0x0C,
                                     0x14, 0x7F, 0x1F, 0x16,
                                     0x5E, 0xBC, 0x8B, 0x31,
                                     0x9B, 0xE6 };

    uint8_t gcu_plaintext_3[18]  = { 0xA8, 0xCA, 0xA6, 0x70,
                                     0x98, 0x74, 0x82, 0x4D,
                                     0x5B, 0x80, 0x40, 0x98,
                                     0xB7, 0x69, 0x36, 0x4F,
                                     0xD5, 0xAC };

    uint8_t gcu_ciphertext_3[18] = { 0xB9, 0xA0, 0xF5, 0xDD,
                                     0x05, 0x48, 0x24, 0xC5,
                                     0xD8, 0x26, 0xA8, 0xF3,
                                     0x3D, 0x8C, 0x61, 0x6B,
                                     0xD1, 0x07 };

    uint8_t gcu_plaintext_4[18]  = { 0x36, 0x20, 0xAA, 0x33,
                                     0x00, 0x77, 0x59, 0x16,
                                     0x41, 0xD9, 0xD6, 0xA7,
                                     0x3B, 0xBC, 0x8C, 0xA6,
                                     0x53, 0xE4 };

    uint8_t gcu_ciphertext_4[18] = { 0xE4, 0x00, 0x13, 0xBA,
                                     0x42, 0xF7, 0x7C, 0xD1,
                                     0x68, 0x5E, 0xAB, 0x0F,
                                     0xA9, 0x5B, 0x8F, 0x76,
                                     0xDC, 0x3F };

    uint8_t gcu_plaintext_6[18]  = { 0x12, 0xC1, 0x11, 0x1A,
                                     0x6C, 0xB0, 0xF8, 0xD3,
                                     0xF1, 0x83, 0x06, 0x77,
                                     0x97, 0xCB, 0x2E, 0xBF,
                                     0x5B, 0x6C };

    uint8_t gcu_ciphertext_6[18] = { 0x48, 0xF8, 0x08, 0x7E,
                                     0x63, 0xEE, 0x3C, 0x59,
                                     0x6F, 0x42, 0x02, 0xA9,
                                     0x44, 0xF8, 0xEE, 0x25,
                                     0xDD, 0xD0 };

    uint8_t gcu_plaintext_7[18]  = { 0xA6, 0x41, 0x88, 0xFB,
                                     0xB8, 0x2B, 0xAE, 0x69,
                                     0x41, 0x19, 0xFC, 0x45,
                                     0x01, 0xA7, 0xB2, 0xEB,
                                     0xCB, 0xC5 };

    uint8_t gcu_ciphertext_7[18] = { 0x30, 0x73, 0x6A, 0xD5,
                                     0x39, 0x13, 0x58, 0x56,
                                     0x00, 0x22, 0x31, 0xEC,
                                     0x7F, 0x18, 0x2B, 0x3D,
                                     0x03, 0x2D };

    uint16_t gcu_key_1[7] = { 0x0000, 0x0000, 0x0000, 0x0000,
                              0x0000, 0x0000,
                              0x001c };

    uint16_t gcu_key_2[7] = { 0xC5F9, 0x7B00, 0x89D3, 0xE84E,
                              0xC582, 0xF740,
                              0x001E };

    uint16_t gcu_key_3[7] = { 0x4B65, 0xE3CA, 0xBFCF, 0x78B1,
                              0x4F69, 0x88D6,
                              0x001E };

    uint16_t gcu_key_4[7] = { 0x06CF, 0xC095, 0x2794, 0xBE2D,
                              0xDEE5, 0x4BE3,
                              0x001C };

    uint16_t gcu_key_6[7] = { 0x8A50, 0x9DAA, 0xF1A7, 0xE0F8,
                              0x897C, 0x2CEB,
                              0x001C };

    uint16_t gcu_key_7[7] = { 0xB1D3, 0x590B, 0xDE75, 0xCA23,
                              0x2CCC, 0x233E,
                              0x001E };

    uint64_t key;
    uint64_t z0, z1, z2, z3, z4, z5;
    uint32_t IV;
    int ret, dir;

    extract_params(&key, &IV, &dir, gcu_key_1);
    z0 = 0;
    GEA1(key, IV, dir, &z0);
    ret = memcmp_bitstream(z0, gcu_ciphertext_1, gcu_plaintext_1);
    assert(ret == 0);

    extract_params(&key, &IV, &dir, gcu_key_2);
    z1 = 0;
    GEA1(key, IV, dir, &z1);
    ret = memcmp_bitstream(z1, gcu_ciphertext_2, gcu_plaintext_2);
    assert(ret == 0);

    extract_params(&key, &IV, &dir, gcu_key_3);
    z2 = 0;
    GEA1(key, IV, dir, &z2);
    ret = memcmp_bitstream(z2, gcu_ciphertext_3, gcu_plaintext_3);
    assert(ret == 0);

    extract_params(&key, &IV, &dir, gcu_key_4);
    z3 = 0;
    GEA1(key, IV, dir, &z3);
    ret = memcmp_bitstream(z3, gcu_ciphertext_4, gcu_plaintext_4);
    assert(ret == 0);

    extract_params(&key, &IV, &dir, gcu_key_6);
    z4 = 0;
    GEA1(key, IV, dir, &z4);
    ret = memcmp_bitstream(z4, gcu_ciphertext_6, gcu_plaintext_6);
    assert(ret == 0);

    extract_params(&key, &IV, &dir, gcu_key_7);
    z5 = 0;
    GEA1(key, IV, dir, &z5);
    ret = memcmp_bitstream(z5, gcu_ciphertext_7, gcu_plaintext_7);
    assert(ret == 0);
}
