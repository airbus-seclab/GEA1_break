#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <x86intrin.h>

#include "exploit.h"
#include "file.h"
#include "timing.h"
#include "gea1.h"

// from main.c
extern int verbosity;

// LFSR_B

void bench_LFSR_B()
{
    uint64_t c1,c2;
    CLOCK_VARS(1);
    volatile uint64_t bitstream;
    uint32_t i, nr_calls = 1000;

    bitstream = 0;
    CLOCK_START(0);
    c1 = __rdtsc();
    for(i=0; i<nr_calls; i++) {
        bitstream += lfsr_galois_B(0xffffffff, 64);
    }
    c2 = __rdtsc();
    CLOCK_STOP(0);
    printf("\t-> lfsr_galois_B(bitstream:%d bits): [time = %.2f us, cycles=%ld]\n", 64, US(CLOCK_GET(0))/nr_calls, (c2-c1)/nr_calls);
}

// RegisterB

void __bench_RegisterB(int nr_bits)
{
    uint64_t c1,c2;
    CLOCK_VARS(1);
    volatile uint64_t bitstream;
    uint32_t i, nr_calls=1000;

    bitstream = 0;
    CLOCK_START(0);
    c1 = __rdtsc();
    for(i=0; i<nr_calls; i++) {
        bitstream += RegisterB(0x48ff6611, nr_bits);
    }
    c2 = __rdtsc();
    CLOCK_STOP(0);
    printf("\t\t+ %d bits on average: [time = %.2f us, cycles=%ld]\n", nr_bits, US(CLOCK_GET(0))/nr_calls, (c2-c1)/nr_calls);
}

void bench_RegisterB()
{
    int i, nr_bits_max=32;

    printf("\t-> RegisterB:\n");
    for(i=20; i<nr_bits_max; i++)
        __bench_RegisterB(i);

    __bench_RegisterB(32);
    __bench_RegisterB(64);
}

void __bench_RegisterB2(int nr_bits)
{
    uint64_t c1,c2;
    CLOCK_VARS(1);
    volatile uint64_t bitstream;
    uint32_t i, nr_calls=1000;

    setup_f_table();

    bitstream = 0;
    CLOCK_START(0);
    c1 = __rdtsc();
    for(i=0; i<nr_calls; i++) {
        bitstream += RegisterB2(0x48ff6611, nr_bits);
    }
    c2 = __rdtsc();
    CLOCK_STOP(0);
    printf("\t\t+ %d bits on average: [time = %.2f us, cycles=%ld]\n", nr_bits, US(CLOCK_GET(0))/nr_calls, (c2-c1)/nr_calls);
}

void bench_RegisterB2()
{
    int i, nr_bits_max=32;

    printf("\t-> RegisterB2:\n");
    for(i=20; i<nr_bits_max; i++)
        __bench_RegisterB2(i);

    __bench_RegisterB2(32);
    __bench_RegisterB2(64);
}

// RegisterA

void __bench_RegisterA(int nr_bits)
{
    uint64_t c1,c2;
    CLOCK_VARS(1);
    volatile uint64_t bitstream;
    uint32_t i, nr_calls=1000;

    bitstream = 0;
    CLOCK_START(0);
    c1 = __rdtsc();
    for(i=0; i<nr_calls; i++) {
        bitstream += RegisterA(0x48ff6611, nr_bits);
    }
    c2 = __rdtsc();
    CLOCK_STOP(0);
    printf("\t\t+ %d bits on average: [time = %.2f us, cycles=%ld]\n", nr_bits, US(CLOCK_GET(0))/nr_calls, (c2-c1)/nr_calls);
}

void bench_RegisterA()
{
    int i, nr_bits_max=32;

    printf("\t-> RegisterA:\n");
    for(i=20; i<nr_bits_max; i++)
        __bench_RegisterA(i);

    __bench_RegisterA(32);
    __bench_RegisterA(64);
}

void __bench_RegisterA2(int nr_bits)
{
    uint64_t c1,c2;
    CLOCK_VARS(1);
    volatile uint64_t bitstream;
    uint32_t i, nr_calls=1000;

    bitstream = 0;
    CLOCK_START(0);
    c1 = __rdtsc();
    for(i=0; i<nr_calls; i++) {
        bitstream += RegisterA2(0x48ff6611, nr_bits);
    }
    c2 = __rdtsc();
    CLOCK_STOP(0);
    printf("\t\t+ %d bits on average: [time = %.2f us, cycles=%ld]\n", nr_bits, US(CLOCK_GET(0))/nr_calls, (c2-c1)/nr_calls);
}

void bench_RegisterA2()
{
    int i, nr_bits_max=32;

    printf("\t-> RegisterA2:\n");
    for(i=20; i<nr_bits_max; i++)
        __bench_RegisterA2(i);

    __bench_RegisterA2(32);
    __bench_RegisterA2(64);
}

// RegisterC

void __bench_RegisterC(int nr_bits)
{
    uint64_t c1,c2;
    CLOCK_VARS(1);
    volatile uint64_t bitstream;
    uint32_t i, nr_calls=1000;

    bitstream = 0;
    CLOCK_START(0);
    c1 = __rdtsc();
    for(i=0; i<nr_calls; i++) {
        bitstream += RegisterC(0x48ff6611, nr_bits);
    }
    c2 = __rdtsc();
    CLOCK_STOP(0);
    printf("\t\t+ %d bits on average: [time = %.2f us, cycles=%ld]\n", nr_bits, US(CLOCK_GET(0))/nr_calls, (c2-c1)/nr_calls);
}

void bench_RegisterC()
{
    int i, nr_bits_max=32;

    printf("\t-> RegisterC:\n");
    for(i=20; i<nr_bits_max; i++)
        __bench_RegisterC(i);
    __bench_RegisterC(32);
    __bench_RegisterC(64);
}

void __bench_RegisterC2(int nr_bits)
{
    uint64_t c1,c2;
    CLOCK_VARS(1);
    volatile uint64_t bitstream;
    uint32_t i, nr_calls=1000;

    bitstream = 0;
    CLOCK_START(0);
    c1 = __rdtsc();
    for(i=0; i<nr_calls; i++) {
        bitstream += RegisterC2(0x48ff6611, nr_bits);
    }
    c2 = __rdtsc();
    CLOCK_STOP(0);
    printf("\t\t+ %d bits on average: [time = %.2f us, cycles=%ld]\n", nr_bits, US(CLOCK_GET(0))/nr_calls, (c2-c1)/nr_calls);
}

void bench_RegisterC2()
{
    int i, nr_bits_max=32;

    printf("\t-> RegisterC2:\n");
    for(i=20; i<nr_bits_max; i++)
        __bench_RegisterC2(i);
    __bench_RegisterC2(32);
    __bench_RegisterC2(64);
}

// Sorting

void bench_sort1()
{
    uint64_t c1,c2;
    CLOCK_VARS(1);
    uint64_t *p = NULL;
    int i, nr_elements = NR_TAC_ELEMENTS_MAX, nr_calls = 1000;
    uint32_t r_val;

    p = malloc(nr_elements * sizeof(uint64_t));
    assert(p);

    // Generates the list of random elements.
    for(i=0; i<nr_elements; i++) {
        r_val = (random() & 0xffffffff);
        p[i] = ((unsigned long)r_val << 32) | i;
    }

    CLOCK_START(0);
    c1 = __rdtsc();
    for(i=0; i<nr_calls; i++) {
        seq_search64(random() & 0xffffffff, p, nr_elements);
    }
    c2 = __rdtsc();
    CLOCK_STOP(0);
    printf("\t-> Seq Search on average over %d (unsorted) elements: [time=%.4f ms, cycles=%ld]\n", nr_elements, MS(CLOCK_GET(0))/nr_calls, (c2-c1)/nr_calls);

    if(verbosity)
        print_uint64_array_as_hex(p, 3);

    CLOCK_START(0);
    c1 = __rdtsc();
    radix_sort(p, nr_elements);
    c2 = __rdtsc();
    CLOCK_STOP(0);
    printf("\t-> Radix Sort over %d (unsorted) elements took: [time=%.4f ms, cycles=%ld]\n", nr_elements, MS(CLOCK_GET(0))/nr_calls, (c2-c1));

    if(verbosity)
        print_uint64_array_as_hex(p, 3);

    CLOCK_START(0);
    c1 = __rdtsc();
    for(i=0; i<nr_calls; i++) {
        seq_search64(random() & 0xffffffff, p, nr_elements);
    }
    c2 = __rdtsc();
    CLOCK_STOP(0);
    printf("\t-> Seq Search on average over %d (sorted) elements: [time=%.4f ms, cycles=%ld]\n", nr_elements, MS(CLOCK_GET(0))/nr_calls, (c2-c1)/nr_calls);

    CLOCK_START(0);
    c1 = __rdtsc();
    for(i=0; i<nr_calls; i++) {
        b_search64(random() & 0xffffffff, p, nr_elements);
    }
    c2 = __rdtsc();
    CLOCK_STOP(0);
    printf("\t-> Bin Search on average over %d (sorted) elements: [time=%.4f ms, cycles=%ld]\n", nr_elements, MS(CLOCK_GET(0))/nr_calls, (c2-c1)/nr_calls);
}

void __bench_sort2_cuckoo(char *directory)
{
    char fname[512];
    uint64_t nr_success = 0;
    uint64_t nr_failures = 0;
    uint64_t nr_collisions = 0;
    uint64_t nr_insert_errors = 0;
    uint32_t key, value;
    int64_t sz, *p = NULL;
    CLOCK_VARS(1);
    uint64_t nr_elements = (1UL<<32);
    uint64_t j;
    BUCKET *ht = NULL;
    int i, ret;

    if(!is_directory_created(directory)) {
        printf("[-] Wrong directory, cannot run bench_sort2()\n");
        return;
    }

    i = random() % 256;

    printf("\t-> Cuckoo benchmarking (can take a bit of time)\n");

    memset(fname, 0, sizeof(fname));
    snprintf(fname, sizeof(fname)-1, "%s/"SORTED_TABLE_FMT, directory, i);
    sz = get_file_size(fname);
    if(sz < 0) {
        return;
    }

    assert(sz == 8*N);

    p = malloc(sz);
    assert(p);

    ret = read_file(fname, (uint8_t *)p, sz);
    if(ret) {
        printf("[-] Error, could not read %lu bytes in %s\n", sz, fname);
        free(p);
        return;
    }

    // Step1. Prepare the table
    cuckoo_setup_ht(&ht);
    for(int j=0; j<N; j++) {

        key   = (uint32_t)(p[j] >> 32);
        value = (uint32_t)(p[j]);

        if(!key) {
            if(verbosity > 1)
                printf("[!] Skipping 0 key!\n");
            continue;
        }

        ret = cuckoo_put(key, value, ht);
        if(ret == -1) {
            nr_insert_errors++;
        }

        if(ret == -2) {
            nr_collisions++;
        }

    }
    free(p);
    printf("\t\t+ cuckoo_put(): Inserted %lu/%d elements of table %d\n", N-nr_collisions-nr_insert_errors, N, i);
    printf("\t\t                Collisions: %lu [%.2f%%]\n", nr_collisions, (double)nr_collisions*100.0/N);

    // Step2. Searching elements.
    CLOCK_START(0);
    for (j=0; j < nr_elements; j++) {
        ret = cuckoo_lookup(j, ht);
        if (ret == -1) {
            nr_failures += 1;
        } else {
            nr_success += 1;
        }
    }
    CLOCK_STOP(0);

    printf("\t\t+ cuckoo_lookup(): Searching for %lu elements in table %d took: %.2f ms, i.e., %.2f ns per element.\n", nr_elements,
                                                                                                                        i,
                                                                                                                        MS(CLOCK_GET(0)),
                                                                                                                        NS(CLOCK_GET(0)) / ((double)(nr_elements)));
    printf("\t\t                   Success: %lu, Failure: %lu\n", nr_success, nr_failures);

    cuckoo_free_ht(&ht);
}

extern uint32_t *sorted_Tab[NR_V_ELEMENTS_MAX];
extern uint64_t TabIndex[NR_V_ELEMENTS_MAX][(1<<NR_BITS_IDX)];

void __bench_sort2_bsearch(char *directory)
{
    uint64_t nr_success = 0;
    uint64_t nr_failures = 0;
    int64_t *p = NULL;
    uint64_t nr_elements = (1UL<<28);
    uint64_t index_qword;
    uint32_t idx1, idx2;
    CLOCK_VARS(1);
    int i;
    uint64_t j;

    if(!is_directory_created(directory)) {
        printf("[-] Wrong directory, cannot run bench_sort2()\n");
        return;
    }

    i = random() % 256;

    printf("\t-> b-search benchmarking (can take a bit of time)\n");

    // Step1. Prepare the table
    alloc_all_sorted_Tab();
    load_sorted_Tab(directory, 16);
    i = random() % 16;

    // Step1. Searching elements.
    // Since nr_elements is 1<<28, we should have nr_success close to 1<<20,
    // which is true practically speaking.
    CLOCK_START(0);
    for (j=0; j < (nr_elements); j++) {
        index_qword = TabIndex[i][(j >> (32-NR_BITS_IDX)) & MASK_IDX];
        idx1 = (index_qword>>32);
        idx2 = (index_qword&0xFFFFFFFF);
        int ret = b_search32(j, &sorted_Tab[i][idx1], idx2-idx1+1);
        if (ret == -1) {
            nr_failures += 1;
        } else {
            nr_success += 1;
        }
    }
    CLOCK_STOP(0);

    printf("\t\t+ b_search32(): Searching for %lu elements in table %d took: %.2f ms, i.e., %.2f ns per element.\n", nr_elements,
                                                                                                                     i,
                                                                                                                     MS(CLOCK_GET(0)),
                                                                                                                     NS(CLOCK_GET(0)) / ((double)(nr_elements)));
    printf("\t\t                Success: %lu, Failure: %lu\n", nr_success, nr_failures);

    free(p);
    free_all_sorted_Tab();
}

void bench_sort2(char *directory)
{
    __bench_sort2_bsearch(directory);
    __bench_sort2_cuckoo(directory);
}
