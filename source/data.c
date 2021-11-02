#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>

#include "exploit.h"
#include "file.h"

// from main.c
extern int verbosity;

// Exported globals
uint32_t *unsorted_Tab[NR_V_ELEMENTS_MAX];
uint32_t *sorted_Tab[NR_V_ELEMENTS_MAX];
uint64_t TabIndex[NR_V_ELEMENTS_MAX][(1<<NR_BITS_IDX)];
BUCKET *ht[NR_V_ELEMENTS_MAX];

/* Unsorted Tab */

int alloc_unsorted_Tab(int lower_bound, int upper_bound)
{
    uint64_t size_allocated = 0;
    void *p;
    int i;
    
    size_allocated = 2 * sizeof(uint32_t) * (upper_bound - lower_bound + 1);

    // TODO: add support huge pagetables?
    for(i=0; i<NR_V_ELEMENTS; i++) {
        p = mmap(NULL,
                 size_allocated,
                 PROT_READ|PROT_WRITE,
                 MAP_PRIVATE|MAP_ANONYMOUS,
                 -1,
                 0);
        if(p == (void *)-1) {
            printf("[!] Error, could not allocate %lu bytes of memory!\n", size_allocated);
            return -1;
        }
        unsorted_Tab[i] = p;
    }

    if(verbosity > 1)
        printf("\t-> Allocated: %.2f Gb\n", (float)(size_allocated*NR_V_ELEMENTS)/(1<<30));
    return 0;
}

void free_unsorted_Tab(int lower_bound, int upper_bound)
{
    uint64_t size_allocated = 0;
    int i;

    size_allocated = 2 * sizeof(uint32_t) * (upper_bound - lower_bound + 1);
    for(i=0; i<NR_V_ELEMENTS; i++) {
        munmap(unsorted_Tab[i], size_allocated);
    }

    if(verbosity)
        printf("\t-> Freed: %.2f Gb\n", (float)(size_allocated*NR_V_ELEMENTS)/(1<<30));
}

int save_unsorted_Tab(int lower_bound, int upper_bound, char *dirname)
{
    char fname[512];
    int i, fd, ret;
    uint32_t nr_bytes_remaining;
    int offset;

    for(i=0; i<NR_V_ELEMENTS; i++) {

        memset(fname, 0, sizeof(fname));
        snprintf(fname, sizeof(fname)-1, "%s/"UNSORTED_TABLE_FMT, dirname, i, lower_bound, upper_bound);
        fd = open(fname, O_CREAT | O_RDWR, S_IRUSR|S_IWUSR|S_IRGRP);
        if(fd < 0) {
            printf("[-] save_unsorted_Tab(): Could not save the computation in %s [errno:%d]\n", fname, errno);
            return -1;
        }

        nr_bytes_remaining = 2 * sizeof(uint32_t) * (upper_bound - lower_bound + 1);
        uint8_t *p = (uint8_t *)unsorted_Tab[i];
        offset = 0;
        while(nr_bytes_remaining) {
            ret = write(fd, &p[offset], nr_bytes_remaining);
            if(ret < 0) {
                close(fd);
                printf("[-] save_unsorted_Tab(): write() failed [errno:%d]\n", errno);
                return -2;
            }
            nr_bytes_remaining -= ret;
            offset += ret;
        }
        close(fd);
    }
    return 0;
}

/* sorted Tab */

int alloc_all_sorted_Tab()
{
    uint64_t size_allocated = 0;
    void *p;
    int i;

    size_allocated = sizeof(uint32_t) * NR_TAC_ELEMENTS;

    // TODO: add support huge pagetables?
    for(i=0; i<NR_V_ELEMENTS; i++) {
        p = mmap(NULL,
                 size_allocated,
                 PROT_READ|PROT_WRITE,
                 MAP_SHARED|MAP_ANONYMOUS,
                 -1,
                 0);

        if(p == (void *)-1) {
            printf("[!] alloc_all_sorted_Tab(): Could not allocate %lu bytes of memory!\n", size_allocated);
            return -1;
        }
        sorted_Tab[i] = p;
    }

    if(verbosity > 1)
        printf("\t-> Allocated: %.2f Gb\n", (float)(size_allocated*NR_V_ELEMENTS)/(1<<30));

    return 0;
}

void free_all_sorted_Tab()
{
    uint64_t size_allocated = 0;
    int i;

    size_allocated = sizeof(uint32_t) * NR_TAC_ELEMENTS;
    for(i=0; i<NR_V_ELEMENTS; i++) {
        munmap(sorted_Tab[i], size_allocated);
        sorted_Tab[i] = NULL;
    }

    if(verbosity)
        printf("\t-> Freed: %.2f Gb\n", (float)(size_allocated*NR_V_ELEMENTS)/(1<<30));

    return;
}

int load_sorted_Tab(char *dirname, int nr_tables)
{
    char fname[512];
    int i, ret;
    uint32_t *p;
    uint64_t *q, sz = 2 * sizeof(uint32_t) * NR_TAC_ELEMENTS;

    ASSERT(nr_tables <= NR_V_ELEMENTS_MAX);

    char *tmp = malloc(sz);
    if(!tmp) {
        printf("[-] load_sorted_Tab(): Could not allocate %ld bytes [errno:%d]!\n", sz, errno);
        return -1;
    }

    for(i=0; i<nr_tables; i++) {

        memset(fname, 0, sizeof(fname));
        snprintf(fname, sizeof(fname)-1, "%s/"SORTED_TABLE_FMT, dirname, i);

        ret = read_file(fname, (uint8_t *)tmp, sz);
        if(unlikely(ret < 0)) {
            free(tmp);
            return -2;
        }

        p = (uint32_t *)sorted_Tab[i];
        q = (uint64_t *)tmp;
        for(int j=0; j<NR_TAC_ELEMENTS; j++) {
            p[j] = (q[j] >> 32);
        }

        memset(fname, 0, sizeof(fname));
        snprintf(fname, sizeof(fname)-1, "%s/"SORTED_INDEX_FMT, dirname, i);
        ret = read_file(fname, (uint8_t *)TabIndex[i], (1<<NR_BITS_IDX) * sizeof(uint64_t));
        if(unlikely(ret < 0)) {
            printf("[-] load_sorted_Tab(): Could not load %s...\n", fname);
            free(tmp);
            return -3;
        }

    }

    free(tmp);
    return 0;
}

int load_hash_Tab(char *dirname, int idx0, int nr_tables)
{
    char fname[512];
    int i, ii, ret;

    ASSERT(nr_tables <= NR_V_ELEMENTS_MAX);

    for(i=idx0, ii=0; i<(idx0+nr_tables); ii++, i++) {

        cuckoo_setup_ht(&ht[ii]);
        memset(fname, 0, sizeof(fname));
        snprintf(fname, sizeof(fname)-1, "%s/"SORTED_CUCKOO_FMT, dirname, i);
        ret = read_file(fname, (uint8_t *)ht[ii], NR_BUCKETS * sizeof(BUCKET));
        if(unlikely(ret < 0)) {
            printf("[-] load_hash_Tab(): Could not load %s...\n", fname);
            return -2;
        }

    }

    return 0;
}

void unload_hash_Tab(int nr_tables)
{
    ASSERT(nr_tables <= NR_V_ELEMENTS_MAX);
    for(int i=0; i<nr_tables; i++) {
        cuckoo_free_ht(&ht[i]);
    }
}
