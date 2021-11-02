#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "exploit.h"

#define GET_KEY_64(element)  ((element)>>32)
#define GET_KEY_32(element)  (element)

/*
 * Based on the original Radix Sort implementation from:
 * https://www.geeksforgeeks.org/radix-sort/
 *
 */

uint64_t tmp[NR_TAC_ELEMENTS_MAX]; // tmp array of 128 MB (max)
int count[256];

// We use radix 256 in this version.
void countSort(uint64_t arr[], int nr_elements, int offset)
{
    int i;

    memset(count, 0, sizeof(count));

    // Store count of occurrences in count[]
    for(i=0; i<nr_elements; i++)
        count[(GET_KEY_64(arr[i]) >> offset) & 0xff]++;
 
    for(i=1; i<256; i++)
        count[i] += count[i-1];
 
    // Build the output array
    for(i=nr_elements-1; i >= 0; i--) {
        tmp[count[(GET_KEY_64(arr[i]) >> offset) & 0xff] - 1] = arr[i];
        count[(GET_KEY_64(arr[i]) >> offset) & 0xFF]--;
    }

    for(i=0; i<nr_elements; i++)
        arr[i] = tmp[i];
}

// The main function to that sorts arr[] of size n using Radix Sort
void radix_sort(uint64_t arr[], uint32_t nr_elements)
{
    uint32_t i;

    //~ assert(arr_size <= NR_TAC_ELEMENTS_MAX);
    memset(tmp, 0, sizeof(tmp));
    for(i=0; i<32; i+=8) {
        countSort(arr, nr_elements, i);
    }
}

/*
 * Search algorithms with seq_search() and b_search()
 * seq_search is only used for benchmarking (obviously).
 */

// Naive implementation of Wikipedia's algorithm:
// https://fr.wikipedia.org/wiki/Recherche_dichotomique
// Returns -1 in case the element is not found, its index otherwise
// Note: NR_TAC_ELEMENTS_MAX < (1<<31) thus it works

int b_search64(uint32_t key, uint64_t *p, uint32_t arr_size)
{
    int begin, end, mid;
    int found = 0;
    
    ASSERT(arr_size <= NR_TAC_ELEMENTS_MAX);
    
    begin=0;
    end=arr_size;

    while(!found && begin<=end) {
        mid = (begin + end)/2;
        if (GET_KEY_64(p[mid]) == key) {
            return mid;
        }
        else {
            if(key > GET_KEY_64(p[mid])) {
                begin = mid +1;
            }
            else {
                end = mid-1;
            }
        }
    }
    return -1;
}

int b_search32(uint32_t key, uint32_t *p, uint32_t arr_size)
{
    int begin, end, mid;
    int found = 0;

    ASSERT(arr_size <= NR_TAC_ELEMENTS_MAX);

    begin=0;
    end=arr_size;

    while(!found && begin<=end) {
        mid = (begin + end)/2;
        if (GET_KEY_32(p[mid]) == key) {
            return mid;
        }
        else {
            if(key > GET_KEY_32(p[mid])) {
                begin = mid +1;
            }
            else {
                end = mid-1;
            }
        }
    }
    return -1;
}

// Returns -1 in case the element is not found, its index otherwise
// Note: NR_TAC_ELEMENTS_MAX < (1<<31) thus it works

int seq_search64(uint32_t key, uint64_t *p, uint32_t arr_size)
{
    uint32_t i;

    ASSERT(arr_size <= NR_TAC_ELEMENTS_MAX);
    for(i=0; i<arr_size; i++) {
        if(GET_KEY_64(p[i]) == key) {
            return i;
        }
    }
    return -1;
}
