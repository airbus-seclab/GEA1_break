#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>

#include "exploit.h"
#include "cuckoo.h"

void cuckoo_printBucket(BUCKET *current_b)
{
    printf("Key: %x, H1: %x, H2: %x, H3: %x\n",
           current_b->key,
           H1(current_b->key),
           H2(current_b->key),
           H3(current_b->key));
}

void cuckoo_setup_ht(BUCKET **ht)
{
    *ht = (BUCKET *) calloc(1, NR_BUCKETS * sizeof(BUCKET));
}

void cuckoo_free_ht(BUCKET **ht)
{
    free(*ht);
    *ht = NULL;
}

static __inline__
void swap(BUCKET *b1, BUCKET *b2)
{
    BUCKET b0;
    b0.value = b1->value;
    b0.key = b1->key;
    b1->value = b2->value;
    b1->key = b2->key;
    b2->value = b0.value;
    b2->key = b0.key;
}

int cuckoo_put(uint32_t key, uint32_t value, BUCKET *ht)
{
    BUCKET current_b;
    BUCKET *b1;
    uint32_t index;
    uint32_t counter;

    // TODO.
    if (key == 0) {
        printf("Can keys be all 0?!\n");
        return -2;
    }

#if OPTIM_SKIP_COLLISIONS
    int ret = cuckoo_lookup(key, ht);
    if(ret != -1) {
        return -2;
    }
#endif

    current_b.key = key;
    current_b.value = value;
    
    index = H1(current_b.key);
    b1 = &ht[index];
    swap(&current_b, b1);

    counter = 0;

    while (current_b.key != 0) {

        if (index == H1(current_b.key)) {

            // use H2
            index = H2(current_b.key);
            swap(&current_b, &ht[index]);

        } else if (index == H2(current_b.key)) {

            //use H3
            index = H3(current_b.key);
            swap(&current_b, &ht[index]);

        } else {

            // use H1
            index = H1(current_b.key);
            swap(&current_b, &ht[index]);

        }

        if (counter > 10*LOGN) {
            printf("Alert, stash required?\n");
            return -1;
        }
        
        counter++;
    }

    return 0;
}
