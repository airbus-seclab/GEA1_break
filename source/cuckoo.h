#ifndef __CUCKOO_H__
#define __CUCKOO_H__

#include "exploit.h"

/* Macros */

#ifndef NR_BITS_TAC
#define NR_BITS_TAC  24
#endif

#define DOMAINSIZE  32
#define LOGN        NR_BITS_TAC
#define N           NR_TAC_ELEMENTS
#define NR_BUCKETS  (21307065) // aka ((size_t)ceil(1.27*N))

#define DIFF        (DOMAINSIZE-LOGN)
#define MAXDISTANCE (0x5555AAAA)

#define H1(x)       ((x) % NR_BUCKETS)
#define H2(x)       (((x)>>DIFF) % NR_BUCKETS)
#define H3(x)       (H1(((x) ^ MAXDISTANCE)))

/* Types */

typedef struct _tt {
    uint32_t key;   // This will be used to store 32 bits of keystream.
    uint32_t value; // This will be used to store a file offset.
} BUCKET;

// Note: int works as a return type because the value is an index which
// can never be bigger than 2^24.
static __inline__
int cuckoo_lookup(uint32_t key, BUCKET *ht)
{
    uint32_t index = H1(key);

    if (ht[index].key == key) {
        return ht[index].value;
    }

    index = H2(key);

    if (ht[index].key == key) {
        return ht[index].value;
    }

    index = H3(key);

    if (ht[index].key == key) {
        return ht[index].value;
    }

    return -1;
}

#endif /* __CUCKOO_H__ */
