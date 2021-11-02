#ifndef __LINEAR_ALG_H__
#define __LINEAR_ALG_H__

/*
 * Vector Space elements generation
 */

// Generate an element based on its base2 representation.

static __inline__
uint64_t compute_tac_element(uint32_t elt_idx)
{
    uint64_t q_t = 0;
    uint32_t i;

    for(i=0; i<NR_BITS_TAC_MAX; i++) {
        // Adds base vector
        if((elt_idx>>i)&1) {
            q_t ^= TAC[i];
        }
    }

    return q_t;
}

static __inline__
uint64_t compute_ub_element(uint32_t elt_idx)
{
    uint32_t i;
    uint64_t q_u = 0;

    for(i=0; i<NR_BITS_UB_MAX; i++) {
        // Adds base vector
        if((elt_idx>>i)&1) {
            q_u ^= UB[i];
        }
    }

    return q_u;
}

static __inline__
uint64_t compute_v_element(uint32_t elt_idx)
{
    uint32_t i;
    uint64_t q_v = 0;

    for(i=0; i<NR_BITS_V_MAX; i++) {
        // Adds base vector
        if((elt_idx>>i)&1)
            q_v ^= V[i];
    }

    return q_v;
}

#endif /* __LINEAR_ALG_H__ */
