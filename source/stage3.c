#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "exploit.h"

uint32_t apply_f_2_S_fwd(uint8_t *);
uint32_t apply_f_2_S_bwd(uint8_t *);

// from main.c
extern int verbosity;

void retrieve_K(uint8_t *K, uint8_t *S_225, uint8_t *IV, int dir)
{
    /*
     * This function retrieves K based on S_0, the IV and dir.
     */

    uint8_t F[128];
    uint8_t S_0[64];
    uint8_t S_97[64];
    uint8_t S_225b[64];
    uint8_t S_33_p_j[64];
    uint8_t dir_bit = dir&1;
    int j;

    memset(F, 0, sizeof(F));
    memset(S_0, 0, sizeof(S_0));    
    clock_S_backward(S_97, S_225, F, 128);
    clock_S_forward(S_225b, S_97, F, 128);

    for(j=0; j<64; j++) {
        memcpy(&F[0], IV, 32);
        memcpy(&F[32], &dir_bit, 1);
        memcpy(&F[33], K, j);
        clock_S_forward(S_33_p_j, S_0, F, 33+j);
        K[j] = (S_97[j] ^ apply_f_2_S_fwd(S_33_p_j) ^ S_33_p_j[0])&1;
    }
}
