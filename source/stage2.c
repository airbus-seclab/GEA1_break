#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <linux/mman.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <signal.h>

#include "exploit.h"
#include "file.h"
#include "timing.h"
#include "gea1.h"
#include "transform.h"

extern uint64_t V[8];      // V basis
extern uint64_t TAC[24];   // TAC basis
extern uint64_t UB[32];    // UB basis

#include "linear_alg.h"

// from main.c
extern int verbosity;

// From data.c

#if (OPTIM_LOOKUP == OPTIM_LKUP_CUCKOO)
extern BUCKET *ht[NR_V_ELEMENTS_MAX];
#else
extern uint32_t *sorted_Tab[NR_V_ELEMENTS_MAX];
extern uint64_t TabIndex[NR_V_ELEMENTS_MAX][(1<<NR_BITS_IDX)];
extern int fd_sorted_files[NR_V_ELEMENTS_MAX];
#endif

// from linear_alg.c
extern mzd_t *MA_mat;
extern mzd_t *MC_mat;
extern mzd_t *MB_mat;
extern uint64_t V_elts[NR_V_ELEMENTS_MAX];

#if OPTIM_LIN_ALG
extern uint64_t f_MA[NR_V_ELEMENTS_MAX];
extern uint64_t f_MC[NR_V_ELEMENTS_MAX];
#endif

#if (OPTIM_LOOKUP == OPTIM_LKUP_CUCKOO)
static __inline__
int __stg2_state_recovery_cuckoo(void *arg)
{
    struct lp_arg *larg = (struct lp_arg *)arg;
    uint64_t q_alpha = 0, q_beta = 0, q_gamma = 0;
    uint64_t bitstream_regA, bitstream_regB, bitstream_regC;
    uint64_t candidate;
    uint64_t j, lower_bound, upper_bound;
    int nr_candidates = 0;
    DBG_CLOCK_VARS(4);
    int i, round_idx, ii, shmid;
    struct _target *t = NULL;
    int early_exit = 1;

    mzd_t *u_xor_v = NULL;
    mzd_t *u_xor_v_xor_t = NULL;
    mzd_t *beta = NULL;
#if OPTIM_LIN_ALG
    mzd_t *alpha_0 = NULL; // needs an allocation
    mzd_t *gamma_0 = NULL; // needs an allocation
#else
    mzd_t *alpha = NULL; // needs an allocation
    mzd_t *gamma = NULL; // needs an allocation
#endif

    // First of all bind!
    cpu_bind(larg->id); 

    // Now prepare the shared memory to retrieve the targets.
    shmid = shmget(larg->key, 8192, 0666|IPC_CREAT);
    if(shmid < 0) {
        printf("[-] shmget() failed [errno:%d], exiting...\n", errno);
        exit(EXIT_FAILURE);
    }

    t = (struct _target *)shmat(shmid, (void*)0, 0);
    if(t==(void*)(-1)) {
        printf("[-] shmat() failed [errno:%d], exiting...\n", errno);
        exit(EXIT_FAILURE);
    }

    // Prepare our work load.
    round_idx = larg->round_idx;
    cpu_get_work(&lower_bound, &upper_bound, larg->id, 0, larg->nr_cores, 1, NR_UB_ELEMENTS);

    if(!larg->early_exit)
        early_exit = 0;

#if !OPTIM_BATCH
    uint64_t q0, key_mask;
    q0 = t->keystream[0].bitvector;
    key_mask = t->keystream[0].bitmask;
    if(t->keystream[0].bitlength != 64) {
        early_exit = 0;
    }
#else
    for(int c=0; c<t->nr_targets; c++) {
        if(t->keystream[c].bitlength != 64) {
            early_exit = 0;
            break;
        }
    }
#endif

    if(verbosity > 1) {
        printf("LP_%.4d - [%u, %u]\n", larg->id, (uint32_t)lower_bound, (uint32_t)upper_bound);
    }

    // Initialization of the linear alg objects
    beta = mzd_init(32,1);
    u_xor_v = mzd_init(64,1);
    u_xor_v_xor_t = mzd_init(64,1);

    uint64_t q_u;
    uint64_t q_v;
    uint64_t q_t;
    uint64_t q_u_xor_v;
    uint64_t q_u_xor_v_xor_t;

#if OPTIM_LIN_ALG
    setup_f_MA_MC_elements();
    uint64_t q_alpha_0 = 0;
    uint64_t q_gamma_0 = 0;
    uint64_t q_alpha_i = 0;
    uint64_t q_gamma_i = 0;
    uint64_t q_MA_x_v0 = 0;
    uint64_t q_MC_x_v0 = 0;
    uint64_t q_MA_x_vi = 0;
    uint64_t q_MC_x_vi = 0;
    uint64_t q_f_MA_x_v0_xor_alpha0 = 0;
    uint64_t q_f_MC_x_v0_xor_gamma0 = 0;
    alpha_0 = mzd_init(31,1);
    gamma_0 = mzd_init(33,1);
#else
    alpha = mzd_init(31,1);
    gamma = mzd_init(33,1);
#endif

#if OPTIM_SCHED
    select_computation_scheduling();
#endif

    for(j=lower_bound; j<=upper_bound; j++) {

        q_u = compute_ub_element(j); // Do we precompute this?

        for(i=round_idx*(NR_V_ELEMENTS/STG2_NR_ROUNDS), ii=0; i<(round_idx+1)*(NR_V_ELEMENTS/STG2_NR_ROUNDS); i++, ii++) {

            if(early_exit && (t->nr_state_recovered == t->nr_targets)) {
                goto bye;
            }

            // Step 1: Matrix manipulation
            DBG_CLOCK_START(0);

#if OPTIM_LIN_ALG

            if(unlikely(ii==0)) {

                q_v = V_elts[i];
                q_u_xor_v = q_u ^ q_v;

                transform_qword_2_vect(q_u_xor_v, u_xor_v);
                mzd_mul(alpha_0, MA_mat, u_xor_v, 0); // expensive
                mzd_mul(gamma_0, MC_mat, u_xor_v, 0); // expensive
                transform_vect_2_qword(alpha_0, &q_alpha_0);
                transform_vect_2_qword(gamma_0, &q_gamma_0);

                // Precomputing what comes next
                q_MA_x_v0 = f_MA[i];
                q_MC_x_v0 = f_MC[i];
                q_f_MA_x_v0_xor_alpha0 = q_MA_x_v0 ^ q_alpha_0;
                q_f_MC_x_v0_xor_gamma0 = q_MC_x_v0 ^ q_gamma_0;

                // Setting the right pointers
                q_alpha = q_alpha_0;
                q_gamma = q_gamma_0;

            } else {

                q_MA_x_vi = f_MA[i];
                q_MC_x_vi = f_MC[i];
                q_alpha_i = q_MA_x_vi ^ q_f_MA_x_v0_xor_alpha0;
                q_gamma_i = q_MC_x_vi ^ q_f_MC_x_v0_xor_gamma0;

                // Setting the right pointers
                q_alpha = q_alpha_i;
                q_gamma = q_gamma_i;
            }

#else

            q_v = V_elts[i];
            q_u_xor_v = q_u ^ q_v;

            transform_qword_2_vect(q_u_xor_v, u_xor_v);

            mzd_mul(alpha, MA_mat, u_xor_v, 0); // expensive
            mzd_mul(gamma, MC_mat, u_xor_v, 0); // expensive

            transform_vect_2_qword(alpha, &q_alpha);
            transform_vect_2_qword(gamma, &q_gamma);

#endif

            DBG_CLOCK_STOP(0);

            // Step 2: bitstream generation
            DBG_CLOCK_START(1);
            bitstream_regA = RegisterA2(q_alpha, 32);
            bitstream_regC = RegisterC2(q_gamma, 32);
            DBG_CLOCK_STOP(1);

#if DEBUG_TESTCASE
            if(verbosity && j==27 && i==0) {
                printf("---\n");
                print_line_vector(u_xor_v, 64, "[0, 27] u + v = "); // OK
                printf("[0, 27] alpha = %lx\n", q_alpha);
                printf("[0, 27] gamma = %lx\n", q_gamma);
                printf("[0, 27] LA = %lx\n", bitstream_regA); // OK
                printf("[0, 27] LC = %lx\n", bitstream_regC); // OK
                if(bitstream_regA != (uint32_t)0x25cfab4eeb9bb463) {
                    printf("[!] Error: LA is incorrect!\n");
                    kill(0, SIGSEGV);
                }
                if(bitstream_regC != (uint32_t)0xd5bfa43aa906154e) {
                    printf("[!] Error: LC is incorrect!\n");
                    kill(0, SIGSEGV);
                }
                printf("---\n");
            }
#endif

#if OPTIM_BATCH
            // Not super super clean.
            for(int c=0; c<t->nr_targets; c++) {
            uint64_t q0, key_mask;
            if(t->keystream[c].solved)
                continue;
            q0 = t->keystream[c].bitvector;
            key_mask = t->keystream[c].bitmask;
#endif

            candidate = bitstream_regA ^ bitstream_regC ^ (uint32_t)q0;
            uint32_t x = (uint32_t)(candidate);

            // Step3: searching the pattern.
            DBG_CLOCK_START(2);
            int idx = cuckoo_lookup(x, ht[ii]);
            DBG_CLOCK_STOP(2);

            if(unlikely(idx > 0)) {

                time_t stop = time(NULL);
                nr_candidates++;
                DBG_CLOCK_START(3);

                q_t = compute_tac_element((uint32_t)idx);

#if OPTIM_LIN_ALG
                q_v = V_elts[i];
                q_u_xor_v = q_u ^ q_v;
#endif

                q_u_xor_v_xor_t = q_t ^ q_u_xor_v;

                transform_qword_2_vect(q_u_xor_v_xor_t, u_xor_v_xor_t);
                mzd_mul(beta, MB_mat, u_xor_v_xor_t, 0);
                transform_vect_2_qword(beta, &q_beta);

                bitstream_regA = RegisterA2(q_alpha, 64);
                bitstream_regB = RegisterB2(q_beta, 64);
                bitstream_regC = RegisterC2(q_gamma, 64);
                candidate = bitstream_regA ^ bitstream_regB ^ bitstream_regC;

                if((candidate & key_mask) == (q0 & key_mask)) {
                    uint64_t q_sol = 0;
                    transform_vect_2_qword(u_xor_v_xor_t, &q_sol);
#if OPTIM_BATCH
                    printf("[+] State found for b%02d in %.2fs [%.2fm]!\n", c, (double)(stop-larg->start), (double)(stop-larg->start)/60);
#else
                    printf("[+] State found in %.2fs [%.2fm]!\n", (double)(stop-larg->start), (double)(stop-larg->start)/60);
#endif
                    if(unlikely(verbosity)) {
                        printf("\tUB = %x\n", (uint32_t)j);
                        printf("\tV = %x\n", i);
                        printf("\tT = %x\n", (uint32_t)idx);
                    }
                    printf("\tS = %lx\n", q_sol);
#if OPTIM_BATCH
                    if(!(t->keystream[c].solved))
                        t->nr_state_recovered++;
                    t->keystream[c].solved++;
#else
                    if(!(t->keystream[0].solved))
                        t->nr_state_recovered++;
                    t->keystream[0].solved++;
#endif
                }
                DBG_CLOCK_STOP(3);
            }

#if OPTIM_BATCH
            }
#endif

       }
    }

bye:
    shmdt(t);

#if OPTIM_SCHED
    select_io_scheduling();
#endif

#if DEBUG_TIMING
    if(unlikely(verbosity))
        printf("LinAlg: %.2fs, bitstream generation: %.2fs, b-search: %.2fs, false-positives: %.2fs\n", DBG_CLOCK_GET(0),
                                                                                                        DBG_CLOCK_GET(1),
                                                                                                        DBG_CLOCK_GET(2),
                                                                                                        DBG_CLOCK_GET(3));
#endif

    if(unlikely((verbosity > 1) && nr_candidates))
        printf("\t-> %d candidates occured\n", nr_candidates);

    exit(EXIT_SUCCESS);
}
#endif


#if (OPTIM_LOOKUP == OPTIM_LKUP_BSEARCH)
static __inline__
int __stg2_state_recovery_bsearch(void *arg)
{
    struct lp_arg *larg = (struct lp_arg *)arg;
    uint64_t q_alpha = 0, q_beta = 0, q_gamma = 0;
    uint64_t bitstream_regA, bitstream_regB, bitstream_regC;
    uint64_t candidate;
    uint64_t j, lower_bound, upper_bound;
    int nr_candidates = 0;
    DBG_CLOCK_VARS(4);
    int i, shmid;
    struct _target *t = NULL;
    int early_exit = 1;

    mzd_t *u_xor_v = NULL;
    mzd_t *u_xor_v_xor_t = NULL;
    mzd_t *beta = NULL;
#if OPTIM_LIN_ALG
    mzd_t *alpha_0 = NULL; // needs an allocation
    mzd_t *gamma_0 = NULL; // needs an allocation
#else
    mzd_t *alpha = NULL; // needs an allocation
    mzd_t *gamma = NULL; // needs an allocation
#endif

    // First of all bind!
    cpu_bind(larg->id); 

    // Now prepare the shared memory to retrieve the targets.
    shmid = shmget(larg->key, 8192, 0666|IPC_CREAT);
    if(shmid < 0) {
        printf("[-] shmget() failed [errno:%d], exiting...\n", errno);
        exit(EXIT_FAILURE);
    }

    t = (struct _target *)shmat(shmid, (void*)0, 0);
    if(t==(void*)(-1)) {
        printf("[-] shmat() failed [errno:%d], exiting...\n", errno);
        exit(EXIT_FAILURE);
    }

    lower_bound = larg->id * (NR_UB_ELEMENTS / larg->nr_cores);
    upper_bound = (larg->id+1) * (NR_UB_ELEMENTS / larg->nr_cores) - 1;

    if(!larg->early_exit)
        early_exit = 0;

#if !OPTIM_BATCH
    uint64_t q0, key_mask;
    q0 = t->keystream[0].bitvector;
    key_mask = t->keystream[0].bitmask;
    if(t->keystream[0].bitlength != 64) {
        early_exit = 0;
    }
#else
    for(int c=0; c<t->nr_targets; c++) {
        if(t->keystream[c].bitlength != 64) {
            early_exit = 0;
            break;
        }
    }
#endif

    if(verbosity > 1) {
        printf("LP_%.4d - [%u, %u]\n", larg->id, (uint32_t)lower_bound, (uint32_t)upper_bound);
    }

    // Initialization of the linear alg objects
    beta = mzd_init(32,1);
    u_xor_v = mzd_init(64,1);
    u_xor_v_xor_t = mzd_init(64,1);

    uint64_t q_u;
    uint64_t q_v;
    uint64_t q_t;
    uint64_t q_u_xor_v;
    uint64_t q_u_xor_v_xor_t;

#if OPTIM_LIN_ALG
    setup_f_MA_MC_elements();
    uint64_t q_alpha_0 = 0;
    uint64_t q_gamma_0 = 0;
    uint64_t q_alpha_i = 0;
    uint64_t q_gamma_i = 0;
    uint64_t q_MA_x_v0 = 0;
    uint64_t q_MC_x_v0 = 0;
    uint64_t q_MA_x_vi = 0;
    uint64_t q_MC_x_vi = 0;
    uint64_t q_f_MA_x_v0_xor_alpha0 = 0;
    uint64_t q_f_MC_x_v0_xor_gamma0 = 0;
    alpha_0 = mzd_init(31,1);
    gamma_0 = mzd_init(33,1);
#else
    alpha = mzd_init(31,1);
    gamma = mzd_init(33,1);
#endif

#if OPTIM_SCHED
    select_computation_scheduling();
#endif

    for(j=lower_bound; j<=upper_bound; j++) {

        q_u = compute_ub_element(j); // DO WE PRECOMPUTE THIS?

        for(i=0; i<NR_V_ELEMENTS; i++) {

            if(early_exit && (t->nr_state_recovered == t->nr_targets)) {
                goto bye;
            }

            // Step 1: Matrix manipulation
            DBG_CLOCK_START(0);

#if OPTIM_LIN_ALG

            if(unlikely(i==0)) {

                q_v = V_elts[0];
                q_u_xor_v = q_u ^ q_v;

                transform_qword_2_vect(q_u_xor_v, u_xor_v);
                mzd_mul(alpha_0, MA_mat, u_xor_v, 0); // expensive
                mzd_mul(gamma_0, MC_mat, u_xor_v, 0); // expensive
                transform_vect_2_qword(alpha_0, &q_alpha_0);
                transform_vect_2_qword(gamma_0, &q_gamma_0);

                // Precomputing what comes next
                q_MA_x_v0 = f_MA[0];
                q_MC_x_v0 = f_MC[0];
                q_f_MA_x_v0_xor_alpha0 = q_MA_x_v0 ^ q_alpha_0;
                q_f_MC_x_v0_xor_gamma0 = q_MC_x_v0 ^ q_gamma_0;

                // Setting the right pointers
                q_alpha = q_alpha_0;
                q_gamma = q_gamma_0;

            } else {

                q_MA_x_vi = f_MA[i];
                q_MC_x_vi = f_MC[i];
                q_alpha_i = q_MA_x_vi ^ q_f_MA_x_v0_xor_alpha0;
                q_gamma_i = q_MC_x_vi ^ q_f_MC_x_v0_xor_gamma0;

                // Setting the right pointers
                q_alpha = q_alpha_i;
                q_gamma = q_gamma_i;
            }

#else

            q_v = V_elts[i];
            q_u_xor_v = q_u ^ q_v;

            transform_qword_2_vect(q_u_xor_v, u_xor_v);

            mzd_mul(alpha, MA_mat, u_xor_v, 0); // expensive
            mzd_mul(gamma, MC_mat, u_xor_v, 0); // expensive

            transform_vect_2_qword(alpha, &q_alpha);
            transform_vect_2_qword(gamma, &q_gamma);

#endif

            DBG_CLOCK_STOP(0);

            // Step 2: bitstream generation
            DBG_CLOCK_START(1);
            bitstream_regA = RegisterA2(q_alpha, 32);
            bitstream_regC = RegisterC2(q_gamma, 32);
            DBG_CLOCK_STOP(1);

#if DEBUG_TESTCASE
            if(verbosity && j==27 && i==0) {
                printf("---\n");
                print_line_vector(u_xor_v, 64, "[0, 27] u + v = "); // OK
                printf("[0, 27] alpha = %lx\n", q_alpha);
                printf("[0, 27] gamma = %lx\n", q_gamma);
                printf("[0, 27] LA = %lx\n", bitstream_regA); // OK
                printf("[0, 27] LC = %lx\n", bitstream_regC); // OK
                if(bitstream_regA != (uint32_t)0x25cfab4eeb9bb463) {
                    printf("[!] Error: LA is incorrect!\n");
                    kill(0, SIGSEGV);
                }
                if(bitstream_regC != (uint32_t)0xd5bfa43aa906154e) {
                    printf("[!] Error: LC is incorrect!\n");
                    kill(0, SIGSEGV);
                }
                printf("---\n");
            }
#endif

#if OPTIM_BATCH
            // Not super super clean.
            for(int c=0; c<t->nr_targets; c++) {
            uint64_t q0, key_mask;
            if(t->keystream[c].solved)
                continue;
            q0 = t->keystream[c].bitvector;
            key_mask = t->keystream[c].bitmask;
#endif
            candidate = bitstream_regA ^ bitstream_regC ^ (uint32_t)q0;
            uint32_t x = (uint32_t)(candidate);

            // Step3: searching the pattern.
            DBG_CLOCK_START(2);

            uint64_t index_qword;
            uint32_t idx1, idx2;

            index_qword = TabIndex[i][(x >> (32-NR_BITS_IDX)) & MASK_IDX];
            idx1 = (index_qword>>32);
            idx2 = (index_qword&0xFFFFFFFF);

            uint8_t *p = (uint8_t *)sorted_Tab[i];
            int idx = b_search32(x, (uint32_t *)&p[4*idx1], idx2-idx1+1);
            if(idx >= 0)
                idx += idx1;

            DBG_CLOCK_STOP(2);

            if(unlikely(idx > 0)) {

                uint32_t recovered_t;
                time_t stop = time(NULL);

                nr_candidates++;
                DBG_CLOCK_START(3);

                uint64_t tmp64 = 0;
                int fd;
                fd = fd_sorted_files[i];
                lseek(fd, idx*8, SEEK_SET); // align on 64 bits for potential cache effects.
                read(fd, &tmp64, 8);
                recovered_t = tmp64 & 0xFFFFFFFF;

                q_t = compute_tac_element(recovered_t);

#if OPTIM_LIN_ALG
                q_v = V_elts[i];
                q_u_xor_v = q_u ^ q_v;
#endif

                q_u_xor_v_xor_t = q_t ^ q_u_xor_v;

                transform_qword_2_vect(q_u_xor_v_xor_t, u_xor_v_xor_t);
                mzd_mul(beta, MB_mat, u_xor_v_xor_t, 0);
                transform_vect_2_qword(beta, &q_beta);

                bitstream_regA = RegisterA2(q_alpha, 64);
                bitstream_regB = RegisterB2(q_beta, 64);
                bitstream_regC = RegisterC2(q_gamma, 64);
                candidate = bitstream_regA ^ bitstream_regB ^ bitstream_regC;

                if((candidate & key_mask) == (q0 & key_mask)) {
                    uint64_t q_sol = 0;
                    transform_vect_2_qword(u_xor_v_xor_t, &q_sol);
#if OPTIM_BATCH
                    printf("[+] State found for b%02d in %.2fs [%.2fm]!\n", c, (double)(stop-larg->start), (double)(stop-larg->start)/60);
#else
                    printf("[+] State found in %.2fs [%.2fm]!\n", (double)(stop-larg->start), (double)(stop-larg->start)/60);
#endif
                    if(unlikely(verbosity)) {
                        printf("\tUB = %x\n", (uint32_t)j);
                        printf("\tV = %x\n", i);
                        printf("\tT = %x\n", recovered_t);
                    }
                    printf("\tS = %lx\n", q_sol);
#if OPTIM_BATCH
                    if(!(t->keystream[c].solved))
                        t->nr_state_recovered++;
                    t->keystream[c].solved++;
#else
                    if(!(t->keystream[0].solved))
                        t->nr_state_recovered++;
                    t->keystream[0].solved++;
#endif
                }
                DBG_CLOCK_STOP(3);
            }

#if OPTIM_BATCH
            }
#endif

       }
    }

bye:
    shmdt(t);

#if OPTIM_SCHED
    select_io_scheduling();
#endif

#if DEBUG_TIMING
    if(unlikely(verbosity))
        printf("LinAlg: %.2fs, bitstream generation: %.2fs, b-search: %.2fs, false-positives: %.2fs\n", DBG_CLOCK_GET(0),
                                                                                                        DBG_CLOCK_GET(1),
                                                                                                        DBG_CLOCK_GET(2),
                                                                                                        DBG_CLOCK_GET(3));
#endif

    if(unlikely((verbosity > 1) && nr_candidates))
        printf("\t-> %d candidates occured\n", nr_candidates);

    exit(EXIT_SUCCESS);
}
#endif

int stg2_state_recovery(void *arg)
{
#if (OPTIM_LOOKUP == OPTIM_LKUP_BSEARCH)
    return __stg2_state_recovery_bsearch(arg);
#else
    return __stg2_state_recovery_cuckoo(arg);
#endif
}
