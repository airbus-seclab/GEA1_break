#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
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

// from linear_alg.c
extern uint64_t V_elts[NR_V_ELEMENTS_MAX];
extern mzd_t *MB_mat;
#if OPTIM_LIN_ALG
extern uint64_t f_MB[NR_V_ELEMENTS_MAX];
#endif

// from data.c
extern uint32_t *unsorted_Tab[NR_V_ELEMENTS_MAX];

int stg1a_create_raw_data(void *arg)
{
    struct lp_arg *larg = (struct lp_arg *)arg;
    uint32_t state;
    uint64_t keystream = 0;
    uint64_t *p_keystream = NULL;
    uint64_t lower_bound_r, upper_bound_r, j;
    int i, jj, round, ret;
    DBG_CLOCK_VARS(6);

    mzd_t *t_xor_v = NULL;
    uint64_t q_t = 0;

#if OPTIM_LIN_ALG
    setup_f_MB_elements();
    mzd_t *beta_0 = NULL;
    uint64_t q_v = 0;
    uint64_t q_t_xor_v = 0;
    uint64_t q_beta_0 = 0;
    uint64_t q_beta_i = 0;
    uint64_t q_MB_x_v0 = 0;
    uint64_t q_MB_x_vi = 0;
    uint64_t q_f_MB_x_v0_xor_beta0 = 0;
#else
    mzd_t *v = NULL;
    mzd_t *t = NULL;
    mzd_t *beta = NULL;
#endif

    // First of all bind!
    cpu_bind(larg->id);

    t_xor_v = mzd_init(64,1);
#if OPTIM_LIN_ALG
    beta_0 = mzd_init(32,1);
#else
    t = mzd_init(64,1);
    v = mzd_init(64,1);
    beta = mzd_init(32,1);
#endif

    // Using the full range would require 32 GB allocated which is too much
    // these days for a lot of setup thus using 16 GB at a time is better.
    // Note: We could obviously go lower but then it would not make a lot
    // of sense since the computational power would (probably) be laking
    // as well.
    for(round=0; round<STG1A_NR_ROUNDS; round++) {

        cpu_get_work(&lower_bound_r, &upper_bound_r, larg->id, round, larg->nr_cores, STG1A_NR_ROUNDS, NR_TAC_ELEMENTS);

        if(verbosity > 1)
            printf("[LP_%.4d] - [%ld, %ld]\n", larg->id, lower_bound_r, upper_bound_r);

        DBG_CLOCK_START(0);
        ret = alloc_unsorted_Tab(lower_bound_r, upper_bound_r);
        assert(ret == 0); // TODO
        DBG_CLOCK_STOP(0);

        for(j=lower_bound_r, jj=0; j<=upper_bound_r; j++, jj++) {

            DBG_CLOCK_START(1);
            q_t = compute_tac_element(j);
#if !OPTIM_LIN_ALG
            transform_qword_2_vect(q_t, t);
#endif
            DBG_CLOCK_START(1);

            for(i=0; i<NR_V_ELEMENTS; i++) {

                DBG_CLOCK_START(2);
#if OPTIM_LIN_ALG
                if(unlikely(i==0)) {

                    q_v = V_elts[0];
                    q_MB_x_v0 = f_MB[0];
                    q_t_xor_v = q_t ^ q_v;
                    transform_qword_2_vect(q_t_xor_v, t_xor_v);
                    mzd_mul(beta_0, MB_mat, t_xor_v, 0); // expensive
                    transform_vect_2_qword(beta_0, &q_beta_0);
                    q_f_MB_x_v0_xor_beta0 = q_MB_x_v0 ^ q_beta_0;
                    state = q_beta_0;

                } else {

                    q_MB_x_vi = f_MB[i];
                    q_beta_i = q_MB_x_vi ^ q_f_MB_x_v0_xor_beta0;
                    state = q_beta_i;

                }
#else
                transform_qword_2_vect(V_elts[i], v);
                mzd_add(t_xor_v, t, v);
                mzd_mul(beta, MB_mat, t_xor_v, 0); // Requires alg optimization as well.
                transform_vect_2_dword(beta, &state);
#endif
                DBG_CLOCK_STOP(2);

                DBG_CLOCK_START(3);
                keystream = RegisterB2(state, 32);
                DBG_CLOCK_STOP(3);

#if DEBUG_TESTCASE
                if(verbosity && j==27 && i==0) {
                    mzd_t *zB = mzd_init(32,1);
                    uint64_t t_xor_v_27 = 0;
#if OPTIM_LIN_ALG
                    q_v = V_elts[i];
                    t_xor_v_27 = q_t ^ q_v;
                    transform_qword_2_vect(t_xor_v_27, t_xor_v);
#else
                    transform_vect_2_qword(t_xor_v, &t_xor_v_27);
#endif
                    printf("---\n");
                    print_line_vector(t_xor_v, 64, "[0, 27] t + v = "); // OK
                    transform_dword_2_vect(keystream, zB);
                    print_line_vector(zB, 32, "[0, 27] LB = "); // OK
                    mzd_free(zB);

                    if(keystream != (uint32_t)0xeba5e891e3fd10f9) {
                        printf("[!] Error: LB is incorrect!\n");
                        kill(0, SIGSEGV);
                    }

                    if(t_xor_v_27 != 0x46df14947d00001bUL) {
                        printf("[!] Error: (t+v) is incorrect!\n");
                        kill(0, SIGSEGV);
                    }
                    printf("---\n");
                }
#endif

                p_keystream = (uint64_t *)unsorted_Tab[i];
                p_keystream[jj] = (((keystream & 0xffffffff) << 32) | ((uint32_t)(j)));
            }
        }

        DBG_CLOCK_START(4);
        ret = save_unsorted_Tab(lower_bound_r, upper_bound_r, larg->dirname);
        DBG_CLOCK_STOP(4)
        ASSERT(ret == 0); // TODO

        if(verbosity)
            printf("[+] Deleting memory\n");

        DBG_CLOCK_START(5);
        free_unsorted_Tab(lower_bound_r, upper_bound_r);
        DBG_CLOCK_STOP(5);
    }

#if DEBUG_TIMING
    if(unlikely(verbosity))
        printf("create_Tab: %.2fs, compute_tac_element: %.2fs, lin_alg: %.2fs, RegisterB2: %.2fs, save_Tab: %.2fs, delete_Tab: %.2fs\n", DBG_CLOCK_GET(0),
                                                                                                                                         DBG_CLOCK_GET(1),
                                                                                                                                         DBG_CLOCK_GET(2),
                                                                                                                                         DBG_CLOCK_GET(3),
                                                                                                                                         DBG_CLOCK_GET(4),
                                                                                                                                         DBG_CLOCK_GET(5));
#endif

#if !OPTIM_LIN_ALG
    mzd_free(t);
    mzd_free(v);
    mzd_free(beta);
#endif
    mzd_free(t_xor_v);

    exit(EXIT_SUCCESS);
}

#if (OPTIM_LOOKUP == OPTIM_LKUP_BSEARCH)

// from data.c
extern uint64_t TabIndex[NR_V_ELEMENTS_MAX][(1<<NR_BITS_IDX)];

static __inline__
void create_index(void *mapped_file, int i)
{
    uint64_t *p = (uint64_t *)mapped_file;
    uint32_t j,k;
    uint32_t idx1, idx2;
    int found;

    for(k=0; k<(1<<NR_BITS_IDX); k++) {
        found = 0;
        idx1=0;
        idx2 = 0;
        int nxt = 0;

        for(j=nxt; j<NR_TAC_ELEMENTS; j++) {
            if(k == ((p[j] >> (64-NR_BITS_IDX)) & MASK_IDX)) {
                if(found == 0) {
                    idx1 = j;
                    idx2 = j;
                    found = 1;
                } else {
                    idx2 = j;
                }
            } else {
                if(found) {
                    nxt = j;
                    break;
                }
            }
        }
        ASSERT(found==1);
        ASSERT(idx2 >= idx1);
        // Finally update the array
        TabIndex[i][k] = (((uint64_t)(idx1)<<32) | idx2);
    }
}

static __inline__
int __create_lkup_tables_bsearch(void *arg)
{
    struct lp_arg *larg = (struct lp_arg *)arg;
    struct dirent *dir;
    char fname_unsorted[512];
    char fname[512];
    struct stat st;
    int ret, round;
    DIR *d = NULL;
    char *mapped_file = NULL, *p_mapped_file = NULL;
    uint64_t lower_bound_r, upper_bound_r, i;
    DBG_CLOCK_VARS(5);

    // First of all bind!
    cpu_bind(larg->id);

    mapped_file = malloc(2 * sizeof(uint32_t) * NR_TAC_ELEMENTS);
    if(unlikely(!mapped_file)) {
        printf("[-] __create_lkup_tables_bsearch() failed: Could not allocate memory!\n");
        free(mapped_file);
        exit(EXIT_FAILURE);
    }

    for(round=0; round<STG1B_NR_ROUNDS; round++) {

        cpu_get_work(&lower_bound_r, &upper_bound_r, larg->id, round, larg->nr_cores, STG1B_NR_ROUNDS, NR_V_ELEMENTS);

        if(verbosity > 1)
            printf("[LP_%.4d] - [%ld, %ld]\n", larg->id, lower_bound_r, upper_bound_r);

        for(i=lower_bound_r; i<=upper_bound_r; i++) {

            DBG_CLOCK_START(0);
            p_mapped_file = mapped_file;

            d = opendir(larg->dirname);
            if(unlikely(!d)) {
                printf("[-] __create_lkup_tables_bsearch() failed: opendir(%s) failed! [errno:%d]\n", larg->dirname, errno);
                free(mapped_file);
                exit(EXIT_FAILURE);
            }

            memset(fname_unsorted, 0, sizeof(fname_unsorted));
            snprintf(fname_unsorted, sizeof(fname_unsorted)-1, "unsorted_%.3d_", (int)i);

            while((dir = readdir(d))) {

                // If this triggers then someone is playing us a trick ;>
                // Or there is an uuexpected bug o_O;;
                assert((uint32_t)(p_mapped_file-mapped_file) <= (2 * sizeof(uint32_t) * NR_TAC_ELEMENTS));

                if(memcmp(dir->d_name, fname_unsorted, strlen(fname_unsorted)))
                    continue;

                snprintf(fname, sizeof(fname)-1, "%s/%s", larg->dirname, dir->d_name);
                memset(&st, 0, sizeof(st));
                ret = lstat(fname, &st);
                ASSERT(ret == 0); // TODO
                ret = read_file(fname, (uint8_t *)p_mapped_file, st.st_size);
                if(ret < 0) {
                    printf("[-] __create_lkup_tables_bsearch() failed to open %s [err:%d]\n", fname, ret);
                    free(mapped_file);
                    exit(EXIT_FAILURE);
                }

                p_mapped_file += st.st_size;
            }
            closedir(d);
            DBG_CLOCK_STOP(0);

            // Sorting the file.
            DBG_CLOCK_START(1);
            radix_sort((uint64_t *)mapped_file, NR_TAC_ELEMENTS);
            DBG_CLOCK_STOP(1);

    #if 0
            print_uint64_array_as_hex((uint64_t *)mapped_file, 20);
    #endif

            // Saving the file
            memset(fname, 0, sizeof(fname));
            snprintf(fname, sizeof(fname)-1, "%s/"SORTED_TABLE_FMT, larg->dirname, (int)i);

            DBG_CLOCK_START(2);
            ret = write_file(fname, (uint8_t *)mapped_file, 2 * sizeof(uint32_t) * NR_TAC_ELEMENTS);
            DBG_CLOCK_STOP(2);
            if(unlikely(ret < 0)) {
                printf("[-] __create_lkup_tables_bsearch() failed to write into %s [err:%d]\n", fname, ret);
                free(mapped_file);
                exit(EXIT_FAILURE);
            }

            DBG_CLOCK_START(3);
            create_index(mapped_file, i);
            DBG_CLOCK_STOP(3);

            // Saving the file
            DBG_CLOCK_START(4);
            memset(fname, 0, sizeof(fname));
            snprintf(fname, sizeof(fname)-1, "%s/"SORTED_INDEX_FMT, larg->dirname, (int)i);
            ret = write_file(fname, (uint8_t *)TabIndex[i], sizeof(uint64_t) * (1<<NR_BITS_IDX));
            DBG_CLOCK_STOP(4);
            if(ret < 0) {
                printf("[-] __create_lkup_tables_bsearch() failed to write into %s [err:%d]\n", fname, ret);
                free(mapped_file);
                exit(EXIT_FAILURE);
            }

        }

    }

#if DEBUG_TIMING
    if(unlikely(verbosity))
        printf("Load: %.2fs, Sort: %.2fs, Write: %.2fs, create_index: %.2fs, save_index: %.2fs\n", DBG_CLOCK_GET(0),
                                                                                                   DBG_CLOCK_GET(1),
                                                                                                   DBG_CLOCK_GET(2),
                                                                                                   DBG_CLOCK_GET(3),
                                                                                                   DBG_CLOCK_GET(4));
#endif

    free(mapped_file);
    exit(EXIT_SUCCESS);
}

#else /* OPTIM_LOOKUP == OPTIM_LKUP_CUCKOO */

extern BUCKET *ht[NR_V_ELEMENTS_MAX];

static __inline__
int __create_lkup_tables_cuckoo(void *arg)
{
    struct lp_arg *larg = (struct lp_arg *)arg;
    struct dirent *dir;
    char fname_unsorted[512];
    char fname[512];
    struct stat st;
    int j, round, ret;
    DIR *d = NULL;
    char *mapped_file = NULL, *p_mapped_file = NULL;
    uint64_t i, lower_bound_r, upper_bound_r;
    DBG_CLOCK_VARS(5);

    // First of all bind!
    cpu_bind(larg->id);

    mapped_file = malloc(2 * sizeof(uint32_t) * NR_TAC_ELEMENTS);
    if(unlikely(!mapped_file)) {
        printf("[-] __create_lkup_tables_cuckoo() failed: Could not allocate memory!\n");
        free(mapped_file);
        exit(EXIT_FAILURE);
    }

    for(round=0; round<STG1B_NR_ROUNDS; round++) {

        cpu_get_work(&lower_bound_r, &upper_bound_r, larg->id, round, larg->nr_cores, STG1B_NR_ROUNDS, NR_V_ELEMENTS);
        if(verbosity > 1)
            printf("[LP_%.4d] - [%ld, %ld]\n", larg->id, lower_bound_r, upper_bound_r);

        for(i=lower_bound_r; i<=upper_bound_r; i++) {

            DBG_CLOCK_START(0);
            p_mapped_file = mapped_file;

            d = opendir(larg->dirname);
            if(unlikely(!d)) {
                printf("[-] __create_lkup_tables_cuckoo() failed: opendir(%s) failed! [errno:%d]\n", larg->dirname, errno);
                free(mapped_file);
                exit(EXIT_FAILURE);
            }

            memset(fname_unsorted, 0, sizeof(fname_unsorted));
            snprintf(fname_unsorted, sizeof(fname_unsorted)-1, "unsorted_%.3d_", (int)i);

            while((dir = readdir(d))) {

                // If this triggers then someone is playing us a trick ;>
                // Or there is an uuexpected bug o_O;;
                assert((uint32_t)(p_mapped_file-mapped_file) <= (2 * sizeof(uint32_t) * NR_TAC_ELEMENTS));

                if(memcmp(dir->d_name, fname_unsorted, strlen(fname_unsorted)))
                    continue;

                snprintf(fname, sizeof(fname)-1, "%s/%s", larg->dirname, dir->d_name);
                memset(&st, 0, sizeof(st));
                ret = lstat(fname, &st);
                ASSERT(ret == 0); // TODO
                ret = read_file(fname, (uint8_t *)p_mapped_file, st.st_size);
                if(ret < 0) {
                    printf("[-] __create_lkup_tables_cuckoo() failed to open %s [err:%d]\n", fname, ret);
                    free(mapped_file);
                    exit(EXIT_FAILURE);
                }

                p_mapped_file += st.st_size;
            }
            closedir(d);
            DBG_CLOCK_STOP(0);

            ht[i] = NULL;
            cuckoo_setup_ht(&ht[i]);

            DBG_CLOCK_START(3);
            uint64_t *p = (uint64_t *)mapped_file;
            for(j=0; j<NR_TAC_ELEMENTS; j++) {

                uint32_t key   = (uint32_t)(p[j] >> 32);
                uint32_t value = (uint32_t)(p[j]);

                if(!key) {
                    if(verbosity > 1)
                        printf("[!] Skipping 0 key!\n");
                    continue;
                }

                cuckoo_put(key, value, ht[i]);
            }
            DBG_CLOCK_STOP(3);

            // Saving the file
            DBG_CLOCK_START(4);
            memset(fname, 0, sizeof(fname));
            snprintf(fname, sizeof(fname)-1, "%s/"SORTED_CUCKOO_FMT, larg->dirname, (int)i);
            ret = write_file(fname, (uint8_t *)ht[i], NR_BUCKETS * sizeof(BUCKET));
            cuckoo_free_ht(&ht[i]);
            ht[i] = NULL;
            DBG_CLOCK_STOP(4);
            if(ret < 0) {
                printf("[-] __create_lkup_tables_cuckoo() failed to write into %s [err:%d]\n", fname, ret);
                free(mapped_file);
                exit(EXIT_FAILURE);
            }

        }

    }

#if DEBUG_TIMING
    if(unlikely(verbosity))
        printf("Load: %.2fs, Sort: %.2fs, Write: %.2fs, X: %.2fs, Y: %.2fs\n", DBG_CLOCK_GET(0),
                                                                                                   DBG_CLOCK_GET(1),
                                                                                                   DBG_CLOCK_GET(2),
                                                                                                   DBG_CLOCK_GET(3),
                                                                                                   DBG_CLOCK_GET(4));
#endif

    free(mapped_file);
    exit(EXIT_SUCCESS);
}

#endif

int stg1b_create_lkup_tables(void *arg)
{
#if (OPTIM_LOOKUP == OPTIM_LKUP_BSEARCH)
    return __create_lkup_tables_bsearch(arg);
#else
    return __create_lkup_tables_cuckoo(arg);
#endif
}
