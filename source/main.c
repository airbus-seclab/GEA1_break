#include <stdio.h>
#include <argp.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/shm.h>

#include "exploit.h"
#include "file.h"
#include "timing.h"
#include "transform.h"

int verbosity = 0;
extern struct argp argp;
int nr_provided_cores = 0;

void do_tests()
{
    CLOCK_VARS(1);

    printf("[+] Satety tests\n");
    CLOCK_START(0);
    test_cpu_load();
    test_hw();
    test_transform_state1();
    test_transform_state2();
    test_init_S();
    test_retrieve_K();
    test_registerB();
    test_registerA();
    test_registerC();
    test_rotate();
    test_initA();
    test_initB();
    test_initC();
    test_GEA1();
    CLOCK_STOP(0);
    printf("\t-> OK [%.2fs]\n", CLOCK_GET(0));
}

void do_bench(char *dirname)
{
    printf("[+] Benchmarking\n");

#if OPTIM_SCHED
    select_computation_scheduling();
#endif
    bench_LFSR_B();
    bench_RegisterA();
    bench_RegisterA2();
    bench_RegisterB();
    bench_RegisterB2();
    bench_RegisterC();
    bench_RegisterC2();
#if OPTIM_SCHED
    select_io_scheduling();
#endif
    if(!dirname)
        bench_sort1();
    else
        bench_sort2(dirname);
}

int do_precomputation(char *dirname)
{
    time_t t1, t2;
    CLOCK_VARS(1);
    struct lp_arg *largs = NULL;
    pid_t *pids = NULL;
    int wstatus;
    int i;
    int nr_cores2;

    largs = calloc(nr_provided_cores, sizeof(struct lp_arg));
    pids = calloc(nr_provided_cores, sizeof(pid_t));

    if(!largs || !pids) {
        printf("[-] Running out of memory...\n");
        free(largs);
        free(pids);
        return -1;
    }

    printf("[+] Preparing V, TAC basis\n");
    CLOCK_START(0);
    setup_v_basis();
    setup_tac_basis();
    CLOCK_STOP(0);
    printf("\t-> OK [%.2f ms]\n", MS(CLOCK_GET(0)));

    printf("[+] Preparing MB matrix\n");
    CLOCK_START(0);
    setup_MB_matrix();
    CLOCK_STOP(0);
    if(unlikely(verbosity))
        printf("\t-> OK [%.2f ms]\n", MS(CLOCK_GET(0)));

    printf("[+] Preparing the v elements for all the cores\n");
    CLOCK_START(0);
    precompute_v_elements();
    CLOCK_STOP(0);
    if(unlikely(verbosity))
        printf("\t-> OK [%.2f ms]\n", MS(CLOCK_GET(0)));

    // Generate the keystream
    if(NR_BITS_TAC != NR_BITS_TAC_MAX)
        printf("[+] Generating RegB keystreams O(2^%d) [Demo]\n", NR_BITS_TAC);
    else
        printf("[+] Generating RegB keystreams O(2^32) [Full]\n");
    printf("\t-> using %d cores\n", nr_provided_cores);

    for(i=0; i<nr_provided_cores; i++) {
        largs[i].id = i;
        largs[i].nr_cores = nr_provided_cores;
        largs[i].dirname = dirname;
    }

    t1 = time(NULL);

    for(i=0; i<nr_provided_cores; i++) {
        pids[i] = fork();
        if(!pids[i]) {
            stg1a_create_raw_data(&largs[i]);
        }
    }

    for(i=0; i<nr_provided_cores; i++) {
        wstatus = 0;
        wait(&wstatus);
    }

    t2 = time(NULL);
    printf("\t-> All LP have terminated\n");
    if(unlikely(verbosity))
        printf("\t-> OK [ %lds ~ %.2fm]\n", t2-t1, (float)(t2-t1)/60);

    // Cleaning the pids array
    memset(pids, 0, nr_provided_cores * sizeof(pid_t));
    memset(largs, 0, nr_provided_cores * sizeof(struct lp_arg));

    printf("[+] Sorting the tables\n");
    t1 = time(NULL);

    // Handling corner cases.
    nr_cores2 = nr_provided_cores;
    if(nr_cores2 > NR_V_ELEMENTS)
        nr_cores2 = NR_V_ELEMENTS;

    for(i=0; i<nr_cores2; i++) {
        largs[i].id = i;
        largs[i].nr_cores = nr_cores2;
        largs[i].dirname = dirname;
    }

    for(i=0; i<nr_cores2; i++) {
        pids[i] = fork();
        if(!pids[i]) {
            stg1b_create_lkup_tables(&largs[i]);
        }
    }

    for(i=0; i<nr_cores2; i++) {
        wstatus = 0;
        wait(&wstatus);
    }

    t2 = time(NULL);
    if(unlikely(verbosity))
        printf("\t-> OK [ %lds ~ %.2fm ]\n", t2-t1, (float)(t2-t1)/60);

#if DEBUG_MALLOC
    printf("[+] Freeing everything!\n");
    CLOCK_START(0);
    free_MB_matrix();
    CLOCK_STOP(0);
    if(unlikely(verbosity))
        printf("\t-> OK [ %.2fs ]\n", CLOCK_GET(0));
#endif
    free(largs);
    free(pids);
    return 0;
}

#if (OPTIM_LOOKUP == OPTIM_LKUP_BSEARCH)
int fd_sorted_files[NR_V_ELEMENTS_MAX];

static __inline__
int __bruteforce_bsearch(struct arguments *args)
{
    CLOCK_VARS(1);
    time_t start, end;
    int wstatus, i, ret;
    struct lp_arg *largs = NULL;
    pid_t *pids = NULL;
    char fname[512];
    uint64_t size_allocated;
    time_t start2 = time(NULL);
    int fd;
    char *f_name_tmp = NULL;
    struct _target *t = NULL;
    key_t key;
    int shmid;

    largs = calloc(nr_provided_cores, sizeof(struct lp_arg));
    pids = calloc(nr_provided_cores, sizeof(pid_t));

    if(unlikely(!largs || !pids)) {
        printf("[-] Running out of memory...\n");
        ret = -1;
        goto bye;
    }

    printf("[+] Preparing V, B, TAC basis\n");
    CLOCK_START(0);
    setup_v_basis();
    setup_ub_basis();
    setup_tac_basis();
    CLOCK_STOP(0);
    if(unlikely(verbosity))
        printf("\t-> OK [%.2f ms]\n", MS(CLOCK_GET(0)));

    printf("[+] Preparing MA, MB, MC\n");
    CLOCK_START(0);
    setup_MA_matrix();
    setup_MB_matrix();
    setup_MC_matrix();
    CLOCK_STOP(0);
    if(unlikely(verbosity))
        printf("\t-> OK [%.2f ms]\n", MS(CLOCK_GET(0)));

    printf("[+] Preparing the v elements for all the cores\n");
    CLOCK_START(0);
    precompute_v_elements();
    CLOCK_STOP(0)
    if(unlikely(verbosity))
        printf("\t-> OK [%.2f ms]\n", MS(CLOCK_GET(0)));

    // TODO: proper error handling.
    printf("[+] Preparing memory to load/store the results of the computation\n");
    ret = alloc_all_sorted_Tab();
    if(unlikely(ret)) {
        ret = -7;
        goto bye;
    }

    size_allocated = sizeof(uint32_t) * NR_TAC_ELEMENTS * NR_V_ELEMENTS;
    if(unlikely(verbosity))
        printf("\t-> Allocated: %.2f Gb\n", (float)(size_allocated)/(1<<30));

    printf("[+] Loading computation from %s/\n", args->dir_name);
    start = time(NULL);
    ret = load_sorted_Tab(args->dir_name, NR_V_ELEMENTS); // TODO.
    if(unlikely(ret < 0)) {
        ret = -6;
        goto bye;
    }

    end = time(NULL);
    if(unlikely(verbosity))
        printf("\t-> OK [%lds]\n", end-start);

    // Open the sorted files so that the children inherits FD.
    memset(fd_sorted_files, 0, sizeof(fd_sorted_files));
    for(i=0; i<NR_V_ELEMENTS_MAX; i++) {
        memset(fname, 0, sizeof(fname));
        snprintf(fname, sizeof(fname)-1, "%s/"SORTED_TABLE_FMT, args->dir_name, i);
        fd = open(fname, O_RDONLY);
        if(unlikely(fd < 0)) {
            ret = -2;
            goto bye;
        }
        fd_sorted_files[i] = fd;
    }

    f_name_tmp = create_tmp_file();
    if(!f_name_tmp) {
        printf("[-] Error, create_tmp_file() failed!\n");
        ret = -3;
        goto bye;
    }

    if(verbosity > 1) {
        printf("[+] Created %s file\n", f_name_tmp);
    }

    key = ftok(f_name_tmp, getpid()&0xFF);
    shmid = shmget(key, 8192, 0666|IPC_CREAT);
    if(shmid < 0) {
        printf("[-] Error, shmget() failed [errno:%d]\n", errno);
        ret = -4;
        goto bye;
    }

    t = (struct _target *) shmat(shmid, (void*)0, 0);
    if(t==(void*)(-1)) {
        printf("[-] Error, shmat() failed [errno:%d]\n", errno);
        ret = -5;
        goto bye;
    }

    memcpy(t, &args->target, sizeof(struct _target));

    if(NR_BITS_UB != NR_BITS_UB_MAX)
#if OPTIM_BATCH
        printf("[+] Generating RegA+RegC keystreams (2^%d) to crack %d keystreams [Demo]\n", NR_BITS_UB, args->target.nr_targets);
#else
        printf("[+] Generating RegA+RegC keystreams (2^%d) to crack 0x%lx [Demo]\n", NR_BITS_UB, args->target.keystream[0].bitvector);
#endif
    else
        printf("[+] Generating RegA+RegC keystreams (2^32) [Full]\n");
    printf("\t-> using %d cores\n", nr_provided_cores);

    start = time(NULL);

    for(i=0; i<nr_provided_cores; i++) {
        largs[i].id = i;
        largs[i].nr_cores = nr_provided_cores;
        largs[i].dirname = args->dir_name;
        largs[i].key = key;
        largs[i].start = start2;
        largs[i].round_idx = 0;
        largs[i].early_exit = args->all ? 0 : 1;
    }

    for(i=0; i<nr_provided_cores; i++) {
        pids[i] = fork();
        if(!pids[i]) {
            stg2_state_recovery(&largs[i]);
        }
    }

    for(i=0; i<nr_provided_cores; i++) {
        wstatus = 0;
        wait(&wstatus);
    }
    end = time(NULL);

    printf("\t-> All LP have terminated\n");
    if(unlikely(verbosity))
        printf("\t-> OK [%lds]\n", end-start);

    ret = 0;

    // TODO. Missing things.
bye:

    // Closing FD.
    for(i=0; i<NR_V_ELEMENTS_MAX; i++) {
        if(fd_sorted_files[i])
            close(fd_sorted_files[i]);
        fd_sorted_files[i] = 0;
    }

    if(t)
        shmdt(t);
    if(f_name_tmp) {
        unlink(f_name_tmp);
        free(f_name_tmp);
    }

#if DEBUG_MALLOC
    printf("[+] Freeing everything!\n");
    CLOCK_START(0)
    free_MC_matrix();
    free_MB_matrix();
    free_MA_matrix();
    CLOCK_STOP(0)
    if(unlikely(verbosity))
        printf("\t-> OK [ %.2fs ]\n", cpu_time_used);
#endif
    if(largs)
        free(largs);
    if(pids)
        free(pids);
    return ret;
}

#else

static __inline__
int __bruteforce_cuckoo(struct arguments *args)
{
    CLOCK_VARS(1);
    time_t start, end;
    int wstatus, i, round, ret;
    struct lp_arg *largs = NULL;
    pid_t *pids = NULL;
    time_t start2 = time(NULL);
    char *f_name_tmp = NULL;
    struct _target *t = NULL;
    key_t key;
    int shmid;

    largs = calloc(nr_provided_cores, sizeof(struct lp_arg));
    pids = calloc(nr_provided_cores, sizeof(pid_t));

    if(!largs || !pids) {
        printf("[-] Running out of memory...\n");
        ret = -1;
        goto bye;
    }

    printf("[+] Preparing V, B, TAC basis\n");
    CLOCK_START(0);
    setup_v_basis();
    setup_ub_basis();
    setup_tac_basis();
    CLOCK_STOP(0);
    if(unlikely(verbosity))
        printf("\t-> OK [%.2f ms]\n", MS(CLOCK_GET(0)));

    printf("[+] Preparing MA, MB, MC\n");
    CLOCK_START(0);
    setup_MA_matrix();
    setup_MB_matrix();
    setup_MC_matrix();
    CLOCK_STOP(0);
    if(unlikely(verbosity))
        printf("\t-> OK [%.2f ms]\n", MS(CLOCK_GET(0)));

    printf("[+] Preparing the v elements for all the cores\n");
    CLOCK_START(0);
    precompute_v_elements();
    CLOCK_STOP(0)
    if(unlikely(verbosity))
        printf("\t-> OK [%.2f ms]\n", MS(CLOCK_GET(0)));

    f_name_tmp = create_tmp_file();
    if(!f_name_tmp) {
        printf("[-] Error, create_tmp_file() failed!\n");
        ret = -2;
        goto bye;
    }

    if(verbosity > 1) {
        printf("[+] Created %s file\n", f_name_tmp);
    }

    key = ftok(f_name_tmp, getpid()&0xFF);
    shmid = shmget(key, 8192, 0666|IPC_CREAT);
    if(shmid < 0) {
        printf("[-] Error, shmget() failed [errno:%d]\n", errno);
        ret = -3;
        goto bye;
    }

    t = (struct _target *) shmat(shmid, (void*)0, 0);
    if(t==(void*)(-1)) {
        printf("[-] Error, shmat() failed [errno:%d]\n", errno);
        ret = -4;
        goto bye;
    }

    memcpy(t, &args->target, sizeof(struct _target));

    for(round=0; round<STG2_NR_ROUNDS; round++) {

        // Let's avoid working for nothing.
        if(!args->all && t->nr_state_recovered == t->nr_targets) {
            break;
        }

        printf("[+] Loading hash tables [%d,%d] from %s/\n", round*(NR_V_ELEMENTS/STG2_NR_ROUNDS), ((round+1)*(NR_V_ELEMENTS/STG2_NR_ROUNDS)-1), args->dir_name);
        start = time(NULL);
        ret = load_hash_Tab(args->dir_name, round*(NR_V_ELEMENTS/STG2_NR_ROUNDS), (NR_V_ELEMENTS/STG2_NR_ROUNDS));
        if(ret < 0) {
            ret = -5;
            goto bye;
        }

        end = time(NULL);
        if(unlikely(verbosity))
            printf("\t-> OK [%lds]\n", end-start);

        if(NR_BITS_UB != NR_BITS_UB_MAX)
#if OPTIM_BATCH
            printf("[+] Generating RegA+RegC keystreams (2^%d) to crack %d keystreams [Demo]\n", NR_BITS_UB, args->target.nr_targets);
#else
            printf("[+] Generating RegA+RegC keystreams (2^%d) to crack 0x%lx [Demo]\n", NR_BITS_UB, args->target.keystream[0].bitvector);
#endif
        else
            printf("[+] Generating RegA+RegC keystreams (2^32) [Full]\n");
        printf("\t-> using %d cores\n", nr_provided_cores);

        start = time(NULL);

        for(i=0; i<nr_provided_cores; i++) {
            largs[i].id = i;
            largs[i].nr_cores = nr_provided_cores;
            largs[i].dirname = args->dir_name;
            largs[i].key = key;
            largs[i].start = start2;
            largs[i].round_idx = round;
            largs[i].early_exit = args->all ? 0 : 1;
        }

        for(i=0; i<nr_provided_cores; i++) {
            pids[i] = fork();
            if(!pids[i]) {
                stg2_state_recovery(&largs[i]);
            }
        }

        for(i=0; i<nr_provided_cores; i++) {
            wstatus = 0;
            wait(&wstatus);
        }
        end = time(NULL);

        printf("\t-> All LP have terminated\n");
        if(unlikely(verbosity))
            printf("\t-> OK [%lds]\n", end-start);

        printf("[+] Unloading hash tables from %s/\n", args->dir_name);
        start = time(NULL);
        unload_hash_Tab((NR_V_ELEMENTS/2));
        end = time(NULL);
        if(unlikely(verbosity))
            printf("\t-> OK [%lds]\n", end-start);

    }

    ret = 0;

bye:

    if(t)
        shmdt(t);
    if(f_name_tmp) {
        unlink(f_name_tmp);
        free(f_name_tmp);
    }

#if DEBUG_MALLOC
    printf("[+] Freeing everything!\n");
    CLOCK_START(0)
    free_MC_matrix();
    free_MB_matrix();
    free_MA_matrix();
    CLOCK_STOP(0)
    if(unlikely(verbosity))
        printf("\t-> OK [ %.2fs ]\n", cpu_time_used);
#endif
    if(largs)
        free(largs);
    if(pids)
        free(pids);
    return ret;
}
#endif

int do_bruteforce(struct arguments *args)
{
#if (OPTIM_LOOKUP == OPTIM_LKUP_CUCKOO)
    return __bruteforce_cuckoo(args);
#else
    return __bruteforce_bsearch(args);
#endif
}

static __inline__
void clean_arguments(struct arguments *args)
{
    args->mode = MODE_TEST;
    args->dir_name = NULL;
#if OPTIM_BATCH
    args->batch = NULL;
#endif
    memset(&args->target, 0, sizeof(args->target));
    args->IV = 0;
    args->IV_is_set = 0;
    args->S = 0;
    args->S_is_set = 0;
    args->flag = false;
    args->flag_is_set = 0;
    args->nr_cores = cpu_get_nr_cores();
    args->verbosity = 0;
    args->all = 0;
}

int main(int argc, char **argv)
{
    struct arguments args;
    int ret;

    clean_arguments(&args);

    // Once and for all.
    setup_f_table();

    // Perform the parsing of the CLI arguments.
    argp_parse(&argp, argc, argv, 0, 0, &args);
    nr_provided_cores = args.nr_cores;

    // Fixes the verbosity
    verbosity = args.verbosity;

    // Default mode.
    if(args.mode == MODE_TEST) {
        do_tests();
        exit(EXIT_SUCCESS);
    }

    // Used to check how fast our routines are.
    // TODO: Create an estimation of the global time of exploitation on
    // given system.
    else if(args.mode == MODE_BENCH) {
        do_bench(args.dir_name);
        exit(EXIT_SUCCESS);
    }

    // Generate the required tables
    // Store these tables on disk (--db)
    else if(args.mode == MODE_PRECOMPUTATION) {
        if(!args.dir_name) {
            printf("[-] Please provide an output file using --dir to save the bitstream\n");
            exit(EXIT_FAILURE);
        }

        ret = create_directory(args.dir_name);
        if(ret < 0) {
            printf("[-] Failed to create directory %s [ret=%d]\n", args.dir_name, ret);
            exit(EXIT_FAILURE);
        }

        do_precomputation(args.dir_name);
        exit(EXIT_SUCCESS);
    }

    else if(args.mode == MODE_BRUTEFORCE) {

        if(!args.dir_name || !is_directory_created(args.dir_name)) {
            printf("[-] Please provide a valid location using --dir to load the precomputation results\n");
            exit(EXIT_FAILURE);
        }

#if OPTIM_BATCH
        if(!args.target.nr_targets) {
            printf("[-] Please provide your keystreams in hex:length,[...] using --batch\n");
            exit(EXIT_FAILURE);
        }

        if(verbosity) {
            printf("[+] Batch mode! Attempting to crack:\n");
            for(int i=0; i<args.target.nr_targets; i++) {
                printf("\t-> [b%02d] %.16lx (%d) [mask:%lx]\n", i,
                                                                args.target.keystream[i].bitvector,
                                                                args.target.keystream[i].bitlength,
                                                                args.target.keystream[i].bitmask);
            }
        }
#else
        if(args.target.nr_targets != 1) {
            printf("[-] Please provide a single keystream in hex using --keystream\n");
            exit(EXIT_FAILURE);
        }

        if(!args.target.keystream[0].bitlength) {
            printf("[-] Please provide a valid keystream bitlength using --length\n");
            exit(EXIT_FAILURE);
        }

        if(args.target.keystream[0].bitlength < 56 || args.target.keystream[0].bitlength > 64) {
            printf("[-] Please provide a length in range [56,64]\n");
            exit(EXIT_FAILURE);
        }
#endif

        do_bruteforce(&args);
        exit(EXIT_SUCCESS);
    }

    else if(args.mode == MODE_REVERSE) {

        uint8_t K[64];
        uint8_t S_225[64];
        uint8_t IV[32];
        uint64_t q_K = 0;

        if(!args.IV_is_set) {
            printf("[-] Please provide the 32 bits IV using --iv\n");
            exit(EXIT_FAILURE);
        }

        if(!args.S_is_set) {
            printf("[-] Please provide the recovered 64 bits S using --state\n");
            exit(EXIT_FAILURE);
        }

        if(!args.flag_is_set) {
            printf("[-] Please provide the direction flag using -f\n");
            exit(EXIT_FAILURE);
        }

        if(verbosity) {
            printf("[+] Recovering key using state:%lx iv:%x dir:%d\n", args.S, args.IV, args.flag);
        }

        memset(K, 0, sizeof(K));
        transform_qword_2_list(args.S, S_225, 64);
        transform_qword_2_list(args.IV, IV, 32);
        retrieve_K(K, S_225, IV, args.flag);
        transform_list_2_qword(K, 64, &q_K);

        printf("K = %lx\n", q_K);
        exit(EXIT_SUCCESS);
    }

    return 0;
}
