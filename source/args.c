#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <argp.h>

#include "exploit.h"

#if OPTIM_LOOKUP == OPTIM_LKUP_CUCKOO
#define BACKEND_STR "cuckoo"
#else
#define BACKEND_STR "bsearch"
#endif

#if OPTIM_BATCH
#define SINGLE_BATCH_STR "batch"
#else
#define SINGLE_BATCH_STR "single"
#endif

#if OPTIM_MEM == OPTIM_MEM_HIGH
#define MEM_STR "high"
#else
#define MEM_STR "low"
#endif

#if NR_BITS_UB == 32
#define DEMO_STR ""
#else
#define DEMO_STR "/demo"
#endif

const char *argp_program_version = "GEA1_break v0.3 - "BACKEND_STR"/"SINGLE_BATCH_STR"/"MEM_STR""DEMO_STR;

const char *argp_program_bug_address = "roderick.asselineau@airbus.com";
static char doc[] = "\nImplementation of the attack described in https://eprint.iacr.org/2021/819.pdf to recover GEA-1 keys.";
static char args_doc[] = "";

// Adds verbosity

static struct argp_option options[] = {
    { "tests",          't', 0,                                             0, "Run in test mode", 0},
    { "bench",          'b', 0,                                             0, "Run the benchmarks mode", 0},
    { "precomputation", 'p', 0,                                             0, "Run the precomputation sage (stage #1)", 0},
    { "bruteforce",     'x', 0,                                             0, "Run the key recovery stage (stage #2)", 0},
    { "reverse",        'r', 0,                                             0, "Return the key based on the IV and dir_flag (stage #3)", 0},
    { "dir",            'd', "dir",                                         0, "The directoring storing the results of the precomputation", 0},
#if OPTIM_BATCH
    { "batch",          'k', "k1(hex):b1len[,k2(hex):b2len][,...]",         0, "The keystreams", 0},
#else
    { "keystream",      'k', "keystream (hex)",                             0, "The keystream", 0},
    { "length",         'l', "keystream length (bits)",                     0, "The keystream length (must be >= 56 && <= 64)", 0},
#endif
    { "all",            'a', 0,                                             0, "prevent an early exit in stage #2", 0},
    { "state",          's', "recovered_state (hex)",                       0, "The S recovered in stage #2", 0},
    { "iv",             'i', "iv (hex)",                                    0, "The IV", 0},
    { "flag",           'f', "dir_flag {0,1}",                              0, "The direction flag", 0},
    { "core",           'c', "nr_cores",                                    0, "The number of cores to use (default is maximum available)", 0},
    { "verbose",        'v', 0,                                             0, "Increase the verbosity level (default: 0)", 0},
    { 0 } 
};

// https://helloacm.com/c-coding-exercise-number-of-1-bits-revisited/
int hamming_weight(uint64_t n)
{
    int r = n & 1;
    while(n >>= 1)
        r += (n & 1);
    return r;
}

int handle_cpu(long *nr_cpu)
{
    long nr_available_cores = cpu_get_nr_cores();

    if(nr_available_cores < 1 || *nr_cpu < 1)
        return -1;

    // If we requested more CPU than available.
    if(*nr_cpu > nr_available_cores) {
        printf("[!] Requested: %ld / %ld cores, providing: %ld\n", *nr_cpu, nr_available_cores, nr_available_cores);
        *nr_cpu = nr_available_cores;
    }

    return 0;
}

#if OPTIM_BATCH
// Ok this is a very simple/lazy parser but users ought to know what they
// do anyway... :)
int handle_batch(char *arg, struct arguments *arguments)
{
    char *chunk = strtok(arg, ":,");
    int i=0;
    while(chunk) {

        // Overflow? ;>
        if((i/2) >= NR_KS_MAX) {
            printf("[!] Too many keystreams specified, keeping the %d first.\n", NR_KS_MAX);
            break;
        }

        if(!(i%2)) {
            arguments->target.keystream[i/2].bitvector = strtoull(chunk, NULL, 16);  // 64 bits value
            if(!arguments->target.keystream[i/2].bitvector)
                return -1;
            arguments->target.keystream[i/2].bitlength = 64;
            arguments->target.keystream[i/2].bitmask = 0xffffffffffffffff;
            arguments->target.keystream[i/2].solved = 0;
            arguments->target.nr_targets += 1;
        } else {
            arguments->target.keystream[(i-1)/2].bitlength = strtoul(chunk, NULL, 10);
            if(arguments->target.keystream[(i-1)/2].bitlength > 64 || arguments->target.keystream[(i-1)/2].bitlength < 56)
                return -2;
            if(arguments->target.keystream[(i-1)/2].bitlength == 64)
                arguments->target.keystream[(i-1)/2].bitmask = 0xffffffffffffffff;
            else
                arguments->target.keystream[(i-1)/2].bitmask = ((1UL<<(arguments->target.keystream[(i-1)/2].bitlength))-1);
        }
        chunk = strtok(NULL, ":,");
        i++;
    }

    return 0;
}
#endif

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;
    long nr_cpu;

    switch (key) {
        case 't':
            arguments->mode = MODE_TEST;
            break;
        case 'b':
            arguments->mode = MODE_BENCH;
            break;
        case 'p':
            arguments->mode = MODE_PRECOMPUTATION;
            break;
        case 'x':
            arguments->mode = MODE_BRUTEFORCE;
            break;
        case 'a':
            arguments->all = 1;
            break;
        case 'r':
            arguments->mode = MODE_REVERSE;
            break;
        case 'd':
            arguments->dir_name = strdup(arg);
            break;
        case 's':
            arguments->S = strtoull(arg, NULL, 16); // 64 bits value
            arguments->S_is_set = 1;
            break;
        case 'i':
            arguments->IV = strtoul(arg, NULL, 16); // 32 bits value
            arguments->IV_is_set = 1;
            break;
#if OPTIM_BATCH
        case 'k':
            arguments->batch = strdup(arg);
            if(handle_batch(arguments->batch, arguments) < 0) {
                free(arguments->batch);
                return ARGP_ERR_UNKNOWN;
            }
            free(arguments->batch);
            arguments->batch = NULL;
            break;
#else
        // Without the batch mode, we only care about a single keystream
        case 'k':
            // Currently we do not accept 0 bitvector because errno is not
            // set properly to EINVAL even when the results of the conversion
            // is messed up therefore we have no way to distinguish errors
            // properly.
            arguments->target.keystream[0].bitvector = strtoull(arg, NULL, 16);  // 64 bits value
            if(!arguments->target.keystream[0].bitvector)
                return ARGP_ERR_UNKNOWN;
            arguments->target.keystream[0].solved = 0; // only interesting in batch mode.
            arguments->target.nr_targets += 1;
            break;
        case 'l':
            arguments->target.keystream[0].bitlength = strtoul(arg, NULL, 10);
            if(arguments->target.keystream[0].bitlength >= 64 || arguments->target.keystream[0].bitlength < 56)
                arguments->target.keystream[0].bitmask = 0xFFFFFFFFFFFFFFFF;
            else
                arguments->target.keystream[0].bitmask = ((1UL<<(arguments->target.keystream[0].bitlength))-1);
            break;
#endif
        case 'f':
            arguments->flag = (strtol(arg, NULL, 10) == 1);  // 1 bit value
            arguments->flag_is_set = 1;
            break;
        case 'c':
            nr_cpu = strtol(arg, NULL, 10);
            if(handle_cpu(&nr_cpu) < 0)
                return ARGP_ERR_UNKNOWN;
            arguments->nr_cores = nr_cpu;
            break;
        case 'v':
            arguments->verbosity += 1;
            break;
        case ARGP_KEY_ARG:
            return 0;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };
