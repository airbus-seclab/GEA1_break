#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <ctype.h>

#include "exploit.h"

void cpu_get_work(uint64_t *lower_bound, uint64_t *upper_bound, uint32_t cpu_id, uint32_t round_idx, uint32_t nr_cores, uint32_t nr_rounds, uint64_t nr_elements)
{
    uint64_t lower_bound_0, upper_bound_0;
    uint32_t delta;

    lower_bound_0 = (cpu_id+0) * (uint32_t)(nr_elements / nr_cores);
    if((cpu_id+1) == nr_cores)
        upper_bound_0 = nr_elements - 1;
    else
        upper_bound_0 = (cpu_id+1) * (uint32_t)(nr_elements / nr_cores) - 1;

    delta = (uint32_t)((upper_bound_0-lower_bound_0+1) / nr_rounds);

    *lower_bound = lower_bound_0 + (round_idx)*(delta);
    if((round_idx+1) == nr_rounds)
        *upper_bound = upper_bound_0;
    else
        *upper_bound = lower_bound_0 + (round_idx+1)*(delta) - 1;
}

int cpu_get_nr_cores()
{
    return sysconf(_SC_NPROCESSORS_ONLN);
}

int cpu_bind(int cpu_id)
{
    cpu_set_t set;
    int ret;

    CPU_ZERO(&set);
    CPU_SET(cpu_id, &set);
    ret = sched_setaffinity(0, sizeof(set), &set);
    return ret; 
}

