#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <linux/sched.h>

#include "exploit.h"

// from main.c
extern int verbosity;

#if OPTIM_SCHED
void select_computation_scheduling(void)
{
    struct sched_param param = {0};
    int policy, ret;

    policy = sched_getscheduler(0);
    if(policy == SCHED_BATCH)
        return;

    ret = sched_setscheduler(0, SCHED_BATCH, &param);
    policy = sched_getscheduler(0);
    if(verbosity && (ret == -1 || policy != SCHED_BATCH)) {
        printf("[!] select_computation_scheduling() failed to set the SCHED_BATCH policy\n");
    }
    return;
}

void select_io_scheduling(void)
{
    struct sched_param param = {0};
    int policy, ret;

    policy = sched_getscheduler(0);
    if(policy == SCHED_OTHER)
        return;

    ret = sched_setscheduler(0, SCHED_OTHER, &param);
    policy = sched_getscheduler(0);
    if(verbosity && (ret == -1 || policy != SCHED_OTHER)) {
        printf("[!] select_io_scheduling() failed to set the SCHED_OTHER policy\n");
    }
    return;
}
#endif
