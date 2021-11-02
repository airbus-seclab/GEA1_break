#ifndef __TIMING_H__
#define __TIMING_H__

#include "exploit.h"

// Conversion API
#define MS(x)   (1000*(x))
#define US(x)   (1000*1000*(x))
#define NS(x)   (1000*1000*1000*(x))

// Timing API
#define CLOCK_VARS(i)   clock_t __t1[(i)] = {0}, __t2[(i)] = {0}; \
                        double __cpu_time_used[i] = {0};
#define CLOCK_START(i)  __t1[(i)] = clock()
#define CLOCK_STOP(i)   __t2[(i)] = clock(); \
                        __cpu_time_used[(i)] += ((double)(__t2[(i)] - __t1[(i)])) / CLOCKS_PER_SEC;
#define CLOCK_GET(i)    __cpu_time_used[(i)]

#if DEBUG_TIMING
#define DBG_CLOCK_VARS(i)    CLOCK_VARS(i)
#define DBG_CLOCK_START(i)   CLOCK_START(i)
#define DBG_CLOCK_STOP(i)    CLOCK_STOP(i)
#define DBG_CLOCK_GET(i)     CLOCK_GET(i)
#else
#define DBG_CLOCK_VARS(i)
#define DBG_CLOCK_START(i)
#define DBG_CLOCK_STOP(i)
#define DBG_CLOCK_GET(i)
#endif

// Clocking API

#endif /* __TIMING_H__ */
