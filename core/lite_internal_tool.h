#ifndef _INCLUDE_LITE_INTERNAL_TOOL_H
#define _INCLUDE_LITE_INTERNAL_TOOL_H

#include "lite.h"
enum LITE_STAT {
    LITE_STAT_ADD,
    LITE_STAT_CLEAR,
    LITE_STAT_TEMP
};

long long int client_internal_stat(long long input, int flag);
inline long long client_get_time_difference(ktime_t inputtime, ktime_t endtime);
#endif
