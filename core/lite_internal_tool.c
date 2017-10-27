#include "lite_internal_tool.h"
long long int Internal_Stat_Sum=0;
int Internal_Stat_Count=0;
EXPORT_SYMBOL(Internal_Stat_Count);

long long int client_internal_stat(long long input, int flag)
{
        if(flag == LITE_STAT_ADD)
        {
                Internal_Stat_Sum += input;
                Internal_Stat_Count ++;
                return 0;
        }
        else if(flag == LITE_STAT_CLEAR)
        {
                long long int ret;
                ret = Internal_Stat_Sum / Internal_Stat_Count;
		printk(KERN_CRIT "%lld / %d \n", Internal_Stat_Sum, Internal_Stat_Count);
                Internal_Stat_Sum = 0;
                Internal_Stat_Count = 0;
                return ret;
        }
        else if(flag == LITE_STAT_TEMP)
        {
                long long ret;
                ret = Internal_Stat_Sum / Internal_Stat_Count;
                return ret;
        }
        printk(KERN_CRIT "%s Error: flag undefined - %d\n", __func__, flag);
        return -1;
}
EXPORT_SYMBOL(client_internal_stat);

inline long long client_get_time_difference(ktime_t inputtime, ktime_t endtime)
{
	return (long long) ktime_to_ns(ktime_sub(endtime, inputtime));
}
EXPORT_SYMBOL(client_get_time_difference);




