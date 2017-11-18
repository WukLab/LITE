#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <pthread.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <malloc.h>
#include "lite-lib.h"


int write_mode = 0;

int run_times = 10000;


int init_log(int remote_node)
{
        uint64_t xact_ID;
	uint64_t test_key;
	int i, j;
	int *random_idx;
	struct timespec start, end;
	double *total_lat;
	char *write = memalign(sysconf(_SC_PAGESIZE),1024*1024*4);
	memset(write, 0x36, 1024*64);
	//=========================RDMA syscall experiments=======================
	int n=run_times;
	int testsize[12]={8,8,64,128,512,1024,1024*2,1024*4,1024*8, 1024*16, 1024*32, 1024*64};
	int password=100;

	test_key = userspace_liteapi_alloc_remote_mem(remote_node, 1024*1024*4, 0, password);
        printf("finish allocation get key %d\n", test_key);
	for(j=0;j<12;j++)
	{
		for(i=0;i<n;i++)
		{
			userspace_liteapi_rdma_write(test_key, write, testsize[j], 0, password);
		}
	        printf("finish write %d\n", testsize[j]);
	}
	
	return 0;
}

int internal_value=0;
int main(int argc, char *argv[])
{
        if(argc==2)
        {
        	init_log(atoi(argv[1]));
        }
	return ;
}
