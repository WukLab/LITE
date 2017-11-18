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

int main(int argc, char *argv[])
{
        printf("Ready to join a LITE cluster\n");
        userspace_liteapi_join("192.168.1.1", 18500, 1);
        printf("after join cluster as %d\n", userspace_liteapi_get_node_id());
	return 0;
}
