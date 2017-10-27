#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include "uthash.h"
#include "lite-cd-base.h"
//#include "buddy.h"

#define _GNU_SOURCE

#define ATOMIC_MAX_SIZE 4096
#define CHECKPOINT_THRESH 10000 //1000000
#define CHECKPOINT_THRESH_COUNT 100000 //100 //1000000
#define CHECKPOINT_SIZE 100

#ifndef LITE_CD_SETUP
#define LITE_CD_SETUP

struct sockaddr_in *node_addr;

//int network_init(int num_node, const char *server_list[]);
int network_init(int ib_port, int ethernet_port, int option);
//int network_reply(int node_id, char *content);
int handle_remote_request(int node_id, char *msg, int size);


#endif
