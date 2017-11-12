#define _GNU_SOURCE

#ifndef HAVE_SERVER_H
#define HAVE_SERVER_H


//This is the version modified from 000be840c215d5da3011a2c7b486d5ae122540c4
//It adds LOCKS, sge, and other things  into the system
//Client.h is also modified.
//Server is also modified to match this patch
//Patch SERIAL_VERSION_ID: 04202300
//Please make sure that this version is not fully tested inside dsnvm (interactions are not fully tested)

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <malloc.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>

#include "mgmt_server.h"
#include "lite-cd-base.h"
#include <pthread.h>    /* POSIX Threads */
#include <semaphore.h>


struct list_head {
	struct list_head *next, *prev;
};

struct atomic_struct{
        void    *vaddr;
        size_t  len;
};

#include "fifo.h"


//#define LITE_ROCE
#ifdef LITE_ROCE
	#define SGID_INDEX 0
#else
	#define SGID_INDEX -1
#endif

#define MAX_NODE 16
#define FIRST_ASK_MR_SET 16
#define LID_SEND_RECV_FORMAT "0000:0000:000000:000000:00000000000000000000000000000000"
#define LISTEN_BACKLOG 10
#define LISTEN_PORT 18500
#define SEND_BUF_LENGTH 4096
#define RECV_DEPTH 2048
#define NODE_ID 0
#define MESSAGE_SIZE 4096
#define MAX_LOCK 1024

#define NUM_PARALLEL_CONNECTION 4
#define MAX_ATOMIC_SEND_NUM 4096
#define MAX_CONNECTION MAX_NODE*NUM_PARALLEL_CONNECTION
#define MAX_PARALLEL_THREAD 32 //Assume that MAX_NODE * NUM_PARALLEL_CONNECT is smaller than 256
#define WRAP_UP_NUM_FOR_WRID 256 //since there are 64 bits in wr_id, we are going to use 9-12 bits to do thread id waiting passing
#define WRAP_UP_NUM_FOR_WAITING_INBOX 256
#define WRAP_UP_NUM_FOR_CIRCULAR_ID 256
#define WRAP_UP_NUM_FOR_TYPE 65536 //since there are 64 bits in wr_id, we are going to use 9-12 bits to do thread id waiting passing
#define CIRCULAR_BUFFER_LENGTH 1024

#ifdef LITE_ROCE
	#define LITE_MTU IBV_MTU_1024
#else
	#define LITE_MTU IBV_MTU_4096
#endif

pthread_mutex_t atomic_accessing_lock[MAX_NODE];
sem_t get_thread_waiting_number_semaphore;
pthread_mutex_t get_thread_waiting_number_mutex;
//pthread_mutex_t connection_lock[MAX_CONNECTION];
pthread_mutex_t connection_lock;
sem_t send_reply_wait_semaphore;
pthread_mutex_t send_reply_wait_mutex;
pthread_mutex_t num_lock_mutex;
pthread_mutex_t fifo_lock_mutex;

#define HIGH_PRIORITY 8
#define LOW_PRIORITY 0
#define CONGESTION_ALERT 2
#define CONGESTION_WARNING 1
#define CONGESTION_FREE 0

volatile unsigned long long int shared_locks[MAX_LOCK]  __attribute__((aligned(0x1000)));
struct liteapi_two_ports{
    int ib_port;
    int ethernet_port;
    int options;
};


struct liteapi_post_receive_intermediate_struct
{
    uintptr_t header;
    uintptr_t msg;
};
struct liteapi_header{
    uint32_t        src_id;
    uint64_t        store_addr;
    uint64_t        store_semaphore;
    uint32_t        length;
    int             priority;
    int             type;
};
struct send_and_reply_format
{       
        uint32_t        src_id;
        uint64_t        store_addr;
        uint64_t        store_semaphore;
        uint32_t        length;
        int             type;
        char            *msg;
	int	 	bridge_destination;
	int		bridge_source;
	int		bridge_remain_hops;
	struct		list_head list;
};
  enum {
    MSG_MR,
    MSG_DONE,
    MSG_NODE_JOIN,
    MSG_NODE_JOIN_UD,
    MSG_SERVER_SEND,
    MSG_CLIENT_SEND,
    MSG_CREATE_LOCK,
    MSG_CREATE_LOCK_REPLY,
    MSG_RESERVE_LOCK,
    MSG_ASSIGN_LOCK,
    MSG_UNLOCK,
    MSG_ASK_LOCK,
    MSG_ASK_LOCK_REPLY,
    MSG_GET_REMOTEMR,
    MSG_GET_REMOTE_ATOMIC_OPERATION,
    MSG_GET_REMOTEMR_REPLY,
    MSG_GET_SEND_AND_REPLY_1,
    MSG_GET_SEND_AND_REPLY_2,
    MSG_GET_ATOMIC_START,
    MSG_GET_ATOMIC_MID,
    MSG_GET_ATOMIC_REPLY,
    MSG_GET_ATOMIC_SINGLE_START,
    MSG_GET_ATOMIC_SINGLE_MID,
    MSG_ASK_MR_1,
    MSG_ASK_MR_2,
    MSG_MR_REQUEST,
    MSG_GET_SEND_AND_REPLY_OPT_1,
    MSG_GET_SEND_AND_REPLY_OPT_2,
    MSG_GET_INTERNAL_EXCHANGE,
    MSG_DIST_BARRIER,
    MSG_GET_FINISH,
    MSG_QUERY_PORT_1,
    MSG_QUERY_PORT_2,
    MSG_PASS_LOCAL_IMM,
    MSG_DO_RC_POST_RECEIVE,
    MSG_DO_UD_POST_RECEIVE,
    MSG_DO_ACK
  };
  enum lock_state{
    LOCK_USED,
    LOCK_AVAILABLE,
    LOCK_LOCK,
    LOCK_ASSIGNED
  };
struct buf_message
{
        char buf[MESSAGE_SIZE];
};

struct lmr_info {
        //struct ib_device      *context;
        //struct ib_pd          *pd;
        void                    *addr;
        size_t                  length;
        //uint32_t              handle;
        uint32_t                lkey;
        uint32_t                rkey;
        uint32_t                node_id;                                                      
};

typedef struct lmr_info remote_spinlock_t;

struct client_ah_combined
{
        int                     qpn;
	int                     node_id;
       	int                     qkey;
	int                     dlid;
	union ibv_gid		gid;
};

struct lite_context {
	struct ibv_context	*context;
	struct ibv_comp_channel *channel;
	struct ibv_pd		*pd;
	struct ibv_cq		*cq; // one completion queue for all qps
	struct ibv_qp		*qp; // multiple queue pair for multiple connections
	struct client_ah_combined *ah_attrUD;
	struct ibv_ah		**ah;
    struct ibv_qp       *loopback_in;
    struct ibv_qp       *loopback_out;
    struct ibv_cq       *loopback_cq;
	int			 size;
	int			 send_flags;
	int			 rx_depth;
//	int			 pending;
	struct ibv_port_attr     portinfo;
	int 			num_connections;
	int             num_node;
    int             num_parallel_connection;
    int             *num_alive_connection;
    
    int recv_num;
    unsigned int *atomic_request_num;
    int parallel_thread_num;

	enum s_state {
		SS_INIT,
		SS_MR_SENT,
        SS_RDMA_WAIT,
		SS_RDMA_SENT,
		SS_DONE_SENT,
        SS_MSG_WAIT,
        SS_MSG_SENT
	} *send_state;

	enum r_state {
		RS_INIT,
		RS_MR_RECV,
        RS_RDMA_WAIT,
        RS_RDMA_RECV,
		RS_DONE_RECV
	} *recv_state;
    enum t_state {
		TS_WAIT,
		TS_DONE
	} *thread_state;
    
    
    int send_reply_wait_num;   
    
    
    struct atomic_struct **atomic_buffer;
    int *atomic_buffer_total_length;
    int *atomic_buffer_cur_length;
    
    int (*send_handler)(char *addr, uint32_t size);
	int (*send_reply_handler)(char *input_addr, uint32_t input_size, char *output_addr, uint32_t *output_size, int sender_id);
	int (*atomic_send_handler)(struct atomic_struct *input_list, uint32_t length, char *output_buf, uint32_t *output_size, int sender_id);
    int (*atomic_single_send_handler)(struct atomic_struct *input_list, uint32_t length, int sender_id);
    int num_used_lock;
    struct lmr_info shared_locks_mr[MAX_LOCK];
    fifo_t **shared_locks_fifo_queue;
    union ibv_gid gid;
};
struct lite_dest {
    int node_id;
	int lid;
	int qpn;
	int psn;
	union ibv_gid gid;
};

struct client_data{
    char server_name[INET6_ADDRSTRLEN];
    char server_information_buffer[MAX_CONNECTION][sizeof(LID_SEND_RECV_FORMAT)];
};
struct server_reply_format{
    int number_of_nodes; //This specifies the number of nodes excluded the last one(which initializes the latest connection to the server)
    struct client_data client_list[MAX_NODE];
};


struct ibv_mr *server_register_memory_api(int connection_id, void *addr, int size, int flag);
int liteapi_reg_send_handler(int (*input_funptr)(char *addr, uint32_t length));
int liteapi_reg_send_reply_handler(int (*input_funptr)(char *input_buf, uint32_t size, char *output_buf, uint32_t *output_size, int sender_id));
int liteapi_reg_atomic_send_handler(int (*input_funptr)(struct atomic_struct *input_list, uint32_t length, char *output_buf, uint32_t *output_size, int sender_id));
int liteapi_reg_atomic_single_send_handler(int (*input_funptr)(struct atomic_struct *input_list, uint32_t length, int sender_id));
int server_get_waiting_id_by_semaphore(void);
int server_send_request(int connection_id, enum mode s_mode, struct lmr_info *remote_mr, void *addr, int size);
int liteapi_send_message(int target_node, char *msg, int size);
int liteapi_send_reply(int target_node, char *msg, int size, char *output_msg);
int server_rdma_read(int target_node, struct lmr_info *mr_addr, void *local_addr, int size);
int server_rdma_write(int target_node, struct lmr_info *mr_addr, void *local_addr, int size);
int server_atomic_send_reply(int target_node, struct atomic_struct *input_atomic, int length, char *output_msg, int *output_length);
int server_get_remotemr(int target_node, void *addr, int size, struct lmr_info *ret_mr);

int server_loopback_read(struct lmr_info *remote_mr, struct lmr_info *local_mr);
int server_loopback_compare_swp(struct lmr_info *remote_mr, struct lmr_info *local_mr, unsigned long long guess_value, unsigned long long swp_value);

#endif
