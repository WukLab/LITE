/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#ifndef HAVE_CLIENT_H
#define HAVE_CLIENT_H


//This is the version modified from 000be840c215d5da3011a2c7b486d5ae122540c4
//It adds LOCKS, sge, and other things  into the system
//Client.h is also modified.
//Server is also modified to match this patch
//Patch SERIAL_VERSION_ID: 04202300
//Please make sure that this version is not fully tested inside dsnvm (interactions are not fully tested)


#include <linux/sched.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <linux/sort.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/memory.h>
#include <linux/pagemap.h>
//#include <linux/mm_inline.h>
//#include <linux/rmap.h>
#include <linux/buffer_head.h>
#include <asm/tlbflush.h>
#include <linux/semaphore.h>
#include <linux/completion.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/parser.h>
#include <linux/random.h>
#include <linux/jiffies.h>
#include <linux/device.h>
#include <linux/atomic.h>
#include <rdma/ib_verbs.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <linux/types.h>
#include <linux/syscalls.h>

#include <linux/semaphore.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/spinlock_types.h>
#include <linux/hashtable.h>
#include <linux/wait.h>
#include <linux/time.h>
#include <linux/jiffies.h>
//#include <asm-generic/io.h>

//#include "dsnvm-common.h"

#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/mman.h>
#include <linux/cdev.h>
//
#include "lite_syscall.h"
//#include "lite_test.h"
#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))


#define DEBUG_SHINYEH

#define LITE_ROCE

#ifdef LITE_ROCE
	#define SGID_INDEX 0
#else
	#define SGID_INDEX -1
#endif

#define MAX_LITE_NUM 4
#define MESSAGE_SIZE 4096

#define LITE_USERSPACE_FLAG 1
#define LITE_KERNELSPACE_FLAG 0
#define LITE_LINUX_PAGE_OFFSET 0x00000fff
#define LITE_LINUX_PAGE_SIZE 4096

#define CIRCULAR_BUFFER_LENGTH 256

#define MAX_NODE 32
#define MAX_NODE_BIT 5

#define LISTEN_PORT 18500

#define RECV_DEPTH 256
#define CONNECTION_ID_PUSH_BITS_BASED_ON_RECV_DEPTH 8
#define NUM_PARALLEL_CONNECTION 4
#define GET_NODE_ID_FROM_POST_RECEIVE_ID(id) (id>>8)/NUM_PARALLEL_CONNECTION
#define GET_POST_RECEIVE_DEPTH_FROM_POST_RECEIVE_ID(id) (id&0x000000ff)

#ifdef LITE_ROCE
	#define LITE_MTU IB_MTU_1024
#else
	#define LITE_MTU IB_MTU_4096
#endif

//#define LITE_GET_TIME
//#define LITE_GET_TIME_MULTISGE

#define UD_QP_SL 1

#define LID_SEND_RECV_FORMAT "0000:0000:000000:000000:00000000000000000000000000000000"
#define NUM_POLLING_THREADS 1
#define NUM_POLLING_WC 32
#define MAX_CONNECTION MAX_NODE * NUM_PARALLEL_CONNECTION //Assume that MAX_CONNECTION is smaller than 256
#define MAX_PARALLEL_THREAD 64
#define WRAP_UP_NUM_FOR_WRID 256 //since there are 64 bits in wr_id, we are going to use 9-12 bits to do thread id waiting passing
#define WRAP_UP_NUM_FOR_CIRCULAR_ID 256
#define WRAP_UP_NUM_FOR_WAITING_INBOX 256
#define WRAP_UP_NUM_FOR_TYPE 65536 //since there are 64 bits in wr_id, we are going to use 9-12 bits to do thread id waiting passing
//const int MESSAGE_SIZE = 4096;
//const int CIRCULAR_BUFFER_LENGTH = 256;
//const int MAX_NODE = 4;
#define POST_RECEIVE_CACHE_SIZE 2048
#define SERVER_ID 0


#define HIGH_PRIORITY 4
#define LOW_PRIORITY 0
#define KEY_PRIORITY 8
#define USERSPACE_LOW_PRIORITY_DELAY 64
#define USERSPACE_LOW_PRIORITY_THRESHOLD 2
#define USERSPACE_HIGH_PRIORITY 16
#define USERSPACE_LOW_PRIORITY 17
#define CONGESTION_ALERT 2
#define CONGESTION_WARNING 1
#define CONGESTION_FREE 0

#define PRIORITY_START 1
#define PRIORITY_END 2

#define PRIORITY_CHECKING_PERIOD_US 100
#define PRIORITY_CHECKING_THRESHOLD_US 32
#define PRIORITY_CHECKING_THRESHOLD_COUNTER 250

#define PRIORITY_WRITE 1
#define PRIORITY_READ 2
#define PRIORITY_SR 3

//MULTICAST RELATED
#define MAX_MULTICAST_HOP 16
#define MAX_LENGTH_OF_ATOMIC 256

//ASYIO RELATED
#define RING_BUFFER_LENGTH 1024
#define RING_BUFFER_MAXSIZE 4096
#define REMOTE_MEMORY_PAGE_SIZE	RING_BUFFER_MAXSIZE
#define INTERARRIVAL_UNLESS_FENCE 1
#define ASY_SETUP_COMPLETE true 

//alloc continuous memory related
#define LITE_MEM_OFFSET 0x100000000

// IMM_ related things
#define NUM_OF_CORES 2
//Model 2 --> 2-6-24 (Send-recv-opcode, port, offset)
#define IMM_SEND_REPLY_SEND	0x80000000
#define IMM_SEND_REPLY_RECV	0x40000000
#define IMM_SEND_ONLY_FLAG      0xffffffffffffffff
#define IMM_PORT_PUSH_BIT	24
#define IMM_GET_PORT_NUMBER(imm) (imm<<2)>>26
#define IMM_GET_OFFSET		0x00ffffff
//#define IMM_GET_SEMAPHORE	0x3fffffff
#define IMM_GET_SEMAPHORE	0x00ffffff
#define IMM_GET_OPCODE		0x0f000000
#define IMM_GET_OPCODE_NUMBER(imm) (imm<<4)>>28
#define IMM_DATA_BIT 32
#define IMM_NUM_OF_SEMAPHORE 64
#define IMM_MAX_PORT 64
#define IMM_MAX_PORT_BIT 6
#define IMM_MAX_PORT_BITMASK 0x3F
#define IMM_MAX_PRIORITY 64
#define IMM_MAX_PRIORITY_BIT 6
#define IMM_MAX_PRIORITY_BITMASK 0x3F

#define IMM_MAX_SGE_LENGTH 31

#define IMM_MAX_SIZE IMM_PORT_CACHE_SIZE/NUM_OF_CORES
#define IMM_SEND_SLEEP_SIZE_THRESHOLD 40960
#define IMM_SEND_SLEEP_TIME_THRESHOLD 10
#define IMM_ROUND_UP 4096
//#define IMM_PORT_CACHE_SIZE 1024*1024*4
#define IMM_PORT_CACHE_SIZE 4194304 // 1024*1024*4
#define IMM_ACK_PORTION 4

//Lock related
#define LITE_MAX_LOCK_NUM 1024
#define LITE_MAX_WAIT_QUEUE 64

//Memory Related
#define LITE_MEMORY_BLOCK 4194304 //1024*1024*4
#ifdef LITE_ROCE
	#define LITE_MAX_MEMORY_BLOCK 16 //4MB * 16 = 64MB
#else
	#define LITE_MAX_MEMORY_BLOCK 32 //4MB * 32 = 128MB
#endif



//struct semaphore atomic_accessing_lock[MAX_NODE];
//struct semaphore mr_mutex;
//struct semaphore get_thread_waiting_number_semaphore;
//struct semaphore get_thread_waiting_number_mutex;
//struct semaphore send_reply_wait_semaphore;
//struct semaphore send_reply_wait_mutex;

inline void get_time_start(void);
void get_time_end(void);
inline void get_cycle_start(void);
void get_cycle_end(void);

#define SEND_REPLY_WAIT -101
#define SEND_REPLY_EMPTY -102
#define SEND_REPLY_PORT_NOT_OPENED -103
#define SEND_REPLY_PORT_IS_FULL -104
#define SEND_REPLY_SIZE_TOO_BIG -105
#define SEND_REPLY_FAIL -106
#define SEND_REPLY_ACK 0

enum mode {
	M_WRITE,
	M_READ,
	LITE_SEND_MESSAGE_IMM_ONLY,
	LITE_SEND_MESSAGE_HEADER_AND_IMM,
	LITE_SEND_MESSAGE_HEADER_ONLY
};

enum lock_state{
	LOCK_AVAILABLE,
	LOCK_GET_LOCK,
	UNLOCK_ALREADY_ARRIVED,
	WAIT_FOR_UNLOCK
//	LOCK_USED,
//	LOCK_AVAILABLE,
//	LOCK_LOCK,
//	LOCK_ASSIGNED
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

struct lmr_info {
	//struct ib_device	*context;
	//struct ib_pd		*pd;
	void			*addr;
	size_t			length;
	//uint32_t		handle;
	uint32_t		lkey;
	uint32_t		rkey;
	uint32_t		node_id;
};

#define LITE_PAGE_SHIFT		12
#define LITE_PAGE_SIZE			(1UL << LITE_PAGE_SHIFT)

struct max_reply_msg {
	char msg[LITE_PAGE_SIZE];
	int length;
};

struct atomic_struct{
	void	*vaddr;
	size_t	len;
};

/*struct hash_lmr_info{
	uint32_t node_id;
	int size;
	struct lmr_info *data;
	uint64_t hash_key;
	struct hlist_node hlist;
};*/

struct hash_asyio_key{
	uint32_t node_id;
	int size;//total length
	struct lmr_info **datalist;
	int list_length;

	uint64_t permission;

	int	initialized_flag;
	int	count;
	int	mr_local_index;//For hash usage
	unsigned long *bitmap;
	unsigned long bitmap_size;
	unsigned long *askmr_bitmap;
	int	link_flag;
	
	struct hlist_node hlist;
	struct list_head list;
	
	uint64_t lite_handler;
	int priority;

	int password;
};

struct hash_page_key{
	char *addr;
	int dirty_flag;
	int link_flag;

	int target_node;
	uint64_t lite_handler;
	uint64_t hash_key;
	int offset;
	int priority;
	uint32_t page_num;
	struct hash_asyio_key *mother_addr;

	struct hlist_node hlist;
};

struct hash_mraddr_to_lmr_metadata{
	struct hash_asyio_key *mother_addr;
	uint64_t hash_key;//actually it's mr.addr
	uint64_t lmr;
	struct hlist_node hlist;
};

struct ask_mr_form{
	uint64_t identifier;
	//int identifier_length;
	uint64_t permission;
	unsigned int designed_port;
};

struct ask_mr_table{
	uint64_t lmr;
	uint64_t identifier;
	uint64_t permission;
	uint64_t hash_key;
	struct hlist_node hlist;
};

struct ask_mr_reply_form{
	uint64_t op_code;
	int total_length;
	int node_id;
	uint64_t permission;
	uint64_t list_length;
	struct lmr_info reply_mr[LITE_MAX_MEMORY_BLOCK];
};

struct mr_request_form{
	struct lmr_info request_mr;
	struct lmr_info copyto_mr;
	uint64_t offset;
	uint64_t copyto_offset;
	uint64_t size;
	uint64_t op_code;
};

enum register_application_port_ret{
	REG_FAIL = -1,
	REG_PORT_TOO_LARGE = -2,
	REG_SIZE_TOO_LARGE = -3,
	REG_NAME_TOO_LONG = -4,
	REG_PORT_OCCUPIED = -5,
	REG_DO_QUERY_FIRST = -6,
        REG_DO_LOCAL_SEND = -7
};

struct app_reg_port{
	struct lmr_info ring_mr;
	unsigned int port;
	unsigned int node;
	uint64_t hash_key;
	uint64_t port_node_key;
	void *addr;
	char name[32];
	struct hlist_node hlist;
	int remote_imm_ring_index;
	spinlock_t remote_imm_offset_lock;
	uint64_t last_ack_index;
	spinlock_t last_ack_index_lock;
};

struct imm_ack_form{
	int node_id;
	unsigned int designed_port;
	int ack_offset;
};

struct lite_lock_form{
	int lock_num;
	struct lmr_info lock_mr;
	uint64_t ticket_num;
};

typedef struct lite_lock_form remote_spinlock_t;

struct lite_lock_reserve_form{
	int lock_num;
	uint64_t ticket_num;
};

struct lite_lock_queue_element{
	uint64_t        store_addr;
	uint64_t        store_semaphore;	
	uint32_t        src_id;
	unsigned int	ticket_num;
	int	lock_num;
	int	state;
	int	tar_lock_index;
	struct hlist_node hlist;
};

enum mr_request_op_code{
	OP_REMOTE_MEMSET=0,
	OP_REMOTE_MEMCPY=1,
	OP_REMOTE_REREGISTER=2,
	OP_REMOTE_DEREGISTER=3,
	OP_REMOTE_FREE=4,
	OP_REMOTE_MEMMOV=5
};

enum permission_mode{
	MR_READ_FLAG=0x01,
	MR_WRITE_FLAG=0x02,
	MR_SHARE_FLAG=0x04,
	MR_ADMIN_FLAG=0x08,
	MR_ATOMIC_FLAG=0x10,
	MR_ASK_SUCCESS=0,
	MR_ASK_REFUSE=1,
	MR_ASK_UNPERMITTED=2,
	MR_ASK_HANDLER_ERROR=3,
	MR_ASK_UNKNOWN=4
};


enum asy_page_dirty_status{
	ASY_PAGE_DIRTY=1,
	ASY_PAGE_CLEAN=0
};

enum asy_page_link_status{
	ASY_PAGE_LINK=1,
	ASY_PAGE_UNLINK=0
};

struct asy_page_fence_linked_list_entry{
	struct hash_page_key *pag_addr;
	struct list_head list;
};

struct send_and_reply_format
{       
        uint32_t        src_id;
        uint64_t        store_addr;
	uint64_t	store_semaphore;
        uint32_t        length;
	int		type;
        char            *msg;
	int		priority;
	struct list_head list;
};



#define QUEUE_ACK 0
#define QUEUE_POST_RECV 1
#define QUEUE_HIGH 2
#define QUEUE_MEDIUM 3
#define QUEUE_LOW 4
#define QUEUE_NUM_OF_QUEUE 5

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
	MSG_GET_SEND_AND_REPLY_1_UD,
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
	MSG_DO_ACK_INTERNAL,
	MSG_DO_ACK_REMOTE
};

struct buf_message
{
	char buf[MESSAGE_SIZE];
};


enum {
	PINGPONG_RECV_WRID = 1,
	PINGPONG_SEND_WRID = 2,
};


struct asy_IO_header
{
	int target_node;
	uint64_t lite_handler;
	int size;
	int priority;
	uint64_t offset;
	int complete;
	int type;
	uint32_t page_num;
	char *addr;
	int* wait_id_addr; 
};

enum asy_IO_event_type {
	ASY_READ=1,
	ASY_WRITE=2,
	ASY_FENCE=3,
	ASY_INIT=4,
	SYN_WRITE=5,
	REMOTE_MEMSET=6,
	ASY_READ_PREFETCH=7,
	ASY_WAIT=8
};

struct client_ah_combined
{
	int			qpn;
	int			node_id;
	int			qkey;
	int			dlid;
	union ib_gid		gid;
};

//Related to remote imm-write

struct imm_message_metadata
{
	//uint32_t size;
	uint32_t designed_port;
	uint32_t source_node_id;
        uintptr_t store_addr;
	uint32_t store_rkey;
	uint32_t store_semaphore;
	uint32_t size;
};

struct imm_header_from_cq_to_port
{       
        uint32_t        source_node_id;
	uint64_t	offset;
};


struct imm_header_from_cq_to_userspace
{       
        void *ret_addr;
        int receive_size;
        void *reply_descriptor;
        void *ret_length;
	struct list_head list;
};

struct lite_context {
	struct ib_context	*context;
	struct ib_comp_channel *channel;
	struct ib_pd		*pd;
	struct ib_cq		**cq; // one completion queue for all qps
	atomic_t *cq_block;
    	wait_queue_head_t *cq_block_queue;
	struct ib_cq		**send_cq;
	struct ib_qp		**qp; // multiple queue pair for multiple connections
	
	struct ib_qp		*qpUD;// one UD qp for all the send-reply connections
	struct ib_cq		*cqUD;
	struct ib_cq		*send_cqUD;
	struct ib_ah 		**ah;
	struct client_ah_combined *ah_attrUD;
	struct ib_qp		*loopback_in;
	struct ib_qp		*loopback_out;
	struct ib_cq		*loopback_cq;
	spinlock_t		loopback_lock;


	int recv_numUD;
	spinlock_t connection_lockUD;

	int			 size;
	int			 send_flags;
	int			 rx_depth;
//	int			 pending;
	struct ib_port_attr     portinfo;
        int                     ib_port;
	int 			num_connections;
	int             num_node;
	int             num_parallel_connection;
	atomic_t             *num_alive_connection;
	atomic_t		num_alive_nodes;
	struct ib_mr *proc;
	int node_id;


	int *recv_num;
	atomic_t *atomic_request_num;
        //unsigned long     *atomic_request_num;
	atomic_t *atomic_request_num_high;
	atomic_t parallel_thread_num;
    

	enum s_state {
		SS_INIT,
		SS_MR_SENT,
	        SS_RDMA_WAIT,
		SS_RDMA_SENT,
		SS_DONE_SENT,
	        SS_MSG_WAIT,
	        SS_MSG_SENT,
	        SS_GET_REMOTE_WAIT,
	        SS_GET_REMOTE_DONE,
	        MSG_GET_SEND_AND_REPLY
	} *send_state;

	enum r_state {
		RS_INIT,
		RS_MR_RECV,
        RS_RDMA_WAIT,
        RS_RDMA_RECV,
		RS_DONE_RECV
	} *recv_state;
    
    
	atomic_t send_reply_wait_num;

	struct atomic_struct **atomic_buffer;
	int *atomic_buffer_total_length;
	int *atomic_buffer_cur_length;


   	int (*send_handler)(char *addr, uint32_t size, int sender_id);
	int (*send_reply_handler)(char *input_addr, uint32_t input_size, char *output_addr, uint32_t *output_size, int sender_id);
	int (*atomic_send_handler)(struct atomic_struct *input_list, uint32_t length, char *output_buf, uint32_t *output_size, int sender_id);
	int (*atomic_single_send_handler)(struct atomic_struct *input_list, uint32_t length, int sender_id);
	int (*send_reply_opt_handler)(char *input_buf, uint32_t size, void **output_buf, uint32_t *output_size, int sender_id);
	int (*ask_mr_handler)(struct ask_mr_form *ask_form, uint32_t source_id, uint64_t *litekey_addr, uint64_t *permission);

	atomic_t* connection_congestion_status;
	ktime_t* connection_timer_start;
	ktime_t* connection_timer_end;
	
	struct liteapi_header *first_packet_header, *other_packet_header;
	int *connection_id_array;
	uintptr_t *length_addr_array;
	void **output_header_addr;
	void **first_header_addr;
	void **mid_addr;

	//Needed for cross-nodes-implementation
        atomic_t alive_connection;
	atomic_t num_completed_threads;

	//Related to AsyIO
	atomic_t asy_current_job;
	atomic_t asy_latest_job;
	
	char **asy_tmp_buffer;
	struct asy_IO_header *asy_tmp_header;

	atomic_t asy_fence_counter;
	
	atomic_t mr_index_counter;
	//struct list_head asy_fence_list;
	//struct list_head asy_fence_list_ms;

	//Related to Emulator
	int *bridge_tar;
	int bridge_num_nodes;

	//Related to barrier
	atomic_t dist_barrier_counter;
	int dist_barrier_idx;
        int last_barrier_idx[MAX_NODE];
	
	//Related to lmr
	atomic_t lmr_inc;

	//This is contradict to each ring for each process (use EREP to search inside the code)
	//Related to imm
	//void **local_imm_ring_buffer;
	//struct imm_metadata *remote_imm_metadata;
	//struct lmr_info **local_imm_ring_mr;
	
	//void **imm_cache_perport;
	struct imm_header_from_cq_to_port **imm_waitqueue_perport;
        unsigned int imm_waitqueue_perport_count_poll[IMM_MAX_PORT];
        unsigned int imm_waitqueue_perport_count_recv[IMM_MAX_PORT];
	wait_queue_head_t imm_receive_block_queue[IMM_MAX_PORT];
	int imm_perport_reg_num[IMM_MAX_PORT];//-1 no registeration, 0 up --> how many
	spinlock_t imm_perport_lock[IMM_MAX_PORT];
	spinlock_t imm_waitqueue_perport_lock[IMM_MAX_PORT];
	spinlock_t imm_readyqueue_perport_lock[IMM_MAX_PORT];
        struct imm_header_from_cq_to_userspace imm_wait_userspace_perport[IMM_MAX_PORT];
        int imm_cq_is_available[NUM_POLLING_THREADS];
		//local semaphore related
		void **imm_store_semaphore;
                struct imm_message_metadata *imm_store_header;
		unsigned long *imm_store_semaphore_bitmap;
		spinlock_t *imm_store_semaphore_lock;
                atomic_t imm_store_semaphore_count;
    		wait_queue_head_t *imm_store_block_queue;
		struct task_struct **imm_store_semaphore_task;
	
	atomic_t imm_cache_perport_work_head[IMM_MAX_PORT];
	atomic_t imm_cache_perport_work_tail[IMM_MAX_PORT];
	struct app_reg_port *last_port_node_key_hash_ptr;


	//#define IMM_MAX_PORT 64
	//
	atomic_t *connection_count;
	
	//Lock related
	atomic_t lock_num;
	struct lite_lock_form *lock_data;

	struct lite_lock_queue_element *lock_queue;

	//memory allocated
	atomic_t current_alloc_size;
        //priority related
        atomic_t high_cur_num_write;
        atomic_t high_cur_num_read;
        atomic_t high_cur_num_sr;
        atomic_t low_cur_num_write;
        atomic_t low_cur_num_read;
        atomic_t low_cur_num_sr;
	atomic_t slow_counter;
	atomic_t low_total_num_write;
	atomic_t low_total_num_read;
	atomic_t low_total_num_sr;
	wait_queue_head_t priority_block_queue;

	union ib_gid gid;
};

typedef struct lite_context ltc;

struct lite_dest {
	int node_id;
	int lid;
	int qpn;
	int psn;
	union ib_gid gid;
};

struct client_data{
	char server_information_buffer[sizeof(LID_SEND_RECV_FORMAT)];
};

struct thread_pass_struct{
	ltc *ctx;
	struct ib_cq *target_cq;
	char *msg;
	struct send_and_reply_format *sr_request;
};


struct reply_struct{
        void *addr;
        int size;
        uintptr_t descriptor;
};

struct receive_struct{
        unsigned int designed_port;
        void *ret_addr;
        int receive_size;
        void *descriptor;
        int block_call;
};

#endif
