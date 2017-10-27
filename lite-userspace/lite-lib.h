#ifndef FIT_TEST
#define FIT_TEST

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <malloc.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/syscall.h>

#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <time.h>

#define max(x, y)				\
({						\
	x > y ? x : y;		\
})

#define IMM_SEND_ONLY_FLAG      0xffffffffffffffff

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
struct lite_lock_form{
	int lock_num;
	struct lmr_info lock_mr;
	uint64_t ticket_num;
};
typedef struct lite_lock_form remote_spinlock_t;

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

#define	__NR_lite_remote_memset		319
#define	__NR_lite_fetch_add		320
#define	__NR_lite_rdma_synwrite		321
#define	__NR_lite_rdma_read		322
#define	__NR_lite_ask_lmr		323
#define __NR_lite_dist_barrier		327
#define __NR_lite_add_ask_mr_table	328
#define __NR_lite_compare_swp		329
#define __NR_lite_alloc_remote		330

#define __NR_lite_register_application	332
#define	__NR_lite_receive_message	334
#define	__NR_lite_send_reply_imm	335
#define	__NR_lite_reply_message		336
#define	__NR_lite_get_node_id		337
#define	__NR_lite_query_port		338
#define	__NR_lite_alloc_memory		339

#define __NR_lite_umap_testsyscall       331

#define __NR_lite_wrap_alloc		340

#define __NR_lite_create_lock		341
#define __NR_lite_ask_lock		342
#define __NR_lite_lock			343
#define __NR_lite_unlock			344
#define __NR_lite_get_total_node		345
#define __NR_lite_reply_and_receive_message     346
#define __NR_lite_join                  347

#define __ACTIVE_NODES	3
#define LIMITATION 1024*1024*4
#define PAGE_SHIFT 12

#define IMM_MAX_PORT 64
#define IMM_MAX_PORT_BIT 6
#define IMM_MAX_PRIORITY 64
#define IMM_MAX_PRIORITY_BIT 6

#define SEND_REPLY_WAIT -101

#define CHECK_LENGTH 100000

#define USERSPACE_HIGH_PRIORITY 16
#define USERSPACE_LOW_PRIORITY 17
#define NULL_PRIORITY 0

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
#define BLOCK_CALL 1
inline int userspace_liteapi_get_node_id(void);
inline int userspace_liteapi_get_total_node(void);
inline int userspace_liteapi_dist_barrier(unsigned int num);
inline int userspace_liteapi_register_application(unsigned int destined_port, unsigned int max_size_per_message, unsigned int max_user_per_node, char *name, uint64_t name_len);
inline int userspace_liteapi_receive_message(unsigned int port, void *ret_addr, int receive_size, uintptr_t *descriptor, int block_call);
inline int userspace_liteapi_receive_message_high(unsigned int port, void *ret_addr, int receive_size, uintptr_t *descriptor, int block_call);
inline int userspace_liteapi_receive_message_low(unsigned int port, void *ret_addr, int receive_size, uintptr_t *descriptor, int block_call);
inline int userspace_liteapi_receive_message_fast(unsigned int port, void *ret_addr, int receive_size, uintptr_t *descriptor, int *ret_length, int block_call);
inline double userspace_liteapi_receive_message_fast_record(unsigned int port, void *ret_addr, int receive_size, uintptr_t *descriptor, int *ret_length, int block_call);
inline int userspace_liteapi_send_reply_imm(int target_node, unsigned int port, void *addr, int size, void *ret_addr, int max_ret_size);
inline int userspace_liteapi_send_reply_imm_high(int target_node, unsigned int port, void *addr, int size, void *ret_addr, int max_ret_size);
inline int userspace_liteapi_send_reply_imm_low(int target_node, unsigned int port, void *addr, int size, void *ret_addr, int max_ret_size);
inline int userspace_liteapi_send_reply_imm_fast(int target_node, unsigned int port, void *addr, int size, void *ret_addr, int *ret_length, int max_ret_size);
inline int userspace_liteapi_reply_message(void *addr, int size, uintptr_t descriptor);
inline int userspace_liteapi_reply_message_high(void *addr, int size, uintptr_t descriptor);
inline int userspace_liteapi_reply_message_low(void *addr, int size, uintptr_t descriptor);
inline int userspace_liteapi_reply_and_receive_message(void *addr, int size, uintptr_t descriptor, unsigned int port, void *ret_addr, int receive_size, uintptr_t *receive_descriptor);
inline int userspace_liteapi_query_port(int target_node, int designed_port);
inline int userspace_liteapi_wrap_alloc(void *data, int size, uint64_t identifier, int password);
inline int userspace_liteapi_ask_lmr(int memory_node, uint64_t identifier, uint64_t permission, int password);
inline int userspace_liteapi_rdma_read(unsigned lite_handler, void *local_addr, unsigned int size, unsigned int offset, int password);
inline int userspace_liteapi_rdma_read_high(unsigned lite_handler, void *local_addr, unsigned int size, unsigned int offset, int password);
inline int userspace_liteapi_rdma_read_low(unsigned lite_handler, void *local_addr, unsigned int size, unsigned int offset, int password);
inline int userspace_liteapi_rdma_write(unsigned lite_handler, void *local_addr, unsigned int size, unsigned int offset, int password);
inline int userspace_liteapi_rdma_write_high(unsigned lite_handler, void *local_addr, unsigned int size, unsigned int offset, int password);
inline int userspace_liteapi_rdma_write_low(unsigned lite_handler, void *local_addr, unsigned int size, unsigned int offset, int password);
void* userspace_liteapi_alloc_memory(unsigned long size);
inline int userspace_liteapi_create_lock(int target_node, remote_spinlock_t *input);
inline int userspace_liteapi_ask_lock(int target_node, int target_idx, remote_spinlock_t *input);
inline int userspace_liteapi_lock(remote_spinlock_t *input);
inline int userspace_liteapi_unlock(remote_spinlock_t *input);
inline int userspace_liteapi_memset(unsigned lite_handler, int offset, int size);
inline int userspace_liteapi_alloc_remote_mem(unsigned int node_id, unsigned int size, bool atomic_flag, int password);
inline int userspace_liteapi_compare_swp(unsigned long lite_handler, void *local_addr, unsigned long long guess_value, unsigned long long set_value);
inline int userspace_liteapi_add_ask_mr_table(uint64_t identifier, uint64_t lmr, uint64_t permission, int password);
inline int userspace_liteapi_remote_memset(unsigned lite_handler, int offset, int size);
inline int userspace_liteapi_fetch_add(unsigned long lite_handler, void *local_addr, unsigned long long input_value);
inline int userspace_syscall_test(void);
inline int userspace_liteapi_join(char *input_str, int eth_port, int ib_port);
int stick_this_thread_to_core(int core_id);
inline int userspace_liteapi_send(int target_node, unsigned int port, void *addr, int size);
#endif
