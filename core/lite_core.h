#ifndef _INCLUDE_LITE_INTERNAL_H
#define _INCLUDE_LITE_INTERNAL_H

#include "lite_internal_tool.h"
#include "lite.h"

#define COUNT_TIME_START tt_start= ktime_get();
#define COUNT_TIME_END tt_end = ktime_get();\
        client_internal_stat(client_get_time_difference(tt_start, tt_end), LITE_STAT_ADD);\
        if(Internal_Stat_Count==1000) printk(KERN_CRIT "%s: %lld ns\n", __func__, client_internal_stat(0, LITE_STAT_CLEAR));

/* PRIORITY_IMPLEMENT_OR_NOT */
//#define PRIORITY_IMPLEMENTATION_RESOURCE //If not RESOURCE, it would be traffic prioritization directly
//#define PRIORITY_IMPLEMENTATION_TRAFFIC_PRIORITIZATION

/* THREAD_HANDLER_MODEL - CHOOSE ONE*/
#define WAITING_QUEUE_IMPLEMENTATION
//#define IMPLEMENTATION_THREAD_SPAWN
//#define POLLING_THREAD_HANDLING_IMPLEMENTATION

#define ASK_MR_TABLE_HANDLING

/* POLLING OPTIONS - CHOOSE ONE*/
#define BUSY_POLL_MODEL
//#define NOTIFY_MODEL

#define BUSY_POLL_MODEL_UD
//#define NOTIFY_MODEL_UD

//
/* sendreply-send model*/
//#define CPURELAX_MODEL
//#define SCHEDULE_MODEL
#define ADAPTIVE_MODEL

/* sendreply-recv model*/
//#define RECV_WAITQUEUE_MODEL
#define RECV_SCHEDULE_MODEL
//#define RECV_CPURELAX_MODEL
//

//#define SHARE_POLL_CQ_MODEL
#define NON_SHARE_POLL_CQ_MODEL


int client_connect_ctx(ltc *ctx, int connection_id, int port, int my_psn, enum ib_mtu mtu, int sl, struct lite_dest *dest);

ltc *client_init_ctx(int size,int rx_depth, int port, struct ib_device *ib_dev);

ltc *client_init_interface(int ib_port, struct ib_device *ib_dev);

int client_send_message_sge_UD(ltc *ctx, int target_node, int type, void *addr, int size, uint64_t store_addr, uint64_t store_semaphore, int priority);
int client_send_request(ltc *ctx, int connection_id, enum mode s_mode, struct lmr_info *input_mr, void *addr, int size, int offset, int userspace_flag, int *poll_addr);

int client_msg_to_lite_dest(char *msg, struct lite_dest *rem_dest);
int client_gen_msg(ltc *ctx, char *msg, int connection_id);
int client_post_receives_message(ltc *ctx, int connection_id, int n);

int client_close_ctx(struct lite_context *ctx);


struct lmr_info *client_ib_reg_mr(ltc *ctx, void *addr, size_t length, enum ib_access_flags access);

int client_get_mr_id_by_semaphore(void);
int client_get_port_info(struct ib_context *context, int port, struct ib_port_attr *attr);
void client_wire_gid_to_gid(const char *wgid, union ib_gid *gid);
void client_gid_to_wire_gid(const union ib_gid *gid, char wgid[]);

struct hash_asyio_key *lmr_to_mr_metadata(uint64_t input_key);
uint64_t client_hash_mr(struct lmr_info *input_mr);
inline void client_free_recv_buf(void *input_buf);
int client_get_random_number(void);
int client_create_metadata_by_lmr(ltc *ctx, uint64_t ret_key, struct lmr_info **ret_mr_list, int ret_mr_list_length, int target_node, int roundup_size, uint64_t permission, bool local_flag, int password);
inline int client_get_connection_by_atomic_number(ltc *ctx, int target_node, int priority);
void client_setup_liteapi_header(uint32_t src_id, uint64_t store_addr, uint64_t store_semaphore, uint32_t length, int priority, int type, struct liteapi_header *output_header);
int client_send_request_multiplesge(ltc *ctx, int connection_id, enum mode s_mode, struct lmr_info *input_mr, void *addr, int size, int sge_num, struct ib_sge *input_sge);

struct lmr_info *client_alloc_lmr_info_buf(void);
void client_free_lmr_info_buf(void *input_buf);

void poll_cq(struct ib_cq *cq, void *cq_context);
//struct lmr_info *lmr_to_mr(uint64_t input_key);
struct lmr_info **lmr_to_mr(uint64_t input_key, int *length);
int client_check_askmr_table(ltc *ctx, struct ask_mr_form *ask_form, uint32_t source_id, uint64_t *litekey_addr, uint64_t *permission);
uintptr_t client_ib_reg_mr_phys_addr(ltc *ctx, void *addr, size_t length);
inline uintptr_t client_ib_reg_mr_addr(ltc *ctx, void *addr, size_t length);
int client_spawn_send_reply_handler(struct thread_pass_struct *input);
int client_add_newnode(ltc *ctx, char *msg);
int client_add_newnode_pass(struct thread_pass_struct *input);
int client_poll_cq(ltc *ctx, struct ib_cq *target_cq);
int client_poll_cq_pass(struct thread_pass_struct *input);
int client_asy_latest_job_add(ltc *ctx, int type, uint64_t key, int offset, int size);
ltc *client_establish_conn(struct ib_device *ib_dev, char *servername, int eth_port, int ib_port);
int client_send_request_without_polling(ltc *ctx, int connection_id, enum mode s_mode, struct lmr_info *input_mr, void *addr, int size, int offset, int wr_id);
int lmr_permission_check(uint64_t input_key, int input_flag, struct hash_asyio_key **ret_ptr);
int client_compare_swp(ltc *ctx, int connection_id, struct lmr_info *remote_mr, void *addr, uint64_t guess_value, uint64_t swp_value);
int client_compare_swp_loopback(ltc *ctx, struct lmr_info *remote_mr, void *addr, uint64_t guess_value, uint64_t swp_value);
int client_fetch_and_add(ltc *ctx, int connection_id, struct lmr_info *input_mr, void *addr, unsigned long long input_value);
int client_fetch_and_add_loopback(ltc *ctx, struct lmr_info *input_mr, void *addr, unsigned long long input_value);
int client_send_request_polling_only(ltc *ctx, int connection_id, int polling_num, struct ib_wc *wc);
int client_cleanup_module(void);


//The below functions in liteapi are required to modify based on these four
int client_rdma_read_offset(ltc *ctx, uint64_t lite_handler, void *local_addr, int size, int priority, int offset);
int client_rdma_write_offset(ltc *ctx, uint64_t lite_handler, void *local_addr, int size, int priority, int offset);
int client_rdma_write_offset_multiplesge(ltc *ctx, uint64_t lite_handler, void *local_addr, int size, int priority, int offset, int sge_num, struct ib_sge *input_sge);
int client_send_reply_type(ltc *ctx, int target_node, char *msg, int size, char *output_msg, int type);

int client_rdma_write_with_imm(ltc *ctx, int connection_id, struct lmr_info *input_mr, void *addr, int size, int offset, uint32_t imm);
int client_poll_cq_UD(ltc *ctx, struct ib_cq *target_cq);
void *client_alloc_memory_for_mr(unsigned int length);
int client_register_application(ltc *ctx, unsigned int designed_port, unsigned int max_size_per_message, unsigned int max_user_per_node, char *name, uint64_t name_len);
int client_unregister_application(ltc *ctx, unsigned int designed_port);

int client_receive_message(ltc *ctx, unsigned int port, void *ret_addr, int receive_size, uintptr_t *reply_descriptor, void *ret_length, int userspace_flag, int block_call);
int client_reply_message(ltc *ctx, void *addr, int size, uintptr_t descriptor, int userspace_flag, int priority);
int client_query_port(ltc *ctx, int target_node, int desigend_port, int requery_flag);
int client_send_reply_with_rdma_write_with_imm(ltc *ctx, int target_node, unsigned int port, void *addr, int size, void *ret_addr, int max_ret_size, void *ret_length, int userspace_flag, int priority);
int client_send_message_with_rdma_write_with_imm_request(ltc *ctx, int connection_id, uint32_t input_mr_rkey, uintptr_t input_mr_addr, void *addr, int size, int offset, uint32_t imm, enum mode s_mode, struct imm_message_metadata *header, int userspace_flag, int sge_length, struct atomic_struct *input_atomic, int force_poll_flag);
inline int client_get_offset_by_length(ltc *ctx, int target_node, int port, int size);
inline int client_find_qp_id_by_qpnum(ltc *ctx, uint32_t qp_num);
inline int client_find_node_id_by_qpnum(ltc *ctx, uint32_t qp_num);
int client_setup_loopback_connections(ltc *ctx, int size, int rx_depth, int ib_port);
int client_connect_loopback(struct ib_qp *src_qp, int port, int src_psn, enum ib_mtu mtu, int sl, struct lite_dest *dest);
int lite_check_page_continuous(void *local_addr, int size, unsigned long *answer);
int client_send_message_local(ltc *ctx, int target_node, int type, void *addr, int size, uint64_t store_addr, uint64_t store_semaphore, int priority);
int client_send_message_local_reply(ltc *ctx, int target_node, int type, void *addr, int size, uint64_t store_addr, uint64_t store_semaphore, int priority);
int client_internal_poll_sendcq(struct ib_cq *tar_cq, int connection_id, int *check);
int client_alloc_continuous_memory(ltc *ctx, unsigned long long addr, unsigned long size);
int client_add_askmr_table(ltc *ctx, uint64_t identifier, uint64_t lmr, uint64_t permission);
int client_internal_poll_sendcq(struct ib_cq *tar_cq, int connection_id, int *check);

int client_send_reply_with_rdma_write_with_imm_sge(ltc *ctx, int number_of_node, int *target_node, unsigned int port, struct atomic_struct **input_atomic, int *length, struct max_reply_msg *output_msg);


int client_send_message_with_rdma_emulated_for_local(ltc *ctx, int port, void *addr, int size, struct imm_message_metadata *header, int userspace_flag);
#endif
