
#ifndef _INCLUDE_LITE_API_H
#define _INCLUDE_LITE_API_H
#include "lite.h"
#include "lite_core.h"
//static void ibv_add_one(struct ib_device *device);
//static void ibv_release_dev(struct device *dev);
//static void ibv_remove_one(struct ib_device *device);

int liteapi_reg_send_handler(int (*input_funptr)(char *addr, uint32_t length, int sender_id));
int liteapi_reg_send_reply_handler(int (*input_funptr)(char *input_buf, uint32_t size, char *output_buf, uint32_t *output_size, int sender_id));
int liteapi_reg_atomic_send_handler(int (*input_funptr)(struct atomic_struct *input_list, uint32_t length, char *output_buf, uint32_t *output_size, int sender_id));
int liteapi_reg_atomic_single_send_handler(int (*input_funptr)(struct atomic_struct *input_list, uint32_t length, int sender_id));
int liteapi_reg_send_reply_opt_handler(int (*input_funptr)(char *input_buf, uint32_t size, void **output_buf, uint32_t *output_size, int sender_id));
int liteapi_reg_ask_mr_handler(int (*input_funptr)(struct ask_mr_form *ask_form, uint32_t node_id, uint64_t *litekey_addr, uint64_t *permission));
int liteapi_establish_conn(char *servername, int eth_port, int ib_port);
//Do atomic_send_reply. Returned value is the length of output_msg (similar to socket programming)
//int liteapi_atomic_send(int target_node, struct atomic_struct *input_atomic, int length, char *output_msg);
//Do send.
int liteapi_send_message(int node_id, void *local_addr, int size);
//Do send_reply. Returned value is the length of output_msg (similar to socket programming)
int liteapi_send_reply(int node_id, char *send_msg, int send_size, char *ack_msg);
int liteapi_send_reply_type(int target_node, char *msg, int size, char *output_msg, int type);
//Haven't implemented teardown_conn
int liteapi_teardown_conn(void);
int liteapi_rdma_write(uint64_t lite_handler, void *local_addr, int size, int priority);
int liteapi_rdma_read(uint64_t lite_handler, void *local_addr, int size, int priority);
inline void liteapi_free_recv_buf(void *input_buf);
int liteapi_send_reply_opt(int target_node, char *msg, int size, void **output_msg, int priority);
int liteapi_send_message_type(int target_node, void *addr, int size, int type);
int liteapi_send_message_priority(int target_node, void *addr, int size, int priority);
int liteapi_send_message_UD(int target_node, void *addr, int size, int type);
int liteapi_send_reply_UD(int target_node, char *msg, int size, char *output_msg);

//int liteapi_multi_send(int number_of_target, int *target_array, struct atomic_struct *input_atomic);
int liteapi_create_lock(int target_node, void *output_lock);
int liteapi_ask_lock(int target_node, int target_num, void *output_mr);
int liteapi_lock(void *input_void_key);
int liteapi_unlock(void *input_key);

int liteapi_rdma_asywrite_offset(uint64_t lite_handler, void *local_addr, int size, int priority, int offset);
int liteapi_rdma_asyread_offset(uint64_t lite_handler, void *local_addr, int size, int priority, int offset);
int liteapi_rdma_synwrite_offset(uint64_t lite_handler, void *local_addr, int size, int priority, int offset);
int liteapi_rdma_asyfence(void);
int liteapi_rdma_fetch_and_add(uint64_t lite_handler, void *local_addr, unsigned long long input_value, int priority);

inline int liteapi_remote_memset(uint64_t lite_handler, int offset, int size);
//RDMA RELATED
uint64_t liteapi_alloc_remote_mem(unsigned int target_node, unsigned int size, unsigned atomic_flag, int password);
uint64_t liteapi_ask_mr(int memory_space_owner_node, uint64_t identifier, uint64_t permission, int password);
uint64_t liteapi_register_lmr_with_virt_addr(void *addr, int size, bool atomic_flag, int password);

int liteapi_rdma_read_offset_mr(struct lmr_info *mr_addr, void *local_addr, int size, int priority, int offset);
int liteapi_rdma_write_offset_mr(struct lmr_info *mr_addr, void *local_addr, int size, int priority, int offset);
int liteapi_rdma_write_offset(uint64_t lite_handler, void *local_addr, int size, int priority, int offset, int password);
int liteapi_rdma_write_offset_userspace(uint64_t lite_handler, void *local_addr, int size, int priority, int offset, int password);
int liteapi_rdma_read_offset(uint64_t lite_handler, void *local_addr, int size, int priority, int offset, int password);
int liteapi_rdma_read_offset_userspace(uint64_t lite_handler, void *local_addr, int size, int priority, int offset, int password);
int liteapi_rdma_write_offset_multiplesge(uint64_t lite_handler, void *local_addr, int size, int priority, int offset, int sge_num, struct ib_sge *input_sge);
//int liteapi_multi_send_reply(int number_of_target, int *target_array, struct atomic_struct *input_atomic, struct max_reply_msg* reply);
long long get_time_difference(int tid, ktime_t inputtime);
void get_time_difference_str(char *input_str, ktime_t inputtime);
uint64_t liteapi_dist_barrier(unsigned int checknum);
int liteapi_rdma_asywait(void);
int liteapi_add_askmr_table(uint64_t identifier, uint64_t lmr, uint64_t permission, int password);
int liteapi_rdma_compare_and_swp(uint64_t lite_handler, void *local_addr, unsigned long long guess_value, unsigned long long set_value, int priority);
int liteapi_rdma_swp(int target_node, struct lmr_info *mr_addr, void *local_addr, unsigned long long guess, unsigned long long swp_value, int priority);
//int liteapi_multi_send_reply_type(int number_of_target, int *target_array, struct atomic_struct *input_atomic, struct max_reply_msg* reply, int type);
int liteapi_umap_lmr(uint64_t lmr);
//int atomic_send_reply_thread_helper(struct thread_pass_struct *input);

int liteapi_rdma_write_offset_imm(uint64_t lite_handler, void *local_addr, int size, int priority, int offset, int imm);
inline int liteapi_query_port(int target_node, int designed_port, int requery_flag);
//IMM related
inline int liteapi_register_application(unsigned int designed_port, unsigned int max_size_per_message, unsigned int max_user_per_node, char *name, uint64_t name_len);
int liteapi_unregister_application(unsigned int designed_port);
inline int liteapi_receive_message(unsigned int designed_port, void *ret_addr, int receive_size, uintptr_t *descriptor);
inline int liteapi_receive_message_userspace(int size_port, void *ret_addr, void *descriptor, void *ret_length, int block_call, unsigned int priority);
inline int liteapi_reply_message(void *addr, int size, uintptr_t descriptor);

inline int liteapi_reply_message_userspace(void *addr, int size, uintptr_t descriptor, unsigned int priority);

inline int liteapi_reply_and_receive_message(void *addr, int size, uintptr_t descriptor, int port, void *ret_addr, int receive_size, void *receive_descriptor);
inline int liteapi_reply_and_receive_message_userspace(void *addr, int size_port, uintptr_t descriptor, void *ret_addr, int receive_size, void *receive_descriptor);

inline int liteapi_send_reply_imm(int target_node, unsigned int port, void *addr, int size, void *ret_addr, int max_ret_size);
inline int liteapi_send_reply_imm_userspace(int target_node, int size_port, void *addr, void *ret_addr, void *ret_length, unsigned int max_ret_size_and_priority);

int liteapi_rdma_mr_request(uint64_t src_key, int src_offset, uint64_t tar_key, int tar_offset, int size, int op_code);
int liteapi_rdma_mr_memcpy(uint64_t src_key, int src_offset, uint64_t tar_key, int tar_offset, int size);
int liteapi_rdma_mr_memmov(uint64_t src_key, int src_offset, uint64_t tar_key, int tar_offset, int size);
uint64_t liteapi_deregister_mr(uint64_t lmr);

inline int liteapi_get_node_id(void);
inline int liteapi_get_total_node(void);
inline int liteapi_num_connected_nodes(void);
inline int liteapi_alloc_continuous_memory(unsigned long long vaddr, unsigned long size);
uint64_t liteapi_wrapup_alloc_for_remote_access(void *data, unsigned int size, uint64_t identifier, int password);

int liteapi_send_reply_imm_multisge(int number_of_node, int *target_node, int port, struct atomic_struct **input_atomic, int *length, struct max_reply_msg *output_msg);

//For FARM test
inline ltc *liteapi_get_ctx(void);
inline int liteapi_rdma_write_offset_withmr_without_polling(struct lmr_info *mr_addr, void *local_addr, int size, int priority, int offset, int wr_id);


inline int liteapi_priority_hadling(int priority, int flag, unsigned long *priority_jiffies);
#endif
