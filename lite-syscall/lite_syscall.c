
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>

#include "lite_syscall.h"
//#include "client.h"

static uint64_t (*lite_alloc_remote_hook)(unsigned int, unsigned int, unsigned int, int);
static int 	(*lite_remote_memset_hook)(uint64_t, int, int);
static int 	(*lite_fetch_add_hook)(uint64_t, void*, unsigned long long, int);
static int 	(*lite_rdma_synwrite_hook)(uint64_t, void*, int, int, int, int);

static int 	(*lite_rdma_asywrite_hook)(uint64_t, void*, int, int, int);
static int 	(*lite_rdma_read_hook)(uint64_t, void*, int, int, int, int);
static uint64_t	(*lite_ask_lmr_hook)(int, uint64_t, uint64_t, int);
static uint64_t	(*lite_dist_barrier_hook)(unsigned int);
static int	(*lite_add_ask_mr_table_hook)(uint64_t, uint64_t, uint64_t, int);
static int 	(*lite_compare_swp_hook)(uint64_t, void*, unsigned long long, unsigned long long, int);
static int 	(*lite_umap_lmr_hook)(uint64_t);

static int	(*lite_register_application_hook)(unsigned int, unsigned int, unsigned int, char*, uint64_t);
static int 	(*lite_unregister_application_hook)(unsigned int);
static int	(*lite_receive_message_hook)(int, void*, void*, void*, int, unsigned int);
static int	(*lite_send_reply_imm_hook)(int, int, void*, void *, void*, unsigned int);
static int      (*lite_reply_message_hook)(void *, int, uintptr_t, unsigned int);
static int	(*lite_get_node_id_hook)(void);
static int	(*lite_get_total_node_hook)(void);
static int      (*lite_query_port_hook)(int, int, int);
static int      (*lite_alloc_continuous_memory_hook)(unsigned long long, unsigned long);
static uint64_t	(*lite_wrap_alloc_for_remote_access_hook)(void *, unsigned int, uint64_t, int);
static int	(*lite_create_lock_hook)(int, void*);
static int	(*lite_ask_lock_hook)(int, int, void*);
static int	(*lite_lock_hook)(void*);
static int	(*lite_unlock_hook)(void*);
static int      (*lite_reply_and_receive_message_hook)(void *, int, uintptr_t, void *, int, void *);

static int      (*lite_join_hook)(char *, int, int);

int register_lite_hooks(const struct lite_hooks *hooks)
{
	if(unlikely(!hooks))
		return -EINVAL;
	if(unlikely(!hooks->lite_alloc_remote || 
			!hooks->lite_remote_memset ||
			!hooks->lite_fetch_add ||
			!hooks->lite_rdma_synwrite ||
			!hooks->lite_rdma_asywrite ||
			!hooks->lite_rdma_read ||
			!hooks->lite_ask_lmr ||
			!hooks->lite_add_ask_mr_table ||
			!hooks->lite_compare_swp ||
			!hooks->lite_umap_lmr ||
			!hooks->lite_register_application ||
			!hooks->lite_unregister_application ||
			!hooks->lite_receive_message ||
			!hooks->lite_send_reply_imm ||
			!hooks->lite_reply_message ||
			!hooks->lite_get_node_id ||
			!hooks->lite_get_total_node ||
			!hooks->lite_query_port ||
			!hooks->lite_alloc_continuous_memory ||
			!hooks->lite_wrap_alloc_for_remote_access ||
			!hooks->lite_create_lock ||
			!hooks->lite_ask_lock ||
			!hooks->lite_lock ||
			!hooks->lite_unlock ||
                        !hooks->lite_reply_and_receive_message ||
                        !hooks->lite_join))
			{
				return -EINVAL;
			}
	lite_alloc_remote_hook = hooks->lite_alloc_remote;
	lite_remote_memset_hook = hooks->lite_remote_memset;
	lite_fetch_add_hook = hooks->lite_fetch_add;
	lite_rdma_synwrite_hook = hooks->lite_rdma_synwrite;
	lite_rdma_asywrite_hook = hooks->lite_rdma_asywrite;
	lite_rdma_read_hook = hooks->lite_rdma_read;
	lite_ask_lmr_hook = hooks->lite_ask_lmr;
	lite_dist_barrier_hook = hooks->lite_dist_barrier;
	lite_add_ask_mr_table_hook = hooks->lite_add_ask_mr_table;
	lite_compare_swp_hook = hooks->lite_compare_swp;
	lite_umap_lmr_hook = hooks->lite_umap_lmr;
	lite_register_application_hook = hooks->lite_register_application;
	lite_unregister_application_hook = hooks->lite_unregister_application;
	lite_receive_message_hook = hooks->lite_receive_message;
	lite_send_reply_imm_hook = hooks->lite_send_reply_imm;
	lite_reply_message_hook = hooks->lite_reply_message;
	lite_get_node_id_hook = hooks->lite_get_node_id;
	lite_get_total_node_hook = hooks->lite_get_total_node;
	lite_query_port_hook = hooks->lite_query_port;
	lite_alloc_continuous_memory_hook = hooks->lite_alloc_continuous_memory;
	lite_wrap_alloc_for_remote_access_hook = hooks->lite_wrap_alloc_for_remote_access;
	lite_create_lock_hook = hooks->lite_create_lock;
	lite_ask_lock_hook = hooks->lite_ask_lock;
	lite_lock_hook = hooks->lite_lock;
	lite_unlock_hook = hooks->lite_unlock;
        lite_reply_and_receive_message_hook = hooks->lite_reply_and_receive_message;
        lite_join_hook = hooks->lite_join;
	return 0;
}
EXPORT_SYMBOL(register_lite_hooks);
void unregister_lite_hooks(void)
{

	lite_alloc_remote_hook = NULL;
	lite_remote_memset_hook = NULL;
	lite_fetch_add_hook = NULL;
	lite_rdma_synwrite_hook = NULL;
	lite_rdma_asywrite_hook = NULL;
	lite_rdma_read_hook = NULL;
	lite_ask_lmr_hook = NULL;
	lite_dist_barrier_hook = NULL;
	lite_add_ask_mr_table_hook = NULL;
	lite_compare_swp_hook = NULL;
	lite_umap_lmr_hook = NULL;
	lite_register_application_hook = NULL;
	lite_unregister_application_hook = NULL;
	lite_receive_message_hook = NULL;
	lite_send_reply_imm_hook = NULL;
	lite_reply_message_hook = NULL;
	lite_get_node_id_hook = NULL;
	lite_get_total_node_hook = NULL;
	lite_query_port_hook = NULL;
	lite_alloc_continuous_memory_hook = NULL;
	lite_wrap_alloc_for_remote_access_hook = NULL;
	lite_create_lock_hook = NULL;
	lite_ask_lock_hook = NULL;
	lite_lock_hook = NULL;
	lite_unlock_hook = NULL;
        lite_reply_and_receive_message_hook = NULL;
        lite_join_hook = NULL;
}
EXPORT_SYMBOL(unregister_lite_hooks);
//lite

SYSCALL_DEFINE4(lite_alloc_remote, unsigned int, node_id,
				  unsigned int, size,
				  unsigned int,	atomic_flag,
				  int, password)
{
	if(likely(lite_alloc_remote_hook))
	{
		uint64_t lmr;
		lmr = lite_alloc_remote_hook(node_id, size, atomic_flag, password);
		return (long)lmr;
	}
	return -EFAULT;
}

SYSCALL_DEFINE4(lite_wrap_alloc_for_remote_access, void __user *, data,
				  unsigned int, size,
				  uint64_t, identifier,
				  int, password)
{
	if(likely(lite_wrap_alloc_for_remote_access_hook))
	{
		uint64_t lmr;
		lmr = lite_wrap_alloc_for_remote_access_hook(data, size, identifier, password);
		return (long)lmr;
	}
	return -EFAULT;
}

SYSCALL_DEFINE3(lite_remote_memset, 	unsigned long, lmr,
					int, offset,
					int, size)
{
	if(likely(lite_remote_memset_hook))
	{
		lite_remote_memset_hook(lmr, offset, size);
		return 0;
	}
	return -EFAULT;
}

SYSCALL_DEFINE4(lite_fetch_add,    unsigned long, lite_handler,
				  void __user *, local_addr,
				  unsigned long long, input_value,
				  unsigned int,  priority)
{
	if(likely(lite_fetch_add_hook))
	{
		int ret;
		uint64_t output;
		ret = lite_fetch_add_hook(lite_handler, &output, input_value, priority);
		if(ret)
		{
			return -EFAULT;
		}
		if(copy_to_user(local_addr, &output, sizeof(uint64_t)))
		{
			return -EFAULT;
		}
		return 0;

	}
	return -EFAULT;
}


SYSCALL_DEFINE6(lite_rdma_synwrite,unsigned long, lite_handler,
				  void __user *, local_addr,
				  unsigned int,  size,
				  unsigned int,  priority,
				  unsigned int,  offset,
				  int,		 password)
{
	if(likely(lite_rdma_synwrite_hook))
	{
		//void *output;
		int ret;
		//output = kmalloc(size, GFP_KERNEL);
		/*if(copy_from_user(output, local_addr, size))
		{
			kfree(output);
			return -EFAULT;
		}*/
		//ret = lite_rdma_synwrite_hook(lite_handler, output, size, priority, offset, password);
		ret = lite_rdma_synwrite_hook(lite_handler, local_addr, size, priority, offset, password);
		if(ret)
		{
			//kfree(output);
			return -EFAULT;
		}
		//kfree(output);
		return 0;

	}
	return -EFAULT;
}
SYSCALL_DEFINE5(lite_rdma_asywrite,unsigned long, lite_handler,
				  void __user *, local_addr,
				  unsigned int,  size,
				  unsigned int,  priority,
				  unsigned int,  offset)
{
	if(likely(lite_rdma_asywrite_hook))
	{
		void *output;
		int ret;
		output = kmalloc(size, GFP_KERNEL);
		if(copy_from_user(output, local_addr, size))
		{
			kfree(output);
			return -EFAULT;
		}
		ret = lite_rdma_asywrite_hook(lite_handler, output, size, priority, offset);
		if(ret)
		{
			kfree(output);
			return -EFAULT;
		}
		kfree(output);
		return 0;

	}
	return -EFAULT;
}
SYSCALL_DEFINE6(lite_rdma_read,    unsigned long, lite_handler,
				  void __user *, local_addr,
				  unsigned int,  size,
				  unsigned int,  priority,
				  unsigned int,  offset,
				  int,		 password)
{
	if(likely(lite_rdma_read_hook))
	{
		/*void *output;
		int ret;
		output = kmalloc(size, GFP_KERNEL);
		ret = lite_rdma_read_hook(lite_handler, output, size, priority, offset, password);
		if(ret)
		{
			kfree(output);
			return -EFAULT;
		}
		if(copy_to_user(local_addr, output, size))
		{
			kfree(output);
			return -EFAULT;
		}
		kfree(output);*/
		int ret;
		ret = lite_rdma_read_hook(lite_handler, local_addr, size, priority, offset, password);
		if(ret)
		{
			return -EFAULT;
		}
		return 0;

	}
	return -EFAULT;
}
SYSCALL_DEFINE4(lite_ask_lmr,     int,  memory_space_owner_node,
				  uint64_t, identifier,
				  uint64_t, permission,
				  int, password)
{
	if(likely(lite_ask_lmr_hook))
	{
		uint64_t ret;
		ret = lite_ask_lmr_hook(memory_space_owner_node, identifier, permission, password);
		return (long)ret;
	}
	return -EFAULT;
}
SYSCALL_DEFINE1(lite_dist_barrier,	unsigned int, check_num)
{
	if(likely(lite_dist_barrier_hook))
	{
		lite_dist_barrier_hook(check_num);
		return 0;
	}
	return -EFAULT;
}
SYSCALL_DEFINE4(lite_add_ask_mr_table,	uint64_t, identifier,
					uint64_t, lmr, 
					uint64_t, permission,
					int, password)
{
	if(likely(lite_add_ask_mr_table_hook))
	{
		lite_add_ask_mr_table_hook(identifier, lmr, permission, password);
		return 0;
	}
	return -EFAULT;
}
SYSCALL_DEFINE5(lite_compare_swp,    unsigned long, lite_handler,
				  void __user *, local_addr,
				  unsigned long long, guess_value,
				  unsigned long long, set_value,
				  unsigned int,  priority)
{
	if(likely(lite_compare_swp_hook))
	{
		int ret;
		uint64_t output;
		ret = lite_compare_swp_hook(lite_handler, &output, guess_value, set_value, priority);
		if(ret)
		{
			return ret;
		}
		if(copy_to_user(local_addr, &output, sizeof(uint64_t)))
		{
			return -EFAULT;
		}
		return 0;

	}
	return -EFAULT;
}
SYSCALL_DEFINE1(lite_umap_lmr,	unsigned long, lite_handler)
{
	if(likely(lite_umap_lmr_hook))
	{
		int ret;
		ret = lite_umap_lmr_hook(lite_handler);
		return ret;
	}
	return -EFAULT;
}

SYSCALL_DEFINE5(lite_register_application, 	unsigned int, designed_port,
						unsigned int, max_size_per_message,
						unsigned int, max_user_per_node, 
						void  __user*, input_name,
						unsigned int, name_len)
{
	if(likely(lite_register_application_hook))
	{
		int ret;
		char *name = kmalloc(name_len * sizeof(char), GFP_KERNEL);
		ret = copy_from_user(name, input_name, name_len);
		if(ret)
		{
			kfree(name);
			return -EFAULT;
		}
		ret = lite_register_application_hook(designed_port, max_size_per_message, max_user_per_node, name, name_len);
		return ret;
	}
	return -EFAULT;
}

SYSCALL_DEFINE1(lite_unregister_application, unsigned int, port)
{
	if(likely(lite_unregister_application_hook))
	{
		int ret;
		ret = lite_unregister_application_hook(port);
		return ret;
	}
	return -EFAULT;
}

SYSCALL_DEFINE3(lite_query_port, 	int, target_node,
					int, designed_port,
					int, requery_flag)
{
	if(likely(lite_query_port_hook))
	{
		int ret;
		ret = lite_query_port_hook(target_node, designed_port, requery_flag);
		return ret;
	}
	return -EFAULT;
}

SYSCALL_DEFINE6(lite_send_reply_imm, 	int, node,
					int, size_port,
					void __user *, local_addr,
					void __user *, ret_addr,
                                        void __user *, ret_length,
					unsigned int, max_ret_size_and_priority)
{
	if(likely(lite_send_reply_imm_hook))
	{
		int ret;
		ret = lite_send_reply_imm_hook(node, size_port, local_addr, ret_addr, ret_length, max_ret_size_and_priority);
		return ret;
	}
	return -EFAULT;
}

SYSCALL_DEFINE6(lite_receive_message,    int, size_port,
				  	void __user *, local_addr,
					void __user *, descriptor,
                                        void __user *, ret_length,
					int, block_call,
					unsigned int, priority)
{
	if(likely(lite_receive_message_hook))
	{
		int ret;
		ret = lite_receive_message_hook(size_port, local_addr, descriptor, ret_length, block_call, priority);
		return ret;
	}
	return -EFAULT;
}

SYSCALL_DEFINE4(lite_reply_message, 	void __user *, local_addr,
					int, size,
					unsigned long, descriptor,
					unsigned int, priority)
{
	if(likely(lite_reply_message_hook))
	{
		int ret;
		ret = lite_reply_message_hook(local_addr, size, descriptor, priority);
		return ret;
	}
	return -EFAULT;
}

SYSCALL_DEFINE6(lite_reply_and_receive_message,  void __user *, local_addr,
                                                int, size_port, 
                                                unsigned long, descriptor,
                                                void __user *, ret_addr,
                                                int, receive_size,
                                                void __user *, receive_descriptor)
{
	if(likely(lite_reply_and_receive_message_hook))
	{
		int ret;
		ret = lite_reply_and_receive_message_hook(local_addr, size_port, descriptor, ret_addr, receive_size, receive_descriptor);
		return ret;
	}
	return -EFAULT;
}


SYSCALL_DEFINE0(lite_get_node_id)
{
	if(likely(lite_get_node_id_hook))
	{
		int ret;
		ret = lite_get_node_id_hook();
		return ret;
	}
	return -EFAULT;
}


SYSCALL_DEFINE0(lite_get_total_node)
{
	if(likely(lite_get_total_node_hook))
	{
		int ret;
		ret = lite_get_total_node_hook();
		return ret;
	}
	return -EFAULT;
}

SYSCALL_DEFINE2(lite_alloc_continuous_memory, 	unsigned long long, vaddr,
						unsigned long, size)
{
	if(likely(lite_alloc_continuous_memory_hook))
	{
		int ret;
		ret = lite_alloc_continuous_memory_hook(vaddr, size);
		return ret;
	}
	return -EFAULT;
}

SYSCALL_DEFINE2(lite_create_lock, 	int, target_node,
					void __user *, input_addr)
{
	if(likely(lite_create_lock_hook))
	{
		int ret;
		remote_spinlock_t temp_lock;
		ret = lite_create_lock_hook(target_node, (void *)&temp_lock);
		if(copy_to_user(input_addr, &temp_lock, sizeof(remote_spinlock_t)))
			return -EFAULT;
		return ret;
	}
	return -EFAULT;
}

SYSCALL_DEFINE3(lite_ask_lock, 		int, target_node,
					int, target_num, 
					void __user *, input_addr)
{
	if(likely(lite_ask_lock_hook))
	{
		int ret;
		remote_spinlock_t temp_lock;
		ret = lite_ask_lock_hook(target_node, target_num, (void *)&temp_lock);
		if(copy_to_user(input_addr, &temp_lock, sizeof(remote_spinlock_t)))
			return -EFAULT;
		return ret;
	}
	return -EFAULT;
}

SYSCALL_DEFINE1(lite_lock, 		void __user *, input_addr)
{
	if(likely(lite_lock_hook))
	{
		int ret;
		remote_spinlock_t temp_lock;
		if(copy_from_user(&temp_lock, input_addr, sizeof(remote_spinlock_t)))
			return -EFAULT;
		ret = lite_lock_hook((void *)&temp_lock);
		if(copy_to_user(input_addr, &temp_lock, sizeof(remote_spinlock_t)))
			return -EFAULT;
		return ret;
	}
	return -EFAULT;
}

SYSCALL_DEFINE1(lite_unlock, 		void __user *, input_addr)
{
	if(likely(lite_lock_hook))
	{
		int ret;
		remote_spinlock_t temp_lock;
		if(copy_from_user(&temp_lock, input_addr, sizeof(remote_spinlock_t)))
			return -EFAULT;
		ret = lite_unlock_hook((void *)&temp_lock);
		if(copy_to_user(input_addr, &temp_lock, sizeof(remote_spinlock_t)))
			return -EFAULT;
		return ret;
	}
	return -EFAULT;
}

SYSCALL_DEFINE3(lite_join, 		void __user *, input_addr,
                                        int, eth_port,
                                        int, ib_port)
{
	if(likely(lite_lock_hook))
	{
		int ret;
                char ip_str[32];
		if(copy_from_user(ip_str, input_addr, 32))
			return -EFAULT;
		ret = lite_join_hook(ip_str, eth_port, ib_port);
		return ret;
	}
	return -EFAULT;
}
