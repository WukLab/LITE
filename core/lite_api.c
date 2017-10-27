#include <rdma/ib_verbs.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_user_verbs.h>

#include "lite_api.h"

MODULE_AUTHOR("yiying, shinyeh");
MODULE_LICENSE("GPL");


/**
 * lite_api.c: this code is LITE api part. 
 * Most of the function calls are implemeneted in lite_api.c and lite_core.c
 * Roughly, one-sided operations are in lite_api.c.
 * Core functions and connection setup are in lite_core.c
 */

struct lite_hooks import_lite_hooks;
extern struct kmem_cache *lmr_metadata_cache;

extern ktime_t lite_time_start, lite_time_end;

/**
 * get_time_difference - this is internal timing testing function
 * @tid: thread id or other imformation used for debug
 * @inputtime: start_time
 */
long long get_time_difference(int tid, ktime_t inputtime)
{
        ktime_t t_time;
	t_time = ktime_get();
	printk(KERN_ALERT "thread %d run for %lld ns\n", tid, (long long) ktime_to_ns(ktime_sub(t_time, inputtime)));
        return (long long) ktime_to_ns(ktime_sub(lite_time_end, inputtime));
}

uint64_t cycle_start, cycle_end;

#define HANDLER_LENGTH 0
#define HANDLER_INTERARRIVAL 0


#ifdef TEST_MULTI_LOCK
	spinlock_t test_multi_lock_spinlock;
#endif
spinlock_t umap_lmr_lock;



atomic_t global_reqid;
//#define DEBUG_IBV

//spinlock_t send_req_lock[TOTAL_CONNECTIONS];

#ifdef TEST_PRINTK
#define test_printk(x...)	pr_crit(x)
#else
#define test_printk(x...)	do {} while (0)
#endif

///////////////////////////////////////////
//Client.c global parameter
///////////////////////////////////////////

int num_parallel_connection = NUM_PARALLEL_CONNECTION;

#define SRCADDR INADDR_ANY
#define DSTADDR ((unsigned long int)0xc0a87b01) /* 192.168.123.1 */

//FOR handle_ask_mr test
uint64_t gtest_key, gtest_key2;
//ltc *ctx;
ltc *LITE_ctx;
int                     curr_node;

struct ib_device *liteapi_dev;
struct ib_pd *ctx_pd;

extern ktime_t tt_start, tt_end;
extern long long int Internal_Stat_Sum;
extern int Internal_Stat_Count;

static void ibv_add_one(struct ib_device *device)
{
	LITE_ctx = (ltc *)kmalloc(sizeof(ltc), GFP_KERNEL);
	liteapi_dev = device;
	
	ctx_pd = ib_alloc_pd(device);
	if (!ctx_pd) {
		printk(KERN_ALERT "Couldn't allocate PD\n");
	}

	return;
}

static void ibv_remove_one(struct ib_device *device)
{
	return;
}

static void ibv_release_dev(struct device *dev)
{

}

static struct ib_client ibv_client = {
	.name   = "ibv_server",
	.add    = ibv_add_one,
	.remove = ibv_remove_one
};

static struct class ibv_class = {
	.name    = "infiniband_ibvs",
	.dev_release = ibv_release_dev
};


ktime_t liteapi_tt_start, liteapi_tt_end;

long long int liteapi_Internal_Stat_Sum=0;
int liteapi_Internal_Stat_Count=0;

/**
 * liteapi_internal_stat: internal testing function - stat usage
 * @input: input number
 * @flag: setup for ADD, CLEAR, or output temp average
 */
long long int liteapi_internal_stat(long long input, int flag)
{
        if(flag == LITE_STAT_ADD)
        {
                liteapi_Internal_Stat_Sum += input;
                liteapi_Internal_Stat_Count ++;
                return 0;
        }
        else if(flag == LITE_STAT_CLEAR)
        {
                long long int ret;
                ret = liteapi_Internal_Stat_Sum / liteapi_Internal_Stat_Count;
		printk(KERN_CRIT "%lld\n", liteapi_Internal_Stat_Sum);
                liteapi_Internal_Stat_Sum = 0;
                liteapi_Internal_Stat_Count = 0;
                return ret;
        }
        else if(flag == LITE_STAT_TEMP)
        {
                long long ret;
                ret = liteapi_Internal_Stat_Sum / liteapi_Internal_Stat_Count;
                return ret;
        }
        printk(KERN_CRIT "%s Error: flag undefined - %d\n", __func__, flag);
        return -1;
}


/**
 * handle_send: LITE also provides a hook-like call-back functions.
 * But it's not really used in experiments and applications
 */
int handle_send(char *addr, uint32_t length, int sender_id)
{
        client_free_recv_buf(addr);
	//#endif
	//
	//atomic_inc(&bandwidth_start_num);
	//printk(KERN_CRIT "%d\n", atomic_read(&bandwidth_start_num));
	return 0;
}

int handle_send_reply(char *input_buf, uint32_t size, char *output_buf, uint32_t *output_size, int sender_id)//return output_size
{
	//output_buf[0]='o';
	//output_buf[1]='k';
        client_free_recv_buf(input_buf);
	*output_size = 8;
	return 0;
}

int handle_send_reply_opt(char *input_buf, uint32_t size, void **output_buf, uint32_t *output_size, int sender_id)//return output_size
{
	return 0;
}

int handle_atomic_send(struct atomic_struct *input_list, uint32_t length, char *output_buf, uint32_t *output_size, int sender_id)
{
	output_buf[0] = 'o';
	output_buf[1] = 'k';
	*output_size = 2;
	return 0;
}

int handle_ask_mr(struct ask_mr_form *ask_form, uint32_t source_id, uint64_t *litekey_addr, uint64_t *permission)
{
	printk(KERN_CRIT "get request %u with permission %u\n", (unsigned int)ask_form->identifier, (unsigned int)ask_form->permission);
	if(ask_form->identifier == 3378)
	{
		memcpy(litekey_addr, &gtest_key, sizeof(uint64_t));
		*permission |= MR_READ_FLAG | MR_WRITE_FLAG | MR_SHARE_FLAG;
		//printk(KERN_CRIT "inside handler-1 %u %u", *litekey_addr, (unsigned int)gtest_key);
	}
	else if(ask_form->identifier==3379)
	{
		memcpy(litekey_addr, &gtest_key2, sizeof(uint64_t));
		*permission |= MR_READ_FLAG | MR_SHARE_FLAG;
		//printk(KERN_CRIT "inside handler-2 %u %u", *litekey_addr, (unsigned int)gtest_key);
	}
	else
	{
		printk(KERN_CRIT "error else %u\n", (unsigned int)ask_form->identifier);
		return MR_ASK_REFUSE;
	}

	return MR_ASK_SUCCESS;
}

/**
 * liteapi_add_askmr_table - add LMR/lite_handler into local handler table to response future map request
 * @identifier: identifier for future request
 * @lmr: lite_handler behind the targetted LMR
 * @permission: maximum granted permission
 * @password: pin code of the lite_handler
 */
int liteapi_add_askmr_table(uint64_t identifier, uint64_t lmr, uint64_t permission, int password)
{
	struct hash_asyio_key *src_ptr;
	ltc *ctx = LITE_ctx;
	src_ptr = lmr_to_mr_metadata(lmr);
	if(!src_ptr)
		return MR_ASK_REFUSE;
	if(src_ptr->password != password)
		return MR_ASK_REFUSE;
	client_add_askmr_table(ctx, identifier, lmr, permission);
	return 0;
}
EXPORT_SYMBOL(liteapi_add_askmr_table);

int liteapi_rdma_asyfence(void)
{
	return 0;
}
EXPORT_SYMBOL(liteapi_rdma_asyfence);

int get_respected_index_and_length(int offset, int length, int *access_index, int *access_length, int *access_offset, int *accumulate_length) //20ns
{
        int i;
        int first_index;

        int remaining_size;
        int access_length_before_the_first_tail;
        remaining_size = length;
        access_length_before_the_first_tail = LITE_MEMORY_BLOCK - ((offset + LITE_MEMORY_BLOCK) % LITE_MEMORY_BLOCK);
        first_index = offset / LITE_MEMORY_BLOCK;
        access_index[0] = first_index;
        access_length[0] = MIN(remaining_size, access_length_before_the_first_tail);
        access_offset[0] = offset;
        accumulate_length[0] = 0;
        remaining_size = length - access_length[0];
        i = 1;//From the second if needed
        while(remaining_size >= LITE_MEMORY_BLOCK)
        {
                access_index[i] = first_index + i;
                access_length[i] = LITE_MEMORY_BLOCK;
                access_offset[i] = 0;
                accumulate_length[i] = length - remaining_size;
                remaining_size = remaining_size - LITE_MEMORY_BLOCK;
                i++;
        }
        if(remaining_size > 0)//need to access the last block
        {
                access_index[i] = first_index + i;
                access_length[i] = remaining_size;
                access_offset[i] = 0;
                accumulate_length[i] = length - remaining_size;
                i++;
        }

        return i;
}


int liteapi_rdma_mr_request(uint64_t src_key, int src_offset, uint64_t tar_key, int tar_offset, int size, int op_code)
{
	int target_node;
	struct lmr_info **src_addr_list, **tar_addr_list;
	struct lmr_info *src_addr, *tar_addr;
	struct hash_asyio_key *src_ptr, *tar_ptr;
	struct mr_request_form request_form;
	uint64_t ret;
	uintptr_t tempptr;
	int wait_send_reply_id = SEND_REPLY_WAIT;
	ltc *ctx = LITE_ctx;

	if(src_offset + size > LITE_MEMORY_BLOCK)
	{
		printk(KERN_CRIT "%s: [error] mr operation can only support request within the first block[BETA]", __func__);
		return 0;
	}
	
	// get src
	src_ptr = lmr_to_mr_metadata(src_key);
	if(!src_ptr)
		return MR_ASK_REFUSE;
	if(!(src_ptr->permission & MR_WRITE_FLAG))
		return MR_ASK_REFUSE;
	src_addr_list = src_ptr->datalist;
	if(!src_addr_list)
		return MR_ASK_UNKNOWN;
	// get tar
	if(op_code != OP_REMOTE_MEMSET)
	{
		tar_ptr = lmr_to_mr_metadata(tar_key);
		if(!tar_ptr)
			return MR_ASK_REFUSE;
		if(!(tar_ptr->permission & MR_WRITE_FLAG))
			return MR_ASK_REFUSE;
		tar_addr_list = tar_ptr->datalist;
		if(!tar_addr_list)
			return MR_ASK_UNKNOWN;
	}
	
	src_addr = src_addr_list[0];
	tar_addr = tar_addr_list[0];
		
	target_node = src_addr->node_id;
			
	memset(&request_form, 0, sizeof(struct mr_request_form));
	memcpy(&request_form.request_mr, src_addr, sizeof(struct lmr_info));
	if(op_code != OP_REMOTE_MEMSET)
		memcpy(&request_form.copyto_mr, tar_addr, sizeof(struct lmr_info));
	request_form.offset = src_offset;
	request_form.copyto_offset = tar_offset;
	request_form.size = size;
	request_form.op_code = op_code;
	if(target_node != ctx->node_id)
	{
		tempptr = client_ib_reg_mr_addr(ctx, &request_form, sizeof(struct mr_request_form));
		client_send_message_sge_UD(ctx, target_node, MSG_MR_REQUEST, (void *)tempptr, sizeof(struct mr_request_form), (uint64_t)&ret, (uint64_t)&wait_send_reply_id, LOW_PRIORITY);
	}
	else
	{
		client_send_message_local(ctx, target_node, MSG_MR_REQUEST, &request_form, sizeof(struct mr_request_form), (uint64_t)&ret, (uint64_t)&wait_send_reply_id, LOW_PRIORITY);
	}
	
	while(wait_send_reply_id==SEND_REPLY_WAIT)
		cpu_relax();

	return ret;
}

int liteapi_rdma_mr_memcpy(uint64_t src_key, int src_offset, uint64_t tar_key, int tar_offset, int size)
{
	return liteapi_rdma_mr_request(src_key, src_offset, tar_key, tar_offset, size, OP_REMOTE_MEMCPY);
}
EXPORT_SYMBOL(liteapi_rdma_mr_memcpy);

int liteapi_rdma_mr_memmov(uint64_t src_key, int src_offset, uint64_t tar_key, int tar_offset, int size)
{
	return liteapi_rdma_mr_request(src_key, src_offset, tar_key, tar_offset, size, OP_REMOTE_MEMMOV);
}
EXPORT_SYMBOL(liteapi_rdma_mr_memmov);


/**
 * liteapi_remote_memset - does a remote set to a remote LMR
 * @lite_handler: lite handler
 * @offset: starting offset
 * @size: request size
 * it currently only does zero for memset
 * This function would support password as other operations in later version
 */
inline int liteapi_remote_memset(uint64_t lite_handler, int offset, int size)
{
	return liteapi_rdma_mr_request(lite_handler, offset, 0, 0, size, OP_REMOTE_MEMSET);
}
EXPORT_SYMBOL(liteapi_remote_memset);

int liteapi_rdma_write(uint64_t lite_handler, void *local_addr, int size, int priority)
{
	int target_node;
	int connection_id;
	struct lmr_info *mr_addr;
	struct hash_asyio_key *mr_ptr;
	ltc *ctx = LITE_ctx;
	mr_ptr = lmr_to_mr_metadata(lite_handler);
	if(!mr_ptr)
		return MR_ASK_REFUSE;
	if(!(mr_ptr->permission & MR_WRITE_FLAG))
		return MR_ASK_REFUSE;
	mr_addr = mr_ptr->datalist[0];
	if(!mr_addr)
		return MR_ASK_UNKNOWN;
	target_node = mr_addr->node_id;
	connection_id = client_get_connection_by_atomic_number(ctx, target_node, priority);
	client_send_request(ctx, connection_id, M_WRITE, mr_addr, local_addr, size, 0, LITE_KERNELSPACE_FLAG, 0);
	return 0;
}
EXPORT_SYMBOL(liteapi_rdma_write);

inline int liteapi_priority_handling(int priority, int flag, unsigned long *priority_jiffies, int type)
{
	#ifdef PRIORITY_IMPLEMENTATION_TRAFFIC_PRIORITIZATION
	ltc *ctx = LITE_ctx;
	if(flag == PRIORITY_START)
	{
		if(priority == USERSPACE_HIGH_PRIORITY)
		{
			*priority_jiffies = jiffies;
                        switch(type)
                        {
                                case PRIORITY_WRITE:
			                atomic_inc(&ctx->high_cur_num_write);
                                        break;
                                case PRIORITY_READ:
			                atomic_inc(&ctx->high_cur_num_read);
                                        break;
                                case PRIORITY_SR:
			                atomic_inc(&ctx->high_cur_num_sr);
                                        break;
                                default:
                                        printk(KERN_CRIT "[%s] error type %d\n", __func__, type);
                        }
		}
		else if(priority == USERSPACE_LOW_PRIORITY)
		{
			int cur_high,cur_low,total_low;
                        switch(type)
                        {
                                case PRIORITY_WRITE:
			                cur_low = atomic_inc_return(&ctx->low_cur_num_write);
			                total_low = atomic_inc_return(&ctx->low_total_num_write);
			                cur_high = atomic_read(&ctx->high_cur_num_write);
                                        break;
                                case PRIORITY_READ:
			                cur_low = atomic_inc_return(&ctx->low_cur_num_read);
			                total_low = atomic_inc_return(&ctx->low_total_num_read);
			                cur_high = atomic_read(&ctx->high_cur_num_read);
                                        break;
                                case PRIORITY_SR:
			                cur_low = atomic_inc_return(&ctx->low_cur_num_sr);
			                total_low = atomic_inc_return(&ctx->low_total_num_sr);
			                cur_high = atomic_read(&ctx->high_cur_num_sr);
                                        break;
                                default:
                                        printk(KERN_CRIT "[%s] error type %d\n", __func__, type);
			                cur_low = 0;
			                total_low = 0;
			                cur_high = 0;
                        }
			if(cur_high>=USERSPACE_LOW_PRIORITY_THRESHOLD)
				usleep_range(96, 128);
			else if(atomic_read(&ctx->slow_counter)>PRIORITY_CHECKING_THRESHOLD_COUNTER)
				usleep_range(64, 128);
			else if(cur_high>0&&(cur_low>cur_high))
				usleep_range(32, 64);
			/*if(cur_high>=USERSPACE_LOW_PRIORITY_THRESHOLD)
				usleep_range(64, 128);
			else if(atomic_read(&ctx->slow_counter)>PRIORITY_CHECKING_THRESHOLD_COUNTER)
				usleep_range(64, 129);
			else if(cur_high>0&& (cur_low>cur_high))
				usleep_range(1, 4);*/
			/* original configuration
                        if(cur_high>=USERSPACE_LOW_PRIORITY_THRESHOLD)
				usleep_range(USERSPACE_LOW_PRIORITY_DELAY, USERSPACE_LOW_PRIORITY_DELAY*2);
			else if(atomic_read(&ctx->slow_counter)>PRIORITY_CHECKING_THRESHOLD_COUNTER)
			{
				usleep_range(USERSPACE_LOW_PRIORITY_DELAY, USERSPACE_LOW_PRIORITY_DELAY*2);
			}
			else if(cur_high>0&& (cur_low>cur_high))
				usleep_range(USERSPACE_LOW_PRIORITY_DELAY/USERSPACE_LOW_PRIORITY_THRESHOLD, USERSPACE_LOW_PRIORITY_DELAY/USERSPACE_LOW_PRIORITY_THRESHOLD*2);*/
			//else if(cur_high>0&&total_low%8<8-cur_high)
			//	usleep_range(3, 6);
		}
	}
	else if(flag == PRIORITY_END)
	{
        	if(priority == USERSPACE_HIGH_PRIORITY)
		{
			unsigned long cur_jiffies = jiffies;
                        switch(type)
                        {
                                case PRIORITY_WRITE:
			                atomic_dec(&ctx->high_cur_num_write);
                                        break;
                                case PRIORITY_READ:
			                atomic_dec(&ctx->high_cur_num_read);
                                        break;
                                case PRIORITY_SR:
			                atomic_dec(&ctx->high_cur_num_sr);
                                        break;
                                default:
                                        printk(KERN_CRIT "[%s] error type %d\n", __func__, type);
                        }
			if((cur_jiffies - *priority_jiffies)*1000*1000/HZ >=PRIORITY_CHECKING_THRESHOLD_US)
				atomic_inc(&ctx->slow_counter);
			else
				atomic_dec(&ctx->slow_counter);
		}
	        else if(priority == USERSPACE_LOW_PRIORITY)
                {
                        switch(type)
                        {
                                case PRIORITY_WRITE:
			                atomic_dec(&ctx->low_cur_num_write);
                                        break;
                                case PRIORITY_READ:
			                atomic_dec(&ctx->low_cur_num_read);
                                        break;
                                case PRIORITY_SR:
			                atomic_dec(&ctx->low_cur_num_sr);
                                        break;
                                default:
                                        printk(KERN_CRIT "[%s] error type %d\n", __func__, type);
                        }
                }
	}
	#endif
	return 0;
}

int liteapi_rdma_write_offset(uint64_t lite_handler, void *local_addr, int size, int priority, int offset, int password)
{
	int target_node;
	int connection_id;
	struct lmr_info *mr_addr;
	struct hash_asyio_key *mr_ptr;
	ltc *ctx = LITE_ctx;
	//ktime_t self_time = ktime_get();
	mr_ptr = lmr_to_mr_metadata(lite_handler);
	//get_time_difference(lite_handler, self_time);
	if(!mr_ptr)
		return MR_ASK_REFUSE;
	if(!(mr_ptr->permission & MR_WRITE_FLAG))
		return MR_ASK_REFUSE;
	if(mr_ptr->password != password)
		return MR_ASK_REFUSE; 
	mr_addr = mr_ptr->datalist[0];
	if(!mr_addr)
		return MR_ASK_UNKNOWN;
	target_node = mr_addr->node_id;
	if(target_node == ctx->node_id)//local access
	{
		void *real_addr;
		real_addr = __va(mr_addr->addr);//get virtual addr from physical addr
		memcpy(real_addr+offset, local_addr, size);
		return 0;
	}
	connection_id = client_get_connection_by_atomic_number(ctx, target_node, priority);
	client_send_request(ctx, connection_id, M_WRITE, mr_addr, local_addr, size, offset, LITE_KERNELSPACE_FLAG, 0);
	return 0;
}
EXPORT_SYMBOL(liteapi_rdma_write_offset);


/**
 * liteapi_rdma_write_offset_userspace - processing write request from userspace
 * @lite_handler: lite_handler behind the targetted LMR
 * @local_addr: input address
 * @size: request size
 * @priority: high, low, or non
 * @offset: request offset
 * @password: pin code of the lite_handler
 */
int liteapi_rdma_write_offset_userspace(uint64_t lite_handler, void *local_addr, int size, int priority, int offset, int password)
{
	int target_node;
	int connection_id;
	struct lmr_info *mr_addr;
	struct lmr_info **mr_addr_list;
	int request_length;
	int i, curr_index, curr_offset, curr_length, curr_accumulate;
	struct hash_asyio_key *mr_ptr;
	void *real_addr;
        void *real_addr_list[LITE_MAX_MEMORY_BLOCK];
	ltc *ctx = LITE_ctx;
	struct ib_device *ibd = (struct ib_device *)ctx->context;
	unsigned long phys_addr;
        int ret;
	int access_index[LITE_MAX_MEMORY_BLOCK], access_length[LITE_MAX_MEMORY_BLOCK], access_offset[LITE_MAX_MEMORY_BLOCK], accumulate_length[LITE_MAX_MEMORY_BLOCK];
        int poll_status[LITE_MAX_MEMORY_BLOCK], connection_id_list[LITE_MAX_MEMORY_BLOCK];
	unsigned long priority_jiffies;
	
        
        //memset(access_index, 0, sizeof(int)*LITE_MAX_MEMORY_BLOCK);
	//memset(access_length, 0, sizeof(int)*LITE_MAX_MEMORY_BLOCK);
	//memset(access_offset, 0, sizeof(int)*LITE_MAX_MEMORY_BLOCK);
	//memset(accumulate_length, 0, sizeof(int)*LITE_MAX_MEMORY_BLOCK);
	
	//pte_t *pte = lite_get_pte(current->mm, (unsigned long)local_addr);
	//struct page *page = pte_page(*pte);
	//unsigned long phys_addr = page_to_phys(page) + (((uintptr_t)local_addr)&LITE_LINUX_PAGE_OFFSET);
	//real_addr = (void *)phys_to_dma(ibd->dma_device, (phys_addr_t)phys_addr);

	mr_ptr = lmr_to_mr_metadata(lite_handler);
	if(!mr_ptr)
		return MR_ASK_REFUSE;
	if(!(mr_ptr->permission & MR_WRITE_FLAG))
		return MR_ASK_REFUSE;
	if(mr_ptr->password != password)
		return MR_ASK_REFUSE; 
	mr_addr_list = mr_ptr->datalist;
	if(!mr_addr_list)
		return MR_ASK_UNKNOWN;
	if(priority)
		liteapi_priority_handling(priority, PRIORITY_START, &priority_jiffies, PRIORITY_WRITE);
        if(offset+size<LITE_MEMORY_BLOCK)
        {
                request_length = 1;
                access_index[0] = 0;
                access_length[0] = size;
                access_offset[0] = offset;
                accumulate_length[0] = 0;
        }
        else
        {
        	request_length = get_respected_index_and_length(offset, size, access_index, access_length, access_offset, accumulate_length);
        }
        for(i = 0; i < request_length;i++)
        {
                curr_index = access_index[i];
                curr_length = access_length[i];
                curr_offset = access_offset[i];
                curr_accumulate = accumulate_length[i];	
                mr_addr = mr_addr_list[curr_index];
                poll_status[i] = SEND_REPLY_WAIT;
                real_addr_list[i]=0;
                connection_id_list[i] = -1;
                if(!mr_addr)
                {
                        printk(KERN_CRIT "%s: error in access %d mr\n", __func__, i);
                        if(priority == USERSPACE_HIGH_PRIORITY)
                                atomic_dec(&ctx->high_cur_num_write);
                        return -EFAULT;
                }
                target_node = mr_addr->node_id;
                
                if(target_node == ctx->node_id)//local access
                {
                        void *real_addr;
                        real_addr = __va(mr_addr->addr + curr_offset);//get virtual addr from physical addr
                        if(copy_from_user(real_addr, local_addr + curr_accumulate, curr_length))
                        {
                                if(priority == USERSPACE_HIGH_PRIORITY)
                                        atomic_dec(&ctx->high_cur_num_write);
                                return -EFAULT;
                        }
                        continue;
                }
                connection_id = client_get_connection_by_atomic_number(ctx, target_node, priority);
                connection_id_list[i] = connection_id;
                ret = lite_check_page_continuous(local_addr + curr_accumulate, curr_length, &phys_addr);
                if(ret)//It's continuous
                {	
                        real_addr = (void *)phys_to_dma(ibd->dma_device, (phys_addr_t)phys_addr);
                        client_send_request(ctx, connection_id, M_WRITE, mr_addr, real_addr, curr_length, curr_offset, LITE_USERSPACE_FLAG, &poll_status[i]);
                }
                else
                {
                        real_addr_list[i] = kmalloc(curr_length, GFP_KERNEL);
                        if(copy_from_user(real_addr_list[i], local_addr + curr_accumulate, curr_length))
                        {
                                kfree(real_addr_list[i]);
                                if(priority == USERSPACE_HIGH_PRIORITY)
                                        atomic_dec(&ctx->high_cur_num_write);
                                return -EFAULT;
                        }
                        client_send_request(ctx, connection_id, M_WRITE, mr_addr, real_addr_list[i], curr_length, curr_offset, LITE_KERNELSPACE_FLAG, &poll_status[i]);
                }
        }
        for(i = 0; i < request_length;i++)
        {
                if(connection_id_list[i]<0)//local access
                        continue;
                client_internal_poll_sendcq(ctx->send_cq[connection_id_list[i]], connection_id_list[i], &poll_status[i]);
                if(real_addr_list[i])
                        kfree(real_addr_list[i]);
        }
	if(priority)
		liteapi_priority_handling(priority, PRIORITY_END, &priority_jiffies, PRIORITY_WRITE);
	return 0;
}
EXPORT_SYMBOL(liteapi_rdma_write_offset_userspace);


/**
 * liteapi_rdma_read_offset_userspace - processing read request from userspace
 * @lite_handler: lite_handler behind the targetted LMR
 * @local_addr: input address
 * @size: request size
 * @priority: high, low, or non
 * @offset: request offset
 * @password: pin code of the lite_handler
 */
int liteapi_rdma_read_offset_userspace(uint64_t lite_handler, void *local_addr, int size, int priority, int offset, int password)
{
	//test2 starts (ends in lite_internal.c takes 111ns)
	int target_node;
	int connection_id;
	struct lmr_info *mr_addr;
	struct lmr_info **mr_addr_list;
	int request_length;
	int i, curr_index, curr_offset, curr_length, curr_accumulate;
	struct hash_asyio_key *mr_ptr;
	void *real_addr;
        void *real_addr_list[LITE_MAX_MEMORY_BLOCK];
	unsigned long phys_addr;
	ltc *ctx = LITE_ctx;
	struct ib_device *ibd = (struct ib_device *)ctx->context;
	int access_index[LITE_MAX_MEMORY_BLOCK], access_length[LITE_MAX_MEMORY_BLOCK], access_offset[LITE_MAX_MEMORY_BLOCK], accumulate_length[LITE_MAX_MEMORY_BLOCK];
        int poll_status[LITE_MAX_MEMORY_BLOCK], connection_id_list[LITE_MAX_MEMORY_BLOCK];
	unsigned long priority_jiffies;

	memset(access_index, 0, sizeof(int)*LITE_MAX_MEMORY_BLOCK);
	memset(access_length, 0, sizeof(int)*LITE_MAX_MEMORY_BLOCK);
	memset(access_offset, 0, sizeof(int)*LITE_MAX_MEMORY_BLOCK);
	memset(accumulate_length, 0, sizeof(int)*LITE_MAX_MEMORY_BLOCK);
	

	//test1 starts	
	mr_ptr = lmr_to_mr_metadata(lite_handler);
	if(!mr_ptr)
		return MR_ASK_REFUSE;
	if(!(mr_ptr->permission & MR_READ_FLAG))
		return MR_ASK_REFUSE;
	if(mr_ptr->password != password)
		return MR_ASK_REFUSE; 
	mr_addr_list = mr_ptr->datalist;
	if(!mr_addr_list)
		return MR_ASK_UNKNOWN;
	//test1 ends - takes 30ns
	if(priority)
		liteapi_priority_handling(priority, PRIORITY_START, &priority_jiffies, PRIORITY_READ);
	request_length = get_respected_index_and_length(offset, size, access_index, access_length, access_offset, accumulate_length);
	for(i=0;i<request_length;i++)
	{
		curr_index = access_index[i];
		curr_length = access_length[i];
		curr_offset = access_offset[i];
		curr_accumulate = accumulate_length[i];	
		mr_addr = mr_addr_list[curr_index];
                poll_status[i] = SEND_REPLY_WAIT;
                real_addr_list[i]=0;
                connection_id_list[i] = -1;
		
		target_node = mr_addr->node_id;
		if(target_node == ctx->node_id)//local access
		{
			void *real_addr;
			real_addr = __va(mr_addr->addr + curr_offset);//get virtual addr from physical addr
			//memcpy(local_addr, real_addr+offset, size);
			if(copy_to_user(local_addr + curr_accumulate, real_addr, curr_length))
				return -EFAULT;
			continue;
		}
		connection_id = client_get_connection_by_atomic_number(ctx, target_node, priority);
                connection_id_list[i] = connection_id;
		

		if(lite_check_page_continuous(local_addr + curr_accumulate , curr_length, &phys_addr))//It's continuous
		{	
			real_addr = (void *)phys_to_dma(ibd->dma_device, (phys_addr_t)phys_addr);
			//printk(KERN_CRIT "%s: continuous %d\n", __func__, size);
			client_send_request(ctx, connection_id, M_READ, mr_addr, real_addr, curr_length, curr_offset, LITE_USERSPACE_FLAG, &poll_status[i]);
		}
		else
		{
			real_addr_list[i] = kmalloc(curr_length, GFP_KERNEL);
			client_send_request(ctx, connection_id, M_READ, mr_addr, real_addr_list[i], curr_length, curr_offset, LITE_KERNELSPACE_FLAG, &poll_status[i]);
		}
	}
	for(i = 0; i < request_length;i++)
        {
                if(connection_id_list[i]<0)//local access
                        continue;
		curr_index = access_index[i];
		curr_length = access_length[i];
		curr_offset = access_offset[i];
		curr_accumulate = accumulate_length[i];	
		mr_addr = mr_addr_list[curr_index];
                client_internal_poll_sendcq(ctx->send_cq[connection_id_list[i]], connection_id_list[i], &poll_status[i]);
                if(real_addr_list[i])
                {
			if(copy_to_user(local_addr + curr_accumulate, real_addr_list[i], curr_length))
			{
				kfree(real_addr_list[i]);
				return -EFAULT;
			}
			kfree(real_addr_list[i]);
                }
        }
	if(priority)
		liteapi_priority_handling(priority, PRIORITY_END, &priority_jiffies, PRIORITY_READ);
	//test4 ends
	return 0;
}
EXPORT_SYMBOL(liteapi_rdma_read_offset_userspace);

int liteapi_rdma_write_offset_imm(uint64_t lite_handler, void *local_addr, int size, int priority, int offset, int imm)
{
	int target_node;
	int connection_id;
	struct lmr_info *mr_addr;
	struct hash_asyio_key *mr_ptr;
	ltc *ctx = LITE_ctx;
	//ktime_t self_time = ktime_get();
	mr_ptr = lmr_to_mr_metadata(lite_handler);
	//get_time_difference(lite_handler, self_time);
	if(!mr_ptr)
		return MR_ASK_REFUSE;
	if(!(mr_ptr->permission & MR_WRITE_FLAG))
		return MR_ASK_REFUSE;
	mr_addr = mr_ptr->datalist[0];
	if(!mr_addr)
		return MR_ASK_UNKNOWN;
	target_node = mr_addr->node_id;
	//printk(KERN_CRIT "%s: node %d :%x %x %x", __func__, target_node, mr_addr->addr, mr_addr->lkey, mr_addr->rkey);
	connection_id = client_get_connection_by_atomic_number(ctx, target_node, priority);
	client_rdma_write_with_imm(ctx, connection_id, mr_addr, local_addr, size, offset, imm);
	return 0;
}
EXPORT_SYMBOL(liteapi_rdma_write_offset_imm);

/**
 * liteapi_register_application - register an application to a specific port for RPC function
 * @designed_port: the targetted port
 * @max_size_per_message: register the possible max size
 * @max_user_per_node: maximum user per node for this operation(not used in current version but for future QoS development)
 * @name: name/string of the application
 * @name_len: length of the name
 */
inline int liteapi_register_application(unsigned int designed_port, unsigned int max_size_per_message, unsigned int max_user_per_node, char *name, uint64_t name_len)
{
	ltc *ctx = LITE_ctx;
	return client_register_application(ctx, designed_port, max_size_per_message, max_user_per_node, name, name_len);
}
EXPORT_SYMBOL(liteapi_register_application);

/**
 * liteapi_unregister_application - remove the registration of the specific application
 * @designed_port: targetted port
 * This function will support password in the future version. 
 * This function is in beta version
 */
int liteapi_unregister_application(unsigned int designed_port)
{
	ltc *ctx = LITE_ctx;
	return client_unregister_application(ctx, designed_port);
}
EXPORT_SYMBOL(liteapi_unregister_application);

inline int liteapi_receive_message(unsigned int designed_port, void *ret_addr, int receive_size, uintptr_t *descriptor)
{
	ltc *ctx = LITE_ctx;
	return client_receive_message(ctx, designed_port, ret_addr, receive_size, descriptor, 0, 0, 1);
}
EXPORT_SYMBOL(liteapi_receive_message);

/**
 * liteapi_receive_message_userspace - processing a receive request (RPC-server) from userspace
 * @size_port: the combination of size and port (which is inputted from LITE-userspace library)
 * @ret_addr: address to keep received message
 * @descriptor: address to keep the header/descriptor of the received message (for reply usage)
 * @ret_length: keep the returned length of the message (for fast_receive)
 * @block_call: flag to show whether this is a blocking call or not
 * @priority: receive priority
 * return: length of received message
 */
inline int liteapi_receive_message_userspace(int size_port, void *ret_addr, void *descriptor, void *ret_length, int block_call, unsigned int priority)
{
	ltc *ctx = LITE_ctx;
        int ret;
	unsigned long priority_jiffies;
	if(priority)
		liteapi_priority_handling(priority, PRIORITY_START, &priority_jiffies, PRIORITY_SR);
	ret = client_receive_message(ctx, size_port&IMM_MAX_PORT_BITMASK, ret_addr, size_port>>IMM_MAX_PORT_BIT, (uintptr_t *)descriptor, ret_length, 1, block_call);
        //ret = client_receive_message(ctx, size_port%IMM_MAX_PORT, ret_addr, size_port/IMM_MAX_PORT, (uintptr_t *)descriptor, ret_length, 1, block_call);
	if(priority)
		liteapi_priority_handling(priority, PRIORITY_END, &priority_jiffies, PRIORITY_SR);
	//test7 ends
        return ret;
}
EXPORT_SYMBOL(liteapi_receive_message_userspace);

inline int liteapi_reply_message(void *addr, int size, uintptr_t descriptor)
{
	ltc *ctx = LITE_ctx;
	int ret;
	#ifdef LITE_GET_TIME
		struct timespec ts, te, diff;
		getnstimeofday(&ts);
	#endif
	ret = client_reply_message(ctx, addr, size, descriptor, 0, HIGH_PRIORITY);
	#ifdef LITE_GET_TIME                                                                      
		getnstimeofday(&te);
		diff = timespec_sub(te,ts);
		printk("[%s] time %lu\n", __func__, diff.tv_nsec);
	#endif
	return ret;
}
EXPORT_SYMBOL(liteapi_reply_message);

/**
 * liteapi_reply_message_userspace - processing a reply request in RPC from userspace
 * @addr: input address
 * @size: reply size
 * @descriptor: header of reply message (returned by lite_api_receive)
 * @priority: priority of the request
 */
inline int liteapi_reply_message_userspace(void *addr, int size, uintptr_t descriptor, unsigned int priority)
{
	ltc *ctx = LITE_ctx;
        int ret;
	unsigned long priority_jiffies;
	if(priority)
		liteapi_priority_handling(priority, PRIORITY_START, &priority_jiffies, PRIORITY_SR);
	ret = client_reply_message(ctx, addr, size, descriptor, 1, priority);
	if(priority)
		liteapi_priority_handling(priority, PRIORITY_END, &priority_jiffies, PRIORITY_SR);
        return ret;
}
EXPORT_SYMBOL(liteapi_reply_message_userspace);


inline int liteapi_reply_and_receive_message(void *addr, int size, uintptr_t descriptor, int port, void *ret_addr, int receive_size, void *receive_descriptor)
{
        ltc *ctx = LITE_ctx;
        int ret;
	ret = client_reply_message(ctx, addr, size, descriptor, 0, HIGH_PRIORITY);
        if(ret)
                return ret;
        ret = client_receive_message(ctx, port, ret_addr, receive_size, receive_descriptor, 0, 0, 1);
        return ret;
}
EXPORT_SYMBOL(liteapi_reply_and_receive_message);

/**
 * liteapi_reply_and_receive_message_userspace - a layer 4 optimization of RPC function to avoid one extra syscall cost
 * @addr: input address
 * @size_port: the combination of size and port (which is inputted from LITE-userspace library)
 * @descriptor: input header of the message (same as reply)
 * @ret_addr: address to keep received message
 * @receive_size: max receive size (same as receive)
 * @receive_descriptor: the header of received message (same as receive)
 * return: length of received message
 */
inline int liteapi_reply_and_receive_message_userspace(void *addr, int size_port, uintptr_t descriptor, void *ret_addr, int receive_size, void *receive_descriptor)
{
	/*unsigned long *tmp;
	if(!benchmark_phys_addr)
	{
		lite_check_page_continuous(addr, 0, &benchmark_phys_addr);
		benchmark_real_addr = __va(benchmark_phys_addr);
	}
	tmp = benchmark_real_addr;
	mdelay(1);
	*tmp=0;*/

        ltc *ctx = LITE_ctx;
        int ret;
	ret = client_reply_message(ctx, addr, size_port/IMM_MAX_PORT, descriptor, 1, HIGH_PRIORITY);
        if(ret)
                return ret;
        ret = client_receive_message(ctx, size_port%IMM_MAX_PORT, ret_addr, receive_size, receive_descriptor, 0, 1, 1);
        return 0;
}
EXPORT_SYMBOL(liteapi_reply_and_receive_message_userspace);


inline int liteapi_send_reply_imm(int target_node, unsigned int port, void *addr, int size, void *ret_addr, int max_ret_size)
{
	ltc *ctx = LITE_ctx;
	int ret;
	#ifdef LITE_GET_TIME
		struct timespec ts, te, diff;
		getnstimeofday(&ts);
	#endif
	ret = client_send_reply_with_rdma_write_with_imm(ctx, target_node, port, addr, size, ret_addr, max_ret_size, 0, 0, HIGH_PRIORITY);
	#ifdef LITE_GET_TIME
		getnstimeofday(&te);
		diff = timespec_sub(te,ts);
		printk("[%s] time %lu\n", __func__, diff.tv_sec*1000000+diff.tv_nsec/1000);
	#endif
	return ret;
}
EXPORT_SYMBOL(liteapi_send_reply_imm);

/**
 * liteapi_send_reply_imm_userspace - processing a send-reply request (RPC) from userspace
 * @target_node: target node id
 * @size_port: the combination of size and port (which is inputted from LITE-userspace library)
 * @addr: input address
 * @ret_addr: address to keep received message
 * @ret_length: keep the returned length of the message (for fast_receive)
 * @max_ret_size_and_priority: the combination of max_ret_size and priority (inputted from LITE-userspace library)
 * return: length of received message
 */
inline int liteapi_send_reply_imm_userspace(int target_node, int size_port, void *addr, void *ret_addr, void *ret_length, unsigned int max_ret_size_and_priority)
{
	ltc *ctx = LITE_ctx;
	int ret;
	//int priority = max_ret_size_and_priority%IMM_MAX_PRIORITY;
	int priority = max_ret_size_and_priority&IMM_MAX_PRIORITY_BITMASK;
	unsigned long priority_jiffies;
	//test5 starts (ends in client_send_message_with_rdma_write_with_imm_request before post_send) takes 270 ns
	if(priority)
		liteapi_priority_handling(priority, PRIORITY_START, &priority_jiffies, PRIORITY_SR);
	//ret = client_send_reply_with_rdma_write_with_imm(ctx, target_node, size_port%IMM_MAX_PORT, addr, size_port/IMM_MAX_PORT, ret_addr, max_ret_size_and_priority/IMM_MAX_PRIORITY, ret_length, 1, priority);
	ret = client_send_reply_with_rdma_write_with_imm(ctx, target_node, size_port&IMM_MAX_PORT_BITMASK, addr, size_port>>IMM_MAX_PORT_BIT, ret_addr, max_ret_size_and_priority>>IMM_MAX_PRIORITY_BIT, ret_length, 1, priority);
	if(priority)
		liteapi_priority_handling(priority, PRIORITY_END, &priority_jiffies, PRIORITY_SR);
	//test13 ends
	return ret;
}
EXPORT_SYMBOL(liteapi_send_reply_imm_userspace);

int liteapi_send_reply_imm_multisge(int number_of_node, int *target_node, int port, struct atomic_struct **input_atomic, int *length, struct max_reply_msg *output_msg)
{
        ltc *ctx = LITE_ctx;
        int ret;
	#ifdef LITE_GET_TIME
		struct timespec ts, te, diff;
		getnstimeofday(&ts);
	#endif
        ret = client_send_reply_with_rdma_write_with_imm_sge(ctx, number_of_node, target_node, port, input_atomic, length, output_msg);
	#ifdef LITE_GET_TIME
		getnstimeofday(&te);
		diff = timespec_sub(te,ts);
		printk("[%s] time %lu number_of_nodes %d\n", __func__, diff.tv_sec*1000000+diff.tv_nsec/1000, number_of_node);
	#endif
        return ret;
}
EXPORT_SYMBOL(liteapi_send_reply_imm_multisge);

inline int liteapi_rdma_write_offset_withmr_without_polling(struct lmr_info *mr_addr, void *local_addr, int size, int priority, int offset, int wr_id)
{
	int target_node = mr_addr->node_id;
	ltc *ctx = LITE_ctx;
	int connection_id = client_get_connection_by_atomic_number(ctx, target_node, priority);
	client_send_request_without_polling(ctx, connection_id, M_WRITE, mr_addr, local_addr, size, offset, wr_id);
	return connection_id;
}
EXPORT_SYMBOL(liteapi_rdma_write_offset_withmr_without_polling);

int liteapi_rdma_write_offset_without_polling(uint64_t lite_handler, void *local_addr, int size, int priority, int offset, int connection_id, int wr_id)
{
	int target_node;
	struct lmr_info *mr_addr;
	struct hash_asyio_key *mr_ptr;
	ltc *ctx = LITE_ctx;
	//ktime_t self_time = ktime_get();
	mr_ptr = lmr_to_mr_metadata(lite_handler);
	//get_time_difference(lite_handler, self_time);
	if(!mr_ptr)
		return MR_ASK_REFUSE;
	if(!(mr_ptr->permission & MR_WRITE_FLAG))
		return MR_ASK_REFUSE;
	mr_addr = mr_ptr->datalist[0];
	if(!mr_addr)
		return MR_ASK_UNKNOWN;
	target_node = mr_addr->node_id;
	client_send_request_without_polling(ctx, connection_id, M_WRITE, mr_addr, local_addr, size, offset, wr_id);
	return 0;
}

int liteapi_rdma_write_offset_mr(struct lmr_info *mr_addr, void *local_addr, int size, int priority, int offset)
{
	int target_node;
	int connection_id;
	ltc *ctx = LITE_ctx;
	if(!mr_addr)
		return MR_ASK_UNKNOWN;
	target_node = mr_addr->node_id;
	connection_id = client_get_connection_by_atomic_number(ctx, target_node, priority);
	client_send_request(ctx, connection_id, M_WRITE, mr_addr, local_addr, size, offset, LITE_KERNELSPACE_FLAG, 0);
	return 0;
}
EXPORT_SYMBOL(liteapi_rdma_write_offset_mr);

int liteapi_rdma_read(uint64_t lite_handler, void *local_addr, int size, int priority)
{
	int target_node;
	int connection_id;
	struct lmr_info *mr_addr;
	struct hash_asyio_key *mr_ptr;
	ltc *ctx = LITE_ctx;
	mr_ptr = lmr_to_mr_metadata(lite_handler);
	if(!mr_ptr)
		return MR_ASK_REFUSE;
	if(!(mr_ptr->permission & MR_READ_FLAG))
		return MR_ASK_REFUSE;
	mr_addr = mr_ptr->datalist[0];
	if(!mr_addr)
		return MR_ASK_UNKNOWN;
	target_node = mr_addr->node_id;
	connection_id = client_get_connection_by_atomic_number(ctx, target_node, priority);
	client_send_request(ctx, connection_id, M_READ, mr_addr, local_addr, size, 0, LITE_KERNELSPACE_FLAG, 0);
	return 0;
}
EXPORT_SYMBOL(liteapi_rdma_read);

int liteapi_rdma_read_offset_mr(struct lmr_info *mr_addr, void *local_addr, int size, int priority, int offset)
{
	int target_node;
	int connection_id;
	ltc *ctx = LITE_ctx;
	if(!mr_addr)
		return MR_ASK_UNKNOWN;
	target_node = mr_addr->node_id;
	connection_id = client_get_connection_by_atomic_number(ctx, target_node, priority);
	client_send_request(ctx, connection_id, M_READ, mr_addr, local_addr, size, offset, LITE_KERNELSPACE_FLAG, 0);
	return 0;
}
EXPORT_SYMBOL(liteapi_rdma_read_offset_mr);

int liteapi_rdma_read_offset(uint64_t lite_handler, void *local_addr, int size, int priority, int offset, int password)
{
	int target_node;
	int connection_id;
	struct lmr_info *mr_addr;
	struct hash_asyio_key *mr_ptr;
	ltc *ctx = LITE_ctx;
	mr_ptr = lmr_to_mr_metadata(lite_handler);
	if(!mr_ptr)
		return MR_ASK_REFUSE;
	if(!(mr_ptr->permission & MR_READ_FLAG))
		return MR_ASK_REFUSE;
	if(mr_ptr->password != password)
		return MR_ASK_REFUSE; 
	mr_addr = mr_ptr->datalist[0];
	if(!mr_addr)
		return MR_ASK_UNKNOWN;
	target_node = mr_addr->node_id;
	if(target_node == ctx->node_id)//local access
	{
		void *real_addr;
		real_addr = __va(mr_addr->addr);//get virtual addr from physical addr
		memcpy(local_addr, real_addr+offset, size);
		return 0;
	}
	connection_id = client_get_connection_by_atomic_number(ctx, target_node, priority);
	client_send_request(ctx, connection_id, M_READ, mr_addr, local_addr, size, offset, LITE_KERNELSPACE_FLAG, 0);
	return 0;
}
EXPORT_SYMBOL(liteapi_rdma_read_offset);

int liteapi_rdma_read_offset_multiplesge(uint64_t lite_handler, void *local_addr, int size, int priority, int offset, int sge_num, struct ib_sge *input_sge)
{
	int target_node;
	int connection_id;
	struct lmr_info *mr_addr;
	struct lmr_info test_key;
	struct hash_asyio_key *mr_ptr;
	ltc *ctx = LITE_ctx;
	mr_ptr = lmr_to_mr_metadata(lite_handler);
	if(!mr_ptr)
		return MR_ASK_REFUSE;
	if(!(mr_ptr->permission & MR_READ_FLAG))
		return MR_ASK_REFUSE;
	mr_addr = mr_ptr->datalist[0];
	if(!mr_addr)
		return MR_ASK_UNKNOWN;
	memcpy(&test_key, mr_addr, sizeof(struct lmr_info));
	test_key.addr = test_key.addr + offset;
	target_node = mr_addr->node_id;
	connection_id = client_get_connection_by_atomic_number(ctx, target_node, priority);
	client_send_request_multiplesge(ctx, connection_id, M_READ, &test_key, local_addr, size, sge_num, input_sge);
	return 0;
}

int liteapi_rdma_write_offset_multiplesge(uint64_t lite_handler, void *local_addr, int size, int priority, int offset, int sge_num, struct ib_sge *input_sge)
{
	int target_node;
	int connection_id;
	struct lmr_info *mr_addr;
	struct lmr_info test_key;
	struct hash_asyio_key *mr_ptr;
	ltc *ctx = LITE_ctx;
	mr_ptr = lmr_to_mr_metadata(lite_handler);
	if(!mr_ptr)
		return MR_ASK_REFUSE;
	if(!(mr_ptr->permission & MR_WRITE_FLAG))
		return MR_ASK_REFUSE;
	mr_addr = mr_ptr->datalist[0];
	if(!mr_addr)
		return MR_ASK_UNKNOWN;
	memcpy(&test_key, mr_addr, sizeof(struct lmr_info));
	test_key.addr = test_key.addr + offset;
	target_node = mr_addr->node_id;
	connection_id = client_get_connection_by_atomic_number(ctx, target_node, priority);
	client_send_request_multiplesge(ctx, connection_id, M_WRITE, &test_key, local_addr, size, sge_num, input_sge);
	return 0;
}

/**
 * liteapi_rdma_write_offset_userspace - this is an API interface for future development
 */
int liteapi_rdma_asywrite_offset(uint64_t lite_handler, void *local_addr, int size, int priority, int offset)
{
	return 0;
}
EXPORT_SYMBOL(liteapi_rdma_asywrite_offset);

int liteapi_rdma_asyread_offset(uint64_t lite_handler, void *local_addr, int size, int priority, int offset)
{
	return 0;
}
EXPORT_SYMBOL(liteapi_rdma_asyread_offset);

int liteapi_rdma_synwrite_offset(uint64_t lite_handler, void *local_addr, int size, int priority, int offset)
{
	return 0;
}

int liteapi_rdma_asywait(void)
{
	return 0;
}
EXPORT_SYMBOL(liteapi_rdma_asywait);


/**
 * liteapi_rdma_compare_and_swp - processing compare and swp request
 * @lite_handler: lite_handler behind the targetted LMR
 * @local_addr: input address
 * @guess_value: compare value
 * @set_value: swap value
 * @priority: priority of this request
 * This function would support password as other operations in later version
 */
int liteapi_rdma_compare_and_swp(uint64_t lite_handler, void *local_addr, unsigned long long guess_value, unsigned long long set_value, int priority)
{
	//int connection_id = client_get_connection_by_atomic_number(target_node, priority);
	//client_fetch_add(connection_id, mr_addr, local_addr, size);
	//return 0;
	int target_node;
        int ret;
	//mr_addr = client_id_to_mr(lite_handler);
	//if(!mr_addr)
	//	return 1;
	
	ltc *ctx = LITE_ctx;
	struct hash_asyio_key *temp_ptr;
	int connection_id;
	ret = lmr_permission_check(lite_handler, MR_ATOMIC_FLAG, &temp_ptr);
	if(ret)
		return ret;

	target_node = temp_ptr->datalist[0]->node_id;
        if(target_node != ctx->node_id)
        {
        	connection_id = client_get_connection_by_atomic_number(ctx, target_node, priority);
	        ret = client_compare_swp(ctx, connection_id, temp_ptr->datalist[0], local_addr, guess_value, set_value);
        }
        else
        {
	        ret = client_compare_swp_loopback(ctx, temp_ptr->datalist[0], local_addr, guess_value, set_value);
        }
        return ret;
}
EXPORT_SYMBOL(liteapi_rdma_compare_and_swp);

/**
 * liteapi_rdma_fetch_and_add - do fetch_and_add operation to a targetted LMR
 * @lite_handler: lite_handler behind the targetted LMR
 * @local_addr: input address
 * @input_value: input value of fetch_and_'add'
 * @priority: high, low, or non
 * This function would support password as other operations in later version
 */
int liteapi_rdma_fetch_and_add(uint64_t lite_handler, void *local_addr, unsigned long long input_value, int priority)
{
	//int connection_id = client_get_connection_by_atomic_number(target_node, priority);
	//client_fetch_add(connection_id, mr_addr, local_addr, size);
	//return 0;
	int target_node;
	int connection_id;
	//mr_addr = client_id_to_mr(lite_handler);
	//if(!mr_addr)
	//	return 1;
	
	struct hash_asyio_key *temp_ptr;
	int ret=0;
	ltc *ctx = LITE_ctx;
	ret = lmr_permission_check(lite_handler, MR_ATOMIC_FLAG, &temp_ptr);
	if(ret)
		return ret;

	target_node = temp_ptr->datalist[0]->node_id;
        if(target_node != ctx->node_id)
        {
        	connection_id = client_get_connection_by_atomic_number(ctx, target_node, priority);
	        client_fetch_and_add(ctx, connection_id, temp_ptr->datalist[0], local_addr, input_value);
        }
	else
        {
                client_fetch_and_add_loopback(ctx, temp_ptr->datalist[0], local_addr, input_value);
        }
	return 0;
}
EXPORT_SYMBOL(liteapi_rdma_fetch_and_add);

int liteapi_rdma_swp(int target_node, struct lmr_info *mr_addr, void *local_addr, unsigned long long guess, unsigned long long swp_value, int priority)
{
	ltc *ctx = LITE_ctx;
	int connection_id = client_get_connection_by_atomic_number(ctx, target_node, priority);
	return client_compare_swp(ctx, connection_id, mr_addr, local_addr, guess, swp_value);
}
EXPORT_SYMBOL(liteapi_rdma_swp);

int liteapi_send_message(int target_node, void *addr, int size)
{
	int priority = LOW_PRIORITY;
	ltc *ctx = LITE_ctx;
	uintptr_t tempaddr;
	tempaddr = client_ib_reg_mr_addr(ctx, addr, size);
	client_send_message_sge_UD(ctx, target_node, MSG_CLIENT_SEND, (void *)tempaddr, size, 0, 0, priority);

	return size;
}
EXPORT_SYMBOL(liteapi_send_message);

int liteapi_send_message_priority(int target_node, void *addr, int size, int priority)
{
	
	ltc *ctx = LITE_ctx;
	uintptr_t tempaddr;
	tempaddr = client_ib_reg_mr_addr(ctx, addr, size);
	client_send_message_sge_UD(ctx, target_node, MSG_CLIENT_SEND, (void *)tempaddr, size, 0, 0, priority);

	return size;
}
EXPORT_SYMBOL(liteapi_send_message_priority);

int liteapi_send_message_type(int target_node, void *addr, int size, int type)
{
	int priority = LOW_PRIORITY;
	ltc *ctx = LITE_ctx;
	uintptr_t tempaddr;
	tempaddr = client_ib_reg_mr_addr(ctx, addr, size);
	client_send_message_sge_UD(ctx, target_node, type, (void *)tempaddr, size, 0, 0, priority);
	return size;
}
EXPORT_SYMBOL(liteapi_send_message_UD);

int liteapi_send_message_UD(int target_node, void *addr, int size, int type)
{
	int priority = LOW_PRIORITY;
	uintptr_t tempaddr;
	ltc *ctx = LITE_ctx;
	tempaddr = client_ib_reg_mr_addr(ctx, addr, size);
	//client_send_message_addr(connection_id, MSG_CLIENT_SEND, (void *)tempaddr, size, 0);
	client_send_message_sge_UD(ctx, target_node, type, (void *)tempaddr, size, 0, 0, priority);
	return target_node;
}

int liteapi_send_reply(int target_node, char *msg, int size, char *output_msg)
{
	uintptr_t tempaddr;
	int priority = LOW_PRIORITY;
	int wait_send_reply_id;
	ltc *ctx = LITE_ctx;
	wait_send_reply_id = SEND_REPLY_WAIT;
	tempaddr = client_ib_reg_mr_addr(ctx, msg, size);
	client_send_message_sge_UD(ctx, target_node, MSG_GET_SEND_AND_REPLY_1, (void *)tempaddr, size, (uint64_t)output_msg, (uint64_t)&wait_send_reply_id, priority);
	while(wait_send_reply_id==SEND_REPLY_WAIT)
		cpu_relax();
	return wait_send_reply_id;
}
EXPORT_SYMBOL(liteapi_send_reply);

int liteapi_send_reply_type(int target_node, char *msg, int size, char *output_msg, int type)
{
	uintptr_t tempaddr;
	int priority = LOW_PRIORITY;
	int wait_send_reply_id;
	ltc *ctx = LITE_ctx;
	wait_send_reply_id = SEND_REPLY_WAIT;
	tempaddr = client_ib_reg_mr_addr(ctx, msg, size);
	client_send_message_sge_UD(ctx, target_node, type, (void *)tempaddr, size, (uint64_t)output_msg, (uint64_t)&wait_send_reply_id, priority);
	while(wait_send_reply_id==SEND_REPLY_WAIT)
		cpu_relax();
	return wait_send_reply_id;
}

int liteapi_send_reply_UD(int target_node, char *msg, int size, char *output_msg)
{	
	int priority = LOW_PRIORITY;
	int wait_send_reply_id = SEND_REPLY_WAIT;
	unsigned long j0,j1,delay;
	uintptr_t tempaddr;
	ltc *ctx = LITE_ctx;
	delay = usecs_to_jiffies(15); /* 20 msec delay */
	tempaddr = client_ib_reg_mr_addr(ctx, msg, size);
retran:
	//client_send_message_addr(connection_id, MSG_CLIENT_SEND, (void *)tempaddr, size, 0);
	client_send_message_sge_UD(ctx, target_node, MSG_GET_SEND_AND_REPLY_1_UD, (void *)tempaddr, size, (uint64_t)output_msg, (uint64_t)&wait_send_reply_id, priority);
	j0 = jiffies; 
	j1 = j0 + delay; 
	while(wait_send_reply_id==SEND_REPLY_WAIT&&time_before(jiffies, j1))
		cpu_relax();
	if(wait_send_reply_id==SEND_REPLY_WAIT)
		goto retran;
		

	return wait_send_reply_id;
}
EXPORT_SYMBOL(liteapi_send_reply_UD);

/**
 * liteapi_dist_barrier: distributed barrier
 * @check_num: requested number of barrier message
 */
uint64_t liteapi_dist_barrier(unsigned int check_num)
{
	int i;
	ltc *ctx = LITE_ctx;
	int source = ctx->node_id;
	int num_alive_nodes = atomic_read(&ctx->num_alive_nodes);
	uintptr_t tempaddr;
	int priority = LOW_PRIORITY;
        int wait_send_reply_id;
        uint64_t output;
	//int connection_id;
	atomic_inc(&ctx->dist_barrier_counter);
        ctx->dist_barrier_idx++;
        source = source + ctx->dist_barrier_idx * MAX_NODE;
	#ifdef LITE_GET_TIME
		struct timespec ts, te, diff;
		getnstimeofday(&ts);
	#endif
	for(i=1;i<=num_alive_nodes;i++)//skip CD
	{
                unsigned long j0,j1,delay;
                delay = msecs_to_jiffies(1000); /* 20 msec delay */
		if(i==ctx->node_id)
			continue;
	        wait_send_reply_id = SEND_REPLY_WAIT;
		tempaddr = client_ib_reg_mr_addr(ctx, &source, sizeof(int));
barrier_resend:
		client_send_message_sge_UD(ctx, i, MSG_DIST_BARRIER, (void *)tempaddr, sizeof(int), (uint64_t)&output, (uint64_t)&wait_send_reply_id, priority);
                j0 = jiffies; 
                j1 = j0 + delay;
	        while(wait_send_reply_id==SEND_REPLY_WAIT&&(time_before(jiffies, j1)))
        		cpu_relax();
                if(wait_send_reply_id == SEND_REPLY_WAIT)
                {
                        printk(KERN_CRIT "%s: lost packet after 1000 msecs\n", __func__);
                        goto barrier_resend;
                }
	}
	#ifdef LITE_GET_TIME                                                                      
		getnstimeofday(&te);
		diff = timespec_sub(te,ts);
		printk("[%s] time-after send %lu\n", __func__, diff.tv_nsec);
	#endif
	//while(atomic_read(&ctx->dist_barrier_counter)<num_alive_nodes)
	while(atomic_read(&ctx->dist_barrier_counter)<check_num)
	{
		schedule();
	}
	atomic_sub(check_num, &ctx->dist_barrier_counter);
	#ifdef LITE_GET_TIME                                                                      
		getnstimeofday(&te);
		diff = timespec_sub(te,ts);
		printk("[%s] time-after receive %lu\n", __func__, diff.tv_nsec);
	#endif
	return 0;
}
EXPORT_SYMBOL(liteapi_dist_barrier);

int liteapi_send_reply_opt(int target_node, char *msg, int size, void **output_msg, int priority)
{
	uintptr_t tempaddr;
	//int priority = LOW_PRIORITY;
	int wait_send_reply_id;
	ltc *ctx = LITE_ctx;
	wait_send_reply_id = SEND_REPLY_WAIT;
	tempaddr = client_ib_reg_mr_addr(ctx, msg, size);
	//client_send_message_addr(connection_id, MSG_GET_SEND_AND_REPLY_1, (void *)tempaddr, size, wait_send_reply_id);
	client_send_message_sge_UD(ctx, target_node, MSG_GET_SEND_AND_REPLY_OPT_1, (void *)tempaddr, size, (uint64_t)output_msg, (uint64_t)&wait_send_reply_id, priority);
	while(wait_send_reply_id==SEND_REPLY_WAIT)
		cpu_relax();
	return wait_send_reply_id;
}
EXPORT_SYMBOL(liteapi_send_reply_opt);


uint64_t liteapi_register_lmr_with_virt_addr(void *addr, int size, bool atomic_flag, int password)
{	
	uint64_t ret_key;
	int roundup_size = ROUND_UP(size, REMOTE_MEMORY_PAGE_SIZE);
	ltc *ctx = LITE_ctx;
	struct lmr_info *ret_mr = client_alloc_lmr_info_buf();
	struct lmr_info **ret_mr_list = (struct lmr_info **)kmalloc(sizeof(struct clitn_ibv_mr *), GFP_KERNEL);
	if(roundup_size > LITE_MEMORY_BLOCK)
	{
		printk(KERN_CRIT "%s: error in request size %d, too big", __func__, size);
		return 0;
	}
	if(atomic_flag==0)
	{
		ret_mr = client_ib_reg_mr(ctx, addr, roundup_size, IB_ACCESS_LOCAL_WRITE|IB_ACCESS_REMOTE_WRITE|IB_ACCESS_REMOTE_READ);
	}
	else if(atomic_flag ==1 && size == sizeof(uint64_t))
		ret_mr = client_ib_reg_mr(ctx, addr, sizeof(uint64_t), IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_ATOMIC);
	else if(atomic_flag ==1 && size != sizeof(uint64_t))
	{
		printk(KERN_CRIT "atomic operation can only be assigned with 8 bytes instead of %d\n", size);
		return MR_ASK_REFUSE;
	}
	else
	{	
		printk(KERN_CRIT "should not be here\n");
		return MR_ASK_REFUSE;
	}
	ret_mr_list[0] = ret_mr;	
	ret_key = atomic_add_return(1, &ctx->lmr_inc);
	if(atomic_flag)
		client_create_metadata_by_lmr(ctx, ret_key, ret_mr_list, 1, ret_mr->node_id, roundup_size, (MR_READ_FLAG | MR_WRITE_FLAG | MR_SHARE_FLAG | MR_ADMIN_FLAG | MR_ATOMIC_FLAG), 1, password);
	else
		client_create_metadata_by_lmr(ctx, ret_key, ret_mr_list, 1, ret_mr->node_id, roundup_size, (MR_READ_FLAG | MR_WRITE_FLAG | MR_SHARE_FLAG | MR_ADMIN_FLAG), 1, password);
	kfree(ret_mr_list);
	return ret_key;
}
EXPORT_SYMBOL(liteapi_register_lmr_with_virt_addr);

/**
 * liteapi_wrapup_alloc_for_remote_access - a layer 4 optimization to
 * create a LMR at local and add identifier to respond table
 * @data: input data
 * @size: request size
 * @identifier: identifier for future map
 * @password: password of this LMR (with lite handler)
 */
uint64_t liteapi_wrapup_alloc_for_remote_access(void *data, unsigned int size, uint64_t identifier, int password)
{
	ltc *ctx = LITE_ctx;
	void *addr;
	uint64_t tmp_lmr;
	struct lmr_info *ret_mr;
	struct lmr_info **ret_mr_list;
	int ret;
	int i;
	int roundup_size;
	int required_mr_num;
	int remaining_size;
	int request_size;
	int accumulate_size;
	
	roundup_size = ROUND_UP(size, REMOTE_MEMORY_PAGE_SIZE);
	required_mr_num = ROUND_UP(roundup_size, LITE_MEMORY_BLOCK) / LITE_MEMORY_BLOCK;
        if(required_mr_num > LITE_MAX_MEMORY_BLOCK)
        {
                printk(KERN_CRIT "%s: request size %d(roundup %d) is too big\n", __func__, size, roundup_size);
                return -EFAULT;
        }
	ret_mr_list = (struct lmr_info **)kmalloc(sizeof(struct clent_ibv_mr *) * required_mr_num, GFP_KERNEL);
	remaining_size = size;
	accumulate_size = 0;

	for(i=0;i<required_mr_num;i++)
	{
		request_size = MIN(remaining_size, LITE_MEMORY_BLOCK);
		addr = client_alloc_memory_for_mr(request_size*sizeof(char));
		memset(addr, 0, request_size);
		ret_mr = client_ib_reg_mr(ctx, addr, request_size, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ);	
		ret_mr_list[i] = ret_mr;
		ret = copy_from_user(addr, data + accumulate_size, request_size);
		accumulate_size = accumulate_size + request_size;
		remaining_size = remaining_size - LITE_MEMORY_BLOCK;
		//if(size > 1024*1024*4)
		//	printk(KERN_CRIT "%s: required_mr %d, size %d r-size %d, a-size %d request %d remain %d\n", __func__, required_mr_num, size, roundup_size, accumulate_size,  request_size, remaining_size);
		if(ret)
			return -EFAULT;	
	}
	tmp_lmr = atomic_add_return(1, &ctx->lmr_inc);
	client_create_metadata_by_lmr(ctx, tmp_lmr, ret_mr_list, required_mr_num, ctx->node_id, roundup_size, (MR_READ_FLAG | MR_WRITE_FLAG | MR_SHARE_FLAG | MR_ADMIN_FLAG), 0, password);
	liteapi_add_askmr_table(identifier, tmp_lmr, MR_READ_FLAG | MR_WRITE_FLAG | MR_SHARE_FLAG, password);
	kfree(ret_mr_list);
	
	return tmp_lmr;
}
EXPORT_SYMBOL(liteapi_wrapup_alloc_for_remote_access);

/**
 * liteapi_alloc_remote_mem - alloc a memory space at the remote side as a LMR
 * @target_node: id of the remote node
 * @size: requested size
 * @atomic_flag: will this memory space be used for atomic operations?
 * @password: pin code for this memory region
 */
uint64_t liteapi_alloc_remote_mem(unsigned int target_node, unsigned int size, unsigned atomic_flag, int password)
{
	uintptr_t tempaddr;
	int wait_send_reply_id;
	ltc *ctx = LITE_ctx;
	//struct lmr_info *ret_mr = (struct lmr_info *)kmem_cache_alloc(lmr_info_cache, GFP_KERNEL);

	int roundup_size = ROUND_UP(size, REMOTE_MEMORY_PAGE_SIZE);
	int remaining_size = roundup_size;
	int required_mr_num = (ROUND_UP(roundup_size, LITE_MEMORY_BLOCK)) / LITE_MEMORY_BLOCK;
	int request_size;
	struct lmr_info **ret_mr_list = (struct lmr_info **)kmalloc(sizeof(struct clent_ibv_mr *) * required_mr_num, GFP_KERNEL);
	struct lmr_info *ret_mr;
	uint64_t tmp_lmr;
	int i,j;
        int total_node = liteapi_get_total_node();
        int round_robin_node;
        int *round_robin_list;

	if(atomic_flag ==1 && size != sizeof(uint64_t))
	{
		printk(KERN_CRIT "atomic operation can only be assigned with 8 bytes instead of %d\n", size);
		return MR_ASK_REFUSE;
	}	
        if(target_node == 0)
        {
                round_robin_list = kmalloc(sizeof(int)*total_node-1, GFP_KERNEL);
                j=0;
                for(i=1;i<=total_node;i++)
                {
                        if(i!=ctx->node_id)
                        {
                                round_robin_list[j]=i;
                                j++;
                        }
                }
		for(i=0;i<required_mr_num && remaining_size >0;i++)
		{
                        round_robin_node = round_robin_list[i%(total_node-1)];
                        printk(KERN_CRIT "%s: RR allocate piece %d on node %d\n", __func__, i, round_robin_node);
			ret_mr = client_alloc_lmr_info_buf();
			wait_send_reply_id = SEND_REPLY_WAIT;
			request_size = MIN(remaining_size, LITE_MEMORY_BLOCK);
			if(request_size <=0)
			{
				printk("%s: error in request_size %d handling\n", __func__, request_size);
				break;
			}
			tempaddr = client_ib_reg_mr_addr(ctx, &request_size, sizeof(int));
			if(atomic_flag)
			{
				remaining_size=sizeof(uint64_t);
				client_send_message_sge_UD(ctx, round_robin_node, MSG_GET_REMOTE_ATOMIC_OPERATION, (void *)tempaddr, sizeof(int), (uint64_t)ret_mr, (uint64_t)&wait_send_reply_id, LOW_PRIORITY);
			}
			else
			{
				client_send_message_sge_UD(ctx, round_robin_node, MSG_GET_REMOTEMR, (void *)tempaddr, sizeof(int), (uint64_t)ret_mr, (uint64_t)&wait_send_reply_id, LOW_PRIORITY);
			}
			while(wait_send_reply_id==SEND_REPLY_WAIT)
				cpu_relax();
			ret_mr_list[i] = ret_mr;
			remaining_size = remaining_size - LITE_MEMORY_BLOCK; 
		}
                kfree(round_robin_list);
        }
	if(target_node != ctx->node_id) //remote side allocation
	{
		for(i=0;i<required_mr_num && remaining_size >0;i++)
		{
			ret_mr = client_alloc_lmr_info_buf();
			wait_send_reply_id = SEND_REPLY_WAIT;
			request_size = MIN(remaining_size, LITE_MEMORY_BLOCK);
			if(request_size <=0)
			{
				printk("%s: error in request_size %d handling\n", __func__, request_size);
				break;
			}
			tempaddr = client_ib_reg_mr_addr(ctx, &request_size, sizeof(int));
			if(atomic_flag)
			{
				remaining_size=sizeof(uint64_t);
				client_send_message_sge_UD(ctx, target_node, MSG_GET_REMOTE_ATOMIC_OPERATION, (void *)tempaddr, sizeof(int), (uint64_t)ret_mr, (uint64_t)&wait_send_reply_id, LOW_PRIORITY);
			}
			else
			{
				client_send_message_sge_UD(ctx, target_node, MSG_GET_REMOTEMR, (void *)tempaddr, sizeof(int), (uint64_t)ret_mr, (uint64_t)&wait_send_reply_id, LOW_PRIORITY);
			}
			while(wait_send_reply_id==SEND_REPLY_WAIT)
				cpu_relax();
			ret_mr_list[i] = ret_mr;
			remaining_size = remaining_size - LITE_MEMORY_BLOCK; 
		}
	}
	else//local allocation
	{
		void *addr;
		for(i=0;i<required_mr_num;i++)
		{
			request_size = MIN(remaining_size, LITE_MEMORY_BLOCK);
			addr = client_alloc_memory_for_mr(request_size*sizeof(char));
			if(atomic_flag)
			{
				request_size = sizeof(uint64_t);
				ret_mr = client_ib_reg_mr(ctx, addr, request_size, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_ATOMIC);
			}
			else
				ret_mr = client_ib_reg_mr(ctx, addr, request_size, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ);	
			ret_mr_list[i] = ret_mr;
			remaining_size = remaining_size - LITE_MEMORY_BLOCK; 
		}
	}
	tmp_lmr = atomic_add_return(1, &ctx->lmr_inc);
	//printk(KERN_CRIT "%s: lmr %d required_mr_num %d, roundupsize %d\n", __func__, tmp_lmr, required_mr_num, roundup_size);
	if(atomic_flag)
	{
		client_create_metadata_by_lmr(ctx, tmp_lmr, ret_mr_list, 1, target_node, sizeof(uint64_t), (MR_READ_FLAG | MR_WRITE_FLAG | MR_SHARE_FLAG | MR_ADMIN_FLAG | MR_ATOMIC_FLAG), 0, password);
	}
	else
		client_create_metadata_by_lmr(ctx, tmp_lmr, ret_mr_list, required_mr_num, target_node, roundup_size, (MR_READ_FLAG | MR_WRITE_FLAG | MR_SHARE_FLAG | MR_ADMIN_FLAG), 0, password);
	//printk(KERN_CRIT "%s: lmr %d finish\n", __func__, tmp_lmr);
	
	return tmp_lmr;
}
EXPORT_SYMBOL(liteapi_alloc_remote_mem);


/**
 * liteapi_query_port - get the metadata information for RPC request
 * must be performed before issueing a RPC request
 * @target_node: target node id
 * @designed_port: target port
 * @requery_flag: if the metadata is already in local cache, query again?
 */
inline int liteapi_query_port(int target_node, int designed_port, int requery_flag)
{	
	ltc *ctx = LITE_ctx;
	return client_query_port(ctx, target_node, designed_port, requery_flag);
}
EXPORT_SYMBOL(liteapi_query_port);


uint64_t liteapi_deregister_mr(uint64_t lmr)
{
	struct lmr_info *mr_addr;
	struct hash_asyio_key *mr_ptr;
	int i;


	int max_number_of_target = 8;
	int real_number_of_target = 0;
	int *target_array=kmalloc(sizeof(int)*max_number_of_target, GFP_KERNEL);
	struct atomic_struct *temp_ato = kmalloc(sizeof(struct atomic_struct)*max_number_of_target, GFP_KERNEL);
	struct max_reply_msg *reply = kmalloc(sizeof(struct max_reply_msg)*max_number_of_target, GFP_KERNEL);
	struct mr_request_form ret_form; 


	mr_ptr = lmr_to_mr_metadata(lmr);
	if(!mr_ptr)
		return MR_ASK_REFUSE;
	if(!(mr_ptr->permission & MR_ADMIN_FLAG))
		return MR_ASK_REFUSE;
	mr_addr = mr_ptr->datalist[0];
	if(!mr_addr)
		return MR_ASK_UNKNOWN;

	
	/*for(i=find_next_bit(mr_ptr->askmr_bitmap, MAX_NODE, 0);i<MAX_NODE;)
	{
		memset(&ret_form, 0, sizeof(struct mr_request_form));
		memcpy(&ret_form.request_mr, mr_addr, sizeof(struct lmr_info));
		ret_form.op_code = OP_REMOTE_DEREGISTER;
		printk(KERN_CRIT "deregister send to %d\n", i);
		liteapi_send_reply_type(i, (char *)&ret_form, sizeof(struct mr_request_form), (char *)&ret, MSG_MR_REQUEST);
		clear_bit(i, mr_ptr->askmr_bitmap);
		i=find_next_bit(mr_ptr->askmr_bitmap, MAX_NODE, i);
	}*/			
	for(i=find_next_bit(mr_ptr->askmr_bitmap, MAX_NODE, 0);i<MAX_NODE;)
	{
		target_array[real_number_of_target]=i;
		clear_bit(i, mr_ptr->askmr_bitmap);
		real_number_of_target++;
		i=find_next_bit(mr_ptr->askmr_bitmap, MAX_NODE, i);
	}		
	memset(&ret_form, 0, sizeof(struct mr_request_form));
	memcpy(&ret_form.request_mr, mr_addr, sizeof(struct lmr_info));
	ret_form.op_code = OP_REMOTE_DEREGISTER;
	for(i=0;i<real_number_of_target;i++)
	{
		temp_ato[i].vaddr=&ret_form;
		temp_ato[i].len=sizeof(struct mr_request_form);
	}	
	
	//liteapi_multi_send_reply_type(real_number_of_target, target_array, temp_ato, reply, MSG_MR_REQUEST);
	//It was liteapi_multi_send_reply
	for(i=0;i<real_number_of_target;i++)
	{
		liteapi_send_reply_type(target_array[i], temp_ato[i].vaddr, temp_ato[i].len, (char *)&reply[i], MSG_MR_REQUEST);
	}
	return 0;
}
EXPORT_SYMBOL(liteapi_deregister_mr);


/**
 * liteapi_umap_lmr - remove lmr from a local map table
 * @lite_handler: lite_handler behind the targetted LMR
 * This function would support password as other operations in later version
 */
int liteapi_umap_lmr(uint64_t lmr)
{
	struct hash_asyio_key *entry;
        return 0;
	entry = lmr_to_mr_metadata(lmr);
	if(!entry)
		return MR_ASK_UNKNOWN; 
	//spin_lock(&(ASYIO_HASHTABLE_LOCK[entry->hash_key]));
	spin_lock(&umap_lmr_lock);
	hash_del(&entry->hlist);
	//spin_unlock(&(ASYIO_HASHTABLE_LOCK[entry->hash_key]));
	spin_unlock(&umap_lmr_lock);
	kmem_cache_free(lmr_metadata_cache, entry);
	//printk(KERN_CRIT "umap %d\n", lmr);
	return MR_ASK_SUCCESS;
}
EXPORT_SYMBOL(liteapi_umap_lmr);

/**
 * liteapi_ask_mr - ask remote node for a LMR info (lite_map)
 * @memory_space_owner_node: master node id
 * @identifier: name/id of the respected LMR
 * @permission: the level of granted permission
 * @password: the pin code for accessing this LMR (if request is granted)
 */
uint64_t liteapi_ask_mr(int memory_space_owner_node, uint64_t identifier, uint64_t permission, int password) //This api need to be re-implemented, especially in the receiving side (poll-cq) for the asyIO record
{	
	struct ask_mr_form input_mr_form;
	uintptr_t tempaddr;
	int priority = LOW_PRIORITY;
	int wait_send_reply_id;
	
	ltc *ctx = LITE_ctx;

	struct ask_mr_reply_form reply_mr_form;

	input_mr_form.identifier = identifier;
	input_mr_form.permission = permission;
	
	wait_send_reply_id = SEND_REPLY_WAIT;

	if(memory_space_owner_node!=ctx->node_id)//remote request
	{
		tempaddr = client_ib_reg_mr_addr(ctx, &input_mr_form, sizeof(struct ask_mr_form));
		client_send_message_sge_UD(ctx, memory_space_owner_node, MSG_ASK_MR_1, (void *)tempaddr, sizeof(struct ask_mr_form), (uint64_t)&reply_mr_form, (uint64_t)&wait_send_reply_id, priority);
	}
	else
	{
		client_send_message_local(ctx, memory_space_owner_node, MSG_ASK_MR_1, &input_mr_form, sizeof(struct ask_mr_form), (uint64_t)&reply_mr_form, (uint64_t)&wait_send_reply_id, priority);
	}
	while(wait_send_reply_id==SEND_REPLY_WAIT)
		schedule();
	if(reply_mr_form.op_code == MR_ASK_SUCCESS)
	{
		uint64_t ret_key;
		struct lmr_info *ret_mr;
		struct lmr_info **ret_mr_list;
		int ret;
		int i;
		ret_mr_list = (struct lmr_info **)kmalloc(sizeof(struct lmr_info *) * reply_mr_form.list_length, GFP_KERNEL);
		for(i=0;i<reply_mr_form.list_length;i++)
		{
			ret_mr = client_alloc_lmr_info_buf();
			memcpy(ret_mr, &reply_mr_form.reply_mr[i], sizeof(struct lmr_info));
			ret_mr_list[i]=ret_mr;
		}
		ret_key = atomic_add_return(1, &ctx->lmr_inc);
		
		ret = client_create_metadata_by_lmr(ctx, ret_key, ret_mr_list, reply_mr_form.list_length, reply_mr_form.node_id, reply_mr_form.total_length, reply_mr_form.permission, 0, password);
		kfree(ret_mr_list);
		return ret_key;
	}
	printk(KERN_CRIT "[%s] FAIL in askmr node %d id %lu\n", __func__, memory_space_owner_node, (unsigned long)identifier);
	return reply_mr_form.op_code;

}
EXPORT_SYMBOL(liteapi_ask_mr);

/**
 * liteapi_create_lock - create a lock for future lock operations
 * @target_node: target node id (to hold the lock)
 * @output_lock: the address to keep lock
 */
int liteapi_create_lock(int target_node, void *output_lock)
{
	int wait_send_reply_id;
	uintptr_t tempaddr;
	char *msg = kmalloc(sizeof(char)*8, GFP_KERNEL);
	ltc *ctx = LITE_ctx;
	remote_spinlock_t *tmp;
	tmp = output_lock;
	if(target_node==SERVER_ID)
	{
		printk(KERN_CRIT "%s:[error] server can't process this request: %d\n", __func__, target_node);
		return 1;
	}
	wait_send_reply_id = SEND_REPLY_WAIT;	
	
	if(target_node!=ctx->node_id)
	{
		tempaddr = client_ib_reg_mr_addr(ctx, msg, 8);
		client_send_message_sge_UD(ctx, target_node, MSG_CREATE_LOCK, (void *)tempaddr, 8, (uint64_t)output_lock, (uint64_t)&wait_send_reply_id, KEY_PRIORITY);
	}
	else
	{
		client_send_message_local(ctx, target_node, MSG_CREATE_LOCK, (void *)msg, 8, (uint64_t)output_lock, (uint64_t)&wait_send_reply_id, KEY_PRIORITY);
	}
	
	while(wait_send_reply_id==SEND_REPLY_WAIT)
		cpu_relax();
	return tmp->lock_num;
}
EXPORT_SYMBOL(liteapi_create_lock);

/**
 * liteapi_ask_lock - ask a lock from a remote node
 * @target_node: target node id (to hold the lock)
 * @target_num: the id of a specific lock
 * @output_lock: address of lock
 */
int liteapi_ask_lock(int target_node, int target_num, void *output_lock)
{
	int wait_send_reply_id;
	uintptr_t tempaddr;
	ltc *ctx = LITE_ctx;
	remote_spinlock_t *tmp;
	tmp = output_lock;
	if(target_node==SERVER_ID)
	{
		printk(KERN_CRIT "%s:[error] server can't process this request: %d\n", __func__, target_node);
		return 1;
	}
	wait_send_reply_id = SEND_REPLY_WAIT;
	if(target_node != ctx->node_id)
	{
		tempaddr = client_ib_reg_mr_addr(ctx, &target_num, sizeof(int));
		client_send_message_sge_UD(ctx, target_node, MSG_ASK_LOCK, (void *)tempaddr, sizeof(int), (uint64_t)output_lock, (uint64_t)&wait_send_reply_id, KEY_PRIORITY);
	}
	else
	{
		client_send_message_local(ctx, target_node, MSG_ASK_LOCK, (void *)&target_num, sizeof(int), (uint64_t)output_lock, (uint64_t)&wait_send_reply_id, KEY_PRIORITY);
	}
	while(wait_send_reply_id==SEND_REPLY_WAIT)
        {
		cpu_relax();
        }
        if(tmp->lock_num != target_num)
	{
		printk(KERN_CRIT "%s: ask node %d with %d doesn't match ret %d\n", __func__, target_node, target_num, tmp->lock_num);
	}
	return tmp->lock_num;
}
EXPORT_SYMBOL(liteapi_ask_lock);

/**
 * liteapi_lock - lock
 * @input_void_key: input lock
 */
int liteapi_lock(void *input_void_key)
{
	uint64_t ret = 0;
	int connection_id;
	remote_spinlock_t *input_key = input_void_key;
	int target_node = input_key->lock_mr.node_id;
	ltc *ctx = LITE_ctx;
	if(input_key->ticket_num!=LOCK_AVAILABLE)
	{
		printk(KERN_CRIT "%s: can't relock a lock with ticket-%llu which is originally used\n", __func__, input_key->ticket_num);
		return SEND_REPLY_FAIL;
	}

	if(target_node != ctx->node_id)//regular usage through remote accessing
	{
		connection_id = client_get_connection_by_atomic_number(ctx, target_node, KEY_PRIORITY);
		client_fetch_and_add(ctx, connection_id, &input_key->lock_mr, &ret, 1);
		input_key->ticket_num = ret + 1;//Return value is the old value, therefore, LITE needs to add 1
		if(input_key->ticket_num==LOCK_GET_LOCK)
		{
			//printk(KERN_CRIT "%s: tic-%llu get lock\n", __func__, input_key->ticket_num);
		}
		else
		{
			int wait_send_reply_id;
			uintptr_t tempaddr;
			struct lite_lock_reserve_form reserve_form;
			int ret_num;
			//printk(KERN_CRIT "%s: tic-%llu send to lock\n", __func__, input_key->ticket_num);
			
			reserve_form.lock_num = input_key->lock_num;
			reserve_form.ticket_num = input_key->ticket_num;
			
			wait_send_reply_id = SEND_REPLY_WAIT;
			tempaddr = client_ib_reg_mr_addr(ctx, &reserve_form, sizeof(struct lite_lock_reserve_form));
			client_send_message_sge_UD(ctx, input_key->lock_mr.node_id, MSG_RESERVE_LOCK, (void *)tempaddr, sizeof(struct lite_lock_reserve_form), (uint64_t)&ret_num, (uint64_t)&wait_send_reply_id, KEY_PRIORITY);	
			while(wait_send_reply_id==SEND_REPLY_WAIT)
				schedule();
			//printk(KERN_CRIT "%s: tic-%llu get lock after retry\n", __func__, input_key->ticket_num);
		}
	}
	else
	{
		client_fetch_and_add_loopback(ctx, &input_key->lock_mr, &ret, 1);
		input_key->ticket_num = ret + 1;//Return value is the old value, therefore, LITE needs to add 1
		if(input_key->ticket_num==LOCK_GET_LOCK)
		{
			//printk(KERN_CRIT "%s: tic-%llu get lock\n", __func__, input_key->ticket_num);
		}
		else
		{
			int wait_send_reply_id;
			struct lite_lock_reserve_form reserve_form;
			int ret_num;
			//printk(KERN_CRIT "%s: tic-%llu send to lock\n", __func__, input_key->ticket_num);
			
			reserve_form.lock_num = input_key->lock_num;
			reserve_form.ticket_num = input_key->ticket_num;
			
			wait_send_reply_id = SEND_REPLY_WAIT;
			client_send_message_local(ctx, input_key->lock_mr.node_id, MSG_RESERVE_LOCK, (void *)&reserve_form, sizeof(struct lite_lock_reserve_form), (uint64_t)&ret_num, (uint64_t)&wait_send_reply_id, KEY_PRIORITY);	
			while(wait_send_reply_id==SEND_REPLY_WAIT)
				schedule();
		}
	}

	return ret;
}
EXPORT_SYMBOL(liteapi_lock);

/**
 * liteapi_unlock - unlock
 * @input_void_key: input lock
 */
int liteapi_unlock(void *input_void_key)
{
	uint64_t ret=0;
	remote_spinlock_t *input_key = input_void_key;
	int connection_id;
	int target_node = input_key->lock_mr.node_id;
	int local_flag = 0;
	ltc *ctx = LITE_ctx;
	if(input_key->ticket_num==LOCK_AVAILABLE)
	{
		//printk(KERN_CRIT "%s: can't unlock a lock without owning lock ticket-%llu\n", __func__, input_key->ticket_num);
		return SEND_REPLY_FAIL;
	}
	//printk(KERN_CRIT "%s: start doing unlock with ticket-%d\n", __func__, input_key->ticket_num);
	if(target_node == ctx->node_id)
		local_flag = 1;
	if(!local_flag)
	{
		connection_id = client_get_connection_by_atomic_number(ctx, target_node, KEY_PRIORITY);
		client_compare_swp(ctx, connection_id, &input_key->lock_mr, &ret, input_key->ticket_num, LOCK_AVAILABLE);
	}
	else
	{
		client_compare_swp_loopback(ctx, &input_key->lock_mr, &ret, input_key->ticket_num, LOCK_AVAILABLE);
	}
	//Original data is written into ret
	if(ret==input_key->ticket_num)//no new incoming users locked the lock
	{
		//printk(KERN_CRIT "%s: release lock ticket-%llu ret-%llu\n", __func__, input_key->ticket_num, ret);
	}
	else
	{
		//In this function, reserve_form should be modified into pointer style since this is not a send-reply call.
		//If this request is in local, the case that this function is returned before the waiting_schedule doesn't read the data
		uintptr_t tempaddr;
		struct lite_lock_reserve_form *reserve_form = kmalloc(sizeof(struct lite_lock_reserve_form), GFP_KERNEL);
		
		reserve_form->lock_num = input_key->lock_num;
		reserve_form->ticket_num = input_key->ticket_num;
		
		if(!local_flag)
		{
			tempaddr = client_ib_reg_mr_addr(ctx, reserve_form, sizeof(struct lite_lock_reserve_form));
			client_send_message_sge_UD(ctx, input_key->lock_mr.node_id, MSG_UNLOCK, (void *)tempaddr, sizeof(struct lite_lock_reserve_form), 0, 0, KEY_PRIORITY);
			kfree(reserve_form);
		}
		else
			client_send_message_local(ctx, input_key->lock_mr.node_id, MSG_UNLOCK, reserve_form, sizeof(struct lite_lock_reserve_form), 0, 0, KEY_PRIORITY);	
		//printk(KERN_CRIT "%s: release lock through message ticket-%llu ret-%llu\n", __func__, input_key->ticket_num, ret);
	}
	input_key->ticket_num = 0;
	return 0;
}
EXPORT_SYMBOL(liteapi_unlock);

void liteapi_free_recv_buf(void *input_buf)
{
	//printk(KERN_CRIT "IB freeing post_receive_cache vaddr %p\n", input_buf);
	//kmem_cache_free(post_receive_cache, input_buf);
	//client_free_recv_buf(input_buf);
	//kmem_cache_free(post_receive_cache, input_buf);
}
EXPORT_SYMBOL(liteapi_free_recv_buf);

inline void get_cycle_start(void)
{
	cycle_start = get_cycles();
}

void get_cycle_end(void)
{
	cycle_end = get_cycles();
	test_printk(KERN_ALERT "inner run for %llu\n", cycle_end-cycle_start);
}

int liteapi_reg_send_handler(int (*input_funptr)(char *addr, uint32_t size, int sender_id))
{
	ltc *ctx = LITE_ctx;
	ctx->send_handler = input_funptr;
	return 0;
}
EXPORT_SYMBOL(liteapi_reg_send_handler);

int liteapi_reg_send_reply_handler(int (*input_funptr)(char *input_addr, uint32_t input_size, char *output_addr, uint32_t *output_size, int sender_id))
{
	ltc *ctx = LITE_ctx;
	ctx->send_reply_handler = input_funptr;
	return 0;
}
EXPORT_SYMBOL(liteapi_reg_send_reply_handler);

int liteapi_reg_send_reply_opt_handler(int (*input_funptr)(char *input_addr, uint32_t input_size, void **output_addr, uint32_t *output_size, int sender_id))
{
	ltc *ctx = LITE_ctx;
	ctx->send_reply_opt_handler = input_funptr;
	return 0;
}
EXPORT_SYMBOL(liteapi_reg_send_reply_opt_handler);

int liteapi_reg_atomic_send_handler(int (*input_funptr)(struct atomic_struct *input_list, uint32_t length, char *output_buf, uint32_t *output_size, int sender_id))
{
	ltc *ctx = LITE_ctx;
	ctx->atomic_send_handler = input_funptr;
	return 0;
}
EXPORT_SYMBOL(liteapi_reg_atomic_send_handler);

int liteapi_reg_atomic_single_send_handler(int (*input_funptr)(struct atomic_struct *input_list, uint32_t length, int sender_id))
{
	ltc *ctx = LITE_ctx;
	ctx->atomic_single_send_handler = input_funptr;
	return 0;
}
EXPORT_SYMBOL(liteapi_reg_atomic_single_send_handler);

int liteapi_reg_ask_mr_handler(int (*input_funptr)(struct ask_mr_form *ask_form, uint32_t source_id, uint64_t *litekey_addr, uint64_t *permission))
{
	ltc *ctx = LITE_ctx;
	ctx->ask_mr_handler = input_funptr;
	return 0;
}
EXPORT_SYMBOL(liteapi_reg_ask_mr_handler);

int liteapi_num_connected_nodes(void)
{
	if(!LITE_ctx)
	{	
		printk(KERN_CRIT "%s: using LITE ctx directly since ctx is NULL\n", __func__);
		return atomic_read(&LITE_ctx->num_alive_nodes);
	}
	return atomic_read(&LITE_ctx->num_alive_nodes);
}
EXPORT_SYMBOL(liteapi_num_connected_nodes);

/**
 * liteapi_get_node_id - get the id of current node
 * return: node id
 */
inline int liteapi_get_node_id(void)
{
	ltc *ctx;
	if(LITE_ctx)
	{
		ctx = LITE_ctx;
		return ctx->node_id;
	}
	return 0;
}
EXPORT_SYMBOL(liteapi_get_node_id);

inline ltc *liteapi_get_ctx(void)
{
        if(LITE_ctx)
                return LITE_ctx;
        return 0;
}
EXPORT_SYMBOL(liteapi_get_ctx);

/**
 * liteapi_get_total_node - get the total number of nodes in the whole LITE cluster
 * return: number of node
 */
inline int liteapi_get_total_node(void)
{
	ltc *ctx;
	if(LITE_ctx)
	{
		ctx = LITE_ctx;
		return atomic_read(&ctx->num_alive_nodes);
	}
	return 0;
}
EXPORT_SYMBOL(liteapi_get_total_node);

/**
 * liteapi_alloc_continuous_memory - alloc contiguous memory from mmap
 * @vaddr: input address
 * @size: request size
 */
inline int liteapi_alloc_continuous_memory(unsigned long long vaddr, unsigned long size)
{
	ltc *ctx = LITE_ctx;
	return client_alloc_continuous_memory(ctx, vaddr, size);
}
EXPORT_SYMBOL(liteapi_alloc_continuous_memory);

/**
 * liteapi_establish_conn: establish a connection to a remote cluster manager
 * @servername: ipv4 address in string form
 * @eth_port: respected remote ethernet port
 * @ib_port: local infiniband device port
 */
int liteapi_establish_conn(char *servername, int eth_port, int ib_port)
{
	ltc *ctx;
	
	printk(KERN_CRIT "Start calling rc_internal to create LITE based on %p\n", liteapi_dev);
	printk(KERN_CRIT "Server:%s eth port:%d ib port:%d\n", servername, eth_port, ib_port);
	
	ctx = client_establish_conn(liteapi_dev, servername, eth_port, ib_port);
	
	if(!ctx)
	{
		printk(KERN_ALERT "%s: ctx %p fail to init_interface \n", __func__, (void *)ctx);
		return 0;	
	}

	spin_lock_init(&umap_lmr_lock);
	LITE_ctx = ctx;
	
	ctx->send_handler = handle_send;
	ctx->send_reply_handler = handle_send_reply;
	ctx->atomic_send_handler = handle_atomic_send;
	ctx->send_reply_opt_handler = handle_send_reply_opt;
	ctx->ask_mr_handler = handle_ask_mr;


	printk(KERN_ALERT "%s: return before establish connection with NODE_ID: %d\n", __func__, ctx->node_id);
	printk(KERN_CRIT "Pass all possible test and return\n");
	/*char temp_test[36];
	uintptr_t tempaddr;
	sprintf(temp_test, "test from client %d\n", ctx->node_id);
	tempaddr = client_ib_reg_mr_addr(ctx, temp_test, 36);
	client_send_message_sge_UD(ctx, 0, MSG_CLIENT_SEND, tempaddr, strlen(temp_test), 0, 0, 0);*/
	return ctx->node_id;
}
EXPORT_SYMBOL(liteapi_establish_conn);

static int __init ibv_init_module(void)
{
	int ret;

	test_printk(KERN_CRIT "installing ibv-API module\n");

	BUILD_BUG_ON(FIELD_SIZEOF(struct ib_wc, wr_id) < sizeof(void *));

	ret = class_register(&ibv_class);
	if (ret) {
		pr_err("couldn't register class ibv\n");
		return ret;
	}
	ret = ib_register_client(&ibv_client);
	if (ret) {
		pr_err("couldn't register IB client\n");
		class_unregister(&ibv_class);
		return ret;
	}

	atomic_set(&global_reqid, 0);
	//liteapi_establish_conn("wuklab13", 1, 10);
	
	//register syscall
	
	import_lite_hooks.lite_alloc_remote = liteapi_alloc_remote_mem;
	import_lite_hooks.lite_remote_memset = liteapi_remote_memset;
	import_lite_hooks.lite_fetch_add = liteapi_rdma_fetch_and_add;
	
	//import_lite_hooks.lite_rdma_synwrite = liteapi_rdma_synwrite_offset;
	//import_lite_hooks.lite_rdma_read = liteapi_rdma_asyread_offset;
	import_lite_hooks.lite_rdma_synwrite = liteapi_rdma_write_offset_userspace;
	import_lite_hooks.lite_rdma_read = liteapi_rdma_read_offset_userspace;
	
	import_lite_hooks.lite_rdma_asywrite = liteapi_rdma_asywrite_offset;
	import_lite_hooks.lite_ask_lmr = liteapi_ask_mr;
	import_lite_hooks.lite_dist_barrier = liteapi_dist_barrier;
	import_lite_hooks.lite_add_ask_mr_table = liteapi_add_askmr_table;
	import_lite_hooks.lite_compare_swp = liteapi_rdma_compare_and_swp;
	import_lite_hooks.lite_umap_lmr = liteapi_umap_lmr;
	
	import_lite_hooks.lite_register_application = liteapi_register_application;
	import_lite_hooks.lite_unregister_application = liteapi_unregister_application;
	
	import_lite_hooks.lite_receive_message = liteapi_receive_message_userspace;
	import_lite_hooks.lite_send_reply_imm = liteapi_send_reply_imm_userspace;
	import_lite_hooks.lite_reply_message = liteapi_reply_message_userspace;
        import_lite_hooks.lite_reply_and_receive_message = liteapi_reply_and_receive_message_userspace;

	import_lite_hooks.lite_get_node_id = liteapi_get_node_id;
	import_lite_hooks.lite_get_total_node = liteapi_get_total_node;
	import_lite_hooks.lite_query_port = liteapi_query_port;
	import_lite_hooks.lite_alloc_continuous_memory = liteapi_alloc_continuous_memory;
	import_lite_hooks.lite_wrap_alloc_for_remote_access = liteapi_wrapup_alloc_for_remote_access;
	import_lite_hooks.lite_create_lock = liteapi_create_lock;
	import_lite_hooks.lite_ask_lock = liteapi_ask_lock;
	import_lite_hooks.lite_lock = liteapi_lock;
	import_lite_hooks.lite_unlock = liteapi_unlock;
        import_lite_hooks.lite_join = liteapi_establish_conn;
	register_lite_hooks(&import_lite_hooks);

	return 0;
}

static void __exit ibv_cleanup_module(void)
{
	unregister_lite_hooks();
	printk(KERN_INFO "Ready to remove module\n");
	client_cleanup_module();
	ib_unregister_client(&ibv_client);
	class_unregister(&ibv_class);
}


module_init(ibv_init_module);
module_exit(ibv_cleanup_module);

