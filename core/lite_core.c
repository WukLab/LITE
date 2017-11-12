#include "lite_core.h"
MODULE_AUTHOR("yiying, shinyeh");
MODULE_LICENSE("GPL");

enum ib_mtu client_mtu_to_enum(int mtu)
{
	switch (mtu) {
	case 256:  return IB_MTU_256;
	case 512:  return IB_MTU_512;
	case 1024: return IB_MTU_1024;
	case 2048: return IB_MTU_2048;
	case 4096: return IB_MTU_4096;
	default:   return -1;
	}
}

int                     is_roce = 0;
enum ib_mtu mtu;
int                     sl;
static int              page_size;
int                     rcnt, scnt;
int                     NODE_ID = -1;
struct client_data full_connect_data[MAX_CONNECTION];
struct client_data my_QPset[MAX_CONNECTION];
int                     ib_port = 1;
static struct task_struct **thread_poll_cq, *thread_handler, *thread_priority_handler;
struct task_struct *asyIO_handler;

struct kmem_cache *post_receive_cache;
struct kmem_cache *s_r_cache;
struct kmem_cache *header_cache;
struct kmem_cache *header_cache_UD;
struct kmem_cache *intermediate_cache;
struct kmem_cache *lmr_info_cache;
struct kmem_cache *lmr_metadata_cache;
EXPORT_SYMBOL(lmr_metadata_cache);

ktime_t lite_time_start, lite_time_end;
EXPORT_SYMBOL(lite_time_start);
EXPORT_SYMBOL(lite_time_end);

struct semaphore add_newnode_mutex;
spinlock_t connection_lock[MAX_CONNECTION];

//asy related cache
struct kmem_cache *asy_page_cache;
struct kmem_cache *asy_hash_page_key_cache;
//struct kmem_cache *asy_fence_list_entry_cache;

struct kmem_cache *app_reg_cache;

//imm related cache
struct kmem_cache *imm_message_metadata_cache;
struct kmem_cache *imm_header_from_cq_to_port_cache;
struct kmem_cache *imm_copy_userspace_buffer_cache;
struct kmem_cache *imm_wait_userspace_buffer_cache;

//lock related cache
struct kmem_cache *lock_queue_element_buffer_cache;


spinlock_t *wq_lock;
struct send_and_reply_format *request_list;

ltc **Connected_Ctx;
atomic_t Connected_LITE_Num;
ktime_t trace_start;
ktime_t trace_end;
long long trace_sum;
int trace_count=0;

#define HASH_TABLE_SIZE_BIT 16
#define ASY_MOVE_BIT 12

DEFINE_HASHTABLE(MR_HASHTABLE, HASH_TABLE_SIZE_BIT);
spinlock_t MR_HASHTABLE_LOCK[1<<HASH_TABLE_SIZE_BIT];

DEFINE_HASHTABLE(ASYIO_HASHTABLE, HASH_TABLE_SIZE_BIT);
EXPORT_SYMBOL(ASYIO_HASHTABLE);
spinlock_t ASYIO_HASHTABLE_LOCK[1<<HASH_TABLE_SIZE_BIT];

DEFINE_HASHTABLE(ASYIO_PAGE_HASHTABLE, HASH_TABLE_SIZE_BIT);
spinlock_t ASYIO_PAGE_HASHTABLE_LOCK[1<<HASH_TABLE_SIZE_BIT];

//EREP

DEFINE_HASHTABLE(LOCAL_MEMORYRING_PORT_HASHTABLE, HASH_TABLE_SIZE_BIT);
spinlock_t LOCAL_MEMORYRING_PORT_HASHTABLE_LOCK[1<<HASH_TABLE_SIZE_BIT];

DEFINE_HASHTABLE(REMOTE_MEMORYRING_PORT_HASHTABLE, HASH_TABLE_SIZE_BIT);
spinlock_t REMOTE_MEMORYRING_PORT_HASHTABLE_LOCK[1<<HASH_TABLE_SIZE_BIT];

//LOCK related

DEFINE_HASHTABLE(LOCK_QUEUE_HASHTABLE, HASH_TABLE_SIZE_BIT);
spinlock_t LOCK_QUEUE_HASHTABLE_LOCK[1<<HASH_TABLE_SIZE_BIT];

//add askmr table
DEFINE_HASHTABLE(ADD_ASKMR_TABLE_HASHTABLE, HASH_TABLE_SIZE_BIT);
spinlock_t ADD_ASKMR_TABLE_HASHTABLE_LOCK[1<<HASH_TABLE_SIZE_BIT];

ktime_t tt_start, tt_end;
EXPORT_SYMBOL(tt_start);
EXPORT_SYMBOL(tt_end);


/**
 * client_find_cq - this function takes a targetted cq and return the index of targetted cq
 * @ctx: LITE context
 * @tar_cq: target cq
 * return: index of target cq
 */
int client_find_cq(ltc *ctx, struct ib_cq *tar_cq)
{
	int i;
	if(ctx->cqUD == tar_cq)
	{
		return NUM_POLLING_THREADS;
	}
	for(i=0;i<NUM_POLLING_THREADS;i++)
	{
		if(ctx->cq[i]==tar_cq)
			return i;
	}

	return -1;
}

/**
 * client_block_until_cqevent - this function interacts with cq event to implement notify model
 * @ctx: LITE context
 * @tar_cq: target cq
 * return: index of target cq
 */
int client_block_until_cqevent(ltc *ctx, struct ib_cq *tar_cq)
{
	int i = client_find_cq(ctx, tar_cq);
	int ret;
	//ktime_t self_time;
	//self_time = ktime_get();
	if(i!=-1)
	{
		/*while(atomic_read(&ctx->cq_block[i])==0 && !kthread_should_stop())
			schedule();*/
	        while(atomic_read(&ctx->cq_block[i])<=0||!kthread_should_stop())
	        {
			ret = wait_event_interruptible_timeout(ctx->cq_block_queue[i], atomic_read(&ctx->cq_block[i])>0||kthread_should_stop(), msecs_to_jiffies(3000));
			if(ret)
				break;
		}
		atomic_dec(&ctx->cq_block[i]);
		return 0;
	}
	else
	{
		printk(KERN_ALERT "Could not find cq in blocker as %p and %d\n", tar_cq, i);
		return 1;
	}
	return 2;
}

void poll_cq(struct ib_cq *cq, void *cq_context)
{
        ltc *ctx;
        int j, i;
        for(j=0;j<MAX_LITE_NUM;j++)
        {
                ctx = Connected_Ctx[j];
                if(ctx)
                {
                	i = client_find_cq(ctx, cq);
	                if(i!=-1)
                	{
                		atomic_inc(&ctx->cq_block[i]);
                	        wake_up_interruptible(&ctx->cq_block_queue[i]);
				//printk(KERN_ALERT "%s wakeup %d %p\n", __func__, i, cq);
                		return;
                	}
                }
        }
	printk(KERN_ALERT "%s Error: Could not find cq in event caller as CQ: %p\n", __func__, cq);
	return;
}

/**
 * lite_get_pte - this function gets the table entries for input address
 * @mm: memory struct
 * @addr: input address
 */
static __always_inline pte_t *lite_get_pte(struct mm_struct *mm, unsigned long addr)
{
        pgd_t *pgd;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;
        pgd = pgd_offset(mm, addr);
        if (unlikely(pgd_none(*pgd)))
		return 0;//BUG();
        pud = pud_offset(pgd, addr);
        if (unlikely(pud_none(*pud)))
		return 0;//BUG();
        pmd = pmd_offset(pud, addr);
        if (unlikely(pmd_none(*pmd)))
		return 0;//BUG();
        pte = pte_offset_map(pmd, addr);
        if (unlikely(pte_none(*pte)))
                return 0;//BUG();
        return pte;
}

/**
 * lite_check_page_continuous - this function checks whether an address+size is continuous or not
 * @local_addr: input address
 * @size: request size
 * @answer: it will keep the physical address of local_addr if it's continuous
 */
int lite_check_page_continuous(void *local_addr, int size, unsigned long *answer) //20ns
{
	//unsigned long phys_addr_base;
	pte_t *pte;
	struct page *page;

	unsigned long ret_phys_addr;
	unsigned long test_phys_addr;
	void *test_addr;
	//if(size > 4096*4)
	//	return 0;
	
	pte = lite_get_pte(current->mm, (unsigned long)local_addr);
	if(!pte)
		return 0;
	page = pte_page(*pte);
	ret_phys_addr = page_to_phys(page) + (((uintptr_t)local_addr)&LITE_LINUX_PAGE_OFFSET);

	test_addr = local_addr + size - 1;
	pte = lite_get_pte(current->mm, (unsigned long)test_addr);
	if(!pte)
		return 0;
	page = pte_page(*pte);
	test_phys_addr = page_to_phys(page) + (((uintptr_t)test_addr)&LITE_LINUX_PAGE_OFFSET);

	if(test_phys_addr != ret_phys_addr + size - 1)//it means non-continuous
	{
		return 0;
	}
	*answer = ret_phys_addr;
	return 1;

	//unsigned long phys_addr = page_to_phys(page) + (((uintptr_t)local_addr)&LITE_LINUX_PAGE_OFFSET);

}
EXPORT_SYMBOL(lite_check_page_continuous);

/**
 * client_connect_lookback: connects two queue pairs to form a local loopback connections
 * @src_qp: source qp
 * @port: infiniband port
 * @mypsn: psn for connection
 * @mtu: mtu configuration
 * @sl: service level
 * @dest: destination qp metadata
 */
int client_connect_loopback(struct ib_qp *src_qp, int port, int my_psn, enum ib_mtu mtu, int sl, struct lite_dest *dest)
{
	struct ib_qp_attr attr = {
		.qp_state	= IB_QPS_RTR,
		.path_mtu	= mtu,
		.dest_qp_num	= dest->qpn,
		.rq_psn		= dest->psn,
		.max_dest_rd_atomic	= 10,
		.min_rnr_timer	= 12,
		.ah_attr	= {
			.dlid		= dest->lid,
			.sl		= sl,
			.src_path_bits	= 0,
			.port_num	= port
		}
	};
	if(SGID_INDEX != -1)
	{
                attr.ah_attr.ah_flags = 1;
                attr.ah_attr.grh.hop_limit = 1;
                //attr.ah_attr.grh.dgid = dest->gid;
		memcpy(&attr.ah_attr.grh.dgid, &dest->gid, sizeof(union ib_gid));
                attr.ah_attr.grh.sgid_index = SGID_INDEX;
	}
        
	printk(KERN_CRIT "%s: lid-%d qpn-%d psn-%d\n", __func__, dest->lid, dest->qpn, dest->psn);
	if(ib_modify_qp(src_qp, &attr, 
				IB_QP_STATE	|
				IB_QP_AV	|
				IB_QP_PATH_MTU	|
				IB_QP_DEST_QPN	|
				IB_QP_RQ_PSN	|
				IB_QP_MAX_DEST_RD_ATOMIC	|
				IB_QP_MIN_RNR_TIMER))
	{
		printk(KERN_CRIT "%s: Fail to modify QP to RTR at loopback qp\n", __func__);
		return 1;
	}


	attr.qp_state	= IB_QPS_RTS;
	attr.timeout	= 14;
	attr.retry_cnt	= 7;
	attr.rnr_retry	= 7;
	attr.sq_psn	= my_psn;
	attr.max_rd_atomic = 10; //was 1
	if(ib_modify_qp(src_qp, &attr,
				IB_QP_STATE	|
				IB_QP_TIMEOUT	|
				IB_QP_RETRY_CNT	|
				IB_QP_RNR_RETRY	|
				IB_QP_SQ_PSN	|
				IB_QP_MAX_QP_RD_ATOMIC))
	{
		printk(KERN_CRIT "%s: Fail to modify QP to RTS at loopback qp\n", __func__);
		return 2;
	}
	return 0;
}

/**
 * client_set_lookback: setup lookback queue pairs and connection
 * @ctx: lite context
 * @size: configuration inline size
 * @rx_depth: depth of QP and CQ
 * @port: infiniband port
 */
int client_setup_loopback_connections(ltc *ctx, int size, int rx_depth, int port)
{
	struct lite_dest loopback_in, loopback_out;
	spin_lock_init(&ctx->loopback_lock);
	ctx->loopback_cq = ib_create_cq((struct ib_device *)ctx->context, poll_cq, NULL, NULL, rx_depth*4+1, 0);
	if(!ctx->loopback_cq)
	{
		printk(KERN_ALERT "%s: Fail to create lookback_cq\n", __func__);
		return -1;
	}
	
	{
		struct ib_qp_attr attr;
                struct ib_qp_attr attr1;
		struct ib_qp_init_attr init_attr = {
			.send_cq = ctx->loopback_cq,
			.recv_cq = ctx->loopback_cq,
			.cap = {
				.max_send_wr = rx_depth + 2,
				.max_recv_wr = rx_depth,
				.max_send_sge = 32,
				.max_recv_sge = 32
			},
			.qp_type = IB_QPT_RC
		};

		ctx->loopback_in = ib_create_qp(ctx->pd, &init_attr);
		if(!ctx->loopback_in)
		{
			printk(KERN_ALERT "%s: Fail to create loopback in qp\n", __func__);
			return -2;
		}
		ib_query_qp(ctx->loopback_in, &attr, IB_QP_CAP, &init_attr);
		if(init_attr.cap.max_inline_data >= size)
		{
			ctx->send_flags |= IB_SEND_INLINE;
		}

                attr1.qp_state = IB_QPS_INIT;
                attr1.pkey_index = 0;
                attr1.port_num = port;
                attr1.qp_access_flags = IB_ACCESS_REMOTE_WRITE|IB_ACCESS_REMOTE_READ|IB_ACCESS_LOCAL_WRITE|IB_ACCESS_REMOTE_ATOMIC;
                attr1.path_mtu = LITE_MTU;
                attr1.retry_cnt = 7;
                attr1.rnr_retry = 7;

		if(ib_modify_qp(ctx->loopback_in, &attr1,
					IB_QP_STATE		|
					IB_QP_PKEY_INDEX	|
					IB_QP_PORT		|
					IB_QP_ACCESS_FLAGS))
		{
			printk(KERN_ALERT "%s: Fail to modify loopback_in\n", __func__);
			ib_destroy_qp(ctx->loopback_in);
			return -3;
		}
	}
	{
		struct ib_qp_attr attr, attr1;
		struct ib_qp_init_attr init_attr = {
			.send_cq = ctx->loopback_cq,
			.recv_cq = ctx->loopback_cq,
			.cap = {
				.max_send_wr = rx_depth + 2,
				.max_recv_wr = rx_depth,
				.max_send_sge = 32,
				.max_recv_sge = 32
			},
			.qp_type = IB_QPT_RC
		};

		ctx->loopback_out = ib_create_qp(ctx->pd, &init_attr);
		if(!ctx->loopback_out)
		{
			printk(KERN_ALERT "%s: Fail to create loopback_out qp\n", __func__);
			return -4;
		}
		ib_query_qp(ctx->loopback_out, &attr, IB_QP_CAP, &init_attr);
		if(init_attr.cap.max_inline_data >= size)
		{
			ctx->send_flags |= IB_SEND_INLINE;
		}

                attr1.qp_state = IB_QPS_INIT;
                attr1.pkey_index = 0;
                attr1.port_num = port;
                attr1.qp_access_flags = IB_ACCESS_REMOTE_WRITE|IB_ACCESS_REMOTE_READ|IB_ACCESS_LOCAL_WRITE|IB_ACCESS_REMOTE_ATOMIC;
                attr1.path_mtu = LITE_MTU;
                attr1.retry_cnt = 7;
                attr1.rnr_retry = 7;

		if(ib_modify_qp(ctx->loopback_out, &attr1,
					IB_QP_STATE		|
					IB_QP_PKEY_INDEX	|
					IB_QP_PORT		|
					IB_QP_ACCESS_FLAGS))
		{
			printk(KERN_ALERT "%s: Fail to modify loopback_out\n", __func__);
			ib_destroy_qp(ctx->loopback_out);
			return -5;
		}
	}
	memset(&loopback_in, 0, sizeof(struct lite_dest));
	loopback_in.lid = ctx->portinfo.lid;
	loopback_in.qpn = ctx->loopback_in->qp_num;
	loopback_in.psn = client_get_random_number() & 0xffffff;
	loopback_in.node_id = 0;
	memcpy(&loopback_in.gid, &ctx->gid, sizeof(union ib_gid));
	//gid_to_wire_gid(&loopback_in.gid, gid);
	memset(&loopback_out, 0, sizeof(struct lite_dest));
	loopback_out.lid = ctx->portinfo.lid;
	loopback_out.qpn = ctx->loopback_out->qp_num;
	loopback_out.psn = client_get_random_number() & 0xffffff;
	loopback_out.node_id = 0;
	memcpy(&loopback_out.gid, &ctx->gid, sizeof(union ib_gid));
	printk(KERN_CRIT "%s: lid-%d qpn-%d psn-%d\n", __func__, loopback_in.lid, loopback_in.qpn, loopback_in.psn);
	printk(KERN_CRIT "%s: lid-%d qpn-%d psn-%d\n", __func__, loopback_out.lid, loopback_out.qpn, loopback_out.psn);
	//gid_to_wire_gid(&loopback_out.gid, gid);
	//
	if(client_connect_loopback(ctx->loopback_in, port, loopback_in.psn, mtu, sl, &loopback_out))
	{
		printk(KERN_CRIT "%s: fail to connect loopback_in to loopback_out\n", __func__);
		return -6;
	}
	printk(KERN_CRIT "%s: connect loopback_in to loopback_out\n", __func__);
	if(client_connect_loopback(ctx->loopback_out, port, loopback_out.psn, mtu, sl, &loopback_in))
	{
		printk(KERN_CRIT "%s: fail to connect loopback_out to loopback_in\n", __func__);
		return -7;
	}
	printk(KERN_CRIT "%s: connect loopback_out to loopback_in\n", __func__);
	return 0;
}

/**
 * client_init_ctx: initialize the whole lite context
 * @size: configuration inline size
 * @rx_depth: depth of QP and CQ
 * @port: infiniband port
 * @ib_dev: infiniband device pointer
 */
ltc *client_init_ctx(int size, int rx_depth, int port, struct ib_device *ib_dev)
{
	int i;
	int num_connections = MAX_CONNECTION;
	ltc *ctx;


	ctx = (ltc*)kmalloc(sizeof(ltc), GFP_KERNEL);
	memset(ctx, 0, sizeof(ltc));
	if(!ctx)
	{
		printk(KERN_ALERT "FAIL to initialize ctx in client_init_ctx\n");
		return NULL;
	}
        ctx->ib_port = port;
	ctx->size = size;
	ctx->send_flags = IB_SEND_SIGNALED;
	ctx->rx_depth = rx_depth;
	ctx->num_connections = num_connections;
	ctx->num_node = MAX_NODE;
	ctx->num_parallel_connection = NUM_PARALLEL_CONNECTION;
	ctx->context = (struct ib_context *)ib_dev;

	
	if(!ctx->context)
	{
		printk(KERN_ALERT "Fail to initialize device / ctx->context\n");
		return NULL;
	}
	ctx->channel = NULL;
	ctx->pd = ib_alloc_pd(ib_dev);
	if(!ctx->pd)
	{
		printk(KERN_ALERT "Fail to initialize pd / ctx->pd\n");
		return NULL;
	}
	ctx->proc = ib_get_dma_mr(ctx->pd, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_ATOMIC);
	ctx->send_state = (enum s_state *)kmalloc(num_connections * sizeof(enum s_state), GFP_KERNEL);	
	ctx->recv_state = (enum r_state *)kmalloc(num_connections * sizeof(enum r_state), GFP_KERNEL);

	if(SGID_INDEX != -1)
	{
		if(ib_query_gid((struct ib_device *)ctx->context, ctx->ib_port, SGID_INDEX, &ctx->gid))
		{
			printk(KERN_ALERT "Fail to query gid\n");
			return NULL;
		}
	}

	//Customized part
	ctx->num_alive_connection = (atomic_t *)kmalloc(ctx->num_node*sizeof(atomic_t), GFP_KERNEL);
	atomic_set(&ctx->num_alive_nodes, 1);
	memset(ctx->num_alive_connection, 0, ctx->num_node*sizeof(atomic_t));
	for(i=0;i<ctx->num_node;i++)
		atomic_set(&ctx->num_alive_connection[i], 0);

	ctx->recv_num = (int *)kmalloc(ctx->num_connections*sizeof(int), GFP_KERNEL);
	memset(ctx->recv_num, 0, ctx->num_connections*sizeof(int));

	ctx->atomic_request_num = (atomic_t *)kmalloc(ctx->num_node*sizeof(atomic_t), GFP_KERNEL);
	memset(ctx->atomic_request_num, 0, ctx->num_node*sizeof(atomic_t));
	for(i=0;i<ctx->num_node;i++)
		atomic_set(&ctx->atomic_request_num[i], -1);

	/*ctx->atomic_request_num = (unsigned long *)kmalloc(ctx->num_node*sizeof(unsigned long), GFP_KERNEL);
	memset(ctx->atomic_request_num, 0, ctx->num_node*sizeof(unsigned long));
	for(i=0;i<ctx->num_node;i++)
		ctx->atomic_request_num[i]=0;*/

	ctx->atomic_request_num_high = (atomic_t *)kmalloc(ctx->num_node*sizeof(atomic_t), GFP_KERNEL);
	memset(ctx->atomic_request_num_high, 0, ctx->num_node*sizeof(atomic_t));
	for(i=0;i<ctx->num_node;i++)
		atomic_set(&ctx->atomic_request_num_high[i], -1);

	atomic_set(&ctx->parallel_thread_num,0);

	atomic_set(&ctx->alive_connection, 0);
	atomic_set(&ctx->num_completed_threads, 0);

	ctx->atomic_buffer = (struct atomic_struct **)kmalloc(num_connections * sizeof(struct atomic_struct *), GFP_KERNEL);
	ctx->atomic_buffer_total_length = (int *)kmalloc(num_connections * sizeof(int), GFP_KERNEL);
	for(i=0;i<num_connections;i++)
		ctx->atomic_buffer_total_length[i]=0;
	ctx->atomic_buffer_cur_length = (int *)kmalloc(num_connections * sizeof(int), GFP_KERNEL);
	for(i=0;i<num_connections;i++)
		ctx->atomic_buffer_cur_length[i]=-1;

	ctx->cq = (struct ib_cq **)kmalloc(NUM_POLLING_THREADS * sizeof(struct ib_cq *), GFP_KERNEL);
	for(i=0;i<NUM_POLLING_THREADS;i++)
	{
		ctx->cq[i]=ib_create_cq((struct ib_device *)ctx->context, poll_cq, NULL, NULL, rx_depth*4+1, 0);
		if(!ctx->cq[i])
		{
			printk(KERN_ALERT "Fail to create cq at %d/ ctx->cq\n", i);
			return NULL;
		}
	}
	ctx->cq_block = (atomic_t *)kmalloc((NUM_POLLING_THREADS+1)*sizeof(atomic_t), GFP_KERNEL);
	for(i=0;i<NUM_POLLING_THREADS+1;i++)
		atomic_set(&ctx->cq_block[i], 0);
	ctx->cq_block_queue = (wait_queue_head_t*)kmalloc((NUM_POLLING_THREADS+1)*sizeof(wait_queue_head_t), GFP_KERNEL);
	for(i=0;i<NUM_POLLING_THREADS+1;i++)
	        init_waitqueue_head(&ctx->cq_block_queue[i]);
	//ctx->cq = ib_create_cq((struct ib_device *)ctx->context, poll_cq, NULL, NULL, rx_depth*4+1, 0);
	//if(!ctx->cq)
	//{
	//	printk(KERN_ALERT "Fail to create cq / ctx->cq\n");
	//	return NULL;
	//}
	ctx->send_cq = (struct ib_cq **)kmalloc(num_connections * sizeof(struct ib_cq *), GFP_KERNEL);

	//congestion related things
	ctx->connection_congestion_status = (atomic_t *)kmalloc(num_connections * sizeof(atomic_t), GFP_KERNEL);
	for(i=0;i<num_connections;i++)
		atomic_set(&ctx->connection_congestion_status[i], CONGESTION_FREE);
	ctx->connection_timer_start = (ktime_t *)kmalloc(num_connections * sizeof(ktime_t), GFP_KERNEL);
	ctx->connection_timer_end = (ktime_t *)kmalloc(num_connections * sizeof(ktime_t), GFP_KERNEL);
	
	ctx->connection_count = (atomic_t *)kmalloc(num_connections * sizeof(atomic_t), GFP_KERNEL);
	for(i=0;i<num_connections;i++)
	{
		atomic_set(&ctx->connection_count[i], 0);
	}

	//atomic multicast send related things

	ctx->first_packet_header = kmalloc(sizeof(struct liteapi_header) * MAX_MULTICAST_HOP, GFP_KERNEL);
	ctx->other_packet_header = kmalloc(sizeof(struct liteapi_header) * MAX_MULTICAST_HOP * MAX_LENGTH_OF_ATOMIC, GFP_KERNEL);
	ctx->output_header_addr = kmalloc(sizeof(void *) * MAX_MULTICAST_HOP * MAX_LENGTH_OF_ATOMIC, GFP_KERNEL);
	ctx->mid_addr = kmalloc(sizeof(void *) * MAX_MULTICAST_HOP * MAX_LENGTH_OF_ATOMIC, GFP_KERNEL);
	ctx->first_header_addr = kmalloc(sizeof(void *) * MAX_MULTICAST_HOP, GFP_KERNEL);
	ctx->connection_id_array = kmalloc(sizeof(int) * MAX_MULTICAST_HOP, GFP_KERNEL);
	ctx->length_addr_array = kmalloc(sizeof(uintptr_t) * MAX_MULTICAST_HOP, GFP_KERNEL);

	//asyIO related design
	atomic_set(&ctx->asy_latest_job, 0);
	atomic_set(&ctx->asy_current_job, 0);
	//Initialize spin_lock
	ctx->asy_tmp_buffer = kmalloc(sizeof(char *) * RING_BUFFER_LENGTH, GFP_KERNEL);
	for(i=0;i<RING_BUFFER_LENGTH;i++)
		ctx->asy_tmp_buffer[i]=kmalloc(RING_BUFFER_MAXSIZE, GFP_KERNEL);
	ctx->asy_tmp_header = kmalloc(sizeof(struct asy_IO_header) * RING_BUFFER_LENGTH, GFP_KERNEL);
	memset(ctx->asy_tmp_header, 0, sizeof(struct asy_IO_header)* RING_BUFFER_LENGTH);
	atomic_set(&ctx->asy_fence_counter, 0);
	atomic_set(&ctx->mr_index_counter, 1);
	//initialize fence list
	//INIT_LIST_HEAD(&ctx->asy_fence_list);
	//INIT_LIST_HEAD(&ctx->asy_fence_list_ms);

	//barrier setup
	
	atomic_set(&ctx->dist_barrier_counter, 0);
        ctx->dist_barrier_idx = 0;
        for(i=0;i<MAX_NODE;i++)
                ctx->last_barrier_idx[i] = 0;

	//lmr setup
	atomic_set(&ctx->lmr_inc, 1024);

	//UD connection setup
	
	ctx->recv_numUD = 0;
	spin_lock_init(&ctx->connection_lockUD);
	ctx->ah = (struct ib_ah **)kmalloc(MAX_NODE * sizeof(struct ib_ah*), GFP_KERNEL);
	ctx->ah_attrUD = (struct client_ah_combined *)kmalloc(MAX_NODE * sizeof(struct client_ah_combined), GFP_KERNEL);
	ctx->cqUD = ib_create_cq((struct ib_device *)ctx->context, poll_cq, NULL, NULL, rx_depth*4+1, 0);
	if(!ctx->cqUD)
	{
		printk(KERN_ALERT "Fail to create cqUD\n");
		return NULL;
	}
	ctx->send_cqUD = ib_create_cq((struct ib_device *)ctx->context, poll_cq, NULL, NULL, rx_depth*4+2, 0);
	if(!ctx->send_cqUD)
	{
		printk(KERN_ALERT "Fail to create send_cqUD\n");
		return NULL;
	}
	{
		struct ib_qp_attr attr, attr1;
		struct ib_qp_init_attr init_attr = {
			.send_cq = ctx->send_cqUD,
			.recv_cq = ctx->cqUD,
			.cap = {
				.max_send_wr = rx_depth*4 + 2,
				.max_recv_wr = rx_depth*4,
				.max_send_sge = 32,
				.max_recv_sge = 32
			},
			.qp_type = IB_QPT_UD
		};

		ctx->qpUD = ib_create_qp(ctx->pd, &init_attr);
		if(!ctx->qpUD)
		{
			printk(KERN_ALERT "Fail to create qpUD\n");
			return NULL;
		}
		ib_query_qp(ctx->qpUD, &attr, IB_QP_CAP, &init_attr);
		if(init_attr.cap.max_inline_data >= size)
		{
			ctx->send_flags |= IB_SEND_INLINE;
		}

                attr1.qp_state = IB_QPS_INIT;
                attr1.pkey_index = 0;
                attr1.port_num = port;
                attr1.qkey = 0x336;

		if(ib_modify_qp(ctx->qpUD, &attr1,
					IB_QP_STATE		|
					IB_QP_PKEY_INDEX	|
					IB_QP_PORT		|
					IB_QP_QKEY))
		{
			printk(KERN_ALERT "Fail to modify qpUD\n");
			ib_destroy_qp(ctx->qpUD);
			return NULL;
		}
		printk(KERN_CRIT "UDqpn %d\n", ctx->qpUD->qp_num);
	}
	{
		struct ib_qp_attr attr = {
			.qp_state		= IB_QPS_RTR
		};

		if(ib_modify_qp(ctx->qpUD, &attr, IB_QP_STATE)) {
			printk(KERN_CRIT "Failed to modify UDQP to RTR\n");
			return NULL;
		}

		attr.qp_state	    = IB_QPS_RTS;
		attr.sq_psn	    = client_get_random_number() & 0xffffff;

		if (ib_modify_qp(ctx->qpUD, &attr,
				  IB_QP_STATE              |
				  IB_QP_SQ_PSN)) {
			printk(KERN_CRIT "Failed to modify UDQP to RTS\n");
			return NULL;
		}
	}
	
	//Finish UD
	//
	
	ctx->qp = (struct ib_qp **)kmalloc(num_connections * sizeof(struct ib_qp *), GFP_KERNEL);
	if(!ctx->qp)
	{
		printk(KERN_ALERT "Fail to create master qp / ctx->qp\n");
		return NULL;
	}

	//ctx->send_cq[0] = ib_create_cq((struct ib_device *)ctx->context, poll_cq, NULL, NULL, rx_depth*4+1, 0);
	for(i=0;i<num_connections;i++)
	{
		struct ib_qp_attr attr, attr1;
                struct ib_qp_init_attr init_attr;

		ctx->send_state[i] = SS_INIT;
		ctx->recv_state[i] = RS_INIT;

                #ifdef SHARE_POLL_CQ_MODEL 
		ctx->send_cq[i] = ctx->send_cq[0];
                #endif
                #ifdef NON_SHARE_POLL_CQ_MODEL
		ctx->send_cq[i] = ib_create_cq((struct ib_device *)ctx->context, poll_cq, NULL, NULL, rx_depth+1, 0);
		//ctx->send_cq[i] = ib_create_cq((struct ib_device *)ctx->context, poll_cq, NULL, NULL, 12000, 0);
                #endif
			init_attr.send_cq = ctx->send_cq[i];//ctx->cq
			//init_attr.recv_cq = ctx->cq;
			init_attr.recv_cq = ctx->cq[i%NUM_POLLING_THREADS];
			        init_attr.cap.max_send_wr = rx_depth + 2;
        			//init_attr.cap.max_send_wr = 12000;
	        	        init_attr.cap.max_recv_wr = rx_depth;
        			init_attr.cap.max_send_sge = 32;
        			init_attr.cap.max_recv_sge = 32;
			init_attr.qp_type = IB_QPT_RC;
			init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;

		ctx->qp[i] = ib_create_qp(ctx->pd, &init_attr);
		if(!ctx->qp[i])
		{
			printk(KERN_ALERT "Fail to create qp[%d]\n", i);
			return NULL;
		}
		ib_query_qp(ctx->qp[i], &attr, IB_QP_CAP, &init_attr);
		if(init_attr.cap.max_inline_data >= size)
		{
			ctx->send_flags |= IB_SEND_INLINE;
		}

                attr1.qp_state = IB_QPS_INIT;
                attr1.pkey_index = 0;
                attr1.port_num = port;
                attr1.qp_access_flags = IB_ACCESS_REMOTE_WRITE|IB_ACCESS_REMOTE_READ|IB_ACCESS_LOCAL_WRITE|IB_ACCESS_REMOTE_ATOMIC;
                attr1.path_mtu = LITE_MTU;
                attr1.retry_cnt = 7;
                attr1.rnr_retry = 7;
                
		if(ib_modify_qp(ctx->qp[i], &attr1,
					IB_QP_STATE		|
					IB_QP_PKEY_INDEX	|
					IB_QP_PORT		|
					IB_QP_ACCESS_FLAGS))
		{
			printk(KERN_ALERT "Fail to modify qp[%d]\n", i);
			ib_destroy_qp(ctx->qp[i]);
			return NULL;
		}
	}

	ctx->imm_store_semaphore = (void **)kmalloc(sizeof(void*)*IMM_NUM_OF_SEMAPHORE, GFP_KERNEL);
	ctx->imm_store_header = (struct imm_message_metadata *)kmalloc(sizeof(struct imm_message_metadata)*IMM_NUM_OF_SEMAPHORE, GFP_KERNEL);
	ctx->imm_store_semaphore_bitmap = kzalloc(sizeof(unsigned long) * BITS_TO_LONGS(IMM_NUM_OF_SEMAPHORE), GFP_KERNEL);
        atomic_set(&ctx->imm_store_semaphore_count, 0);
        ctx->imm_store_semaphore_lock = kmalloc(sizeof(spinlock_t)*IMM_NUM_OF_SEMAPHORE, GFP_KERNEL);
        for(i=0;i<IMM_NUM_OF_SEMAPHORE;i++)
        {
        	spin_lock_init(&ctx->imm_store_semaphore_lock[i]);
                ctx->imm_store_semaphore[i] = NULL;
        }

        ctx->imm_waitqueue_perport = (struct imm_header_from_cq_to_port **)kmalloc(sizeof(struct imm_header_from_cq_to_port *)*IMM_MAX_PORT, GFP_KERNEL);
	for(i=0;i<IMM_MAX_PORT;i++)
	{
                ctx->imm_waitqueue_perport[i] = (struct imm_header_from_cq_to_port *)kmalloc(sizeof(struct imm_header_from_cq_to_port)*IMM_ROUND_UP, GFP_KERNEL);
                ctx->imm_waitqueue_perport_count_recv[i]=0;
                ctx->imm_waitqueue_perport_count_poll[i]=0;
		init_waitqueue_head(&ctx->imm_receive_block_queue[i]);
		spin_lock_init(&ctx->imm_perport_lock[i]);
		spin_lock_init(&ctx->imm_waitqueue_perport_lock[i]);
		//atomic_set(&ctx->imm_perport_reg_num[i], -1);
		ctx->imm_perport_reg_num[i]=-1;
		
                INIT_LIST_HEAD(&(ctx->imm_wait_userspace_perport[i].list));
	}
	
	ctx->imm_store_block_queue = (wait_queue_head_t*)kmalloc((IMM_NUM_OF_SEMAPHORE)*sizeof(wait_queue_head_t), GFP_KERNEL);
	for(i=0;i<IMM_NUM_OF_SEMAPHORE;i++)
	        init_waitqueue_head(&ctx->imm_store_block_queue[i]);
	ctx->imm_store_semaphore_task = (struct task_struct **)kzalloc(sizeof(struct task_struct*)*IMM_NUM_OF_SEMAPHORE, GFP_KERNEL);
	
	//Lock related
	atomic_set(&ctx->lock_num, 0);
	ctx->lock_data = kzalloc(sizeof(struct lite_lock_form)*LITE_MAX_LOCK_NUM, GFP_KERNEL);
	
	//memory related
	atomic_set(&ctx->current_alloc_size, 0);
	
	//server_setup_loopback_connections(ib_dev, size, rx_depth, ib_port);
	//printk(KERN_ALERT "I am here for client_init_ctx\n");
	//
        
        //priority related
        atomic_set(&ctx->high_cur_num_write, 0);
        atomic_set(&ctx->low_cur_num_write, 0);
        atomic_set(&ctx->low_total_num_write, 0);
        atomic_set(&ctx->high_cur_num_read, 0);
        atomic_set(&ctx->low_cur_num_read, 0);
        atomic_set(&ctx->low_total_num_read, 0);
        atomic_set(&ctx->high_cur_num_sr, 0);
        atomic_set(&ctx->low_cur_num_sr, 0);
        atomic_set(&ctx->low_total_num_sr, 0);
	atomic_set(&ctx->slow_counter, 0);
	init_waitqueue_head(&ctx->priority_block_queue);
	
	return ctx;
}

/**
 * client_init_interface: initialize infiniband device interface
 * @port: infiniband port
 * @ib_dev: infiniband device pointer
 */
ltc *client_init_interface(int ib_port, struct ib_device *ib_dev)
{
	int	size = 4096;
	int	rx_depth = RECV_DEPTH;
	int 	x;
	int	ret;
	ltc *ctx;
	mtu = LITE_MTU;
	sl = 0;

	//srand48(time(NULL));
	page_size = 4096;
	x = rdma_port_get_link_layer(ib_dev, ib_port);
	rcnt = 0;
	scnt = 0;
	ctx = client_init_ctx(size, rx_depth, ib_port, ib_dev);
	if(!ctx)
	{
		printk(KERN_ALERT "Fail to do client_init_ctx\n");
		return 0;
	}

	ret = ib_query_port((struct ib_device *)ctx->context, ib_port, &ctx->portinfo);
	if(ret<0)
	{
		printk(KERN_ALERT "Fail to query port\n");
	}
	//do loopback connection
	client_setup_loopback_connections(ctx, 4096, rx_depth, ib_port);
	
	//test_printk(KERN_ALERT "I am here before return client_init_interface\n");
	return ctx;

}
EXPORT_SYMBOL(client_init_interface);

int client_get_random_number(void)
{
	int random_number;
	get_random_bytes(&random_number, sizeof(int));
	return random_number;
}
EXPORT_SYMBOL(client_get_random_number);

void client_gid_to_wire_gid(const union ib_gid *gid, char wgid[])
{
        int i;

        for (i = 0; i < 4; ++i)
        {
                sprintf(&wgid[i * 8], "%08x", htonl(*(uint32_t *)(gid->raw + i * 4)));
        }
}

void client_wire_gid_to_gid(const char *wgid, union ib_gid *gid)
{
        char tmp[9];
        uint32_t v32;
        int i;

        for (tmp[8] = 0, i = 0; i < 4; ++i) {
                memcpy(tmp, wgid + i * 8, 8);
                sscanf(tmp, "%x", &v32);
                *(uint32_t *)(&gid->raw[i * 4]) = ntohl(v32);
        }
}

int client_gen_msg(ltc *ctx, char *msg, int connection_id)
{
	char gid[33];
	struct lite_dest my_dest;
	my_dest.lid = ctx->portinfo.lid;
	/*if(ctx->portinfo.link_layer!= IB_LINK_LAYER_ETHERNET && !my_dest.lid)
	  {
	  test_printk("Could not get local connection_id %d\n", connection_id);
	  return 1;
	  }*/
	memset(&my_dest.gid, 0, sizeof(union ib_gid));
	my_dest.node_id = ctx->node_id;
	my_dest.qpn = ctx->qp[connection_id]->qp_num;
	my_dest.psn = client_get_random_number() & 0xffffff;
	if(SGID_INDEX != -1)
	{
        	ib_query_gid((struct ib_device *)ctx->context, ctx->ib_port, SGID_INDEX, &my_dest.gid);
	}
	client_gid_to_wire_gid(&my_dest.gid, gid);
	sprintf(msg, "%04x:%04x:%06x:%06x:%s", my_dest.node_id, my_dest.lid, my_dest.qpn,my_dest.psn, gid);
	return 0;
}

int client_msg_to_lite_dest(char *msg, struct lite_dest *rem_dest)
{
	char gid[33];
	sscanf(msg, "%x:%x:%x:%x:%s", &rem_dest->node_id, &rem_dest->lid, &rem_dest->qpn, &rem_dest->psn, gid);
	client_wire_gid_to_gid(gid, &rem_dest->gid);
	return 0;
}

inline uintptr_t client_ib_reg_mr_addr(ltc *ctx, void *addr, size_t length)
{
	#ifdef PHYSICAL_ALLOCATION
	return client_ib_reg_mr_phys_addr(ctx, (void *)virt_to_phys(addr), length);
	#endif
	#ifndef PHYSICAL_ALLOCATION
	return (uintptr_t)ib_dma_map_single((struct ib_device *)ctx->context, addr, length, DMA_BIDIRECTIONAL); 
	#endif
}
EXPORT_SYMBOL(client_ib_reg_mr_addr);

void client_ib_dereg_mr_addr(ltc *ctx, void *addr, size_t length)
{
	return ib_dma_unmap_single((struct ib_device *)ctx->context, (uint64_t)addr, length, DMA_BIDIRECTIONAL); 
	//return (uintptr_t)ib_dma_unmap_single((struct ib_device *)ctx->context, addr, length, DMA_BIDIRECTIONAL); 
}

uintptr_t client_ib_reg_mr_phys_addr(ltc *ctx, void *addr, size_t length)
{
	struct ib_device *ibd = (struct ib_device*)ctx->context;
	return (uintptr_t)phys_to_dma(ibd->dma_device, (phys_addr_t)addr);
}
EXPORT_SYMBOL(client_ib_reg_mr_phys_addr);

/**
 * client_ib_reg_mr: get the physical address of a input kernel virtual address
 * @ctx: lite context
 * @addr: input address
 * @length: request length
 * @access: permisison level
 */
struct lmr_info *client_ib_reg_mr(ltc *ctx, void *addr, size_t length, enum ib_access_flags access)
{
	struct lmr_info *ret;
	struct ib_mr *proc;
        proc = ctx->proc;

	//ret = (struct lmr_info *)kmem_cache_alloc(lmr_info_cache, GFP_KERNEL);
	ret = client_alloc_lmr_info_buf();
	//int connection_id = client_get_connection_by_atomic_number(ctx, target_node, LOW_PRIORITY);
	
	#ifdef PHYSICAL_ALLOCATION
	ret->addr = (void *)client_ib_reg_mr_phys_addr(ctx, (void *)virt_to_phys(addr), length);
	#endif
	#ifndef PHYSICAL_ALLOCATION
	ret->addr = (void *)ib_dma_map_single((struct ib_device *)ctx->context, addr, length, DMA_BIDIRECTIONAL); 
	#endif
	
	ret->length = length;
	ret->lkey = proc->lkey;
	ret->rkey = proc->rkey;
	ret->node_id = ctx->node_id;
	//test_printk(KERN_CRIT "length %d addr:%x lkey:%x rkey:%x\n", (int) length, (unsigned int)ret->addr, ret->lkey, ret->rkey);
	return ret;
}
EXPORT_SYMBOL(client_ib_reg_mr);

void header_cache_free(void *ptr)
{
	//printk(KERN_CRIT "free %x\n", ptr);
	kmem_cache_free(header_cache, ptr);
}

void header_cache_UD_free(void *ptr)
{
	//printk(KERN_CRIT "free %x\n", ptr);
	kmem_cache_free(header_cache_UD, ptr);
}

/**
 * client_post_receives_message: post message buffer for RC connections (null buffer, only takes imm message)
 * @ctx: lite context
 * @connection_id: target QP connection
 * @depth: how many message should be post received
 */
int client_post_receives_message(ltc *ctx, int connection_id, int depth)
{
	int i;
        for(i=0;i<depth;i++)
        {
                struct ib_recv_wr wr, *bad_wr = NULL;
                wr.wr_id = i + (connection_id << CONNECTION_ID_PUSH_BITS_BASED_ON_RECV_DEPTH);
                wr.next = NULL;
                wr.sg_list = NULL;
                wr.num_sge = 0;
                ib_post_recv(ctx->qp[connection_id], &wr, &bad_wr);
        }
	return depth;
}
EXPORT_SYMBOL(client_post_receives_message);

/**
 * client_post_receives_message: post message buffer for UD connections
 * @ctx: lite context
 * @depth: how many message should be post received
 */
int client_post_receives_message_UD(ltc *ctx, int depth)
{
	struct ib_recv_wr wr, *bad_wr = NULL;
	struct ib_sge sge[2];
	int i;
        //ktime_t start;
        //ktime_t end;
        //int ret;
	#ifdef LITE_GET_TIME
		struct timespec ts, te, diff;
		getnstimeofday(&ts);
	#endif
		for(i=0;i<depth;i++)
		{
			char *temp_addr, *temp_header_addr;
			uintptr_t mid_addr, mid_header_addr;
			struct liteapi_post_receive_intermediate_struct *p_r_i_struct;

			temp_addr = (char *)kmem_cache_alloc(post_receive_cache, GFP_KERNEL);
			temp_header_addr = (char *)kmem_cache_alloc(header_cache_UD, GFP_KERNEL);
			p_r_i_struct = (struct liteapi_post_receive_intermediate_struct *)kmem_cache_alloc(intermediate_cache, GFP_KERNEL);

			p_r_i_struct->header = (uintptr_t)temp_header_addr;
			p_r_i_struct->msg = (uintptr_t)temp_addr;

			mid_addr = client_ib_reg_mr_addr(ctx, temp_addr, POST_RECEIVE_CACHE_SIZE);
			mid_header_addr = client_ib_reg_mr_addr(ctx, temp_header_addr, sizeof(struct liteapi_header)+40);

			sge[0].addr = (uintptr_t)mid_header_addr;
			sge[0].length = sizeof(struct liteapi_header) + 40;
			sge[0].lkey = ctx->proc->lkey;

			sge[1].addr = (uintptr_t)mid_addr;
			sge[1].length = POST_RECEIVE_CACHE_SIZE;
			sge[1].lkey = ctx->proc->lkey;

			wr.wr_id = (uint64_t)p_r_i_struct;
			wr.next = NULL;
			wr.sg_list = sge;
			wr.num_sge = 2;

                        /*wr.wr_id = i;
                        wr.next = NULL;
                        wr.sg_list = NULL;
                        wr.num_sge = 0;*/

                        //start = ktime_get(); 
                        
			ib_post_recv(ctx->qpUD, &wr, &bad_wr);
                        //if(ret)
                        //        printk(KERN_CRIT "error\n");
                        //end = ktime_get();
                        //client_internal_stat(client_get_time_difference(start, end), LITE_STAT_ADD);
		}
                //printk(KERN_CRIT "%s: LITE_STAT post-receive %d bytes, %lld ns\n", __func__, POST_RECEIVE_CACHE_SIZE, client_internal_stat(0, LITE_STAT_CLEAR));
	#ifdef LITE_GET_TIME                                                                      
		getnstimeofday(&te);
		diff = timespec_sub(te,ts);
		printk("[%s] time %lu\n", __func__, diff.tv_nsec);
	#endif
	return depth;
}

/**
 * client_ktcp_recv: kernel space tcp connection - recv - for cluster intialization
 */
int client_ktcp_recv(struct socket *sock, unsigned char *buf, int len)
{
	struct msghdr msg;
	struct kvec iov;

	{
		if(sock->sk==NULL) return 0;

		iov.iov_base=buf;
		iov.iov_len=len;

		msg.msg_control=NULL;
		msg.msg_controllen=0;
		msg.msg_flags=0;
		msg.msg_name=NULL;
		msg.msg_namelen=0;
		msg.msg_iov=(struct iovec *)&iov;
		msg.msg_iovlen=1;
	}
	//printk(KERN_INFO "ktcp_recv.sock_recvmsg");
	//size=sock_recvmsg(sock,&msg,len,msg.msg_flags);
	kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len, 0);
	//printk(KERN_INFO "ktcp_recved");tyh-
	//printk("the message is : %s\n",buf);
	return 0;

}

/**
 * client_ktcp_recv: kernel space tcp connection - recv - for cluster intialization
 */
int client_ktcp_send(struct socket *sock,char *buf,int len) 
{

	struct msghdr msg;
	struct kvec iov;
	//	printk(KERN_INFO "ktcp_send\n");
	if(sock==NULL)
	{
		printk("ksend the cscok is NULL\n");
		return -1;
	}

	iov.iov_base=buf;
	iov.iov_len=len;

	msg.msg_control=NULL;
	msg.msg_controllen=0;
	msg.msg_flags=0;
	msg.msg_iov=(struct iovec *)&iov;
	msg.msg_iovlen=1;
	msg.msg_name=NULL;
	msg.msg_namelen=0;

	//printk(KERN_INFO "ktcp_send.sock_sendmsg");
	kernel_sendmsg(sock,&msg,&iov, 1, iov.iov_len);
	//printk(KERN_INFO "message sent!");
	return 0;
}

/**
 * client_connect_ctx: connect two RC queue pairs
 * @ctx: lite context
 * @connection_id: target QP connections
 * @port: infiniband port
 * @my_psn: psn number
 * @mtu: mtu number
 * @sl: service level
 * @dest: destionation QP information
 */
int client_connect_ctx(ltc *ctx, int connection_id, int port, int my_psn, enum ib_mtu mtu, int sl, struct lite_dest *dest)//int sgid_idx always set to -1
{
	struct ib_qp_attr attr = {
		.qp_state	= IB_QPS_RTR,
		.path_mtu	= mtu,
		.dest_qp_num	= dest->qpn,
		.rq_psn		= dest->psn,
		.max_dest_rd_atomic	= 10,
		.min_rnr_timer	= 12,
		.ah_attr	= {
			.dlid		= dest->lid,
			.sl		= sl,
			.src_path_bits	= 0,
			.port_num	= port
		}
	};
        /*if(is_roce) {
                //attr.ah_attr.grh.dgid.global.interface_id = dest.gid_global_interface_id;
                //attr.ah_attr.grh.dgid.global.subnet_prefix = dest.gid_global_subnet_prefix;
                attr.ah_attr.grh.dgid.global.interface_id = 0;
                attr.ah_attr.grh.dgid.global.subnet_prefix = 1;
                attr.ah_attr.grh.sgid_index = 0;
                attr.ah_attr.grh.hop_limit = 1;
                attr.ah_attr.dlid = 0;
                attr.ah_attr.ah_flags = 1;//attr.ah_attr.is_global = 1;
        }*/
	if(SGID_INDEX != -1)
	{
		attr.ah_attr.ah_flags = 1;
                attr.ah_attr.grh.hop_limit = 1;
                //attr.ah_attr.grh.dgid = dest->gid;
		memcpy(&attr.ah_attr.grh.dgid, &dest->gid, sizeof(union ib_gid));
	        attr.ah_attr.grh.sgid_index = SGID_INDEX;
	}

	if(ib_modify_qp(ctx->qp[connection_id], &attr, 
				IB_QP_STATE	|
				IB_QP_AV	|
				IB_QP_PATH_MTU	|
				IB_QP_DEST_QPN	|
				IB_QP_RQ_PSN	|
				IB_QP_MAX_DEST_RD_ATOMIC	|
				IB_QP_MIN_RNR_TIMER))
	{
		printk(KERN_ALERT "Fail to modify QP to RTR at connection %d\n", connection_id);
		return 1;
	}


	attr.qp_state	= IB_QPS_RTS;
	attr.timeout	= 14;
	attr.retry_cnt	= 7;
	attr.rnr_retry	= 7;
	attr.sq_psn	= my_psn;
	attr.max_rd_atomic = 10; //was 1
	if(ib_modify_qp(ctx->qp[connection_id], &attr,
				IB_QP_STATE	|
				IB_QP_TIMEOUT	|
				IB_QP_RETRY_CNT	|
				IB_QP_RNR_RETRY	|
				IB_QP_SQ_PSN	|
				IB_QP_MAX_QP_RD_ATOMIC))
	{
		printk(KERN_ALERT "Fail to modify QP to RTS at connection %d\n", connection_id);
		return 2;
	}
	return 0;
}

int client_add_newnode_pass(struct thread_pass_struct *input)
{
	client_add_newnode(input->ctx, input->msg);
	kfree(input);
	do_exit(0);
	return 0;
}

/**
 * client_add_newnode - start connecting a new qp within a new node
 * @ctx: lite context
 * @msg: destinated QP information
 */
int client_add_newnode(ltc *ctx, char *msg)
{
	struct lite_dest rem_dest;
	struct lite_dest my_dest;
	int ret;
	int cur_connection;
	down(&add_newnode_mutex);
	printk(KERN_ALERT "%s: start do add_node with %s\n", __func__, msg);

	client_msg_to_lite_dest(msg, &rem_dest);
	cur_connection = (rem_dest.node_id*ctx->num_parallel_connection)+atomic_read(&ctx->num_alive_connection[rem_dest.node_id]);
	//printk(KERN_ALERT "%s: cur connection %d\n", __func__, cur_connection);
	client_msg_to_lite_dest(my_QPset[cur_connection].server_information_buffer, &my_dest);

#ifdef PRIORITY_IMPLEMENTATION_RESOURCE
	if(cur_connection+1%ctx->num_parallel_connection!=0)//Give low only one QP(0), and high all other QPs (1,2,3)
		ret = client_connect_ctx(ctx, cur_connection, ib_port, my_dest.psn, mtu, sl+1, &rem_dest);
	else
		ret = client_connect_ctx(ctx, cur_connection, ib_port, my_dest.psn, mtu, sl, &rem_dest);
#endif
#ifndef PRIORITY_IMPLEMENTATION_RESOURCE
	ret = client_connect_ctx(ctx, cur_connection, ib_port, my_dest.psn, mtu, sl, &rem_dest);
#endif
	if(ret)
	{
		printk("fail to chreate new node inside add_newnode function\n");
		up(&add_newnode_mutex);
		return 1;
	}
	client_post_receives_message(ctx, cur_connection, ctx->rx_depth);

	atomic_inc(&ctx->num_alive_connection[rem_dest.node_id]);
	
	atomic_inc(&ctx->alive_connection);
	up(&add_newnode_mutex);	
	if(atomic_read(&ctx->num_alive_connection[rem_dest.node_id]) == NUM_PARALLEL_CONNECTION)
	{
		atomic_inc(&ctx->num_alive_nodes);
		//Send a request local new UD to register IMM mr
		//uintptr_t tempaddr;
		//tempaddr = client_ib_reg_mr_addr(ctx, ctx->local_imm_ring_mr[rem_dest.node_id], sizeof(struct lmr_info));
		//client_send_message_sge_UD(ctx, rem_dest.node_id, MSG_PASS_LOCAL_IMM, (void *)tempaddr, sizeof(struct lmr_info), 0, 0, LOW_PRIORITY);
		//printk(KERN_CRIT "%s: complete %d connection %d\n", __func__, NUM_PARALLEL_CONNECTION, rem_dest.node_id);
	}
	
	do_exit(0);
}

/**
 * client_check_ask_mr_table - check local LMR table to find correct lmr and grant permission (also perform permission check)
 * @ctx: lite context
 * @ask_form: LMR map request form
 * @source_id: sender id
 * @litekey_addr: address to keep return LMR
 * @permission: asked permission level
 */
int client_check_askmr_table(ltc *ctx, struct ask_mr_form *ask_form, uint32_t source_id, uint64_t *litekey_addr, uint64_t *permission)
{	
	int found = 0;
	struct ask_mr_table *current_hash_ptr;
	int bucket = ask_form->identifier%(1<<HASH_TABLE_SIZE_BIT);
	rcu_read_lock();
	hash_for_each_possible_rcu(ADD_ASKMR_TABLE_HASHTABLE, current_hash_ptr, hlist, bucket)
	{
		if(current_hash_ptr->hash_key == ask_form->identifier)
		{
			found = 1;
			break;
		}
	}
	rcu_read_unlock();
	if(!found)
	{
		printk(KERN_CRIT "can not find identifier with %lu\n", (long unsigned int)ask_form->identifier);
		return 0;
	}
	*litekey_addr = current_hash_ptr->lmr;
	*permission = current_hash_ptr->permission;
	return MR_ASK_SUCCESS;
}

inline int client_find_qp_id_by_qpnum(ltc *ctx, uint32_t qp_num)
{
	int i;
	for(i=0;i<ctx->num_connections;i++)
	{
		if(ctx->qp[i]->qp_num==qp_num)
			return i;
	}
	return -1;
}

inline int client_find_node_id_by_qpnum(ltc *ctx, uint32_t qp_num)
{
	int tmp = client_find_qp_id_by_qpnum(ctx, qp_num);
	if(tmp>=0)
	{
		return tmp/NUM_PARALLEL_CONNECTION;
	}
	return -1;
}

int client_spawn_send_handler(struct thread_pass_struct *input)
{
	input->ctx->send_handler(input->sr_request->msg, input->sr_request->length, input->sr_request->src_id);
	kfree(input);
	do_exit(0);
	return 0;
}

/**
 * client_register_application - register an application to a specific port for RPC function
 * @ctx: lite context
 * @designed_port: the targetted port
 * @max_size_per_message: register the possible max size
 * @max_user_per_node: maximum user per node for this operation(not used in current version but for future QoS development)
 * @name: name/string of the application
 * @name_len: length of the name
 */
int client_register_application(ltc *ctx, unsigned int designed_port, unsigned int max_size_per_message, unsigned int max_user_per_node, char *name, uint64_t name_len)
{	
	//EREP
	
	struct app_reg_port *current_hash_ptr;
	int found = 0;
	int bucket;
	uint64_t port_node_key;
	struct app_reg_port *entry;
	if(designed_port > IMM_MAX_PORT)
	{
		printk(KERN_CRIT "%s: port %d too large < %d\n", __func__, designed_port, IMM_MAX_PORT);
		return REG_PORT_TOO_LARGE;
	}
	if(max_size_per_message > IMM_PORT_CACHE_SIZE/NUM_OF_CORES)
	{
		printk(KERN_CRIT "%s: size %d too large > %d\n", __func__, (int)max_size_per_message, IMM_PORT_CACHE_SIZE/NUM_OF_CORES);
		return REG_SIZE_TOO_LARGE;
	}
	if(name_len > 32)
	{
		printk(KERN_CRIT "%s: name_len %d too long > 32\n", __func__, (int)name_len);
		return REG_NAME_TOO_LONG;
	}
	//do check first
	port_node_key = (designed_port<<MAX_NODE_BIT) + 0;
	bucket = port_node_key % (1<<HASH_TABLE_SIZE_BIT);
	rcu_read_lock();
	hash_for_each_possible_rcu(LOCAL_MEMORYRING_PORT_HASHTABLE, current_hash_ptr, hlist, bucket)
	{
		if(current_hash_ptr->port_node_key == port_node_key)
		{
			found = 1;
			break;
		}
	}
	rcu_read_unlock();
	if(found)
	{
		printk(KERN_CRIT "%s: port %d is already occupied by %s\n", __func__, designed_port, current_hash_ptr->name);
		return REG_PORT_OCCUPIED;
	}
	//atomic_set(&ctx->imm_perport_reg_num[i], 0);
	ctx->imm_perport_reg_num[designed_port] = 0;

	//register application with 0 only, other rings would only be registered at QUERY_PORT time
	port_node_key = (designed_port<<MAX_NODE_BIT) + 0;
	bucket = port_node_key%(1<<HASH_TABLE_SIZE_BIT);
	entry = (struct app_reg_port *)kmem_cache_alloc(app_reg_cache, GFP_KERNEL);
	memset(entry, 0, sizeof(struct app_reg_port));
	entry->hash_key = bucket;
	entry->port_node_key = port_node_key;
	entry->node = 0;
	entry->port = designed_port;
	memcpy(entry->name, name, name_len);
	spin_lock(&(LOCAL_MEMORYRING_PORT_HASHTABLE_LOCK[bucket]));
	hash_add_rcu(LOCAL_MEMORYRING_PORT_HASHTABLE, &entry->hlist, bucket);
	spin_unlock(&(LOCAL_MEMORYRING_PORT_HASHTABLE_LOCK[bucket]));
	
	//register application with a ring for each node except 0
	/*
	//void *addr;
	//struct lmr_info *ret_mr;
	for(i=0;i<MAX_NODE;i++)
	{
		//do add for each machine
		port_node_key = (designed_port<<MAX_NODE_BIT) + i;
		bucket = port_node_key%(1<<HASH_TABLE_SIZE_BIT);
		entry = (struct app_reg_port *)kmem_cache_alloc(app_reg_cache, GFP_KERNEL);
		memset(entry, 0, sizeof(struct app_reg_port));
		entry->hash_key = bucket;
		entry->port_node_key = port_node_key;
		entry->node = i;
		entry->port = designed_port;
		memcpy(entry->name, name, name_len);
		if(i!=0)
		{
			//addr = client_alloc_memory_for_mr(max_size_per_message * max_user_per_node);
			//ret_mr = client_ib_reg_mr(ctx, addr, max_size_per_message * max_user_per_node, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ);
			addr = client_alloc_memory_for_mr(IMM_PORT_CACHE_SIZE);
			ret_mr = client_ib_reg_mr(ctx, addr, IMM_PORT_CACHE_SIZE, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ);
			memcpy(&entry->ring_mr, ret_mr, sizeof(struct lmr_info));
		}
		spin_lock(&(LOCAL_MEMORYRING_PORT_HASHTABLE_LOCK[bucket]));
		hash_add_rcu(LOCAL_MEMORYRING_PORT_HASHTABLE, &entry->hlist, bucket);
		spin_unlock(&(LOCAL_MEMORYRING_PORT_HASHTABLE_LOCK[bucket]));
		//printk(KERN_CRIT "%s: alloc %s on port %d with machines %d hk %llu rk %llu\n", __func__, entry->name, (int)entry->port, entry->node, entry->hash_key, entry->port_node_key);
	}*/
	
	
	return designed_port;
}
EXPORT_SYMBOL(client_register_application);

/**
 * client_unregister_application - unregister an application
 * This function is still under development
 * @ctx: lite context
 * @designed_port: the targetted port
 */
int client_unregister_application(ltc *ctx, unsigned int designed_port)
{	
	return designed_port;
}
EXPORT_SYMBOL(client_unregister_application);

/**
 * client_receive_message - processing a receive request (RPC-server)
 * @port: target port
 * @ret_addr: address to keep received message
 * @receive_size: max receive size (related to buffer size of ret_addr)
 * @reply_descriptor: address to keep the header/descriptor of the received message (for reply usage)
 * @ret_length: keep the returned length of the message (for fast_receive)
 * @userspace_flag: distinguish this is a kernel request or userspace request
 * @block_call: flag to show whether this is a blocking call or not
 * return: length of received message
 */
int client_receive_message(ltc *ctx, unsigned int port, void *ret_addr, int receive_size, uintptr_t *reply_descriptor, void *ret_length, int userspace_flag, int block_call)
{
	//This ret_addr is 
	struct imm_message_metadata *tmp;
	int get_size;
	int offset;
	int node_id;
	int ret = 0;
	unsigned long phys_addr;
	void *real_addr;
	struct imm_message_metadata *descriptor;
	struct imm_header_from_cq_to_port *new_request;
	struct imm_header_from_cq_to_port *new_tar;
        int i;
	
	struct app_reg_port *current_hash_ptr;
	int found = 0;
	int bucket;
	uint64_t port_node_key;
	int last_ack;
        //int last_ack_index;
	int ack_flag=0;

	if(unlikely(ctx->imm_perport_reg_num[port]<0))//this port is either not opened or no one queried
		return SEND_REPLY_PORT_NOT_OPENED;	
                
	spin_lock(&ctx->imm_perport_lock[port]);
	/*wait_event_interruptible(wq, !list_empty(&(request_list.list)));*/
	/*
	while(list_empty(&(ctx->imm_waitqueue_perport[port].list)))
	{
		schedule();
	}

	//Get header message from list
	spin_lock(&ctx->imm_waitqueue_perport_lock[port]);
	new_request = list_entry(ctx->imm_waitqueue_perport[port].list.next, struct imm_header_from_cq_to_port, list);
	//printk(KERN_CRIT "%s: get %p\n", __func__, new_request);
	list_del(&new_request->list);	
	spin_unlock(&ctx->imm_waitqueue_perport_lock[port]);
	*/
        
        //Generate descriptor for future reply message, this part takes around 40-60ns, sometimes 100ns
	descriptor = (struct imm_message_metadata *)kmem_cache_alloc(imm_message_metadata_cache, GFP_KERNEL);
	if(unlikely(!descriptor))
	{
		printk(KERN_CRIT "%s: descriptor alloc fail\n", __func__);
		//descriptor = (struct imm_message_metadata *)kmem_cache_alloc(imm_message_metadata_cache, GFP_KERNEL);
		spin_unlock(&ctx->imm_perport_lock[port]);
                return SEND_REPLY_FAIL;
	}
	//Have a single try first, it it's a block call, have infinite try
	if(likely(block_call))
	{
		while(1)
		{
                        if(ctx->imm_waitqueue_perport_count_recv[port] < ctx->imm_waitqueue_perport_count_poll[port])
                        {
                                new_tar = ctx->imm_waitqueue_perport[port];
                                new_request = &new_tar[ctx->imm_waitqueue_perport_count_recv[port]%IMM_ROUND_UP];
                                //printk(KERN_CRIT "%s: port:%d count:%d\n", __func__, port, ctx->imm_waitqueue_perport_count_recv[port]);
                                ctx->imm_waitqueue_perport_count_recv[port]++;
                                break;
                        }
                        if(userspace_flag && ret_length)
                        {
                                for(i=0;i<NUM_POLLING_THREADS;i++)
                                {
                                        if(!ctx->imm_cq_is_available[i])
                                                break;
                                }
                                spin_lock(&ctx->imm_waitqueue_perport_lock[port]);
			        //if(i==NUM_POLLING_THREADS&&list_empty(&(ctx->imm_waitqueue_perport[port].list)))//there is no busy cq and there is no live event in the queur
                                if(i==NUM_POLLING_THREADS && ctx->imm_waitqueue_perport_count_recv[port] == ctx->imm_waitqueue_perport_count_poll[port])
                                {
                                        struct imm_header_from_cq_to_userspace *tmp = kmem_cache_alloc(imm_wait_userspace_buffer_cache, GFP_KERNEL);
                                        tmp->receive_size = receive_size;
                                        if(lite_check_page_continuous(ret_addr, receive_size, &phys_addr))//check send buffer continuous
                        			tmp->ret_addr = (void *)phys_to_virt(phys_addr);
                                        else    
                                                tmp->ret_addr = NULL;
		                        if(lite_check_page_continuous(reply_descriptor, sizeof(struct imm_message_metadata *), &phys_addr))//check send buffer continuous
                        			tmp->reply_descriptor = (void *)phys_to_virt(phys_addr);
                                        else
                                                tmp->reply_descriptor = NULL;
		                        if(lite_check_page_continuous(ret_length, sizeof(int), &phys_addr))//check send buffer continuous
                        			tmp->ret_length = (void *)phys_to_virt(phys_addr);
                                        else
                                                tmp->ret_length = NULL;
                                        if(tmp->ret_addr && tmp->reply_descriptor && tmp->ret_length)
                                        {
                                                list_add_tail(&(tmp->list), &ctx->imm_wait_userspace_perport[port].list);
                                                spin_unlock(&ctx->imm_waitqueue_perport_lock[port]);
                                        	spin_unlock(&ctx->imm_perport_lock[port]);
                                                return SEND_REPLY_WAIT;
                                        }
				        kmem_cache_free(imm_wait_userspace_buffer_cache, tmp);
                                }
                                spin_unlock(&ctx->imm_waitqueue_perport_lock[port]);
                        }
			#ifdef RECV_SCHEDULE_MODEL
				schedule();
			#endif
			#ifdef RECV_CPURELAX_MODEL
				cpu_relax();
			#endif
			#ifdef RECV_WAITQUEUE_MODEL
				wait_event_interruptible_timeout(ctx->imm_receive_block_queue[port], !list_empty(&(ctx->imm_waitqueue_perport[port].list)), msecs_to_jiffies(10000));
			#endif
		}
	}
	else
	{
                if(ctx->imm_waitqueue_perport_count_recv[port] < ctx->imm_waitqueue_perport_count_poll[port])
                {
                        new_tar = ctx->imm_waitqueue_perport[port];
                        new_request = &new_tar[ctx->imm_waitqueue_perport_count_recv[port]%IMM_ROUND_UP];
                        ctx->imm_waitqueue_perport_count_recv[port]++;
                }
		else
		{
			spin_unlock(&ctx->imm_perport_lock[port]);
                	kmem_cache_free(imm_message_metadata_cache, descriptor);
			return 0;
		}
		/*if(!list_empty(&(ctx->imm_waitqueue_perport[port].list)))
		{
			new_request = list_entry(ctx->imm_waitqueue_perport[port].list.next, struct imm_header_from_cq_to_port, list);
                        spin_lock(&ctx->imm_waitqueue_perport_lock[port]);
			list_del(&new_request->list);	
                        spin_unlock(&ctx->imm_waitqueue_perport_lock[port]);
		}
		else
		{
			spin_unlock(&ctx->imm_perport_lock[port]);
                	kmem_cache_free(imm_message_metadata_cache, descriptor);
			return 0;
		}*/
	}
	//test9 - starts (from get poll to return takes 50ns (8) and 173ns(4K))
	offset = new_request->offset;
	node_id = new_request->source_node_id;
        //printk(KERN_CRIT "%s: offset %d node_id %d\n", __func__, offset, node_id);
	//free list
	kmem_cache_free(imm_header_from_cq_to_port_cache, new_request);

	//get buffer from hash table based on node and port
	port_node_key = (port<<MAX_NODE_BIT) + node_id;
        current_hash_ptr = ctx->last_port_node_key_hash_ptr;
	if(!current_hash_ptr || current_hash_ptr->port_node_key != port_node_key)
        {
                current_hash_ptr = NULL;
        	bucket = port_node_key % (1<<HASH_TABLE_SIZE_BIT);
        	rcu_read_lock();
        	hash_for_each_possible_rcu(LOCAL_MEMORYRING_PORT_HASHTABLE, current_hash_ptr, hlist, bucket)
        	{
        		if(current_hash_ptr->port_node_key == port_node_key)
        		{
        			found = 1;
                                ctx->last_port_node_key_hash_ptr = current_hash_ptr;
        			break;
        		}
        	}
        	rcu_read_unlock();
        }
        else
        {
                found = 1;
        }

        //The above part takes around 20 ns
	//validate hashtable
	if(unlikely(!found))
	{
		printk(KERN_CRIT "%s: node-%d port-%d [significant error], since ring is not generated yet\n", __func__, node_id, port);
		spin_unlock(&ctx->imm_perport_lock[port]);
		return SEND_REPLY_PORT_NOT_OPENED;
	}
	//validate ring address
	if(unlikely(!current_hash_ptr->addr))
	{
		printk(KERN_CRIT "%s: node-%d port-%d offset-%d [significant error], ring is not generated after query\n", __func__, node_id, port, offset);
		spin_unlock(&ctx->imm_perport_lock[port]);
		return SEND_REPLY_PORT_NOT_OPENED;
	}
	//point to header within ring/buffer based on offset
	tmp = (struct imm_message_metadata *)(current_hash_ptr->addr + offset);
	get_size = tmp->size;
	//Check size
	if(unlikely(get_size > receive_size))
	{
                printk(KERN_CRIT "%s: receive %d but only call with %d\n", __func__, get_size, receive_size);
		spin_unlock(&ctx->imm_perport_lock[port]);
		return SEND_REPLY_SIZE_TOO_BIG;
	}

	//do data memcpy
	//This part could be modified into shared memory to avoid one memcpy
	//But in current design, this memcpy is unavoidable just like send-reply, either memcpy or copy_to_user
        
	//test10 start, memcpy takes 129ns for 4k 20ns for 8B
        //below copy function takes from 30 - 200ns
	if(!userspace_flag)//kernel space, do memcpy directly
		memcpy(ret_addr, ((void *)tmp) + sizeof(struct imm_message_metadata), get_size);
	else//user space
	{
		if(lite_check_page_continuous(ret_addr, get_size, &phys_addr))//check send buffer continuous
		{
			real_addr = (void *)phys_to_virt(phys_addr);
                        memcpy(real_addr, ((void *)tmp) + sizeof(struct imm_message_metadata), get_size);
                }
                else
                {
		        ret = copy_to_user(ret_addr, ((void *)tmp) + sizeof(struct imm_message_metadata), get_size);
        	        if(unlikely(ret))
                        {
		                spin_unlock(&ctx->imm_perport_lock[port]);
                		return SEND_REPLY_FAIL;
                        }
                }
	}
	//test10 ends
	//printk(KERN_CRIT "%s: hash-%p offset-%x tmp-%p recv %s testport-%d testnodeid-%d\n", __func__, current_hash_ptr->addr, offset, tmp, ret_addr, tmp->designed_port, tmp->source_node_id);

	//has to keep data in descriptor
        //these two memcpy (one for pointer, one for data) use 30ns, 100ns(few)
	//test11 starts ends in later this function to test network stack (recording and acking) time which takes 42ns for 8 and 54ns for 4K
	
        memcpy(descriptor, tmp, sizeof(struct imm_message_metadata));
	if(!userspace_flag)//This part is going to record the pointer value of descriptor
        {
		*reply_descriptor = (uintptr_t)descriptor;
        }
	else//This does the same thing which is done by copy_to_user
        {
		if(lite_check_page_continuous(reply_descriptor, sizeof(struct imm_message_metadata *), &phys_addr))//check send buffer continuous
		{
			real_addr = (void *)phys_to_virt(phys_addr);
                        memcpy(real_addr, &descriptor, sizeof(struct imm_message_metadata *));
                }
                else
                {
        		ret = copy_to_user(reply_descriptor, &descriptor, sizeof(struct imm_message_metadata *));
                        if(ret)
                        {
		                spin_unlock(&ctx->imm_perport_lock[port]);
                                return SEND_REPLY_FAIL;
                        }
                }
        }

        if(tmp->source_node_id == ctx->node_id)//local send-reply
        {
                kfree(tmp); //since this address space is allocated in client_send_message_with_rdma_emulated_for_local
        }
        else
        {
                //do ack based on the last_ack_index, submit a request to waiting_queue_handler	
                spin_lock(&current_hash_ptr->last_ack_index_lock);//Check takes around 30-40 ns
                last_ack = current_hash_ptr->last_ack_index;
                offset = offset + sizeof(struct imm_message_metadata) + get_size;
                if( (offset>= last_ack && offset - last_ack >= IMM_PORT_CACHE_SIZE/IMM_ACK_PORTION ) ||
                    (offset < last_ack && offset + IMM_PORT_CACHE_SIZE - last_ack >= IMM_PORT_CACHE_SIZE/IMM_ACK_PORTION))
                {
                        ack_flag = 1;
                        current_hash_ptr->last_ack_index = offset;
                        //printk(KERN_CRIT "[%s] generate ACK with offset %d and index %d\n", __func__, offset, current_hash_ptr->last_ack_index);
                }
                spin_unlock(&current_hash_ptr->last_ack_index_lock);
                if(ack_flag)//Ack takes around 85 - 120 ns
                {	
                        struct send_and_reply_format *pass;
                        pass = kmem_cache_alloc(s_r_cache, GFP_KERNEL);
                        pass->msg = (char*)current_hash_ptr;
                        pass->length = offset;
                        pass->type = MSG_DO_ACK_INTERNAL;

                        spin_lock(&wq_lock[QUEUE_ACK]);
                        list_add_tail(&(pass->list), &request_list[QUEUE_ACK].list);
                        spin_unlock(&wq_lock[QUEUE_ACK]);
                }
                spin_unlock(&ctx->imm_perport_lock[port]);
        }
        //test11 ends
	//test9 ends
        
        //process send-only checking
        if(descriptor->store_addr == (uintptr_t)NULL)
        {
                struct imm_message_metadata *null_descriptor = (struct imm_message_metadata *)IMM_SEND_ONLY_FLAG;
                if(!userspace_flag) 
                        *reply_descriptor = (uintptr_t)NULL;
                else//This does the same thing which is done by copy_to_user
                {
                        if(lite_check_page_continuous(reply_descriptor, sizeof(struct imm_message_metadata *), &phys_addr))//check send buffer continuous
                        {
                                real_addr = (void *)phys_to_virt(phys_addr);
                                memcpy(real_addr, &null_descriptor, sizeof(struct imm_message_metadata *));
                        }
                        else
                        {
                                ret = copy_to_user(reply_descriptor, &null_descriptor, sizeof(struct imm_message_metadata *));
                                if(ret)
                                {
                                        spin_unlock(&ctx->imm_perport_lock[port]);
                                        return SEND_REPLY_FAIL;
                                }
                        }
                }
	        kmem_cache_free(imm_message_metadata_cache, descriptor);
        }
	return get_size;
}
EXPORT_SYMBOL(client_receive_message);

/**
 * client_reply_message - processing a reply request in RPC
 * @ctx: lite context
 * @addr: input address
 * @size: reply size
 * @descriptor: header of reply message (returned by lite_api_receive)
 * @userspace_flag: distinguish this request is from kernel space or userspace
 * @priority: priority of the request
 */
int client_reply_message(ltc *ctx, void *addr, int size, uintptr_t descriptor, int userspace_flag, int priority)
{
	struct imm_message_metadata *tmp = (struct imm_message_metadata *)descriptor;
	int re_connection_id;
	unsigned long phys_addr;
	void *real_addr;
	struct ib_device *ibd = (struct ib_device *)ctx->context;
	//test12 start, ends in client_send_message_with_rdma_write_with_imm_request before post_send (55ns (4K), 56ns(8)) 
        //printk(KERN_CRIT "%s: reply message to %d %d\n", __func__, tmp->source_node_id, tmp->store_semaphore);
        //
        if(tmp->source_node_id != ctx->node_id)//regular remote send-reply
        {
                re_connection_id = client_get_connection_by_atomic_number(ctx, tmp->source_node_id, priority);
                if(!userspace_flag)
                        client_send_message_with_rdma_write_with_imm_request(ctx, re_connection_id, tmp->store_rkey, tmp->store_addr, addr, size, 0, tmp->store_semaphore | IMM_SEND_REPLY_RECV, LITE_SEND_MESSAGE_IMM_ONLY, NULL, LITE_KERNELSPACE_FLAG, 0, NULL, 0);
                else//This function takes 40 ns before send
                {
                        if(lite_check_page_continuous(addr, size, &phys_addr))//check send buffer continuous
                        {
                                real_addr = (void *)phys_to_dma(ibd->dma_device, (phys_addr_t)phys_addr);
                                client_send_message_with_rdma_write_with_imm_request(ctx, re_connection_id, tmp->store_rkey, tmp->store_addr, real_addr, size, 0, tmp->store_semaphore | IMM_SEND_REPLY_RECV, LITE_SEND_MESSAGE_IMM_ONLY, NULL, LITE_USERSPACE_FLAG, 0, NULL, 0);
                        }
                        else
                        {
                                void *reply_addr;
                                int ret;
                                reply_addr = kmem_cache_alloc(imm_copy_userspace_buffer_cache, GFP_KERNEL);
                                ret = copy_from_user(reply_addr, addr, size);
                                if(ret)
                                {
                                        kmem_cache_free(imm_copy_userspace_buffer_cache, reply_addr);
                                        return SEND_REPLY_FAIL;
                                }
                                client_send_message_with_rdma_write_with_imm_request(ctx, re_connection_id, tmp->store_rkey, tmp->store_addr, reply_addr, size, 0, tmp->store_semaphore | IMM_SEND_REPLY_RECV, LITE_SEND_MESSAGE_IMM_ONLY, NULL, LITE_KERNELSPACE_FLAG, 0, NULL, 1);
                                kmem_cache_free(imm_copy_userspace_buffer_cache, reply_addr);
                        }
                }
        }
        else
        {
                int semaphore;
                int ret_size = size;
                if(!userspace_flag)
                {
                        memcpy((void *)tmp->store_addr, addr, ret_size);
                }
                else
                {
                        void *reply_addr;
                        int ret;
                        reply_addr = kmem_cache_alloc(imm_copy_userspace_buffer_cache, GFP_KERNEL);
                        ret = copy_from_user(reply_addr, addr, ret_size);
                        if(ret)
                        {
                                kmem_cache_free(imm_copy_userspace_buffer_cache, reply_addr);
                                return SEND_REPLY_FAIL;
                        }
                        kmem_cache_free(imm_copy_userspace_buffer_cache, reply_addr);
                }
                semaphore = tmp->store_semaphore;
                memcpy((void *)ctx->imm_store_semaphore[semaphore], &ret_size, sizeof(int));
                #ifdef ADAPTIVE_MODEL
                if(semaphore >= IMM_NUM_OF_SEMAPHORE || semaphore <0)
                {
                        printk(KERN_CRIT "%s: [significant error]error semaphore %d\n", __func__, semaphore);
                }
                wake_up_interruptible(&ctx->imm_store_block_queue[semaphore]);//Wakeup waiting queue
                #endif
                #ifdef SCHEDULE_MODEL
                wake_up_process(ctx->imm_store_semaphore_task[semaphore]);
                ctx->imm_store_semaphore_task[semaphore]=NULL;
                #endif
                //spin_lock(&ctx->imm_store_semaphore_lock[semaphore]);
                ctx->imm_store_semaphore[semaphore] = NULL;
                //spin_unlock(&ctx->imm_store_semaphore_lock[semaphore]);
                clear_bit(semaphore, ctx->imm_store_semaphore_bitmap);
        }
	kmem_cache_free(imm_message_metadata_cache, tmp);
	return 0;
}
EXPORT_SYMBOL(client_reply_message);

/**
 * liteapi_query_port - get the metadata information for RPC request
 * must be performed before issueing a RPC request
 * @ctx: lite context
 * @target_node: target node id
 * @designed_port: target port
 * @requery_flag: if the metadata is already in local cache, query again?
 */
int client_query_port(ltc *ctx, int target_node, int designed_port, int requery_flag)
{	
	//EREP
	struct ask_mr_form input_mr_form;
	uintptr_t tempaddr;
	int priority = LOW_PRIORITY;
	int wait_send_reply_id;
	struct ask_mr_reply_form reply_mr_form;
	

	struct app_reg_port *entry;
	int bucket;
	uint64_t port_node_key;
	//check first
	struct app_reg_port *current_hash_ptr;
	int found=0;
	if(!requery_flag)//If requery is true, skip local check
	{
		port_node_key = (designed_port<<MAX_NODE_BIT) + target_node;
		bucket = port_node_key % (1<<HASH_TABLE_SIZE_BIT);
		rcu_read_lock();
		hash_for_each_possible_rcu(REMOTE_MEMORYRING_PORT_HASHTABLE, current_hash_ptr, hlist, bucket)
		{
			if(current_hash_ptr->port_node_key == port_node_key)
			{
				found = 1;
				break;
			}
		}
		rcu_read_unlock();
		if(found)
		{
			printk(KERN_CRIT "%s: LOCAL node %d port %d remote addr %p remote rkey %d remote id %d\n", __func__, target_node, designed_port, current_hash_ptr->ring_mr.addr, current_hash_ptr->ring_mr.rkey, current_hash_ptr->ring_mr.node_id);
			//printk(KERN_CRIT "%s:find local cache\n", __func__);
			return MR_ASK_SUCCESS;
		}
		else
		{
			printk(KERN_CRIT "%s: can't find node %d port %d in local\n", __func__, target_node, designed_port);
		}
	}
	//Finish checking

	input_mr_form.designed_port = designed_port;
	wait_send_reply_id = SEND_REPLY_WAIT;
	tempaddr = client_ib_reg_mr_addr(ctx, &input_mr_form, sizeof(struct ask_mr_form));
	client_send_message_sge_UD(ctx, target_node, MSG_QUERY_PORT_1, (void *)tempaddr, sizeof(struct ask_mr_form), (uint64_t)&reply_mr_form, (uint64_t)&wait_send_reply_id, priority);
	while(wait_send_reply_id==SEND_REPLY_WAIT)
		cpu_relax();
	if(reply_mr_form.op_code == MR_ASK_SUCCESS)
	{
		port_node_key = (designed_port<<MAX_NODE_BIT) + target_node;
		//printk(KERN_CRIT "%s: using key as %d\n", __func__, port_node_key);
		bucket = port_node_key%(1<<HASH_TABLE_SIZE_BIT);
		entry = (struct app_reg_port *)kmem_cache_alloc(app_reg_cache, GFP_KERNEL);
		memset(entry, 0, sizeof(struct app_reg_port));
		entry->hash_key = bucket;
		entry->port_node_key = port_node_key;
		entry->node = target_node;
		entry->port = designed_port;
		memcpy(&entry->ring_mr, &reply_mr_form.reply_mr, sizeof(struct lmr_info));
		entry->remote_imm_ring_index = 0;
		spin_lock_init(&entry->remote_imm_offset_lock);
		
		spin_lock(&(REMOTE_MEMORYRING_PORT_HASHTABLE_LOCK[bucket]));
		hash_add_rcu(REMOTE_MEMORYRING_PORT_HASHTABLE, &entry->hlist, bucket);
		spin_unlock(&(REMOTE_MEMORYRING_PORT_HASHTABLE_LOCK[bucket]));

		printk(KERN_CRIT "%s: SUCCESS node %d port %d remote addr %p remote rkey %d remote id %d\n", __func__, target_node, designed_port, entry->ring_mr.addr, entry->ring_mr.rkey, entry->ring_mr.node_id);
		return reply_mr_form.op_code;
	}
	printk(KERN_CRIT "FAIL %x\n", (int)reply_mr_form.op_code);
	return reply_mr_form.op_code;
}
EXPORT_SYMBOL(client_query_port);

void *client_alloc_memory_for_mr(unsigned int length)
{
	void *tempptr;
	tempptr = kmalloc(length, GFP_KERNEL);//Modify from kzalloc to kmalloc
	if(!tempptr)
		printk(KERN_CRIT "%s: alloc error %d\n", __func__, length);
	return tempptr;
}
EXPORT_SYMBOL(client_alloc_memory_for_mr);

int priority_handler(ltc *ctx)
{
	int ret;
	while(!kthread_should_stop())
	{
		ret = wait_event_interruptible_timeout(ctx->priority_block_queue, kthread_should_stop(), msecs_to_jiffies(PRIORITY_CHECKING_PERIOD_US));
		atomic_set(&ctx->slow_counter, 0);
		atomic_set(&ctx->low_total_num_write, 0);
		atomic_set(&ctx->low_total_num_read, 0);
		atomic_set(&ctx->low_total_num_sr, 0);
	}
	return 0;
}

/**
 * waiting_queue_handler - processing all the lite-handler operations
 * This function will be splited into better format and sub-functions in the next version
 * @ctx: lite context
 */
int waiting_queue_handler(ltc *ctx)
{
	struct send_and_reply_format *new_request;
	int local_flag;
        int queue_flag;
	//struct list_head *ptr;
	allow_signal(SIGKILL);
	while(1)
	{
		/*wait_event_interruptible(wq, !list_empty(&(request_list.list)));*/
		/*while(  list_empty(&(request_list[QUEUE_ACK].list))&&
                        list_empty(&(request_list[QUEUE_POST_RECV].list))&&
                        list_empty(&(request_list[QUEUE_HIGH].list))&&
                        list_empty(&(request_list[QUEUE_MEDUIM].list))&&
                        list_empty(&(request_list[QUEUE_LOW].list))
                )
		{
			schedule();
			if(kthread_should_stop())
			{
				printk(KERN_ALERT "Stop waiting_event_handler\n");
				return 0;
			}
		}
		spin_lock(&wq_lock);
		new_request = list_entry(request_list.list.next, struct send_and_reply_format, list);
		spin_unlock(&wq_lock);*/

                while(1)
                {
                        if(!list_empty(&(request_list[QUEUE_ACK].list)))
                        {
                                spin_lock(&wq_lock[QUEUE_ACK]);
                                new_request = list_entry(request_list[QUEUE_ACK].list.next, struct send_and_reply_format, list);
                                spin_unlock(&wq_lock[QUEUE_ACK]);
                                queue_flag = QUEUE_ACK;
                                break;
                        }
                        else if(!list_empty(&(request_list[QUEUE_POST_RECV].list)))
                        {
                                spin_lock(&wq_lock[QUEUE_POST_RECV]);
                                new_request = list_entry(request_list[QUEUE_POST_RECV].list.next, struct send_and_reply_format, list);
                                spin_unlock(&wq_lock[QUEUE_POST_RECV]);
                                queue_flag = QUEUE_POST_RECV;
                                break;
                        }
                        else if(!list_empty(&(request_list[QUEUE_HIGH].list)))
                        {
                                spin_lock(&wq_lock[QUEUE_HIGH]);
                                new_request = list_entry(request_list[QUEUE_HIGH].list.next, struct send_and_reply_format, list);
                                spin_unlock(&wq_lock[QUEUE_HIGH]);
                                queue_flag = QUEUE_HIGH;
                                break;
                        }
                        else if(!list_empty(&(request_list[QUEUE_MEDIUM].list)))
                        {
                                spin_lock(&wq_lock[QUEUE_MEDIUM]);
                                new_request = list_entry(request_list[QUEUE_MEDIUM].list.next, struct send_and_reply_format, list);
                                spin_unlock(&wq_lock[QUEUE_MEDIUM]);
                                queue_flag = QUEUE_MEDIUM;
                                break;
                        }
                        else if(!list_empty(&(request_list[QUEUE_LOW].list)))
                        {
                                spin_lock(&wq_lock[QUEUE_LOW]);
                                new_request = list_entry(request_list[QUEUE_LOW].list.next, struct send_and_reply_format, list);
                                spin_unlock(&wq_lock[QUEUE_LOW]);
                                queue_flag = QUEUE_LOW;
                                break;
                        }
			schedule();
			if(kthread_should_stop())
			{
				printk(KERN_ALERT "Stop waiting_event_handler\n");
				return 0;
			}
                }

		if(new_request->src_id == ctx->node_id)
			local_flag = 1;
		else
			local_flag = 0;
		switch(new_request->type)
		{
			case MSG_GET_FINISH:
				printk("Handler terminated\n");
				spin_unlock(&wq_lock[QUEUE_ACK]);
				do_exit(0);
				break;
			case MSG_DO_RC_POST_RECEIVE:
				//new_request->src_id keeps the connection_id (done by client_poll_cq)
				client_post_receives_message(ctx, new_request->src_id, new_request->length);
				break;
			case MSG_DO_UD_POST_RECEIVE:
				client_post_receives_message_UD(ctx, new_request->length);
				break;
			case MSG_SERVER_SEND:
				ctx->send_handler(new_request->msg, new_request->length, new_request->src_id);
				break;
			case MSG_CLIENT_SEND:
				ctx->send_handler(new_request->msg, new_request->length, new_request->src_id);
				break;
                        case MSG_DIST_BARRIER:
                                {
                                        uint64_t temp;
					uintptr_t tempaddr;
                                        int source=0;
                                        int source_id, source_arrive_idx;
                                        memcpy(&source, new_request->msg, new_request->length);
                                        source_id = source%MAX_NODE;
                                        source_arrive_idx = source/MAX_NODE;
                                        if(source_id!=new_request->src_id)
                                                printk(KERN_CRIT "%s: sourceID %d, node_id %d\n", __func__, source_id, new_request->src_id);
                                        else if(ctx->last_barrier_idx[source_id]>=source_arrive_idx)
                                                printk(KERN_CRIT "%s: receive %d duplicate barrier message %d %d\n", __func__, source_id, source_arrive_idx, ctx->last_barrier_idx[source_id]);
                                        else
                                        {
                                                atomic_inc(&ctx->dist_barrier_counter);
                                                ctx->last_barrier_idx[source_id] = source_arrive_idx;
                                        }
					tempaddr = client_ib_reg_mr_addr(ctx, &temp, sizeof(uint64_t));
					//printk(KERN_CRIT "received barrier from node %d\n", source_id);
					client_send_message_sge_UD(ctx, new_request->src_id, MSG_GET_SEND_AND_REPLY_2, (void *)tempaddr, sizeof(uint64_t), new_request->store_addr, new_request->store_semaphore, LOW_PRIORITY);
                                        client_free_recv_buf(new_request->msg);
					//printk(KERN_CRIT "111 received barrier from node %d\n", source_id);
                                }
                                break;
			case MSG_ASK_MR_1:
				{
					uint64_t litekey_addr;
					uint64_t permission=0;
					int ret_priority = LOW_PRIORITY;
					//int connection_id;
					uintptr_t tempaddr;
					struct hash_asyio_key *temp_ptr;
					struct ask_mr_form *input_form;
					struct ask_mr_reply_form ret;
					int found = 0;
					int answer_from_handler;
					int bucket;
					int i;
					memset(&ret, 0, sizeof(struct ask_mr_reply_form));
					input_form = (struct ask_mr_form *)new_request->msg;
					#ifdef ASK_MR_TABLE_HANDLING
						answer_from_handler = client_check_askmr_table(ctx, input_form, new_request->src_id, &litekey_addr, &permission);
					#endif
					#ifndef ASK_MR_TABLE_HANDLING
						answer_from_handler = ctx->ask_mr_handler(input_form, new_request->src_id, &litekey_addr, &permission);//memcpy is required if user wants to keep data
					#endif
					//litekey_addr is returned by pointer from answer_form_handler (user registered function)
					if(answer_from_handler == 0)//Accept the request
					{
						bucket = litekey_addr%(1<<HASH_TABLE_SIZE_BIT);
						rcu_read_lock();
						hash_for_each_possible_rcu(ASYIO_HASHTABLE, temp_ptr, hlist, bucket)
						{
							if(temp_ptr->lite_handler == litekey_addr)
							{
								found = 1;
								break;
							}
						}
						rcu_read_unlock();
						if(found == 0)
						{
							ret.op_code = MR_ASK_HANDLER_ERROR;
						}
						else
						{
							if(temp_ptr->permission & MR_SHARE_FLAG)//can share
							{
								if(input_form->permission & temp_ptr->permission & permission & MR_READ_FLAG) //READ is okay
									ret.permission |= MR_READ_FLAG;
								if(input_form->permission & temp_ptr->permission & permission & MR_WRITE_FLAG) //READ is okay
									ret.permission |= MR_WRITE_FLAG;
								if(input_form->permission & temp_ptr->permission & permission & MR_SHARE_FLAG) //READ is okay
									ret.permission |= MR_SHARE_FLAG;
								if(input_form->permission & temp_ptr->permission & permission & MR_ATOMIC_FLAG) //READ is okay
									ret.permission |= MR_ATOMIC_FLAG;
								for(i=0;i<temp_ptr->list_length;i++)
								{
									memcpy(&ret.reply_mr[i], temp_ptr->datalist[i], sizeof(struct lmr_info));
								}
								ret.op_code = MR_ASK_SUCCESS;
								ret.node_id = temp_ptr->node_id;
								ret.list_length = temp_ptr->list_length;
								ret.total_length = temp_ptr->size;

								set_bit(new_request->src_id, temp_ptr->askmr_bitmap);//which would be used to do deregiter in the future
							}
							else//return fail
							{
								ret.op_code = MR_ASK_UNPERMITTED;
							}
						}
					}
					else//return fail
					{
						ret.op_code = MR_ASK_REFUSE;
					}
					

					if(!local_flag)
					{
						tempaddr = client_ib_reg_mr_addr(ctx, &ret, sizeof(struct ask_mr_reply_form));
						client_send_message_sge_UD(ctx, new_request->src_id, MSG_ASK_MR_2, (void *)tempaddr, sizeof(struct ask_mr_reply_form), new_request->store_addr, new_request->store_semaphore, ret_priority);
						client_free_recv_buf(new_request->msg);
					}
					else
					{
						client_send_message_local_reply(ctx, new_request->src_id, MSG_ASK_MR_2, (&ret), sizeof(struct ask_mr_reply_form), new_request->store_addr, new_request->store_semaphore, ret_priority);
					}
				}
				break;
			case MSG_GET_SEND_AND_REPLY_1_UD:
				{
					char *ret;
					uint32_t ret_size;
					int ret_priority = LOW_PRIORITY;
					uintptr_t tempaddr;
					ret = (char *)kmem_cache_alloc(post_receive_cache, GFP_KERNEL);
					ctx->send_reply_handler(new_request->msg, new_request->length, ret, &ret_size, new_request->src_id);
					tempaddr = client_ib_reg_mr_addr(ctx, ret, ret_size);
					client_send_message_sge_UD(ctx, new_request->src_id, MSG_GET_SEND_AND_REPLY_2, (void *)tempaddr, ret_size, new_request->store_addr, new_request->store_semaphore, ret_priority);
					client_free_recv_buf(ret);
					break;
				}
			case MSG_GET_SEND_AND_REPLY_1:
				{
					char *ret;
					uint32_t ret_size;
					int ret_priority = LOW_PRIORITY;
					//int connection_id;
					uintptr_t tempaddr;

					ret = (char *)kmem_cache_alloc(post_receive_cache, GFP_KERNEL);
					ctx->send_reply_handler(new_request->msg, new_request->length, ret, &ret_size, new_request->src_id);
					tempaddr = client_ib_reg_mr_addr(ctx, ret, ret_size);
					//connection_id = client_get_connection_by_atomic_number(ctx, new_request->src_id, ret_priority);
					//client_send_message_addr(connection_id, MSG_GET_SEND_AND_REPLY_2, (void *)tempaddr, ret_size, new_request->store_id);
					client_send_message_sge_UD(ctx, new_request->src_id, MSG_GET_SEND_AND_REPLY_2, (void *)tempaddr, ret_size, new_request->store_addr, new_request->store_semaphore, ret_priority);
					//kmem_cache_free(post_receive_cache, ret);
					client_free_recv_buf(ret);
					break;
				}
			case MSG_GET_SEND_AND_REPLY_OPT_1:
				{
					unsigned long ret_addr;
					uint32_t ret_size;
					int ret_priority = LOW_PRIORITY;
					//int connection_id;
					uintptr_t tempaddr;

					ctx->send_reply_opt_handler(new_request->msg, new_request->length, (void **)&ret_addr, &ret_size, new_request->src_id);
					tempaddr = client_ib_reg_mr_phys_addr(ctx, (void *)ret_addr, ret_size);
					//connection_id = client_get_connection_by_atomic_number(ctx, new_request->src_id, ret_priority);
					//client_send_message_addr(connection_id, MSG_GET_SEND_AND_REPLY_2, (void *)tempaddr, ret_size, new_request->store_id);
					client_send_message_sge_UD(ctx, new_request->src_id, MSG_GET_SEND_AND_REPLY_OPT_2, (void *)tempaddr, ret_size, new_request->store_addr, new_request->store_semaphore, ret_priority);
					break;
				}
			case MSG_GET_ATOMIC_MID:
				{
					char *ret;
					uint32_t ret_size;
					int ret_priority = LOW_PRIORITY;
					//int connection_id;
					uintptr_t tempaddr;

					ret = (char *)kmem_cache_alloc(post_receive_cache, GFP_KERNEL);
					ctx->atomic_send_handler((struct atomic_struct *)new_request->msg, new_request->length, ret, &ret_size, new_request->src_id);
					tempaddr = client_ib_reg_mr_addr(ctx, ret, ret_size);
					//connection_id = client_get_connection_by_atomic_number(ctx, new_request->src_id, ret_priority);

					client_send_message_sge_UD(ctx, new_request->src_id, MSG_GET_ATOMIC_REPLY, (void *)tempaddr, ret_size, new_request->store_addr, new_request->store_semaphore, ret_priority);
					//mem_cache_free(post_receive_cache, ret);
					client_free_recv_buf(ret);
					break;
				}
			case MSG_GET_ATOMIC_SINGLE_MID:
				{
					ctx->atomic_single_send_handler((struct atomic_struct *)new_request->msg, new_request->length, new_request->src_id);
					break;
				}
			case MSG_GET_REMOTEMR:
				{
					//down(&request_mr[*(int*)ptr]);
					int length;
					//int connection_id;
					void *addr;
					struct lmr_info *ret_mr;
					uintptr_t tempaddr;
					memcpy(&length, new_request->msg, new_request->length);

					//connection_id = client_get_connection_by_atomic_number(ctx, new_request->src_id, LOW_PRIORITY);

					//addr = kmalloc(length * sizeof(char), GFP_KERNEL);//Modify from kzalloc to kmalloc
					addr = client_alloc_memory_for_mr(length*sizeof(char));
                                        if(addr)
                                        {
        					ret_mr = client_ib_reg_mr(ctx, addr, length, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ);
        					tempaddr = client_ib_reg_mr_addr(ctx, ret_mr, sizeof(struct lmr_info));
        					client_send_message_sge_UD(ctx, new_request->src_id, MSG_GET_REMOTEMR_REPLY, (void *)tempaddr, sizeof(struct lmr_info), new_request->store_addr, new_request->store_semaphore, LOW_PRIORITY);
                                        }
                                        else
                                        {
        					ret_mr = client_alloc_lmr_info_buf();
	                                        ret_mr->length = 0;
                                        	ret_mr->lkey = 0;
                                        	ret_mr->rkey = 0;
                                        	ret_mr->node_id = 0;
        					tempaddr = client_ib_reg_mr_addr(ctx, ret_mr, sizeof(struct lmr_info));
        					client_send_message_sge_UD(ctx, new_request->src_id, MSG_GET_REMOTEMR_REPLY, (void *)tempaddr, sizeof(struct lmr_info), new_request->store_addr, new_request->store_semaphore, LOW_PRIORITY);
                                        }
					//kmem_cache_free(post_receive_cache, new_request->msg);
					client_free_lmr_info_buf(ret_mr);
					client_free_recv_buf(new_request->msg);
					//printk(KERN_CRIT "%s: send MR back %x %x %x\n", __func__, (unsigned int)ret_mr->addr, ret_mr->lkey, ret_mr->rkey);
					break;
				}
			case MSG_GET_REMOTE_ATOMIC_OPERATION:
				{
					//down(&request_mr[*(int*)ptr]);
					int length;
					//int connection_id;
					void *addr;
					struct lmr_info *ret_mr;
					uintptr_t tempaddr;

					memcpy(&length, new_request->msg, new_request->length);
					//connection_id = client_get_connection_by_atomic_number(ctx, new_request->src_id, LOW_PRIORITY);

					//addr = kmalloc(length * sizeof(char), GFP_KERNEL);
					addr = client_alloc_memory_for_mr(length*sizeof(char));
					memset(addr, 0, length * sizeof(char));
					ret_mr = client_ib_reg_mr(ctx, addr, length, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_ATOMIC);
					tempaddr = client_ib_reg_mr_addr(ctx, ret_mr, sizeof(struct lmr_info));
					client_send_message_sge_UD(ctx, new_request->src_id, MSG_GET_REMOTEMR_REPLY, (void *)tempaddr, sizeof(struct lmr_info), new_request->store_addr, new_request->store_semaphore, LOW_PRIORITY);
					client_free_lmr_info_buf(ret_mr);
					client_free_recv_buf(new_request->msg);
					break;
				}
			//EREP
			
			case MSG_QUERY_PORT_1:
				{
					uintptr_t tempaddr;
					struct ask_mr_form *input_form;
					struct ask_mr_reply_form ret;
					struct app_reg_port *current_hash_ptr;
					int found = 0;
					int bucket;
					uint64_t port_node_key;
					
					void *addr;
					struct lmr_info *ret_mr=NULL;
					struct app_reg_port *entry;

					memset(&ret, 0, sizeof(struct ask_mr_reply_form));
					input_form = (struct ask_mr_form *)new_request->msg;
					
					//port_node_key = (input_form->designed_port<<MAX_NODE_BIT) + new_request->src_id;
					//printk(KERN_CRIT "%s: start searching from 0\n", __func__);
					//Always search for 0. If 0 is existed, generate one ring for user
					port_node_key = (input_form->designed_port<<MAX_NODE_BIT) + 0;
					bucket = port_node_key % (1<<HASH_TABLE_SIZE_BIT);
					rcu_read_lock();
					hash_for_each_possible_rcu(LOCAL_MEMORYRING_PORT_HASHTABLE, current_hash_ptr, hlist, bucket)
					{
						if(current_hash_ptr->port_node_key == port_node_key)
						{
							found = 1;
							break;
						}
					}
					rcu_read_unlock();
					if(found)
					{

						//printk(KERN_CRIT "%s: at the begining from node %d get query port %d name %s\n", __func__, new_request->src_id, input_form->designed_port, current_hash_ptr->name);
						//do add for this source_id only
						port_node_key = (input_form->designed_port<<MAX_NODE_BIT) + new_request->src_id;
						bucket = port_node_key%(1<<HASH_TABLE_SIZE_BIT);
						entry = (struct app_reg_port *)kmem_cache_alloc(app_reg_cache, GFP_KERNEL);
						memset(entry, 0, sizeof(struct app_reg_port));
						entry->hash_key = bucket;
						entry->port_node_key = port_node_key;
						entry->node = new_request->src_id;
						entry->port = input_form->designed_port;
						entry->last_ack_index = 0;
						spin_lock_init(&entry->last_ack_index_lock);
						memcpy(entry->name, current_hash_ptr->name, strlen(current_hash_ptr->name));
						
						addr = client_alloc_memory_for_mr(IMM_PORT_CACHE_SIZE);
						entry->addr = addr;
						
						ret_mr = client_ib_reg_mr(ctx, addr, IMM_PORT_CACHE_SIZE, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ);
						memcpy(&entry->ring_mr, ret_mr, sizeof(struct lmr_info));

						spin_lock(&(LOCAL_MEMORYRING_PORT_HASHTABLE_LOCK[bucket]));
						hash_add_rcu(LOCAL_MEMORYRING_PORT_HASHTABLE, &entry->hlist, bucket);
						spin_unlock(&(LOCAL_MEMORYRING_PORT_HASHTABLE_LOCK[bucket]));
						
						printk(KERN_CRIT "%s: from node %d get query port %d name %s\n", __func__, new_request->src_id, entry->port, entry->name);
						ret.op_code = MR_ASK_SUCCESS;
						memcpy(&ret.reply_mr, &entry->ring_mr, sizeof(struct lmr_info));
					}
					else
					{
						printk(KERN_CRIT "%s: from node %d fail to get query port %d\n", __func__, new_request->src_id, input_form->designed_port);
						ret.op_code = MR_ASK_REFUSE; 
					}

					//atomic_inc(&ctx->imm_perport_reg_num[input_form->designed_port]);
					ctx->imm_perport_reg_num[input_form->designed_port]++;

					tempaddr = client_ib_reg_mr_addr(ctx, &ret, sizeof(struct ask_mr_reply_form));
					client_send_message_sge_UD(ctx, new_request->src_id, MSG_QUERY_PORT_2, (void *)tempaddr, sizeof(struct ask_mr_reply_form), new_request->store_addr, new_request->store_semaphore, LOW_PRIORITY);
					if(ret_mr)
						client_free_lmr_info_buf(ret_mr);
					client_free_recv_buf(new_request->msg);
					break;
				}
			case MSG_DO_ACK_INTERNAL:
				{
					//First do check again
                                        int offset = new_request->length;
					struct app_reg_port *ptr = (struct app_reg_port *)new_request->msg;
					int target_node = ptr->node;
					int target_port = ptr->port;
					//printk(KERN_CRIT "%s: [generate ACK node-%d port-%d offset-%d]\n", __func__, target_node, target_port, offset);
					//if( (offset>= last_ack && offset - last_ack >= IMM_PORT_CACHE_SIZE/IMM_ACK_PORTION ) ||
					//    (offset< last_ack && offset + IMM_PORT_CACHE_SIZE - last_ack >= IMM_PORT_CACHE_SIZE/IMM_ACK_PORTION))//Pass check again, update index and submit a ACK to the remote side
					{
						struct imm_ack_form ack_packet;
						uintptr_t tempaddr;
						//ptr->last_ack_index = offset;
						ack_packet.node_id= ctx->node_id;
						ack_packet.designed_port = target_port;
						ack_packet.ack_offset = offset;
						tempaddr = client_ib_reg_mr_addr(ctx, &ack_packet, sizeof(struct imm_ack_form));
						client_send_message_sge_UD(ctx, target_node, MSG_DO_ACK_REMOTE, (void *)tempaddr, sizeof(struct imm_ack_form), 0, 0, LOW_PRIORITY);
					}
					break;
				}
			case MSG_DO_ACK_REMOTE:
				{

					int bucket;
					uint64_t port_node_key;
					struct app_reg_port *current_hash_ptr;
					int found=0;
					struct imm_ack_form *tmp = (struct imm_ack_form *)new_request->msg;
					int last_ack = tmp->ack_offset;
					//check first
					port_node_key = (tmp->designed_port<<MAX_NODE_BIT) + tmp->node_id;
					bucket = port_node_key % (1<<HASH_TABLE_SIZE_BIT);
					rcu_read_lock();
					hash_for_each_possible_rcu(REMOTE_MEMORYRING_PORT_HASHTABLE, current_hash_ptr, hlist, bucket)
					{
						if(current_hash_ptr->port_node_key == port_node_key)
						{
							found = 1;
							break;
						}
					}
					rcu_read_unlock();
					if(found)
					{
						current_hash_ptr->last_ack_index = last_ack;
					}
					//printk(KERN_CRIT "%s: [receive ACK node-%d port-%d offset-%d]\n", __func__, tmp->node_id, tmp->designed_port, tmp->ack_offset);
					client_free_recv_buf(new_request->msg);
					break;
				}
			case MSG_CREATE_LOCK:
				{
					void *addr;
					void *ret_mr;
					struct lite_lock_form ret_lock;
					int lock_num;
					uintptr_t tempaddr;
					int source_id;

					memset(&ret_lock, 0, sizeof(struct lite_lock_form));
					lock_num = atomic_inc_return(&ctx->lock_num) -1;
					source_id = new_request->src_id;
					if(lock_num<LITE_MAX_LOCK_NUM)//under MAX_LOCK_NUM and the request is not generated by local node
					{
						addr = client_alloc_memory_for_mr(8*sizeof(char));
						memset(addr, 0, 8 * sizeof(char));
						ret_mr = client_ib_reg_mr(ctx, addr, 8, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_ATOMIC);
						memcpy(&ret_lock.lock_mr, ret_mr, sizeof(struct lmr_info));
						ret_lock.lock_num = lock_num;
						
						memcpy(&ctx->lock_data[lock_num], &ret_lock, sizeof(struct lite_lock_form));
						
						if(!local_flag)
						{
							tempaddr = client_ib_reg_mr_addr(ctx, &ret_lock, sizeof(struct lite_lock_form));
							client_send_message_sge_UD(ctx, new_request->src_id, MSG_CREATE_LOCK_REPLY, (void *)tempaddr, sizeof(struct lite_lock_form), new_request->store_addr, new_request->store_semaphore, LOW_PRIORITY);
							client_free_lmr_info_buf(ret_mr);
						}
						else
						{
							client_send_message_local_reply(ctx, new_request->src_id, MSG_CREATE_LOCK_REPLY, &ret_lock, sizeof(struct lite_lock_form), new_request->store_addr, new_request->store_semaphore, LOW_PRIORITY);
						}

						printk(KERN_CRIT "%s:[create_lock] lock_num:%d addr-%p rkey-%d src_id-%d\n", __func__, ret_lock.lock_num, ret_lock.lock_mr.addr, ret_lock.lock_mr.rkey, ret_lock.lock_mr.node_id);
					}
					else
					{
						printk(KERN_CRIT "%s:[error] fail to create a new lock because it's already hit max lock\n", __func__);
						ret_lock.lock_num = -1;
						if(!local_flag)
                                                {
        						tempaddr = client_ib_reg_mr_addr(ctx, &ret_lock, sizeof(struct lite_lock_form));
        						client_send_message_sge_UD(ctx, new_request->src_id, MSG_CREATE_LOCK_REPLY, (void *)tempaddr, sizeof(struct lite_lock_form), new_request->store_addr, new_request->store_semaphore, LOW_PRIORITY);
                                                }
                                                else
                                                {       
							client_send_message_local_reply(ctx, new_request->src_id, MSG_CREATE_LOCK_REPLY, &ret_lock, sizeof(struct lite_lock_form), new_request->store_addr, new_request->store_semaphore, LOW_PRIORITY);
                                                }
					}
					if(!local_flag)
						client_free_recv_buf(new_request->msg);
					break;
				}
			case MSG_ASK_LOCK:
				{
					struct lite_lock_form ret_lock;
					int lock_num;
					uintptr_t tempaddr;
					int ask_num;
					memcpy(&ask_num, new_request->msg, new_request->length);
					memset(&ret_lock, 0, sizeof(struct lite_lock_form));
					lock_num = atomic_read(&ctx->lock_num);
					if(ask_num < LITE_MAX_LOCK_NUM && ask_num<=lock_num && ctx->lock_data[ask_num].lock_num==ask_num)//lock exist
					{
						memcpy(&ret_lock, &ctx->lock_data[ask_num], sizeof(struct lite_lock_form));
						if(!local_flag)
						{
							tempaddr = client_ib_reg_mr_addr(ctx, &ret_lock, sizeof(struct lite_lock_form));
							client_send_message_sge_UD(ctx, new_request->src_id, MSG_ASK_LOCK_REPLY, (void *)tempaddr, sizeof(struct lite_lock_form), new_request->store_addr, new_request->store_semaphore, LOW_PRIORITY);
						}
						else
						{
							client_send_message_local_reply(ctx, new_request->src_id, MSG_ASK_LOCK_REPLY, &ret_lock, sizeof(struct lite_lock_form), new_request->store_addr, new_request->store_semaphore, LOW_PRIORITY);
						}
						printk(KERN_CRIT "%s:[share_lock] lock_num:%d addr-%p rkey-%d src_id-%d\n", __func__, ret_lock.lock_num, ret_lock.lock_mr.addr, ret_lock.lock_mr.rkey, ret_lock.lock_mr.node_id);
					}
					else
					{
						//printk(KERN_CRIT "%s:[lock doesn't exist] %d\n", __func__, ask_num);
						ret_lock.lock_num = -1;
						if(!local_flag)
						{
							tempaddr = client_ib_reg_mr_addr(ctx, &ret_lock, sizeof(struct lite_lock_form));
							client_send_message_sge_UD(ctx, new_request->src_id, MSG_ASK_LOCK_REPLY, (void *)tempaddr, sizeof(struct lite_lock_form), new_request->store_addr, new_request->store_semaphore, LOW_PRIORITY);
						}
						else
						{
							client_send_message_local_reply(ctx, new_request->src_id, MSG_ASK_LOCK_REPLY, &ret_lock, sizeof(struct lite_lock_form), new_request->store_addr, new_request->store_semaphore, LOW_PRIORITY);
						}
					}
					if(!local_flag)
						client_free_recv_buf(new_request->msg);
					break;
				}
			case MSG_RESERVE_LOCK:
				{
					struct lite_lock_reserve_form *tmp = (struct lite_lock_reserve_form *)new_request->msg;
					int tar_lock = tmp->lock_num;
					int ticket_num = tmp->ticket_num;
					int tar_lock_index = tar_lock * LITE_MAX_LOCK_NUM + ticket_num;
					int found=0;
					struct lite_lock_queue_element *current_lock_hash_ptr;
					int bucket;
					struct lite_lock_queue_element *new_lock_hash_ptr;
					//printk(KERN_CRIT "%s: receive reservelock through message-%llu\n", __func__, tmp->ticket_num);
					
					
					
					bucket = tar_lock_index % (1<<HASH_TABLE_SIZE_BIT);
					rcu_read_lock();
					hash_for_each_possible_rcu(LOCK_QUEUE_HASHTABLE, current_lock_hash_ptr, hlist, bucket)
					{
						if(current_lock_hash_ptr->tar_lock_index == tar_lock_index)
						{
							found = 1;
							hash_del_rcu(&current_lock_hash_ptr->hlist);
							break;
						}
					}
					rcu_read_unlock();
					if(found)//Means the lock is already arrived or there is one old lock
					{
						int ret=1;
						uintptr_t tempaddr;
						if(current_lock_hash_ptr->state!=UNLOCK_ALREADY_ARRIVED)
						{
							printk(KERN_CRIT "%s: [reserve lock error] src_id-%d tar_lock_index-%d state-%d\n", __func__, current_lock_hash_ptr->src_id, tar_lock_index, current_lock_hash_ptr->state);
							if(!local_flag)
								client_free_recv_buf(new_request->msg);
							break;
						}
						//spin_lock(&(LOCK_QUEUE_HASHTABLE_LOCK[bucket]));
						//spin_unlock(&(LOCK_QUEUE_HASHTABLE_LOCK[bucket]));
						if(!local_flag)
						{
							tempaddr = client_ib_reg_mr_addr(ctx, &ret, sizeof(int));
							client_send_message_sge_UD(ctx, new_request->src_id, MSG_ASSIGN_LOCK, (void *)tempaddr, sizeof(int), new_request->store_addr, new_request->store_semaphore, KEY_PRIORITY);
						}
						else
						{
							client_send_message_sge_UD(ctx, new_request->src_id, MSG_ASSIGN_LOCK, &ret, sizeof(int), new_request->store_addr, new_request->store_semaphore, KEY_PRIORITY);
						}
						//kfree(current_hash_ptr);
						//if(current_lock_hash_ptr)
						//	kmem_cache_free(lock_queue_element_buffer_cache, current_lock_hash_ptr);
						//else
						//	printk(KERN_CRIT "%s: free error at line %d\n", __func__, __LINE__);
					}
					else
					{
						//struct lite_lock_queue_element *new_hash_ptr = kmalloc(sizeof(struct lite_lock_queue_element), GFP_KERNEL);
						
						new_lock_hash_ptr = (struct lite_lock_queue_element *)kmem_cache_alloc(lock_queue_element_buffer_cache, GFP_KERNEL);
						new_lock_hash_ptr->store_addr = new_request->store_addr;
						new_lock_hash_ptr->store_semaphore = new_request->store_semaphore;
						new_lock_hash_ptr->src_id = new_request->src_id;
						new_lock_hash_ptr->ticket_num = ticket_num;
						new_lock_hash_ptr->lock_num = tar_lock;
						new_lock_hash_ptr->state = WAIT_FOR_UNLOCK;
						new_lock_hash_ptr->tar_lock_index = tar_lock_index;
						
						spin_lock(&(LOCK_QUEUE_HASHTABLE_LOCK[bucket]));
						hash_add_rcu(LOCK_QUEUE_HASHTABLE, &new_lock_hash_ptr->hlist, bucket);
						spin_unlock(&(LOCK_QUEUE_HASHTABLE_LOCK[bucket]));

					}
					if(!local_flag)
						client_free_recv_buf(new_request->msg);
					break;
				}
			case MSG_UNLOCK:
				{
					struct lite_lock_reserve_form *tmp = (struct lite_lock_reserve_form *)new_request->msg;
					int tar_lock = tmp->lock_num;
					int ticket_num = tmp->ticket_num;
					int next_num = ticket_num + 1;
					int tar_lock_index = tar_lock * LITE_MAX_LOCK_NUM + ticket_num;
					int next_lock_index = tar_lock * LITE_MAX_LOCK_NUM + next_num;
					struct lite_lock_queue_element *current_lock_hash_ptr;
					struct lite_lock_queue_element *next_lock_hash_ptr;
					struct lite_lock_queue_element *new_lock_hash_ptr;
					int bucket;
					int found = 0;
					//printk(KERN_CRIT "%s: receive unlock through message-%llu\n", __func__, tmp->ticket_num);

					bucket = tar_lock_index % (1<<HASH_TABLE_SIZE_BIT);
					rcu_read_lock();
					hash_for_each_possible_rcu(LOCK_QUEUE_HASHTABLE, current_lock_hash_ptr, hlist, bucket)
					{
						if(current_lock_hash_ptr->tar_lock_index == tar_lock_index)
						{
							found = 1;
							hash_del_rcu(&current_lock_hash_ptr->hlist);
							break;
						}
					}
					rcu_read_unlock();
					if(found)//If there is one hash entry, remove it
					{	
						//spin_lock(&(LOCK_QUEUE_HASHTABLE_LOCK[bucket]));
						//hash_del_rcu(&current_lock_hash_ptr->hlist);
						//spin_unlock(&(LOCK_QUEUE_HASHTABLE_LOCK[bucket]));
						//kfree(current_hash_ptr);
						if(current_lock_hash_ptr)
							kmem_cache_free(lock_queue_element_buffer_cache, current_lock_hash_ptr);
						else
							printk(KERN_CRIT "%s: free error at line %d\n", __func__, __LINE__);
					}
					found = 0;
					
					bucket = next_lock_index % (1<<HASH_TABLE_SIZE_BIT);
					rcu_read_lock();
					hash_for_each_possible_rcu(LOCK_QUEUE_HASHTABLE, next_lock_hash_ptr, hlist, bucket)
					{
						if(next_lock_hash_ptr->tar_lock_index == next_lock_index)
						{
							found = 1;
							hash_del_rcu(&next_lock_hash_ptr->hlist);
							break;
						}
					}
					rcu_read_unlock();
					if(found)//If there is one hash entry, unlock it, but don't remove it since this would be removed by future unlock request
					{
						int ret=1;
						uintptr_t tempaddr;
						if(next_lock_hash_ptr->state!=WAIT_FOR_UNLOCK)//unlock the next one
						{
							printk(KERN_CRIT "%s: [unlock error] src_id-%d tar_lock_index-%d state-%d\n", __func__, next_lock_hash_ptr->src_id, next_lock_index, next_lock_hash_ptr->state);
							if(!local_flag)
								client_free_recv_buf(new_request->msg);
							break;
						}
						//printk(KERN_CRIT "%s: unlock arrive after lock-%llu\n", __func__, tmp->ticket_num);
						if(next_lock_hash_ptr->src_id != ctx->node_id)
						{
							tempaddr = client_ib_reg_mr_addr(ctx, &ret, sizeof(int));
							client_send_message_sge_UD(ctx, next_lock_hash_ptr->src_id, MSG_ASSIGN_LOCK, (void *)tempaddr, sizeof(int), next_lock_hash_ptr->store_addr, next_lock_hash_ptr->store_semaphore, KEY_PRIORITY);
						}
						else
						{
							client_send_message_local_reply(ctx, next_lock_hash_ptr->src_id, MSG_ASSIGN_LOCK, &ret, sizeof(int), next_lock_hash_ptr->store_addr, next_lock_hash_ptr->store_semaphore, KEY_PRIORITY);
							//printk(KERN_CRIT "%s: receive unlock through message-%llu\n", __func__, tmp->ticket_num);
						}
						//kfree(next_hash_ptr);
						if(next_lock_hash_ptr)
							kmem_cache_free(lock_queue_element_buffer_cache, next_lock_hash_ptr);
						else
							printk(KERN_CRIT "%s: free error at line %d\n", __func__, __LINE__);
					}
					else
					{
						new_lock_hash_ptr = kmalloc(sizeof(struct lite_lock_queue_element), GFP_KERNEL);
						
						new_lock_hash_ptr->state = UNLOCK_ALREADY_ARRIVED;
						new_lock_hash_ptr->tar_lock_index = next_lock_index;
						
						spin_lock(&(LOCK_QUEUE_HASHTABLE_LOCK[bucket]));
						hash_add_rcu(LOCK_QUEUE_HASHTABLE, &new_lock_hash_ptr->hlist, bucket);
						spin_unlock(&(LOCK_QUEUE_HASHTABLE_LOCK[bucket]));
					}

					if(!local_flag)
						client_free_recv_buf(new_request->msg);
					else
						kfree(new_request->msg);//Only this one is processed different since this message call is in send type instead of send-reply
					break;
				}
			case MSG_MR_REQUEST:
				{
					struct mr_request_form *tar_form;
					//int connection_id;
					uint64_t ret;
					int success_flag=0;
					uintptr_t tempaddr;
					tar_form = (struct mr_request_form *)new_request->msg;
					if(tar_form->op_code == OP_REMOTE_MEMSET)//handling remote memset
					{
						void *real_addr;
						real_addr = __va(tar_form->request_mr.addr); //Grab this code from phys_to_virt() in asm-generic/io.h directly
						memset(real_addr + tar_form->offset, 0, tar_form->size);
						success_flag=1;
					}
					else if(tar_form->op_code == OP_REMOTE_DEREGISTER)
					{
						int found=0;
						//get the lmr metadata first
						struct hash_mraddr_to_lmr_metadata *current_hash_ptr;
						uint64_t input_key = (uint64_t)tar_form->request_mr.addr;
                                                //uint64_t bucket = hash_min((uint64_t)input_key, HASH_TABLE_SIZE_BIT);
	                                        uint64_t bucket = input_key<<HASH_TABLE_SIZE_BIT;
	                                        //int bucket = (uint64_t)tar_form->request_mr.addr%(1<<HASH_TABLE_SIZE_BIT);
                                                //printk(KERN_CRIT "bucket %lx %lx\n", bucket, input_key);
                                                //printk(KERN_CRIT "get deregister request %lx\n", input_key);
						rcu_read_lock();
						hash_for_each_possible_rcu(MR_HASHTABLE, current_hash_ptr, hlist, bucket)
						{
							if(current_hash_ptr->hash_key == input_key)
							{
								found = 1;
								break;
							}
						}
						rcu_read_unlock();
						current_hash_ptr->mother_addr->permission=0;
						success_flag=1;
					}
					else if(tar_form->op_code == OP_REMOTE_MEMMOV || tar_form->op_code == OP_REMOTE_MEMCPY)
					{
						int target_node;
						int connection_id;
						int priority = LOW_PRIORITY;
						void *real_addr;
						real_addr = __va(tar_form->request_mr.addr);
						target_node = tar_form->copyto_mr.node_id;
						if(target_node != ctx->node_id)	
						{
							connection_id = client_get_connection_by_atomic_number(ctx, target_node, priority);
							client_send_request(ctx, connection_id, M_WRITE, &tar_form->copyto_mr, real_addr+tar_form->offset, tar_form->size, tar_form->copyto_offset, LITE_KERNELSPACE_FLAG, 0);
						}
						else
						{
							void *copyto_addr;
							copyto_addr = __va(tar_form->copyto_mr.addr);
							memcpy(copyto_addr+tar_form->copyto_offset, real_addr + tar_form->offset, tar_form->size);
						}
						if(tar_form->op_code == OP_REMOTE_MEMMOV)
						{
							memset(real_addr + tar_form->offset, 0, tar_form->size);
						}
						success_flag=1;
					}
					/*
					else if(tar_form->op_code == OP_REMOTE_FREE)
					{
						int found=0;
						//get the lmr metadata first
						struct hash_mraddr_to_lmr_metadata *current_hash_ptr;
						uint64_t input_key = (uint64_t)tar_form->request_mr.addr;
						int i;						
						rcu_read_lock();
						hash_for_each_possible_rcu(MR_HASHTABLE, current_hash_ptr, hlist, input_key)
						{
							if(current_hash_ptr->hash_key == input_key)
							{
								found = 1;
								break;
							}
						}
						rcu_read_unlock();
						if(found)
						{
							for(i=find_next_bit(temp_ptr->askmr_bitmap, MAX_NODE, 0);i<MAX_NODE;)
							{
								liteapi_send_message(i, )
								i=find_next_bit(temp_ptr->askmr_bitmap, MAX_NODE, i);
							}
						}
						else
						{
							ret = MR_ASK_UNKNOWN;
							tempaddr = client_ib_reg_mr_addr(&ret, sizeof(uint64_t));
							connection_id = client_get_connection_by_atomic_number(new_request->src_id, LOW_PRIORITY);
							client_send_message_sge(connection_id, MSG_GET_SEND_AND_REPLY_2, (void *)tempaddr, sizeof(uint64_t), new_request->store_addr, new_request->store_semaphore, LOW_PRIORITY);
						}
					}
					*/
					//send success message back to the sender
					if(success_flag)
						ret = MR_ASK_SUCCESS;
					else
						ret = MR_ASK_UNKNOWN;
					if(!local_flag)
					{
						tempaddr = client_ib_reg_mr_addr(ctx, &ret, sizeof(uint64_t));
						client_send_message_sge_UD(ctx, new_request->src_id, MSG_GET_SEND_AND_REPLY_2, (void *)tempaddr, sizeof(uint64_t), new_request->store_addr, new_request->store_semaphore, LOW_PRIORITY);
						client_free_recv_buf(new_request->msg);
					}
					else
					{	
						client_send_message_local_reply(ctx, new_request->src_id, MSG_GET_SEND_AND_REPLY_2, &ret, sizeof(uint64_t), new_request->store_addr, new_request->store_semaphore, LOW_PRIORITY);
					}

					break;
				}
			default:
				printk(KERN_ALERT "%s: receive weird event %d\n", __func__, new_request->type);
		}
		spin_lock(&wq_lock[queue_flag]);
		list_del(&new_request->list);
		spin_unlock(&wq_lock[queue_flag]);
		//kfree(new_request);

		kmem_cache_free(s_r_cache, new_request);
		//}
		//spin_unlock(&wq_lock);
	}
}

int client_asy_latest_job_add(ltc *ctx, int type, uint64_t key, int offset, int size)
{
	int tmp=0;
	int required_page_num;
	int bucket = key%(1<<HASH_TABLE_SIZE_BIT);

	//Reserve page numbers based on write requested size
	if(type == ASY_WRITE || type == SYN_WRITE)
	{
		int ini_page_num = offset/RING_BUFFER_MAXSIZE;
		int last_page_num = (size+offset)/RING_BUFFER_MAXSIZE;
		if((size+offset)%RING_BUFFER_MAXSIZE==0)
		{
			last_page_num --;
		}
		required_page_num = last_page_num - ini_page_num + 1;
		tmp = atomic_add_return(required_page_num, &ctx->asy_latest_job);//Roundup
		//printk(KERN_CRIT "add pagenum %d after %d\n", required_page_num, atomic_read(&ctx->asy_latest_job));
	}
	else
	{
		tmp = atomic_inc_return(&ctx->asy_latest_job);
		//printk(KERN_CRIT "get tmp %d after %d\n", tmp, atomic_read(&ctx->asy_latest_job));
	}

	//ctx->asy_latest_job = (ctx->asy_latest_job + 1) % RING_BUFFER_LENGTH;
	if(type == ASY_WRITE || type == ASY_READ || type == SYN_WRITE)//Process Hash table, Increase the respective count
	{

		struct hash_asyio_key *temp_ptr;			
		rcu_read_lock();
		hash_for_each_possible_rcu(ASYIO_HASHTABLE, temp_ptr, hlist, bucket)
		{
			if(temp_ptr->lite_handler==key)
			{
				if(type == ASY_WRITE || type == SYN_WRITE)
					temp_ptr->count = temp_ptr->count + required_page_num;
				else
					temp_ptr->count++;
				break;
			}
		}
		rcu_read_unlock();
		if(!temp_ptr)
		{
			printk(KERN_CRIT "Search error in asy_latest\n");
		}
	}
	//spin_unlock(&ctx->asy_latest_job_lock);

	//Avoid ring buffer over-run
	while(tmp-atomic_read(&ctx->asy_current_job)>RING_BUFFER_LENGTH/2)
		schedule();
	return tmp;
}
EXPORT_SYMBOL(client_asy_latest_job_add);

inline int client_asy_current_job_add(ltc *ctx)
{
	return atomic_inc_return(&ctx->asy_current_job);
}

void asy_page_cache_free(void *ptr)
{
	kmem_cache_free(asy_page_cache, ptr);
}

void asy_hash_page_key_cache_free(void *ptr)
{
	kmem_cache_free(asy_hash_page_key_cache, ptr);
}

/**
 * client_process_userspace_fast_receive - process and push the data to the respected receiver if the receiver is already back to userspace for fast receive
 * @ctx: lite context
 * @ret_addr: receive address
 * @receive_size: max receive size
 * @reply_descriptor: buffer for the header of incomming message (used for reply)
 * @ret_length: buffer for received message size
 * @node_id: source node id
 * @offset: internal offset of port LMR (for internal processing)
 * @port: port of the incomming message
 * @local_flag: distinguish whether this is a local request or not
 */
int client_process_userspace_fast_receive(ltc *ctx, void *ret_addr, int receive_size, void *reply_descriptor, void *ret_length, int node_id, uint64_t offset, int port, int local_flag)
{

        
	struct imm_message_metadata *tmp;
	int get_size;
	struct imm_message_metadata *descriptor;
	
	struct app_reg_port *current_hash_ptr;
	int found = 0;
	int bucket;
	uint64_t port_node_key;
	int last_ack;
	int ack_flag=0;
	
        descriptor = (struct imm_message_metadata *)kmem_cache_alloc(imm_message_metadata_cache, GFP_KERNEL);
	if(unlikely(!descriptor))
	{
		printk(KERN_CRIT "%s: descriptor alloc fail\n", __func__);
                return SEND_REPLY_FAIL;
	}
        if(!local_flag)
        {
                port_node_key = (port<<MAX_NODE_BIT) + node_id;
                current_hash_ptr = ctx->last_port_node_key_hash_ptr;
                if(!current_hash_ptr || current_hash_ptr->port_node_key != port_node_key)
                {
                        current_hash_ptr = NULL;
                        bucket = port_node_key % (1<<HASH_TABLE_SIZE_BIT);
                        rcu_read_lock();
                        hash_for_each_possible_rcu(LOCAL_MEMORYRING_PORT_HASHTABLE, current_hash_ptr, hlist, bucket)
                        {
                                if(current_hash_ptr->port_node_key == port_node_key)
                                {
                                        found = 1;
                                        ctx->last_port_node_key_hash_ptr = current_hash_ptr;
                                        break;
                                }
                        }
                        rcu_read_unlock();
                }
                else
                {
                        found = 1;
                }

                //The above part takes around 20 ns
                //validate hashtable
                if(unlikely(!found))
                {
                        printk(KERN_CRIT "%s: node-%d port-%d [significant error], since ring is not generated yet\n", __func__, node_id, port);
                        return SEND_REPLY_PORT_NOT_OPENED;
                }
                //validate ring address
                if(unlikely(!current_hash_ptr->addr))
                {
                        printk(KERN_CRIT "%s: node-%d port-%d offset-%llu [significant error], ring is not generated after query\n", __func__, node_id, port, offset);
                        return SEND_REPLY_PORT_NOT_OPENED;
                }

                //point to header within ring/buffer based on offset
                tmp = (struct imm_message_metadata *)(current_hash_ptr->addr + offset);
                get_size = tmp->size;
                //Check size
                if(unlikely(get_size > receive_size))
                {
                        printk(KERN_CRIT "%s: receive %d but only call with %d\n", __func__, get_size, receive_size);
                        return SEND_REPLY_SIZE_TOO_BIG;
                }
        }
        else
        {
                tmp = (struct imm_message_metadata *)offset;
                get_size = receive_size;
                current_hash_ptr = NULL;
        }

	//do data memcpy
        
        //below copy function takes from 30 - 200ns
        memcpy(ret_addr, ((void *)tmp) + sizeof(struct imm_message_metadata), get_size);
        memcpy(ret_length, &get_size, sizeof(int));

	//has to keep data in descriptor
        //these two memcpy (one for pointer, one for data) use 30ns, 100ns(few)
	memcpy(descriptor, tmp, sizeof(struct imm_message_metadata));
        if(descriptor->store_addr!= (uintptr_t) NULL)
                memcpy(reply_descriptor, &descriptor, sizeof(struct imm_message_metadata *));
        else//send only processing
        {
                struct imm_message_metadata *null_descriptor = (struct imm_message_metadata *)IMM_SEND_ONLY_FLAG;
                memcpy(reply_descriptor, &null_descriptor, sizeof(struct imm_message_metadata *));
	        kmem_cache_free(imm_message_metadata_cache, descriptor);
        }
	
        //do ack based on the last_ack_index, submit a request to waiting_queue_handler	
	
        if(!local_flag)
        {
                spin_lock(&current_hash_ptr->last_ack_index_lock);//Check takes around 30-40 ns
                last_ack = current_hash_ptr->last_ack_index;

                offset = offset + sizeof(struct imm_message_metadata) + get_size;
                if( (offset>= last_ack && offset - last_ack >= IMM_PORT_CACHE_SIZE/IMM_ACK_PORTION ) ||
                    (offset< last_ack && offset + IMM_PORT_CACHE_SIZE - last_ack >= IMM_PORT_CACHE_SIZE/IMM_ACK_PORTION))
                {
                        ack_flag = 1;
                        current_hash_ptr->last_ack_index = offset;
                        //printk(KERN_CRIT "[%s] generate ACK with offset %d and index %d\n", __func__, offset, current_hash_ptr->last_ack_index);
                }
                spin_unlock(&current_hash_ptr->last_ack_index_lock);
                if(ack_flag)//Ack takes around 85 - 120 ns
                {	
                        struct send_and_reply_format *pass;
                        pass = kmem_cache_alloc(s_r_cache, GFP_KERNEL);
                        pass->msg = (char*)current_hash_ptr;
                        pass->length = offset;
                        //pass->length = (offset / (IMM_PORT_CACHE_SIZE/IMM_ACK_PORTION)) * (IMM_PORT_CACHE_SIZE/IMM_ACK_PORTION);
                        //pass->length = (last_ack_index + 1) % IMM_ACK_PORTION;
                        pass->type = MSG_DO_ACK_INTERNAL;

                        spin_lock(&wq_lock[QUEUE_ACK]);
                        list_add_tail(&(pass->list), &request_list[QUEUE_ACK].list);
                        spin_unlock(&wq_lock[QUEUE_ACK]);
                }
        }
        return 0;
}

int client_poll_cq_pass(struct thread_pass_struct *input)
{
	client_poll_cq(input->ctx, input->target_cq);
	kfree(input);
	printk(KERN_CRIT "%s: kill ctx %p cq %p\n", __func__, (void *)input->ctx, (void *)input->target_cq);
	do_exit(0);
	return 0;
}

/**
 * client_poll_cq - polling the CQ (for RC QP) to get IMM completion
 * @ctx: lite context
 * @target_cq: target polling CQ
 */
int client_poll_cq(ltc *ctx, struct ib_cq *target_cq)
{
	int ne;
	struct ib_wc wc[NUM_POLLING_WC];
	int i, connection_id;
        int temp_tar;
        struct imm_header_from_cq_to_port *tmp;
        int cq_num=-1;
	#ifdef NOTIFY_MODEL
	int test_result=0;
	#endif
	allow_signal(SIGKILL);
        for(i=0;i<NUM_POLLING_THREADS;i++)
        {
                if(ctx->cq[i]==target_cq)
                {
                        cq_num = i;
                        break;
                }
        }
        if(cq_num==-1)
                printk(KERN_CRIT "%s: [significant error] initialize cq %p fail\n", __func__, target_cq);
	//set_current_state(TASK_INTERRUPTIBLE);

	while(1)
	{
#ifdef BUSY_POLL_MODEL
		do{
			//set_current_state(TASK_RUNNING);
			ne = ib_poll_cq(target_cq, NUM_POLLING_WC, wc);
			if(ne < 0)
			{
				printk(KERN_ALERT "poll CQ failed %d\n", ne);
				return 1;
			}
			if(ne==0)
			{
				//if(ne >= 1)
				//	break;
				schedule();
                                ctx->imm_cq_is_available[cq_num]=1;
				//cpu_relax();
				//set_current_state(TASK_INTERRUPTIBLE);
				if(kthread_should_stop())
				{
					printk(KERN_ALERT "Stop cq and return\n");
					return 0;
				}
			}
			//msleep(1);
		}while(ne < 1);
		//test7 starts, ends in liteapi_receive_message_userspace which takes 306ns
		//test8 starts, ends in later this function to test demultiplex latency, 29ns
#endif
#ifdef NOTIFY_MODEL
		ne = ib_poll_cq(target_cq, NUM_POLLING_WC, wc);
		if(ne < 0)
		{
			printk(KERN_ALERT "poll CQ failed %d\n", ne);
			return 1;
		}
		if(ne == 0)
		{
			test_result = ib_req_notify_cq(target_cq, IB_CQ_NEXT_COMP);
			if(test_result < 0)
			{
				printk(KERN_ALERT "notify under 0 as %d\n", test_result);
			}
			test_result = client_block_until_cqevent(ctx, target_cq);
			if(test_result!=0)
			{
				printk(KERN_ALERT "error in poller after block %d\n", test_result);
			}
			ne = ib_poll_cq(target_cq, NUM_POLLING_WC, wc);
		}
		schedule();
		if(kthread_should_stop())
		{
			printk(KERN_ALERT "Stop cq and return\n");
			return 0;
		}
#endif
		//test13 starts ends in lite_liteapi.c to trace between poll and return to user (210ns (4K) 187ns(8))
                ctx->imm_cq_is_available[cq_num]=0;
		for(i=0;i<ne;++i)
		{
                        if(unlikely(wc[i].status!= IB_WC_SUCCESS))
			        printk(KERN_ALERT "%s: failed status (%d) for wr_id %d\n", __func__, wc[i].status, (int) wc[i].wr_id);
                        switch((int)wc[i].opcode)
                        {
                                case IB_WC_RECV_RDMA_WITH_IMM:
                                {
                                        //int node_id = client_find_node_id_by_qpnum(ctx, wc[i].qp->qp_num); //Move this into post-receive after basic impl
                                        int node_id = GET_NODE_ID_FROM_POST_RECEIVE_ID(wc[i].wr_id);
                                        int port;
                                        int offset;
                                        //	trace_start = ktime_get();
                                        //	trace_end = ktime_get();
                                        //	trace_count++;
                                        //	trace_sum += ktime_to_ns(ktime_sub(trace_end, trace_start));
                                        //	printk(KERN_CRIT "run %d for %lld ns\n", trace_count, trace_sum/trace_count);
                                        if(wc[i].wc_flags&&IB_WC_WITH_IMM)
                                        {
                                                if(wc[i].ex.imm_data & IMM_SEND_REPLY_SEND && wc[i].ex.imm_data & IMM_SEND_REPLY_RECV)//opcode
                                                {
                                                        int semaphore;
                                                        int opcode;
                                                        printk(KERN_CRIT "%s: opcode from node %d\n", __func__, node_id);
                                                        semaphore = wc[i].ex.imm_data & IMM_GET_SEMAPHORE;
                                                        opcode = IMM_GET_OPCODE_NUMBER(wc[i].ex.imm_data);
                                                        //printk(KERN_CRIT "%s: case 1 semaphore-%d\n", __func__, semaphore);
                                                        *(int *)(ctx->imm_store_semaphore[semaphore]) = -(opcode);
                                                        ctx->imm_store_semaphore[semaphore] = NULL;
                                                        clear_bit(semaphore, ctx->imm_store_semaphore_bitmap);
                                                }
                                                else if(wc[i].ex.imm_data & IMM_SEND_REPLY_SEND) // only send
                                                {
                                                        //char *tmp_check = kzalloc(1024, GFP_KERNEL);
                                                        //It needs average 150ns to pass a message into event_queue
                                                        offset = wc[i].ex.imm_data & IMM_GET_OFFSET; 
                                                        port = IMM_GET_PORT_NUMBER(wc[i].ex.imm_data);

                                                        //if(atomic_read(&ctx->imm_perport_reg_num[port])<0)//this port is closed
                                                        if(unlikely(ctx->imm_perport_reg_num[port]<0))
                                                        {
                                                                printk(KERN_CRIT "%s: from node %d access to port %d is banned. This should not happen since sender should not be able to send this request out\n", __func__, node_id, port);
                                                        }
                                                        //printk(KERN_CRIT "%s: from node %d access to port %d imm-%x\n", __func__, node_id, port, wc[i].ex.imm_data);
                                                        
                                                        spin_lock(&ctx->imm_waitqueue_perport_lock[port]);
                                                        if(!list_empty(&ctx->imm_wait_userspace_perport[port].list))//someone is waiting inside userspace
                                                        {
                                                                struct imm_header_from_cq_to_userspace *tmp_u;
                                                                tmp_u = list_entry(ctx->imm_wait_userspace_perport[port].list.next, struct imm_header_from_cq_to_userspace, list);
                                				list_del(&tmp_u->list);
                                                                client_process_userspace_fast_receive(ctx, tmp_u->ret_addr, tmp_u->receive_size, tmp_u->reply_descriptor, tmp_u->ret_length, node_id, offset, port, 0);
				                                kmem_cache_free(imm_wait_userspace_buffer_cache, tmp_u);
                                                        }
                                                        else
                                                        {
                                                                //tmp = (struct imm_header_from_cq_to_port *)kmem_cache_alloc(imm_header_from_cq_to_port_cache, GFP_KERNEL);
                                                                //tmp->source_node_id = node_id;
                                                                //tmp->offset = offset;
                                                                //list_add_tail(&(tmp->list), &ctx->imm_waitqueue_perport[port].list);
                                                                temp_tar = ctx->imm_waitqueue_perport_count_poll[port]%IMM_ROUND_UP;
                                                                tmp = ctx->imm_waitqueue_perport[port];
                                                                tmp[temp_tar].source_node_id = node_id;
                                                                tmp[temp_tar].offset = offset;
                                                                //printk(KERN_CRIT "%s: write tar:%d id:%d offset:%d\n", __func__, temp_tar, tmp[temp_tar].source_node_id, tmp[temp_tar].offset);
                                                                ctx->imm_waitqueue_perport_count_poll[port]++;
                                                        }
                                                        spin_unlock(&ctx->imm_waitqueue_perport_lock[port]);
                                                        #ifdef RECV_WAITQUEUE_MODEL
                                                                wake_up_interruptible(&ctx->imm_receive_block_queue[port]);
                                                        #endif
							//test8 ends
                                                }
                                                else //handle reply
                                                {
                                                        int semaphore;
                                                        int length = wc[i].byte_len;
                                                        semaphore = wc[i].ex.imm_data & IMM_GET_SEMAPHORE;
                                                        //printk(KERN_CRIT "%s: case 2 semaphore-%d len-%d\n", __func__, semaphore, wc[i].byte_len);
                                                        //*(int *)(ctx->imm_store_semaphore[semaphore]) = wc[i].byte_len;
                                                        if(semaphore <0 || semaphore >= IMM_NUM_OF_SEMAPHORE || !ctx->imm_store_semaphore[semaphore])
                                                        {
                                                                printk(KERN_CRIT "%s: error in semaphore %d len %d %p\n", __func__, semaphore, length, ctx->imm_store_semaphore[semaphore]);
                                                        }
                                                        memcpy((void *)ctx->imm_store_semaphore[semaphore], &length, sizeof(int));

                                                        #ifdef ADAPTIVE_MODEL
                                                        if(semaphore >= IMM_NUM_OF_SEMAPHORE || semaphore <0)
                                                        {
                                                                printk(KERN_CRIT "%s: [significant error]error semaphore %d\n", __func__, semaphore);
                                                        }
                                                        wake_up_interruptible(&ctx->imm_store_block_queue[semaphore]);//Wakeup waiting queue
                                                        #endif
                                                        #ifdef SCHEDULE_MODEL
                                                        wake_up_process(ctx->imm_store_semaphore_task[semaphore]);
                                                        ctx->imm_store_semaphore_task[semaphore]=NULL;
                                                        #endif
                                                        

                                                        //spin_lock(&ctx->imm_store_semaphore_lock[semaphore]);
                                                        ctx->imm_store_semaphore[semaphore] = NULL;
                                                        //spin_unlock(&ctx->imm_store_semaphore_lock[semaphore]);
                                                        clear_bit(semaphore, ctx->imm_store_semaphore_bitmap);
                                                }
                                        }
                                        //if(wc[i].wr_id%(ctx->rx_depth/4) == ((ctx->rx_depth/4)-1))
                                        if(GET_POST_RECEIVE_DEPTH_FROM_POST_RECEIVE_ID(wc[i].wr_id)%(ctx->rx_depth/4) == ((ctx->rx_depth/4)-1))
                                        {
                                                struct send_and_reply_format *recv;
                                                connection_id = client_find_qp_id_by_qpnum(ctx, wc[i].qp->qp_num);	
                                                recv = kmem_cache_alloc(s_r_cache, GFP_KERNEL);
                                                recv->length = ctx->rx_depth/4;
                                                recv->src_id = connection_id;
                                                recv->type = MSG_DO_RC_POST_RECEIVE;

                                                spin_lock(&wq_lock[QUEUE_POST_RECV]);
                                                list_add_tail(&(recv->list), &request_list[QUEUE_POST_RECV].list);
                                                spin_unlock(&wq_lock[QUEUE_POST_RECV]);
                                                //ctx->recv_num[connection_id]=ctx->recv_num[connection_id] - ctx->rx_depth/4;
                                        }
                                }
                                break;
                                case IB_WC_RECV:
				        printk(KERN_CRIT "%s: receive IB_WC_RECV which should not happened\n", __func__);
                                        break;
                                default:
				        connection_id = client_find_qp_id_by_qpnum(ctx, wc[i].qp->qp_num);
        				printk(KERN_ALERT "%s: connection %d Recv weird event as %d\n", __func__, connection_id, (int)wc[i].opcode);
                        }
		}
	}
	return 0;
}

int client_poll_cq_UD_pass(struct thread_pass_struct *input)
{
	client_poll_cq_UD(input->ctx, input->target_cq);
	kfree(input);
	printk(KERN_CRIT "%s: kill ctx %p UD cq %p\n", __func__, (void *)input->ctx, (void *)input->target_cq);
	do_exit(0);
	return 0;
}

/**
 * client_poll_cq_UD - polling the CQ (for UD QP) to get LITE internal messaging
 * @ctx: lite context
 * @target_cq: target polling CQ
 */
int client_poll_cq_UD(ltc *ctx, struct ib_cq *target_cq)
{
	int ne;
	struct ib_wc wc[NUM_PARALLEL_CONNECTION];
	int i;
	#ifdef NOTIFY_MODEL_UD
	int test_result = 0;
	#endif
	allow_signal(SIGKILL);
	//set_current_state(TASK_INTERRUPTIBLE);

	while(1)
	{
		#ifdef NOTIFY_MODEL_UD
		ne = ib_poll_cq(target_cq, NUM_PARALLEL_CONNECTION, wc);
		if(ne < 0)
		{
			printk(KERN_ALERT "poll CQ failed %d\n", ne);
			return 1;
		}
		if(ne == 0)
		{
			test_result = ib_req_notify_cq(target_cq, IB_CQ_NEXT_COMP);
			if(test_result < 0)
			{
				printk(KERN_ALERT "%s: notify under 0 as %d\n", __func__, test_result);
			}
			test_result = client_block_until_cqevent(ctx, target_cq);
			if(test_result!=0)
			{
				printk(KERN_ALERT "%s: error in poller after block %d\n", __func__, test_result);
			}
			ne = ib_poll_cq(target_cq, NUM_PARALLEL_CONNECTION, wc);
		}
		schedule();
		if(kthread_should_stop())
		{
			printk(KERN_ALERT "Stop cq and return\n");
			return 0;
		}
		#endif


		#ifdef BUSY_POLL_MODEL_UD
		do{
			//set_current_state(TASK_RUNNING);
			ne = ib_poll_cq(target_cq, NUM_PARALLEL_CONNECTION, wc);
			if(ne < 0)
			{
				printk(KERN_ALERT "poll CQ failed %d\n", ne);
				return 1;
			}
			if(ne==0)
			{
				schedule();
				if(kthread_should_stop())
				{
					printk(KERN_ALERT "Stop cq and return\n");
					return 0;
				}
			}
		}while(ne < 1);
		#endif
		for(i=0;i<ne;++i)
		{
			if(wc[i].status != IB_WC_SUCCESS)
			{
				printk(KERN_ALERT "%s: failed status (%d) for wr_id %d\n", __func__, wc[i].status, (int) wc[i].wr_id);
			}
			if((int) wc[i].opcode == IB_WC_RECV)
			{
				char *addr;
				int type;
				struct liteapi_post_receive_intermediate_struct *p_r_i_struct = (struct liteapi_post_receive_intermediate_struct*)wc[i].wr_id;
				struct liteapi_header *header_addr;
				struct liteapi_header temp_header;
				//ktime_t self_time;
				//self_time = ktime_get();

				//header_addr = ((struct liteapi_header*)p_r_i_struct->header)+40;
				memcpy(&temp_header, (void *)p_r_i_struct->header + 40, sizeof(struct liteapi_header));
				header_addr = &temp_header;
				addr = (char *)p_r_i_struct->msg;
				ctx->recv_numUD++;
				type = header_addr->type;
				//printk(KERN_ALERT "receive %d\n", type);
				switch(type)
				{
					case MSG_CLIENT_SEND:
					case MSG_SERVER_SEND:	
					{
						struct send_and_reply_format *recv;
						recv = kmem_cache_alloc(s_r_cache, GFP_KERNEL);
						recv->length = header_addr->length;
						recv->src_id = header_addr->src_id;
						recv->msg = addr;
						recv->type = type;

						spin_lock(&wq_lock[QUEUE_LOW]);
						list_add_tail(&(recv->list), &request_list[QUEUE_LOW].list);
						spin_unlock(&wq_lock[QUEUE_LOW]);
						//kmem_cache_free(header_cache, header_addr);
						header_cache_free(header_addr);
						break;
					}
					case MSG_GET_SEND_AND_REPLY_1:
					case MSG_GET_SEND_AND_REPLY_OPT_1:
					{
						struct send_and_reply_format *recv;

						recv = kmem_cache_alloc(s_r_cache, GFP_KERNEL);
						recv->src_id = header_addr->src_id;
						recv->store_addr = header_addr->store_addr;
						recv->store_semaphore = header_addr->store_semaphore;
						recv->length = header_addr->length;
						recv->msg = addr;
						recv->type = type;

						spin_lock(&wq_lock[QUEUE_LOW]);
						list_add_tail(&(recv->list), &request_list[QUEUE_LOW].list);
						spin_unlock(&wq_lock[QUEUE_LOW]);
						//kmem_cache_free(header_cache, header_addr);
						header_cache_free(header_addr);
						break;
					}	
					case MSG_RESERVE_LOCK:
					case MSG_UNLOCK:
					case MSG_GET_REMOTEMR:
					case MSG_ASK_MR_1:
					case MSG_DIST_BARRIER:
					{
						struct send_and_reply_format *recv;
						recv = kmem_cache_alloc(s_r_cache, GFP_KERNEL);


						recv->src_id = header_addr->src_id;
						recv->store_addr = header_addr->store_addr;
						recv->store_semaphore = header_addr->store_semaphore;
						recv->length = header_addr->length;
						recv->msg = addr;
						recv->type = type;
						
						spin_lock(&wq_lock[QUEUE_HIGH]);
						list_add_tail(&(recv->list), &request_list[QUEUE_HIGH].list);
						spin_unlock(&wq_lock[QUEUE_HIGH]);
						//kmem_cache_free(header_cache, header_addr);
						header_cache_free(header_addr);
						break;
					}
					case MSG_MR_REQUEST:
					{
						struct send_and_reply_format *recv;
						recv = kmem_cache_alloc(s_r_cache, GFP_KERNEL);


						recv->src_id = header_addr->src_id;
						recv->store_addr = header_addr->store_addr;
						recv->store_semaphore = header_addr->store_semaphore;
						recv->length = header_addr->length;
						recv->msg = addr;
						recv->type = type;

						spin_lock(&wq_lock[QUEUE_MEDIUM]);
						list_add_tail(&(recv->list), &request_list[QUEUE_MEDIUM].list);
						spin_unlock(&wq_lock[QUEUE_MEDIUM]);
						//kmem_cache_free(header_cache, header_addr);
						header_cache_free(header_addr);
						break;
					}
					case MSG_GET_REMOTE_ATOMIC_OPERATION:
					case MSG_QUERY_PORT_1:
					case MSG_PASS_LOCAL_IMM:
					case MSG_DO_ACK_REMOTE:
					case MSG_CREATE_LOCK:
					case MSG_ASK_LOCK:
					{
						struct send_and_reply_format *recv;
						recv = kmem_cache_alloc(s_r_cache, GFP_KERNEL);


						recv->src_id = header_addr->src_id;
						recv->store_addr = header_addr->store_addr;
						recv->store_semaphore = header_addr->store_semaphore;
						recv->length = header_addr->length;
						recv->msg = addr;
						recv->type = type;

						spin_lock(&wq_lock[QUEUE_LOW]);
						list_add_tail(&(recv->list), &request_list[QUEUE_LOW].list);
						spin_unlock(&wq_lock[QUEUE_LOW]);
						//kmem_cache_free(header_cache, header_addr);
						header_cache_free(header_addr);
						break;
					}
					case MSG_NODE_JOIN:
					{
						struct task_struct *thread_create_new_node;
						struct thread_pass_struct *input = kmalloc(sizeof(struct thread_pass_struct), GFP_KERNEL);
						input->ctx = ctx;
						input->msg = addr;
						thread_create_new_node = kthread_create((void *)client_add_newnode_pass, input, "create new node");
						//printk(KERN_ALERT "%s: Create RC node %s\n", __func__, input->msg);
						if(IS_ERR(thread_create_new_node))
						{
							printk(KERN_ALERT "Fail to create a new thread for new node\n");
						}
						else
						{
							wake_up_process(thread_create_new_node);
						}
						//kmem_cache_free(header_cache, header_addr);
						header_cache_free(header_addr);
						break;
					}
					case MSG_NODE_JOIN_UD:
					{
						struct client_ah_combined *input_ah_attr;
						struct ib_ah_attr ah_attr;
						int node_id;
						input_ah_attr = (struct client_ah_combined *) addr;
						node_id = input_ah_attr->node_id;
						memcpy(&ctx->ah_attrUD[node_id], addr, sizeof(struct client_ah_combined));
						memset(&ah_attr, 0, sizeof(struct ib_ah_attr));
						ah_attr.dlid      = ctx->ah_attrUD[node_id].dlid;
						ah_attr.sl        = UD_QP_SL;
						ah_attr.src_path_bits = 0;
						ah_attr.port_num = 1;
						if(SGID_INDEX!=-1)
						{
							//ah_attr.grh.dgid = ctx->ah_attrUD[node_id].gid;
							memcpy(&ah_attr.grh.dgid, &ctx->ah_attrUD[node_id].gid, sizeof(union ib_gid));
							ah_attr.ah_flags = 1;
							ah_attr.grh.sgid_index = SGID_INDEX;
							ah_attr.grh.hop_limit = 1;
						}
						ctx->ah[node_id] = ib_create_ah(ctx->pd, &ah_attr);
						printk(KERN_CRIT "%s: create UD dlid %d qpn %d nodeid %d ah %p\n", __func__, ctx->ah_attrUD[node_id].dlid, ctx->ah_attrUD[node_id].qpn, ctx->ah_attrUD[node_id].node_id, ctx->ah[node_id]);
						client_free_recv_buf(addr);
						header_cache_free(header_addr);
						break;
					}
					case MSG_GET_SEND_AND_REPLY_2:
					case MSG_GET_ATOMIC_REPLY:
					case MSG_GET_REMOTEMR_REPLY:
					case MSG_ASSIGN_LOCK:
					case MSG_ASK_MR_2:
					case MSG_QUERY_PORT_2:
					{
						if(header_addr->length > 5120)
						{
							printk(KERN_CRIT "IB_BUG: from lid %d receive type %d with len %d addr: %llu semaphore: %llu\n", wc[i].slid, type, header_addr->length, header_addr->store_addr, header_addr->store_semaphore);
						}
						memcpy((void *)header_addr->store_addr, addr, header_addr->length);
						memcpy((void *)header_addr->store_semaphore, &header_addr->length, sizeof(uint32_t));
						client_free_recv_buf(addr);
						header_cache_free(header_addr);
						break;
					}
					case MSG_CREATE_LOCK_REPLY:
					case MSG_ASK_LOCK_REPLY:
					{
						struct lite_lock_form *tmp;
						tmp = (struct lite_lock_form *)addr;
						if(tmp->lock_num!=-1)
						{
							memcpy((void *)header_addr->store_addr, addr, header_addr->length);
							memcpy((void *)header_addr->store_semaphore, &header_addr->length, sizeof(uint32_t));
						}
						else
						{
							int ret = SEND_REPLY_EMPTY;
							memcpy((void *)header_addr->store_semaphore, &ret, sizeof(int));
						}
						client_free_recv_buf(addr);
						header_cache_free(header_addr);
						break;
					}
					case MSG_GET_SEND_AND_REPLY_OPT_2:
					{
						//*(header_addr->store_addr) = addr;
						//memcpy((void *)header_addr->store_addr, &addr, sizeof(void *));
						*(void **)header_addr->store_addr = addr;
						*(int *)header_addr->store_semaphore = header_addr->length;
						//kmem_cache_free(header_cache, header_addr);
						header_cache_free(header_addr);
						break;
					}
					default:
					{
						printk(KERN_ALERT "%s: [SIGNIFICANT ERROR]from lid %d Weird type received as %d\n", __func__, wc[i].slid, type);
					}	
				}
				/*else if(type == MSG_GET_ATOMIC_START || type == MSG_GET_ATOMIC_SINGLE_START)
				{
					int request_len = 0;
					memcpy(&request_len, addr, header_addr->length);
					//printk(KERN_CRIT "connection %d receive atomic reqs with length %d\n",connection_id, request_len);
					ctx->atomic_buffer[connection_id] = (struct atomic_struct *)kmalloc(request_len * sizeof(struct atomic_struct), GFP_ATOMIC);
					ctx->atomic_buffer_total_length[connection_id] = request_len;
					ctx->atomic_buffer_cur_length[connection_id] = 0;
					//kmem_cache_free(header_cache, header_addr);
					header_cache_free(header_addr);
				}
				else if(type == MSG_GET_ATOMIC_MID || type == MSG_GET_ATOMIC_SINGLE_MID)
				{
					int cur_number;
					if(ctx->atomic_buffer_cur_length[connection_id]<0)
					{
						printk(KERN_CRIT "IB_BUG:RECEIVE ATOMIC_MID without getting ATOMIC_START: from connection :%d data len: %d file type %d cur_len in ctx:%d\n", connection_id,  header_addr->length, type, ctx->atomic_buffer_cur_length[connection_id]);
					}
					cur_number = ctx->atomic_buffer_cur_length[connection_id];
					printk(KERN_CRIT "%d receive atomic reqs cur_number %d vaddr %p len %d num-atomic-receieved %d as type %d \n", connection_id, cur_number, addr, header_addr->length, ctx->atomic_buffer_cur_length[connection_id], type);
					//char *temp_memspace;
					//temp_memspace = kmalloc(RDMA_BUFFER_SIZE*4, GFP_KERNEL);
					//memcpy(temp_memspace, addr, header_addr->length);
					//ctx->atomic_buffer[connection_id][cur_number].vaddr = temp_memspace;
					ctx->atomic_buffer[connection_id][cur_number].vaddr = addr;

					ctx->atomic_buffer[connection_id][cur_number].len = header_addr->length;
					//printk(KERN_CRIT "receive atomic reqs cur_number %d vaddr %lx len %d num-atomic-receieved %d\n", 
					//		cur_number, addr, header_addr->length, ctx->atomic_buffer_cur_length[connection_id]);
					ctx->atomic_buffer_cur_length[connection_id]++;
					if(ctx->atomic_buffer_cur_length[connection_id]==ctx->atomic_buffer_total_length[connection_id])
					{
						//ctx->atomic_send_handler(ctx->atomic_buffer[connection_id], ctx->atomic_buffer_cur_length[connection_id]);
						struct send_and_reply_format *recv;
						recv = kmem_cache_alloc(s_r_cache, GFP_KERNEL);

						recv->msg = (char *)ctx->atomic_buffer[connection_id];
						recv->src_id = header_addr->src_id;
						recv->store_addr = header_addr->store_addr;
						recv->store_semaphore = header_addr->store_semaphore;
						//recv->length = header_addr->length;
						recv->length = ctx->atomic_buffer_total_length[connection_id];
						recv->type = type;

						//					printk(KERN_CRIT "MSG_GET_ATOMIC_MID length %d type %d\n", recv->length, recv->type);

						// temprory fix to always create new thread of handler for atomic operations, TODO: create new apis to do this separately from normal atomic operations
						if (type == MSG_GET_ATOMIC_MID)
						{
							struct thread_pass_struct *thread_pass = kmalloc(sizeof(struct thread_pass_struct), GFP_KERNEL);
							thread_pass->ctx = ctx;
							thread_pass->sr_request = recv;
							kthread_run((void *)atomic_send_reply_thread_helper, thread_pass, "atomicsendreply handler");
						}
						if (type == MSG_GET_ATOMIC_SINGLE_MID)
						{
							struct thread_pass_struct *thread_pass = kmalloc(sizeof(struct thread_pass_struct), GFP_KERNEL);
							thread_pass->ctx = ctx;
							thread_pass->sr_request = recv;
							kthread_run((void *)atomic_send_thread_helper, thread_pass, "atomicsendreply handler");
						}	
						ctx->atomic_buffer_cur_length[connection_id]=-1;
						// normal atomic operations that use the same thread of handler 
						//spin_lock(&wq_lock);
						//list_add_tail(&(recv->list), &request_list.list);
						//spin_unlock(&wq_lock);
					}
					//kmem_cache_free(header_cache, header_addr);
					header_cache_free(header_addr);
				}*/
				if(ctx->recv_numUD==ctx->rx_depth/4)
				{
					//client_post_receives_message_UD(ctx, ctx->rx_depth);
					//ctx->recv_numUD=1;
					struct send_and_reply_format *recv;
					recv = kmem_cache_alloc(s_r_cache, GFP_KERNEL);
					recv->length = ctx->rx_depth/4;
					recv->type = MSG_DO_UD_POST_RECEIVE;

					spin_lock(&wq_lock[QUEUE_POST_RECV]);
					list_add_tail(&(recv->list), &request_list[QUEUE_POST_RECV].list);
					spin_unlock(&wq_lock[QUEUE_POST_RECV]);
					ctx->recv_numUD=ctx->recv_numUD - ctx->rx_depth/4;
				}
				kmem_cache_free(intermediate_cache, p_r_i_struct);
			}
			else
			{	
				printk(KERN_ALERT "UD Recv weird event as %d\n", (int)wc[i].opcode);
			}

		}
	}
	do_exit(0);
	return 0;
}

inline int client_get_congestion_status(ltc *ctx, int connection_id)
{
	return atomic_read(&ctx->connection_congestion_status[connection_id]);
}

/**
 * client_get_connection_by_atomic_number - get a QP based on target node (in RR order)
 * @ctx: lite context
 * @target_node: destionation node id
 * @priority: priority level
 */
inline int client_get_connection_by_atomic_number(ltc *ctx, int target_node, int priority)
{
#ifdef PRIORITY_IMPLEMENTATION_RESOURCE
	if(priority == USERSPACE_LOW_PRIORITY)
		return NUM_PARALLEL_CONNECTION * target_node;
	else
		return atomic_inc_return(&ctx->atomic_request_num[target_node])%(NUM_PARALLEL_CONNECTION-1) + NUM_PARALLEL_CONNECTION * target_node + 1;
#endif
	return atomic_inc_return(&ctx->atomic_request_num[target_node])%(NUM_PARALLEL_CONNECTION) + NUM_PARALLEL_CONNECTION * target_node;
}
EXPORT_SYMBOL(client_get_connection_by_atomic_number);

void client_setup_liteapi_header(uint32_t src_id, uint64_t store_addr, uint64_t store_semaphore, uint32_t length, int priority, int type, struct liteapi_header *output_header)
{
	output_header->src_id = src_id;
	output_header->store_addr = store_addr;
	output_header->store_semaphore = store_semaphore;
	output_header->length = length;
	output_header->priority = priority;
	output_header->type = type;
}
EXPORT_SYMBOL(client_setup_liteapi_header);

/**
 * client_send_message_local - send a LITE internal message to a local controller
 * @ctx: lite context
 * @target_node: always the local node id
 * @type: type of message
 * @addr: message address
 * @size: size of the message
 * @store_addr: address of reply buffer
 * @store_semaphore: semaphore of reply buffer
 * @priority: priority level
 */
int client_send_message_local(ltc *ctx, int target_node, int type, void *addr, int size, uint64_t store_addr, uint64_t store_semaphore, int priority)
{
	struct send_and_reply_format *recv;
	recv = kmem_cache_alloc(s_r_cache, GFP_KERNEL);

	recv->src_id = ctx->node_id;
	recv->store_addr = store_addr;
	recv->store_semaphore = store_semaphore;
	recv->length = size;
	recv->msg = addr;
	recv->type = type;

	spin_lock(&wq_lock[QUEUE_HIGH]);
	list_add_tail(&(recv->list), &request_list[QUEUE_HIGH].list);
	spin_unlock(&wq_lock[QUEUE_HIGH]);
	//kmem_cache_free(header_cache, header_addr);
	return 0;
}
EXPORT_SYMBOL(client_send_message_local);

/**
 * client_send_message_local - reply for a lite local internal message
 * @ctx: lite context
 * @target_node: always the local node id
 * @type: type of message
 * @addr: message address
 * @size: size of the message
 * @store_addr: address of reply buffer
 * @store_semaphore: semaphore of reply buffer
 * @priority: priority level
 */
int client_send_message_local_reply(ltc *ctx, int target_node, int type, void *addr, int size, uint64_t store_addr, uint64_t store_semaphore, int priority)
{
	memcpy((void *)store_addr, addr, size);
	memcpy((void *)store_semaphore, &size, sizeof(int));
	return 0;
}
EXPORT_SYMBOL(client_send_message_local_reply);

/**
 * client_send_message_sge_UD - send a LITE internal message to a remote node
 * @ctx: lite context
 * @target_node: always the local node id
 * @type: type of message
 * @addr: message address
 * @size: size of the message
 * @store_addr: address of reply buffer
 * @store_semaphore: semaphore of reply buffer
 * @priority: priority level
 */
int client_send_message_sge_UD(ltc *ctx, int target_node, int type, void *addr, int size, uint64_t store_addr, uint64_t store_semaphore, int priority)
{	
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge[2];
	int ret;
	int ne, i;
	struct ib_wc wc[2];

	struct liteapi_header output_header;
	void *output_header_addr;

	spin_lock(&ctx->connection_lockUD);

	memset(&wr, 0, sizeof(wr));
	memset(sge, 0, sizeof(struct ib_sge)*2);

	wr.wr_id = type;
	wr.opcode = IB_WR_SEND;
	wr.sg_list = sge;
	wr.num_sge = 2;
	wr.send_flags = IB_SEND_SIGNALED;
	wr.wr.ud.ah = ctx->ah[target_node];
	wr.wr.ud.remote_qpn = ctx->ah_attrUD[target_node].qpn;
	wr.wr.ud.remote_qkey = ctx->ah_attrUD[target_node].qkey;
	//printk(KERN_CRIT "%s: ah %p qpn %d qkey %d\n", __func__, wr.wr.ud.ah, wr.wr.ud.remote_qpn, wr.wr.ud.remote_qkey);

	client_setup_liteapi_header(ctx->node_id, store_addr, store_semaphore, size, priority, type, &output_header);
	output_header_addr = (void *)client_ib_reg_mr_addr(ctx, &output_header, sizeof(struct liteapi_header));
	sge[0].addr = (uintptr_t)output_header_addr;
	sge[0].length = sizeof(struct liteapi_header);
	sge[0].lkey = ctx->proc->lkey;

	sge[1].addr = (uintptr_t)addr;
	sge[1].length = size;
	sge[1].lkey = ctx->proc->lkey;
	ret = ib_post_send(ctx->qpUD, &wr, &bad_wr);
	if(ret==0){
		do{
			ne = ib_poll_cq(ctx->send_cqUD, 1, wc);
			if(ne < 0)
			{
				printk(KERN_ALERT "poll send_cq failed at UD\n");
				return 1;
			}
		}while(ne<1);
		for(i=0;i<ne;i++)
		{
			if(wc[i].status!=IB_WC_SUCCESS)
			{
				printk(KERN_ALERT "send failed at UD as %d\n", wc[i].status);
				return 2;
			}
		}
	}
	else{
		printk(KERN_INFO "send fail at UD\n");
	}
	spin_unlock(&ctx->connection_lockUD);
	return ret;
}
EXPORT_SYMBOL(client_send_message_sge_UD);

int client_send_cq_poller(ltc *ctx)
{
	int ne, i;
	struct ib_wc *wc;
	wc = kmalloc(sizeof(struct ib_wc)*128, GFP_KERNEL);
	while(1)
	{
		do{
			ne = ib_poll_cq(ctx->send_cq[0], 128, wc);
			if(ne < 0)
			{
				printk(KERN_ALERT "%s: poll send_cq polling failed at connection\n", __func__);
			}
			if(ne==0)
			{
				schedule();
				if(kthread_should_stop())
				{
					printk(KERN_ALERT "%s: Stop sendcq-poller and return\n", __func__);
					return 0;
				}
			}
		}while(ne<1);
		for(i=0;i<ne;i++)
		{
			if(wc[i].status!=IB_WC_SUCCESS)
			{
				printk(KERN_ALERT "%s: send request failed at id %llu as %d\n", __func__, wc[i].wr_id, wc[i].status);
			}
			//else
			//	printk(KERN_ALERT "%s: send request success at id %llu as %d\n", __func__, wc[i].wr_id, wc[i].status);
			*(int*)wc[i].wr_id = -wc[i].status;
		}
	}
	return 0;
}

/**
 * client_send_request - issue a RDMA request
 * @ctx: lite context
 * @connection_id: target QP index
 * @s_mode: read or write
 * @input_mr: target memory region information
 * @addr: message address
 * @size: size of the message
 * @offset: remote offset
 * @userspace_flag: distinguish this request is from kernel space or userspace
 * @poll_addr: shared memory space to improve polling efficiency
 */
int client_send_request(ltc *ctx, int connection_id, enum mode s_mode, struct lmr_info *input_mr, void *addr, int size, int offset, int userspace_flag, int *poll_addr)
{
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge;
	//struct lmr_info *ret;
	int ret;
	uintptr_t tempaddr;
	int poll_status = SEND_REPLY_WAIT;

	//#ifdef NON_SHARE_POLL_CQ_MODEL
        //spin_lock(&connection_lock[connection_id]);
        //#endif

	retry_send_request:
	memset(&wr, 0, sizeof(struct ib_send_wr));
	memset(&sge, 0, sizeof(struct ib_sge));

	wr.wr_id = (uint64_t)&poll_status;
        if(poll_addr)
                wr.wr_id = (uint64_t)poll_addr;
	wr.opcode = (s_mode == M_WRITE) ? IB_WR_RDMA_WRITE : IB_WR_RDMA_READ;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IB_SEND_SIGNALED;
	//wr.send_flags = 0;

	wr.wr.rdma.remote_addr = (uintptr_t) (input_mr->addr+offset);
	wr.wr.rdma.rkey = input_mr->rkey;
	if(userspace_flag)
	{
		sge.addr = (uintptr_t)addr;
	}
	else
	{
		tempaddr = client_ib_reg_mr_addr(ctx, addr, size);
		sge.addr = tempaddr;
	}
	sge.length = size;
	sge.lkey = ctx->proc->lkey;

	//test2 ends
	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	//test3 starts (ends in client_internal_poll_sendcq) takes 4973ns for 4K read, and takes 1989ns for 8B read
	if(!ret)
	{
                if(!poll_addr)
                {
        		client_internal_poll_sendcq(ctx->send_cq[connection_id], connection_id, &poll_status);
        		if(poll_status)
	        		goto retry_send_request;
                }
	}
	else
	{
		printk(KERN_INFO "%s: send fail %d ret %d\n", __func__, connection_id, ret);
	}
	
        //#ifdef NON_SHARE_POLL_CQ_MODEL
	//spin_unlock(&connection_lock[connection_id]);
        //#endif
	return 0;
}
EXPORT_SYMBOL(client_send_request);

/**
 * client_internal_poll_sendcq - polling the send-cq by a sharing way
 * @tar_cq: target polling cq
 * @connection_id: target QP index
 * @check: shared memory space to improve sharing polling
 */
int client_internal_poll_sendcq(struct ib_cq *tar_cq, int connection_id, int *check)
{
        #ifdef SHARE_POLL_CQ_MODEL 
	while((*check)==SEND_REPLY_WAIT)
	{
		cpu_relax();
                //schedule();
	}
	return 0;
        #endif
        #ifdef NON_SHARE_POLL_CQ_MODEL	
        int ne, i;
	struct ib_wc wc[2];
        while(1)
        {
                do{
                        ne = ib_poll_cq(tar_cq, 1, wc);
                        if(ne < 0)
                        {
                                printk(KERN_ALERT "poll send_cq failed at connection %d\n", connection_id);
                                return 1;
                        }
                        if((*check)!=SEND_REPLY_WAIT)
                                break;
                }while(ne<1);
		//test3 ends
		//test4 starts (ends in liteapi_rdma_read_offset_userspace takes 15ns)
                for(i=0;i<ne;i++)
                {
                        if(wc[i].status!=IB_WC_SUCCESS)
                        {
                                printk(KERN_ALERT "send request %lu failed as %d\n", (unsigned long)wc[i].wr_id, wc[i].status);
                        }
                        if(wc[i].wr_id)
                                *(int*)wc[i].wr_id = -wc[i].status;
                }
                if((*check)!=SEND_REPLY_WAIT)
                        break;
        }
	return 0;
        #endif
}
EXPORT_SYMBOL(client_internal_poll_sendcq);

/**
 * client_get_offset_and_mr_by_length - get the correspondence offset and memory region info in a send request
 * @ctx: lite context
 * @target_node: target node id
 * @designed_port: get correspondent port
 * @size: request size
 * @mr: buffer for returned LMR info
 */
inline int client_get_offset_and_mr_by_length(ltc *ctx, int target_node, int designed_port, int size, struct lmr_info **mr)
{
	int ret;

	int bucket;
	uint64_t port_node_key;
	//check first
	struct app_reg_port *current_hash_ptr;
	int found=0;
	int last_ack;
        if(target_node==ctx->node_id)
                return REG_DO_LOCAL_SEND;

	port_node_key = (designed_port<<MAX_NODE_BIT) + target_node;
	//printk(KERN_CRIT "%s: checking key as %d\n", __func__, port_node_key);
	bucket = port_node_key % (1<<HASH_TABLE_SIZE_BIT);
	rcu_read_lock();
	hash_for_each_possible_rcu(REMOTE_MEMORYRING_PORT_HASHTABLE, current_hash_ptr, hlist, bucket)
	{
		if(current_hash_ptr->port_node_key == port_node_key)
		{
			found = 1;
			break;
		}
	}
	rcu_read_unlock();
	if(!found)
		return REG_DO_QUERY_FIRST;

	spin_lock(&current_hash_ptr->remote_imm_offset_lock);
	if(current_hash_ptr->remote_imm_ring_index + size >= IMM_PORT_CACHE_SIZE)//If hits the end of ring, write start from 0 directly
		current_hash_ptr->remote_imm_ring_index = size;//Record the last point
	else
		current_hash_ptr->remote_imm_ring_index += size;
	ret = current_hash_ptr->remote_imm_ring_index - size;//Trace back to the real starting point
	spin_unlock(&current_hash_ptr->remote_imm_offset_lock);
	
	//make sure does not over write than lastack
	while(1)
	{
		last_ack = current_hash_ptr->last_ack_index;
		if(ret < last_ack && ret + size > last_ack)
                {
			schedule();
                }
		else
			break;
	}
	*mr = &current_hash_ptr->ring_mr;
	return ret;
}

/**
 * client_get_store_by_addr - get the next available store address for RPC request
 * @ctx: lite context
 * @addr: input address
 */
inline int client_get_store_by_addr(ltc *ctx, void *addr)
{
	int tar;
        spin_lock(&ctx->imm_store_semaphore_lock[0]);
        tar = find_first_zero_bit(ctx->imm_store_semaphore_bitmap, IMM_NUM_OF_SEMAPHORE);
        while(tar==IMM_NUM_OF_SEMAPHORE)
        {
                schedule();
                tar = find_first_zero_bit(ctx->imm_store_semaphore_bitmap, IMM_NUM_OF_SEMAPHORE);
        }
        set_bit(tar, ctx->imm_store_semaphore_bitmap);
        spin_unlock(&ctx->imm_store_semaphore_lock[0]);
        ctx->imm_store_semaphore[tar] = addr;
	return tar;
}

/**
 * client_send_reply_with_rdma_write_with_imm_sge - issue a RDMA request with several sge request - mainly used for multicast in kernel
 * !!!This function is in beta version. Please be aware of the architecture of code!!!
 * @ctx: lite context
 * @number_of_node: number of multicast node
 * @target_node: target node array
 * @port: destinated port
 * @atomic_struct: input message structure
 * @length: length of message array
 * @output_msg: array of reply message buffer
 */
int client_send_reply_with_rdma_write_with_imm_sge(ltc *ctx, int number_of_node, int *target_node, unsigned int port, struct atomic_struct **input_atomic, int *length, struct max_reply_msg *output_msg)
{
	int *tar_offset_start;
	int *connection_id;
	int *store_id;
	int *imm_data;
	int *wait_send_reply_id;
	int *real_size, single_size;
	void **remote_addr;
	uint32_t *remote_rkey;
	struct lmr_info **remote_mr;
	struct imm_message_metadata *output_header;
        int count=0;
	int size_count=0;

        int i,j;
	//struct ib_device *ibd = (struct ib_device *)ctx->context;

        if(!input_atomic || !target_node || port>=IMM_MAX_PORT || !length || !output_msg || port <0 || !number_of_node)
        {
		printk(KERN_CRIT "%s: null input target_node %p port %d input_atomic %p length %p output_msg %p\n", __func__, target_node, port, input_atomic, length, output_msg);
                return -2;
        }
        real_size = kmalloc(sizeof(int) * number_of_node, GFP_KERNEL);
        tar_offset_start = kmalloc(sizeof(int) * number_of_node, GFP_KERNEL);
        remote_mr = kmalloc(sizeof(struct lmr_info *) * number_of_node, GFP_KERNEL);
        connection_id = kmalloc(sizeof(int) * number_of_node, GFP_KERNEL);
        store_id = kmalloc(sizeof(int) * number_of_node, GFP_KERNEL);
        wait_send_reply_id = kmalloc(sizeof(int) * number_of_node, GFP_KERNEL);
        imm_data = kmalloc(sizeof(int) * number_of_node, GFP_KERNEL);
        output_header = kmalloc(sizeof(struct imm_message_metadata) * number_of_node, GFP_KERNEL);
        remote_addr = kmalloc(sizeof(void *) * number_of_node, GFP_KERNEL);
        remote_rkey = kmalloc(sizeof(uint32_t) * number_of_node, GFP_KERNEL);

        for(i=0;i<number_of_node;i++)
        {
                wait_send_reply_id[i] = SEND_REPLY_WAIT;
                single_size = 0;
                if(!input_atomic[i] || !length[i] || !target_node[i] || port >= IMM_MAX_PORT || length[i]>IMM_MAX_SGE_LENGTH)
                {
                        printk(KERN_CRIT "%s: target %d target_node[i] %d atomic_struct %p length %d port %u\n", __func__, i, target_node[i], input_atomic[i], length[i], port);
                        return -2;
                }
                for(j=0;j<length[i];j++)
                {
                        if(!input_atomic[i][j].len || !input_atomic[i][j].vaddr)
                        {
                                printk(KERN_CRIT "%s: target %d:%d null length %d or null addr %p\n", __func__, i, j, (int)input_atomic[i][j].len, input_atomic[i][j].vaddr);
                                return -2;
                        }
                        single_size = single_size + input_atomic[i][j].len;
                }
                real_size[i] = single_size + sizeof(struct imm_message_metadata);
	        if(real_size[i] > IMM_MAX_SIZE)
        	{
        		printk(KERN_CRIT "%s: target %d, message size %d + header is larger than max size %d\n", __func__, i, real_size[i], IMM_MAX_SIZE);
        		return -1;
        	}
	        tar_offset_start[i] = client_get_offset_and_mr_by_length(ctx, target_node[i], port, real_size[i], &remote_mr[i]);
                if(tar_offset_start[i]==REG_DO_QUERY_FIRST)
                {
        		printk(KERN_CRIT "%s: can't find node %d port %d\n", __func__, target_node[i], port);
                        return REG_DO_QUERY_FIRST;
                }
		size_count = size_count + real_size[i];
        }	
	
        for(i=0;i<number_of_node;i++)
        {
        	connection_id[i] = client_get_connection_by_atomic_number(ctx, target_node[i], LOW_PRIORITY);
        	store_id[i] = client_get_store_by_addr(ctx, &wait_send_reply_id[i]);
                imm_data[i] = IMM_SEND_REPLY_SEND | port << IMM_PORT_PUSH_BIT | tar_offset_start[i];
                
                output_header[i].designed_port = port;
                output_header[i].store_addr = client_ib_reg_mr_addr(ctx, output_msg[i].msg, sizeof(struct max_reply_msg));//This part need to be handled careful in the future
                output_header[i].store_rkey = ctx->proc->rkey;
                output_header[i].store_semaphore = store_id[i];
                output_header[i].source_node_id = ctx->node_id;
                output_header[i].size = real_size[i] - sizeof(struct imm_message_metadata);
                remote_addr[i] = remote_mr[i]->addr;
                remote_rkey[i] = remote_mr[i]->rkey;
	        //printk(KERN_CRIT "%s: send imm-%x addr-%lx rkey-%x addr-%lx rkey-%x\n", __func__, imm_data[i], (unsigned long)remote_addr[i], remote_rkey[i], (unsigned long)output_header[i].store_addr, output_header[i].store_rkey);
        }
	for(i=0;i<number_of_node;i++)
        {
                //unsigned long tt;
                //memcpy(&tt, input_atomic[i][0], sizeof(unsigned long));
                //printk(KERN_CRIT "%s: line %d: send to %d with %lu\n", __func__, __LINE__, target_node[i], tt);
                client_send_message_with_rdma_write_with_imm_request(ctx, connection_id[i], remote_rkey[i], (uintptr_t)remote_addr[i], NULL, 0, tar_offset_start[i], imm_data[i], LITE_SEND_MESSAGE_HEADER_AND_IMM, &output_header[i], LITE_KERNELSPACE_FLAG, length[i], input_atomic[i], 0);
        }
        for(i=0;i<number_of_node;i++)	
        {
        	while(wait_send_reply_id[i]==SEND_REPLY_WAIT)
        	{
        		cpu_relax();
        	}
        	if(wait_send_reply_id[i] < 0)
        	{
        		printk(KERN_CRIT "%s: [significant error] send-reply-imm fail with target %d node %d connection-%d store-%d status-%d\n", __func__, i, target_node[i], connection_id[i], store_id[i], wait_send_reply_id[i]);
        	}
                else
                {
                        count++;
                }
                output_msg[i].length = wait_send_reply_id[i];
        }
//	kfree(real_size);
	kfree(tar_offset_start);
	kfree(remote_mr);
	kfree(connection_id);
	kfree(store_id);
	kfree(wait_send_reply_id);
	kfree(imm_data);
	kfree(output_header);
	kfree(remote_addr);
	kfree(remote_rkey);
	
	return count;
}
EXPORT_SYMBOL(client_send_reply_with_rdma_write_with_imm_sge);

/**
 * client_send_reply_with_rdma_write_with_imm - issue a RDMA request with imm - mainly used for RPC
 * @ctx: lite context
 * @target_node: target node
 * @port: destinated port
 * @addr: input address
 * @size: request size
 * @ret_addr: reply message buffer
 * @max_ret_size: max size of the reply message buffer
 * @ret_length: memory space to keep reply length
 * @userspace_flag: distinguish this request is from kernel space or userspace
 * @priority: priority level
 */
int client_send_reply_with_rdma_write_with_imm(ltc *ctx, int target_node, unsigned int port, void *addr, int size, void *ret_addr, int max_ret_size, void *ret_length, int userspace_flag, int priority)
{
	int tar_offset_start;
	int connection_id;
	int store_id;
	int imm_data;
	int wait_send_reply_id = SEND_REPLY_WAIT;
	int real_size = size + sizeof(struct imm_message_metadata);
	void *remote_addr;
	uint32_t remote_rkey;
	struct lmr_info *remote_mr=NULL;
	struct imm_message_metadata *output_header;
	struct imm_message_metadata output_header_send_only;

	void *real_addr=NULL;
	void *real_ret_addr=NULL;
	void *real_retlength_vaddr=NULL;
	int userspace_send_continuous = 0;
	int userspace_reply_continuous = 0;
	int userspace_retlength_continuous = 0;
	unsigned long phys_addr;
	struct ib_device *ibd = (struct ib_device *)ctx->context;
        int local_flag;
        if(target_node == ctx->node_id)
                local_flag = 1;
        else
                local_flag = 0;
	//printk(KERN_CRIT "[%s]: size %d\n", __func__, size);

	if(size+sizeof(struct imm_message_metadata) > IMM_MAX_SIZE)
	{
		printk(KERN_CRIT "%s: message size %d + header is larger than max size %d\n", __func__, size, IMM_MAX_SIZE);
		return -1;
	}
	if(!addr)
	{
		printk(KERN_CRIT "%s: null input addr\n", __func__);
		return -2;
	}
	/*if(!ret_addr) //it was checking ret_addr here. However, LITE uses NULL ret_addr to implement send (without reply).
	{
		printk(KERN_CRIT "%s: null ret addr\n", __func__);
		return -2;
	}*/
	if(port > IMM_MAX_PORT-1)
	{
		printk(KERN_CRIT "%s: port %d too large < %d\n", __func__, port, IMM_MAX_PORT);
		return REG_PORT_TOO_LARGE;
	}
	tar_offset_start = client_get_offset_and_mr_by_length(ctx, target_node, port, real_size, &remote_mr);//40ns
	if(tar_offset_start==REG_DO_QUERY_FIRST)
	{
		printk(KERN_CRIT "%s: can't find node %d port %d\n", __func__, target_node, port);
		return REG_DO_QUERY_FIRST;
	}
	
	//retry_send_reply_with_imm_request:
        if(local_flag)
                connection_id = -1;
        else
        	connection_id = client_get_connection_by_atomic_number(ctx, target_node, LOW_PRIORITY);//25-40ns
	//test6-start takes 59ns, occasionally takes 120-170ns(test 10 times with 10000 average runs in each test, and get 1 number in this range)
	
        
        imm_data = IMM_SEND_REPLY_SEND | port << IMM_PORT_PUSH_BIT | tar_offset_start; 
        if(ret_addr)
        {
                store_id = client_get_store_by_addr(ctx, &wait_send_reply_id);//
        	//test6-end
                //printk(KERN_CRIT "%s: send message to %d %d\n", __func__, target_node, store_id);
        	//imm_data = IMM_SEND_REPLY_SEND | tar_offset_start;
	
                output_header = &ctx->imm_store_header[store_id];
        	output_header->store_addr = client_ib_reg_mr_addr(ctx, ret_addr, max_ret_size);//This part need to be handled careful in the future
                output_header->store_rkey = ctx->proc->rkey;
                output_header->store_semaphore = store_id;
        }
        else
        {
                store_id = -1;
                output_header = &output_header_send_only;
                output_header->store_addr = (uintptr_t)NULL;
                output_header->store_rkey = 0;
                output_header->store_semaphore = 0;
        }
	output_header->designed_port = port;
	output_header->source_node_id = ctx->node_id;
	output_header->size = size;
        if(!local_flag)
        {
        	remote_addr = remote_mr->addr;
        	remote_rkey = remote_mr->rkey;
        }
        else
        {
                remote_addr = NULL;
                remote_rkey = 0;
        }
	//printk(KERN_CRIT "%s: send imm-%x addr-%x rkey-%x oaddr-%x orkey-%x\n", __func__, imm_data, remote_addr, remote_rkey, output_header.store_addr, output_header.store_rkey);

	if(userspace_flag)
	{
                //page checking takes around 40 ns when the page is both continuous
		if(lite_check_page_continuous(addr, size, &phys_addr) && !local_flag)//check send buffer continuous
		{
			userspace_send_continuous = 1;
			real_addr = (void *)phys_to_dma(ibd->dma_device, (phys_addr_t)phys_addr);
		}
		else
		{
			real_addr = kmem_cache_alloc(imm_copy_userspace_buffer_cache, GFP_KERNEL);
			if(copy_from_user(real_addr, addr, size))
			{
				kmem_cache_free(imm_copy_userspace_buffer_cache, real_addr);
				return -EFAULT;
			}
		}
                if(ret_addr)//regular send-reply handling
                {
        		if(lite_check_page_continuous(ret_addr, max_ret_size, &phys_addr) && !local_flag)//check reply buffer continuous
        		{
        			userspace_reply_continuous = 1;
        			real_ret_addr = (void *)phys_to_dma(ibd->dma_device, (phys_addr_t)phys_addr);
        			output_header->store_addr = (uintptr_t) real_ret_addr;//This part need to be handled careful in the future
        		}
        		else{
        			real_ret_addr = kmem_cache_alloc(imm_copy_userspace_buffer_cache, GFP_KERNEL);
        			output_header->store_addr = client_ib_reg_mr_addr(ctx, real_ret_addr, max_ret_size);//This part need to be handled careful in the future
        		}
        
                        if(ret_length && userspace_send_continuous && userspace_reply_continuous && lite_check_page_continuous(ret_length, sizeof(int), &phys_addr))
                        {
                                userspace_retlength_continuous = 1;
                                real_retlength_vaddr = phys_to_virt(phys_addr);
                                *(int *)real_retlength_vaddr = SEND_REPLY_WAIT;
                                ctx->imm_store_semaphore[store_id] = real_retlength_vaddr;
                        }
                }
                else//process send request here if it's a pure send request
                {
        	        client_send_message_with_rdma_write_with_imm_request(ctx, connection_id, remote_rkey, (uintptr_t)remote_addr, real_addr, size, tar_offset_start, imm_data, LITE_SEND_MESSAGE_HEADER_AND_IMM, output_header, LITE_USERSPACE_FLAG, 0, NULL, 1);
                        return 0;
                }
		#ifdef SCHEDULE_MODEL
		ctx->imm_store_semaphore_task[store_id] = get_current();
		set_current_state(TASK_INTERRUPTIBLE);
		#endif
		if(userspace_send_continuous)//since the memory space is using phys directly, it should be treated differently
                {
                        client_send_message_with_rdma_write_with_imm_request(ctx, connection_id, remote_rkey, (uintptr_t)remote_addr, real_addr, size, tar_offset_start, imm_data, LITE_SEND_MESSAGE_HEADER_AND_IMM, output_header, LITE_USERSPACE_FLAG, 0, NULL, 0);
                        if(userspace_retlength_continuous)
                                return 0;
                }
		else//local_sendreply will only be in this category 
                {
                        if(!local_flag)
                        {
        			client_send_message_with_rdma_write_with_imm_request(ctx, connection_id, remote_rkey, (uintptr_t)remote_addr, real_addr, size, tar_offset_start, imm_data, LITE_SEND_MESSAGE_HEADER_AND_IMM, output_header, LITE_KERNELSPACE_FLAG, 0, NULL, 0);//This part is KERNELSPACE_FLAG because we are using kernel virtual address here
                        }
                        else
                        {
        			client_send_message_with_rdma_emulated_for_local(ctx, port, real_addr, size, output_header, LITE_USERSPACE_FLAG);//This part is KERNELSPACE_FLAG because we are using kernel virtual address here
                        }
                }
	}
	else
	{
                if(ret_addr)
                {
        		#ifdef SCHEDULE_MODEL
        		ctx->imm_store_semaphore_task[store_id] = get_current();
        		set_current_state(TASK_INTERRUPTIBLE);
        		#endif
        		client_send_message_with_rdma_write_with_imm_request(ctx, connection_id, remote_rkey, (uintptr_t)remote_addr, addr, size, tar_offset_start, imm_data, LITE_SEND_MESSAGE_HEADER_AND_IMM, output_header, LITE_KERNELSPACE_FLAG, 0, NULL, 0);
                }
                else
                {
        		client_send_message_with_rdma_write_with_imm_request(ctx, connection_id, remote_rkey, (uintptr_t)remote_addr, addr, size, tar_offset_start, imm_data, LITE_SEND_MESSAGE_HEADER_AND_IMM, output_header, LITE_KERNELSPACE_FLAG, 0, NULL, 1);
                        return 0;
                }
	}
	
	#ifdef SCHEDULE_MODEL
	schedule();
	set_current_state(TASK_RUNNING);
	#endif

	
	//cpurelax model
	#ifdef CPURELAX_MODEL
	while(wait_send_reply_id==SEND_REPLY_WAIT)
	{
		cpu_relax();
	}
	#endif

	//adaptive model
	#ifdef ADAPTIVE_MODEL
	if(size<=IMM_SEND_SLEEP_SIZE_THRESHOLD)//If size is small, it should do busy wait here, or the waiting time is too long, it should jump to sleep queue
	{
		unsigned long j0,j1;
		j0 = jiffies;
		j1 = j0 + usecs_to_jiffies(IMM_SEND_SLEEP_TIME_THRESHOLD);
		while(wait_send_reply_id==SEND_REPLY_WAIT && time_before(jiffies, j1))
			//cpu_relax();
			schedule();
	}
	if(wait_send_reply_id==SEND_REPLY_WAIT)//do checking here, if the size is small and time is short, it should get wait_send_reply_id from the above if loop. Else do wait here.
	{
		while(wait_send_reply_id==SEND_REPLY_WAIT)
		{
			if(wait_event_interruptible_timeout(ctx->imm_store_block_queue[store_id], wait_send_reply_id!=SEND_REPLY_WAIT, msecs_to_jiffies(3000)))
				break;
		}
	}
	#endif
	if(unlikely(wait_send_reply_id < 0))
	{
		printk(KERN_CRIT "%s: [significant error] send-reply-imm fail with connection-%d store-%d status-%d\n", __func__, connection_id, store_id, wait_send_reply_id);
                return wait_send_reply_id;
		//goto retry_send_reply_with_imm_request;
	}

	if(userspace_flag)
	{
		if(!userspace_send_continuous)//DO free if we did kmalloc
		{
			kmem_cache_free(imm_copy_userspace_buffer_cache, real_addr);
		}
		if(!userspace_reply_continuous)//do free if we did kmalloc
		{
			if(copy_to_user(ret_addr, real_ret_addr, wait_send_reply_id))
			{
				kmem_cache_free(imm_copy_userspace_buffer_cache, real_ret_addr);
				return -EFAULT;
			}
			kmem_cache_free(imm_copy_userspace_buffer_cache, real_ret_addr);
		}
	}

	return wait_send_reply_id;
}
EXPORT_SYMBOL(client_send_reply_with_rdma_write_with_imm);

/**
 * client_send_message_with_rdma_emulated_for_local - issue a local RPC
 * !!!LITE-RPC is mainly built for remote messaging. This function is still in beta version!!! Please be aware
 * @ctx: lite context
 * @port: destinated port
 * @addr: input address
 * @size: request size
 * @header: header of the message
 * @userspace_flag: distinguish this request is from kernel space or userspace
 */
int client_send_message_with_rdma_emulated_for_local(ltc *ctx, int port, void *addr, int size, struct imm_message_metadata *header, int userspace_flag)
{
        void *output_addr = kmalloc(size + sizeof(struct imm_message_metadata), GFP_KERNEL);
        int node_id = ctx->node_id;
        int temp_tar;
        struct imm_header_from_cq_to_port *tmp;

        memcpy(output_addr, header, sizeof(struct imm_message_metadata));
        memcpy(output_addr + sizeof(struct imm_message_metadata), addr, size);
        spin_lock(&ctx->imm_waitqueue_perport_lock[port]);

        if(!list_empty(&ctx->imm_wait_userspace_perport[port].list))//someone is waiting inside userspace
        {
                struct imm_header_from_cq_to_userspace *tmp_u;
                tmp_u = list_entry(ctx->imm_wait_userspace_perport[port].list.next, struct imm_header_from_cq_to_userspace, list);
                list_del(&tmp_u->list);
                client_process_userspace_fast_receive(ctx, tmp_u->ret_addr, tmp_u->receive_size, tmp_u->reply_descriptor, tmp_u->ret_length, node_id, (uint64_t)output_addr, port, 1);
                kmem_cache_free(imm_wait_userspace_buffer_cache, tmp_u);
                kfree(output_addr);//this is only for local_send_reply since the memory space is allocated at the beginning of this function
        }
        else
        {
                temp_tar = ctx->imm_waitqueue_perport_count_poll[port]%IMM_ROUND_UP;
                tmp = ctx->imm_waitqueue_perport[port];
                tmp[temp_tar].source_node_id = node_id;
                tmp[temp_tar].offset = (uint64_t)output_addr;
                ctx->imm_waitqueue_perport_count_poll[port]++;
        }
        spin_unlock(&ctx->imm_waitqueue_perport_lock[port]);
        #ifdef RECV_WAITQUEUE_MODEL
                wake_up_interruptible(&ctx->imm_receive_block_queue[port]);
        #endif
        return 0;
}

/**
 * client_send_message_with_rdma_write_imm_request - issue a RDMA request with imm
 * @ctx: lite context
 * @connection_id: target QP index
 * @input_mr_rkey: remote key of the target region
 * @input_mr_addr: remote address
 * @addr: input address
 * @size: request size
 * @offset: remote offset
 * @imm: imm data (used for LITE internal messaging including port, offset, and semaphore will be pushed to remote side CQ)
 * @s_mode: request mode
 * @header: header of the message
 * @userspace_flag: distinguish this request is from kernel space or userspace
 * @sge_length: support multiple sge length in this request or not (for multicast)
 * @input_atomic: input multicast message structure (for multicast)
 * @force_poll_flag: force polling or avoid polling if possible
 */
int client_send_message_with_rdma_write_with_imm_request(ltc *ctx, int connection_id, uint32_t input_mr_rkey, uintptr_t input_mr_addr, void *addr, int size, int offset, uint32_t imm, enum mode s_mode, struct imm_message_metadata *header, int userspace_flag, int sge_length, struct atomic_struct *input_atomic, int force_poll_flag)
{
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge[32];
	//struct lmr_info *ret;
	int ret;
	uintptr_t temp_addr;
	uintptr_t temp_header_addr;
	int poll_status = SEND_REPLY_WAIT;
	int read_num=0;
	int flag = 0;
        int i;

	//spin_lock(&connection_lock[connection_id]);
	
	retry_send_imm_request:

	memset(&wr, 0, sizeof(struct ib_send_wr));
	memset(&sge, 0, sizeof(struct ib_sge));
	
	wr.sg_list = sge;
	
	//wr.wr_id = connection_id;

	wr.wr.rdma.remote_addr = (uintptr_t) (input_mr_addr+offset);
	wr.wr.rdma.rkey = input_mr_rkey;
        if(sge_length)//sge design process here, only send side could do sge request
        {
                if(s_mode!= LITE_SEND_MESSAGE_HEADER_AND_IMM)
                {
        		printk(KERN_CRIT "%s: wrong mode %d - in sge design\n", __func__, s_mode);
        		return -1;
                }
                read_num = atomic_inc_return(&ctx->connection_count[connection_id]);
                if(read_num%(RECV_DEPTH/4)==0 || force_poll_flag)
                {
                        wr.wr_id = (uint64_t)&poll_status;
                        wr.send_flags = IB_SEND_SIGNALED;
                        flag = 1;
                }
                else
                {
                        wr.wr_id = (uint64_t)ctx->imm_store_semaphore[header->store_semaphore];//get the real wait_send_reply_id address from store information
                        wr.send_flags = 0;
                }
		
		wr.num_sge = 1 + sge_length;
		wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;
		
		temp_header_addr = client_ib_reg_mr_addr(ctx, header, sizeof(struct imm_message_metadata));

		wr.ex.imm_data = imm;
		
		sge[0].addr = temp_header_addr;
		sge[0].length = sizeof(struct imm_message_metadata);
		sge[0].lkey = ctx->proc->lkey;
                //It's always a kernel space call. Therefore
		#ifdef LITE_GET_SIZE
			int total_size = 0;
		#endif
                for(i=0;i<sge_length;i++)
                {
                        temp_addr = client_ib_reg_mr_addr(ctx, input_atomic[i].vaddr, input_atomic[i].len);
        		sge[i+1].addr = temp_addr;
        		sge[i+1].length = input_atomic[i].len;
        		sge[i+1].lkey = ctx->proc->lkey;
			#ifdef LITE_GET_SIZE
				total_size = total_size + input_atomic[i].len;
			#endif
                }
		#ifdef LITE_GET_SIZE
			printk(KERN_CRIT "[%s] size: %d\n", total_size);
		#endif

        }
        else
        {
                if(s_mode == LITE_SEND_MESSAGE_HEADER_AND_IMM)
                {
                        read_num = atomic_inc_return(&ctx->connection_count[connection_id]);
                        if(read_num%(RECV_DEPTH/4)==0 || force_poll_flag)
                        {
                                wr.wr_id = (uint64_t)&poll_status;
                                wr.send_flags = IB_SEND_SIGNALED;
                                flag = 1;
                        }
                        else
                        {
                                wr.wr_id = (uint64_t)ctx->imm_store_semaphore[header->store_semaphore];//get the real wait_send_reply_id address from store information
                                wr.send_flags = 0;
                        }
                        
                        wr.num_sge = 2;
                        wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;
                        
                        temp_header_addr = client_ib_reg_mr_addr(ctx, header, sizeof(struct imm_message_metadata));

                        wr.ex.imm_data = imm;
                        
                        sge[0].addr = temp_header_addr;
                        sge[0].length = sizeof(struct imm_message_metadata);
                        sge[0].lkey = ctx->proc->lkey;
                        if(userspace_flag == LITE_KERNELSPACE_FLAG)
                        {
                                temp_addr = client_ib_reg_mr_addr(ctx, addr, size);
                                sge[1].addr = temp_addr;
                        }
                        else
                        {
                                sge[1].addr = (uintptr_t)addr;
                        }
                        sge[1].length = size;
                        sge[1].lkey = ctx->proc->lkey;
                }
                else if(s_mode == LITE_SEND_MESSAGE_IMM_ONLY)
                {
                        //read_num = atomic_inc_return(&ctx->connection_count[connection_id]);
                        //if(read_num%(RECV_DEPTH/4)==0 || force_poll_flag)
			if(1)
                        {
                                wr.wr_id = (uint64_t)&poll_status;
                                wr.send_flags = IB_SEND_SIGNALED;
                                flag = 1;
                        }
                        else
                        {
                                wr.wr_id = 0;
                                wr.send_flags = 0;
                        }
                        
                        wr.num_sge = 1;
                        wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;

                        wr.ex.imm_data = imm;
                        if(userspace_flag == LITE_KERNELSPACE_FLAG)
                        {
                                temp_addr = client_ib_reg_mr_addr(ctx, addr, size);
                                sge[0].addr = temp_addr;
                        }
                        else
                        {
                                sge[0].addr = (uintptr_t)addr;
                        }
                        sge[0].length = size;
                        sge[0].lkey = ctx->proc->lkey;
                }
                else
                {
                        printk(KERN_CRIT "%s: wrong mode %d - testing function\n", __func__, s_mode);
                        return -1;
                }
        }
	//test5 ends
	//test12 ends
	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	
	if(!ret)
	{
		if(flag==1)
		{
			client_internal_poll_sendcq(ctx->send_cq[connection_id], connection_id, &poll_status);
			if(poll_status)
				goto retry_send_imm_request;
		}
	}
	else
	{
		printk(KERN_INFO "%s: send fail %d ret %d\n", __func__, connection_id, ret);
		//goto retry_send_imm_request;
		return -2;
	}
	//spin_unlock(&connection_lock[connection_id]);
	return 0;

}

/**
 * client_rdma_write_with_imm - issue a regular rdma write imm request.
 * This function is deprecated. But still keep in code for future development
 */
int client_rdma_write_with_imm(ltc *ctx, int connection_id, struct lmr_info *input_mr, void *addr, int size, int offset, uint32_t imm)
{
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge;
	//struct lmr_info *ret;
	int ret;
	uintptr_t tempaddr;
	int ne, i;
	struct ib_wc wc[2];

	spin_lock(&connection_lock[connection_id]);

	memset(&wr, 0, sizeof(struct ib_send_wr));
	memset(&sge, 0, sizeof(struct ib_sge));

	wr.wr_id = connection_id;
	wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IB_SEND_SIGNALED;

	wr.wr.rdma.remote_addr = (uintptr_t) (input_mr->addr+offset);
	wr.wr.rdma.rkey = input_mr->rkey;
	tempaddr = client_ib_reg_mr_addr(ctx, addr, size);
	//sge.addr = (uint64_t)ret->addr;
	//sge.length = ret->length;
	//sge.lkey = ret->lkey;
	
	wr.ex.imm_data = imm;

	sge.addr = tempaddr;
	sge.length = size;
	sge.lkey = ctx->proc->lkey;

	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	if(ret==0){
		do{
			ne = ib_poll_cq(ctx->send_cq[connection_id], 1, wc);
			if(ne < 0)
			{
				printk(KERN_ALERT "poll send_cq failed at connection %d\n", connection_id);
				return 1;
			}
		}while(ne<1);
		for(i=0;i<ne;i++)
		{
			if(wc[i].status!=IB_WC_SUCCESS)
			{
				printk(KERN_ALERT "%s: send request failed at connection %d as %d\n", __func__, connection_id, wc[i].status);
				return 2;
			}
			else
				break;
		}

	}
	else{
		printk(KERN_INFO "send fail %d\n", connection_id);
	}
	spin_unlock(&connection_lock[connection_id]);
	return 0;
}
EXPORT_SYMBOL(client_rdma_write_with_imm);

/**
 * client_rdma_write_offset - issue a RDMA write request
 * @ctx: lite context
 * @lite_handler: lh
 * @local_addr: input address
 * @size: request size
 * @priority: priority level
 * @offset: remote offset
 */
int client_rdma_write_offset(ltc *ctx, uint64_t lite_handler, void *local_addr, int size, int priority, int offset)
{
	int target_node;
	int connection_id;
	struct lmr_info *mr_addr;
	struct hash_asyio_key *mr_ptr;
	int ret;
	//ktime_t self_time = ktime_get();
	mr_ptr = lmr_to_mr_metadata(lite_handler);
	//get_time_difference(lite_handler, self_time);
	if(!mr_ptr)
		return MR_ASK_REFUSE;
	if(!(mr_ptr->permission & MR_WRITE_FLAG))
		return MR_ASK_REFUSE;
	mr_addr = mr_ptr->datalist[0];//Since kernel can only access the first block because of 4MB limitation
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
	ret = client_send_request(ctx, connection_id, M_WRITE, mr_addr, local_addr, size, offset, LITE_KERNELSPACE_FLAG, 0);
	return ret;
}

/**
 * client_rdma_read_offset - issue a RDMA read request
 * @ctx: lite context
 * @lite_handler: lh
 * @local_addr: input address
 * @size: request size
 * @priority: priority level
 * @offset: remote offset
 */
int client_rdma_read_offset(ltc *ctx, uint64_t lite_handler, void *local_addr, int size, int priority, int offset)
{
	int target_node;
	int connection_id;
	struct lmr_info *mr_addr;
	struct hash_asyio_key *mr_ptr;
	mr_ptr = lmr_to_mr_metadata(lite_handler);
	if(!mr_ptr)
		return MR_ASK_REFUSE;
	if(!(mr_ptr->permission & MR_READ_FLAG))
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

int client_rdma_write_offset_multiplesge(ltc *ctx, uint64_t lite_handler, void *local_addr, int size, int priority, int offset, int sge_num, struct ib_sge *input_sge)
{
	int target_node;
	int connection_id;
	struct lmr_info *mr_addr;
	struct lmr_info test_key;
	struct hash_asyio_key *mr_ptr;
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

int client_send_request_without_polling(ltc *ctx, int connection_id, enum mode s_mode, struct lmr_info *input_mr, void *addr, int size, int offset, int wr_id)
{
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge;
	int ret;
	uintptr_t tempaddr;
	//ktime_t self_time;
	memset(&wr, 0, sizeof(struct ib_send_wr));
	memset(&sge, 0, sizeof(struct ib_sge));

	wr.wr_id = wr_id;
	wr.opcode = (s_mode == M_WRITE) ? IB_WR_RDMA_WRITE : IB_WR_RDMA_READ;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IB_SEND_SIGNALED;

	wr.wr.rdma.remote_addr = (uintptr_t) (input_mr->addr+offset);
	wr.wr.rdma.rkey = input_mr->rkey;
	tempaddr = client_ib_reg_mr_addr(ctx, addr, size);
	sge.addr = tempaddr;
	sge.length = size;
	sge.lkey = ctx->proc->lkey;
	
	//self_time = ktime_get();
	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	//get_time_difference(size, self_time);
	if(ret)
		printk("Error in [%s] ret:%d \n", __func__, ret);
	return 0;
}
EXPORT_SYMBOL(client_send_request_without_polling);

int client_send_request_polling_only(ltc *ctx, int connection_id, int polling_num, struct ib_wc *wc)
{
	int ne, i;
	int cur_num = polling_num;
	while(cur_num)
	{
		do{
			ne = ib_poll_cq(ctx->send_cq[connection_id], 3000, wc);
			if(ne < 0)
			{
				printk(KERN_ALERT "poll send_cq failed at connection %d\n", connection_id);
			}
		}while(ne<1);
		for(i=0;i<ne;i++)
		{
			if(wc[i].status!=IB_WC_SUCCESS)
			{
				printk(KERN_ALERT "send request id:%d failed at connection %d as %d\n", (int)wc[i].wr_id, connection_id, wc[i].status);
			}
		}
		cur_num = cur_num - ne;
	}
	return 0;
}
EXPORT_SYMBOL(client_send_request_polling_only);

/**
 * client_fetch_and_add - issue a fetch_and_add request
 * @ctx: lite context
 * @connection_id: target QP index
 * @input_mr: remote LMR info
 * @addr: input address (keep fetch and add returned value)
 * @input_value: fetch and `add` value
 */
int client_fetch_and_add(ltc *ctx, int connection_id, struct lmr_info *input_mr, void *addr, unsigned long long input_value)
{
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge;
	//struct lmr_info *ret;
	int ret;
	uintptr_t tempaddr;
	int poll_status = SEND_REPLY_WAIT;

	//spin_lock(&connection_lock[connection_id]);
	retry_fetch_and_add:

	memset(&wr, 0, sizeof(struct ib_send_wr));
	memset(&sge, 0, sizeof(struct ib_sge));

	wr.wr_id = (uint64_t)&poll_status;
	wr.opcode = IB_WR_ATOMIC_FETCH_AND_ADD;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IB_SEND_SIGNALED;

	wr.wr.atomic.remote_addr = (uintptr_t)input_mr->addr;
	wr.wr.atomic.rkey = input_mr->rkey;
	wr.wr.atomic.compare_add = input_value;
	
	tempaddr = client_ib_reg_mr_addr(ctx, addr, sizeof(uint64_t));
	
	sge.addr = tempaddr;
	sge.length = sizeof(uint64_t);
	sge.lkey = ctx->proc->lkey;

	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	if(!ret)
	{
		client_internal_poll_sendcq(ctx->send_cq[connection_id], connection_id, &poll_status);
		if(poll_status)
			goto retry_fetch_and_add;
	}
	else
	{
		printk(KERN_INFO "%s: send fail %d\n", __func__, connection_id);
	}
	//spin_unlock(&connection_lock[connection_id]);
	return 0;
}
EXPORT_SYMBOL(client_fetch_and_add);

/**
 * client_fetch_and_add_loopback - issue a fetch_and_add request through local loopback
 * @ctx: lite context
 * @input_mr: remote LMR info
 * @addr: input address (keep fetch and add returned value)
 * @input_value: fetch and `add` value
 */
int client_fetch_and_add_loopback(ltc *ctx, struct lmr_info *input_mr, void *addr, unsigned long long input_value)
{
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge;
	//struct lmr_info *ret;
	int ret;
	uintptr_t tempaddr;
	int ne, i;
	struct ib_wc wc[2];

	spin_lock(&ctx->loopback_lock);

	memset(&wr, 0, sizeof(struct ib_send_wr));
	memset(&sge, 0, sizeof(struct ib_sge));

	wr.opcode = IB_WR_ATOMIC_FETCH_AND_ADD;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IB_SEND_SIGNALED;

	wr.wr.atomic.remote_addr = (uintptr_t)input_mr->addr;
	wr.wr.atomic.rkey = input_mr->rkey;
	wr.wr.atomic.compare_add = input_value;
	
	tempaddr = client_ib_reg_mr_addr(ctx, addr, sizeof(uint64_t));
	
	sge.addr = tempaddr;
	sge.length = sizeof(uint64_t);
	sge.lkey = ctx->proc->lkey;

	ret = ib_post_send(ctx->loopback_out, &wr, &bad_wr);
	if(ret==0){
		do{
			ne = ib_poll_cq(ctx->loopback_cq, 1, wc);
			if(ne < 0)
			{
				printk(KERN_ALERT "poll send_cq failed at loopback\n");
				return 1;
			}
		}while(ne<1);
		for(i=0;i<ne;i++)
		{
			if(wc[i].status!=IB_WC_SUCCESS)
			{
				printk(KERN_ALERT "send request failed at loopback\n");
				return 2;
			}
			else
				break;
		}

	}
	else{
		printk(KERN_INFO "send fail at loopback\n");
	}

	spin_unlock(&ctx->loopback_lock);
	return 0;
}
EXPORT_SYMBOL(client_fetch_and_add_loopback);

int client_send_request_multiplesge(ltc *ctx, int connection_id, enum mode s_mode, struct lmr_info *input_mr, void *addr, int size, int sge_num, struct ib_sge *input_sge)
{
	struct ib_send_wr wr, *bad_wr = NULL;
	//struct lmr_info *ret;
	int ret;
	int ne, i;
	struct ib_wc wc[2];

	spin_lock(&connection_lock[connection_id]);

	memset(&wr, 0, sizeof(struct ib_send_wr));

	wr.wr_id = connection_id;
	wr.opcode = (s_mode == M_WRITE) ? IB_WR_RDMA_WRITE : IB_WR_RDMA_READ;
	wr.sg_list = input_sge;
	wr.num_sge = sge_num;
	wr.send_flags = IB_SEND_SIGNALED;

	wr.wr.rdma.remote_addr = (uintptr_t) input_mr->addr;
	wr.wr.rdma.rkey = input_mr->rkey;

	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	if(ret==0){
		do{
			ne = ib_poll_cq(ctx->send_cq[connection_id], 1, wc);
			if(ne < 0)
			{
				printk(KERN_ALERT "poll send_cq failed at connection %d\n", connection_id);
				return 1;
			}
		}while(ne<1);
		for(i=0;i<ne;i++)
		{
			if(wc[i].status!=IB_WC_SUCCESS)
			{
				printk(KERN_ALERT "send request failed at connection %d as %d\n", connection_id, wc[i].status);
				return 2;
			}
			else
				break;
		}

	}
	else{
		printk(KERN_INFO "send fail %d\n", connection_id);
	}
	spin_unlock(&connection_lock[connection_id]);
	return 0;
}
EXPORT_SYMBOL(client_send_request_multiplesge);

/**
 * client_compare_swp - issue a compare_and_swp request
 * @ctx: lite context
 * @connection_id: target QP index
 * @input_mr: remote LMR info
 * @addr: input address (keep fetch and add returned value)
 * @guess_value: compare value
 * @swp_value: swap value
 */
int client_compare_swp(ltc *ctx, int connection_id, struct lmr_info *remote_mr, void *addr, uint64_t guess_value, uint64_t swp_value)
{
	//test_printk(KERN_CRIT "answer: %llu guess: %llu swp: %llu\n", *(uint64_t *)addr, guess_value, swp_value);
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge;
	uintptr_t tempaddr;
	int ret;
	int poll_status = SEND_REPLY_WAIT;
	//int flags;
	//spin_lock_irqsave(&connection_lock[connection_id], flags);
	//spin_lock(&connection_lock[connection_id]);

	retry_compare_swp:

	memset(&wr, 0, sizeof(wr));
	memset(&sge, 0, sizeof(sge));

	wr.wr_id = (uint64_t)&poll_status;
	wr.opcode = IB_WR_ATOMIC_CMP_AND_SWP;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IB_SEND_SIGNALED;
	wr.wr.atomic.remote_addr = (uintptr_t)remote_mr->addr;
	wr.wr.atomic.rkey = remote_mr->rkey;

	wr.wr.atomic.compare_add = guess_value;
	wr.wr.atomic.swap = swp_value;

	//ret_mr = client_register_memory_api(connection_id, addr, sizeof(uint64_t), IBV_ACCESS_LOCAL_WRITE);
	tempaddr = client_ib_reg_mr_addr(ctx, addr, sizeof(uint64_t));

	sge.addr = tempaddr;
	sge.length = sizeof(uint64_t);
	sge.lkey = ctx->proc->lkey;

	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	if(!ret)
	{
		client_internal_poll_sendcq(ctx->send_cq[connection_id], connection_id, &poll_status);
		if(poll_status)
			goto retry_compare_swp;
	}
	else
	{
		printk(KERN_INFO "%s: send fail %d\n", __func__, connection_id);
	}
	//Check swp value
	if(memcmp(addr, &guess_value, sizeof(uint64_t))==0)
	{
		//test_printk(KERN_CRIT "answer: %llu guess: %llu\n", *(uint64_t *)addr, guess_value);
		return 0;
	}
	return 1;
}
EXPORT_SYMBOL(client_compare_swp);

/**
 * client_compare_swp_loopback - issue a compare_and_swp request through loopback for local
 * @ctx: lite context
 * @input_mr: remote LMR info
 * @addr: input address (keep fetch and add returned value)
 * @guess_value: compare value
 * @swp_value: swap value
 */
int client_compare_swp_loopback(ltc *ctx, struct lmr_info *remote_mr, void *addr, uint64_t guess_value, uint64_t swp_value)
{
	//test_printk(KERN_CRIT "answer: %llu guess: %llu swp: %llu\n", *(uint64_t *)addr, guess_value, swp_value);
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge;
	uintptr_t tempaddr;
	int ret;
	int ne, i;
	struct ib_wc wc[2];
	spin_lock(&ctx->loopback_lock);

	memset(&wr, 0, sizeof(wr));
	memset(&sge, 0, sizeof(sge));

	wr.wr_id = 1;
	wr.opcode = IB_WR_ATOMIC_CMP_AND_SWP;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IB_SEND_SIGNALED;
	wr.wr.atomic.remote_addr = (uintptr_t)remote_mr->addr;
	wr.wr.atomic.rkey = remote_mr->rkey;

	wr.wr.atomic.compare_add = guess_value;
	wr.wr.atomic.swap = swp_value;

	tempaddr = client_ib_reg_mr_addr(ctx, addr, sizeof(uint64_t));

	sge.addr = tempaddr;
	sge.length = sizeof(uint64_t);
	sge.lkey = ctx->proc->lkey;

	ret = ib_post_send(ctx->loopback_out, &wr, &bad_wr);

	if(ret==0){
		do{
			ne = ib_poll_cq(ctx->loopback_cq, 1, wc);
			if(ne < 0)
			{
				printk(KERN_CRIT "%s: poll send_cq failed at loopback\n", __func__);
				return 1;
			}
		}while(ne<1);
		for(i=0;i<ne;i++)
		{
			if(wc[i].status!=IB_WC_SUCCESS)
			{
				printk(KERN_CRIT "%s: send cmp request failed at loopback as %d\n", __func__, wc[i].status);
				return 2;
			}
			else
				break;
		}

	}
	else{
		printk(KERN_INFO "%s: send fail\n", __func__);
	}

	spin_unlock(&ctx->loopback_lock);

	//Check swp value
	if(memcmp(addr, &guess_value, sizeof(uint64_t))==0)
	{
		//test_printk(KERN_CRIT "answer: %llu guess: %llu\n", *(uint64_t *)addr, guess_value);
		return 0;
	}
	return 1;
}
EXPORT_SYMBOL(client_compare_swp_loopback);

/**
 * client_create_metadata_by_lmr - setup all the required metadata for a LMR
 * @ctx: lite context
 * @ret_key: designated lh
 * @ret_mr_list: multiple MRs under a LMR
 * @ret_mr_list_length: length of the list
 * @target_node: remote node id
 * @roundup_size: real size in LMR
 * @permission: permission level
 * @local_flag: local LMR or not?
 * @password: pin code
 */
int client_create_metadata_by_lmr(ltc *ctx, uint64_t ret_key, struct lmr_info **ret_mr_list, int ret_mr_list_length, int target_node, int roundup_size, uint64_t permission, bool local_flag, int password)
{	
	int bucket;
        uint64_t t_bucket;
	struct hash_asyio_key *entry;
	int bitmap_size_with_long;
	struct hash_mraddr_to_lmr_metadata *mraddr_to_lmr_mapping;
	int i;
	bucket = ret_key%(1<<HASH_TABLE_SIZE_BIT);
	entry = (struct hash_asyio_key *)kmem_cache_alloc(lmr_metadata_cache, GFP_KERNEL);
	memset(entry, 0, sizeof(struct hash_asyio_key));
	entry->datalist = (struct lmr_info **) kmalloc(sizeof(struct lmr_info *) * ret_mr_list_length, GFP_KERNEL);
	for(i=0;i<ret_mr_list_length;i++)
	{
		if(ret_mr_list[i])
			entry->datalist[i] = ret_mr_list[i];
		else
		{
			printk(KERN_CRIT "%s: error in replicating mr_list at %d entry\n", __func__, i);
		}
	}
	entry->list_length = ret_mr_list_length;
	entry->node_id = target_node;
	entry->size = roundup_size;
	entry->permission = permission;
	//entry->hash_key = bucket;
	entry->lite_handler = ret_key;
	entry->count = 0;

	entry->password = password;

	if(permission & MR_ADMIN_FLAG)
	{
		entry->askmr_bitmap = kzalloc(sizeof(unsigned long) * BITS_TO_LONGS(MAX_NODE), GFP_KERNEL);
	}

	if(!local_flag)
	{
	
		entry->mr_local_index = atomic_inc_return(&ctx->mr_index_counter);
	
		entry->initialized_flag=0;
		entry->link_flag = ASY_PAGE_UNLINK;
		bitmap_size_with_long = BITS_TO_LONGS(roundup_size/REMOTE_MEMORY_PAGE_SIZE);
		entry->bitmap = kzalloc(sizeof(unsigned long) * bitmap_size_with_long, GFP_KERNEL);
		entry->bitmap_size = roundup_size/REMOTE_MEMORY_PAGE_SIZE;
	}

	//self_time = ktime_get();
	spin_lock(&(ASYIO_HASHTABLE_LOCK[bucket]));
	//hash_add_rcu(ASYIO_HASHTABLE, &entry->hlist, ret_key);
	hash_add_rcu(ASYIO_HASHTABLE, &entry->hlist, bucket);
	spin_unlock(&(ASYIO_HASHTABLE_LOCK[bucket]));
	//get_time_difference(3, self_time);	
	//map mr->addr to lmr since we are going to use this when we do deregister
	
	mraddr_to_lmr_mapping = kzalloc(sizeof (struct hash_mraddr_to_lmr_metadata), GFP_KERNEL);
	mraddr_to_lmr_mapping->mother_addr = entry;
	mraddr_to_lmr_mapping->hash_key = (uint64_t)ret_mr_list[0]->addr;
	mraddr_to_lmr_mapping->lmr = ret_key;
	t_bucket = (uint64_t)ret_mr_list[0]->addr<<HASH_TABLE_SIZE_BIT;
        //printk(KERN_CRIT "input bucket %lx %lx\n", t_bucket, (uint64_t)ret_mr_list[0]->addr);
        //t_bucket = hash_min((uint64_t)ret_mr_list[0]->addr, HASH_TABLE_SIZE_BIT);
	spin_lock(&(MR_HASHTABLE_LOCK[bucket]));
	hash_add_rcu(MR_HASHTABLE, &mraddr_to_lmr_mapping->hlist, t_bucket);
	spin_unlock(&(MR_HASHTABLE_LOCK[bucket]));
	//printk(KERN_CRIT "%s: add key %llu\n", __func__, ret_key);
	
	return password;
}
EXPORT_SYMBOL(client_create_metadata_by_lmr);

/**
 * client_add_askmr_table - add LMR into local table
 * @ctx: lite context
 * @identifier: identifier for reply map request
 * @lmr: target lmr key
 * @permission: granted permission level
 */
int client_add_askmr_table(ltc *ctx, uint64_t identifier, uint64_t lmr, uint64_t permission)
{
	struct ask_mr_table *new_entry;
	int bucket;
	int found = 0;
	struct ask_mr_table *current_hash_ptr;
	bucket = identifier%(1<<HASH_TABLE_SIZE_BIT);
	rcu_read_lock();
	hash_for_each_possible_rcu(ADD_ASKMR_TABLE_HASHTABLE, current_hash_ptr, hlist, bucket)
	{
		if(current_hash_ptr->hash_key == identifier)
		{
			found = 1;
			break;
		}
	}
	rcu_read_unlock();
	if(found)
	{
		printk(KERN_CRIT "%s: identifier %llu is already existed\n", __func__, identifier);
                // if we are going to do replacement instead of warning and return
	        //current_hash_ptr->lmr = lmr;
        	//current_hash_ptr->identifier = identifier;
        	//current_hash_ptr->permission = permission;
                //current_hash_ptr->hash_key = identifier;
		return 1;
	}

	new_entry = kmalloc(sizeof(struct ask_mr_table), GFP_KERNEL);

	new_entry->lmr = lmr;
	new_entry->identifier = identifier;
	new_entry->permission = permission;
	new_entry->hash_key = identifier;

	bucket = identifier%(1<<HASH_TABLE_SIZE_BIT);
	spin_lock(&(ADD_ASKMR_TABLE_HASHTABLE_LOCK[bucket]));
	hash_add_rcu(ADD_ASKMR_TABLE_HASHTABLE, &new_entry->hlist, bucket);
	spin_unlock(&(ADD_ASKMR_TABLE_HASHTABLE_LOCK[bucket]));
	return 0;
}
EXPORT_SYMBOL(client_add_askmr_table);

struct lmr_info *client_alloc_lmr_info_buf(void)
{
	struct lmr_info *temp_alloc;
	temp_alloc = (struct lmr_info *)kmem_cache_alloc(lmr_info_cache, GFP_KERNEL);
	if(!temp_alloc)
	{
		printk(KERN_CRIT "%s: [error] in allocation\n", __func__);
		return 0;
	}
	return temp_alloc;
}
EXPORT_SYMBOL(client_alloc_lmr_info_buf);

void client_free_lmr_info_buf(void *input_buf)
{
	kmem_cache_free(lmr_info_cache, input_buf);
}
EXPORT_SYMBOL(client_free_lmr_info_buf);

void client_free_recv_buf(void *input_buf)
{
	kmem_cache_free(post_receive_cache, input_buf);
}
EXPORT_SYMBOL(client_free_recv_buf);

/**
 * lmr_permission_check - validate the permission of the request
 * @input_key: lite handler key
 * @input_flag: request level
 * @ret_ptr: return target lmr info if request is permittable
 */
int lmr_permission_check(uint64_t input_key, int input_flag, struct hash_asyio_key **ret_ptr)
{
	int bucket;
	int found=0;
	struct hash_asyio_key *temp_ptr;

	bucket = input_key%(1<<HASH_TABLE_SIZE_BIT);
	rcu_read_lock();
	hash_for_each_possible_rcu(ASYIO_HASHTABLE, temp_ptr, hlist, bucket)
	{
		if(temp_ptr->lite_handler == input_key)
		{
			found = 1;
			break;
		}
	}
	rcu_read_unlock();
	if(found == 0)
	{
		return MR_ASK_UNKNOWN;
	}
	if(!(temp_ptr->permission & input_flag))
	{
		return MR_ASK_UNPERMITTED;
	}
	if(ret_ptr)
		*ret_ptr = temp_ptr;
	return 0;
}
EXPORT_SYMBOL(lmr_permission_check);

/**
 * lmr_to_mr_metadata - get the lmr info behind a lite handler
 * @input_key: lite handler
 */
struct hash_asyio_key *lmr_to_mr_metadata(uint64_t input_key) //40 - 60 ns
{
	int found = 0;
	struct hash_asyio_key *current_hash_ptr;
	int bucket = input_key%(1<<HASH_TABLE_SIZE_BIT);
	rcu_read_lock();
	hash_for_each_possible_rcu(ASYIO_HASHTABLE, current_hash_ptr, hlist, bucket)
	{
		if(current_hash_ptr->lite_handler == input_key)
		{
			found = 1;
			break;
		}
	}
	rcu_read_unlock();
	if(!found)
		return 0;
	return current_hash_ptr;

}
EXPORT_SYMBOL(lmr_to_mr_metadata);

/**
 * lmr_to_mr - this function is deprecated and is only used by a testing function
 */
struct lmr_info **lmr_to_mr(uint64_t input_key, int *length)
{
	int found = 0;
	struct hash_asyio_key *current_hash_ptr;

	int bucket;
	bucket = input_key%(1<<HASH_TABLE_SIZE_BIT);
	rcu_read_lock();
	hash_for_each_possible_rcu(ASYIO_HASHTABLE, current_hash_ptr, hlist, bucket)
	{
		if(current_hash_ptr->lite_handler == input_key)
		{
			found = 1;
			break;
		}
	}
	rcu_read_unlock();
	if(!found)
		return 0;
	*length = current_hash_ptr->list_length;
	return current_hash_ptr->datalist;
}
EXPORT_SYMBOL(lmr_to_mr);

int client_rdma_asyhandler_init(ltc *ctx)
{
	int tmp_idx = 0;

	printk(KERN_ALERT "init asy_handler\n");
	//push the event into the buffer
	//Backup the related information
	ctx->asy_tmp_header[tmp_idx].type = ASY_INIT;
	ctx->asy_tmp_header[tmp_idx].complete = ASY_SETUP_COMPLETE;//This line frees the event handler. Without this line, handler will busy waiting here forever
	printk(KERN_ALERT "init asy_handler complete\n");
	return 0;
}

static __always_inline pte_t *lite_get_locked_pte(struct mm_struct *mm,
                                                   unsigned long addr,            
						   spinlock_t **ptl)              
{
	pgd_t *pgd = pgd_offset(mm, addr);
	pud_t *pud = pud_alloc(mm, pgd, addr);
	if (pud) {            
		pmd_t *pmd = pmd_alloc(mm, pud, addr);
		if (pmd) {    
			BUG_ON(pmd_trans_huge(*pmd));  
			return pte_alloc_map_lock(mm, pmd, addr, ptl);
		}             
	}
	BUG();                
	return NULL;          
}

static __always_inline int lite_vm_insert_pfn(struct vm_area_struct *vma, unsigned long addr, unsigned long paddr, bool is_write)
{
	pgprot_t pgprot;
	pte_t *pte, entry;
	spinlock_t *ptl = NULL;
	unsigned long pfn = paddr >> PAGE_SHIFT;
	int ret = 0;

	pte = lite_get_locked_pte(vma->vm_mm, addr, &ptl);
	//pte = lite_get_locked_pte(current->mm, addr, &ptl);

	/* Concurrent fault */
	if (unlikely(!pte_none(*pte))) {
		ret = -EBUSY;
		goto out;
	}

	pgprot = vma->vm_page_prot;
	//memset(&pgprot, 0, sizeof(pgprot_t));
	//pgprot_val(pgprot) = (pgprotval_t)_PAGE_USER|(pgprotval_t)_PAGE_PRESENT;
	if (is_write)
		pgprot_val(pgprot) |= (pgprotval_t)_PAGE_RW;
	else
		pgprot_val(pgprot) &= ~(pgprotval_t)_PAGE_RW;

	entry = pfn_pte(pfn, pgprot);

	set_pte_at(vma->vm_mm, addr, pte, entry);
	//set_pte_at(current->mm, addr, pte, entry);


out:
	pte_unmap_unlock(pte, ptl);
	return ret;
}

int client_alloc_continuous_memory(ltc *ctx, unsigned long long vaddr, unsigned long size)
{       
        //struct vm_area_struct *vma = find_vma(current->mm, addr);
        unsigned long roundup_size = (((1<<PAGE_SHIFT) + size - 1)>>PAGE_SHIFT)<<PAGE_SHIFT;
        //unsigned long u_addr = get_unmapped_area(NULL, 0, roundup_size, 0, 0);
        unsigned long u_addr = vaddr;
        unsigned long p_addr = (unsigned long)kzalloc(roundup_size, GFP_KERNEL);
        struct vm_area_struct *vma = NULL;
        unsigned long cur_size = 0;
        unsigned long cur_paddr = p_addr;
        unsigned long cur_uaddr = u_addr;
        while(cur_size<roundup_size)
        {
                lite_vm_insert_pfn(vma, cur_uaddr, virt_to_phys((void *)cur_paddr), 1);
                cur_size += PAGE_SIZE;
                cur_paddr += PAGE_SIZE;
                cur_uaddr += PAGE_SIZE;
        }
        
        printk(KERN_CRIT "%s: uaddr:%lx paddr:%lx size:%lx vma:%p\n", __func__, u_addr, p_addr, roundup_size, vma);
        printk("%s: test:%s\n", __func__, (char *)p_addr);
        
        //if(copy_to_user((void *)vaddr, &u_addr, sizeof(unsigned long)))
        //      return -EFAULT;
        return 0;
}
EXPORT_SYMBOL(client_alloc_continuous_memory);

/**
 * client_establish_conn - join LITE cluster
 * @ib_dev: infiniband device pointer
 * @servername: string of ip address
 * @eth_port: ethernet port
 * @ib_port: infiniband port
 */
ltc *client_establish_conn(struct ib_device *ib_dev, char *servername, int eth_port, int ib_port)
{
	int     ret;
	int     i;

	int server_id = 0;
	struct lite_dest	my_dest;
	struct lite_dest	rem_dest;
	int port = eth_port;

	struct sockaddr_in	addr;
	struct socket		*excsocket;
	char		*port_buf;
	int		sockfd = -1;
	char		msg[sizeof LID_SEND_RECV_FORMAT];
	//char		recv_msg[sizeof LID_SEND_RECV_FORMAT+30];
	int		ask_number_of_MR_set = 0;
        int             temp_ctx_number;
	struct client_ah_combined recv_ah;
	struct client_ah_combined send_ah;
	struct ib_ah_attr ah_attr;
        unsigned ip_a, ip_b, ip_c, ip_d;
	ltc *ctx;
        temp_ctx_number = atomic_inc_return(&Connected_LITE_Num);
        if(temp_ctx_number>=MAX_LITE_NUM)
        {
                printk(KERN_CRIT "%s Error: already meet the upper bound of connected LITE %d\n", __func__, temp_ctx_number);
                atomic_dec(&Connected_LITE_Num);
                return 0;
        }
        sscanf(servername, "%u.%u.%u.%u", &ip_a, &ip_b, &ip_c, &ip_d);
        if (ip_a > 255 || ip_b > 255 || ip_c > 255 || ip_d > 255) {
                printk(KERN_CRIT "Invalid IP: %s\n", servername);
                return 0;
        }
	
	printk(KERN_CRIT "Start establish connection\n");

	//Build cache for memory --> slab
	post_receive_cache = kmem_cache_create("post_receive_buffer", POST_RECEIVE_CACHE_SIZE, 0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), NULL);
	s_r_cache = kmem_cache_create("send_reply_cache", sizeof(struct send_and_reply_format), 0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), NULL);
	header_cache = kmem_cache_create("header_cache", sizeof(struct liteapi_header), 0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD | SLAB_HWCACHE_ALIGN), NULL);
	header_cache_UD = kmem_cache_create("header_cacheUD", sizeof(struct liteapi_header)+40, 0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD | SLAB_HWCACHE_ALIGN), NULL);
	intermediate_cache = kmem_cache_create("intermediate_cache", sizeof(struct liteapi_post_receive_intermediate_struct), 0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), NULL);
	lmr_info_cache = kmem_cache_create("lmr_info_cache", sizeof(struct lmr_info), 0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), NULL);
	asy_page_cache = kmem_cache_create("asyio_page_cache", REMOTE_MEMORY_PAGE_SIZE, 0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), NULL);
	asy_hash_page_key_cache = kmem_cache_create("asyio_hash_page_key_cache", sizeof(struct hash_page_key), 0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), NULL);
	//asy_fence_list_entry_cache = kmem_cache_create("asyio_fance_list_entry_cache", sizeof(struct asy_page_fence_linked_list_entry), 0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), NULL);
	lmr_metadata_cache = kmem_cache_create("lmr_metadata_cache", sizeof(struct hash_asyio_key), 0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), NULL);
	//IMM related
	imm_message_metadata_cache = kmem_cache_create("imm_message_metadata_cache", sizeof(struct imm_message_metadata), 0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), NULL);
	imm_header_from_cq_to_port_cache = kmem_cache_create("imm_header_from_cq_to_port_cache", sizeof(struct imm_header_from_cq_to_port), 0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), NULL);
	imm_copy_userspace_buffer_cache = kmem_cache_create("imm_copy_userspace_buffer_cache", 1024*1024*4, 0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), NULL);
	imm_wait_userspace_buffer_cache = kmem_cache_create("imm_wait_userspace_buffer_cache", sizeof(struct imm_header_from_cq_to_userspace), 0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), NULL);

	//Register application ring
	app_reg_cache = kmem_cache_create("app_reg_cache", sizeof(struct app_reg_port), 0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), NULL);

	//lock related
	lock_queue_element_buffer_cache = kmem_cache_create("lock_queue_element_cache", sizeof(struct lite_lock_queue_element), 0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), NULL);
	
	ctx = client_init_interface(ib_port, ib_dev);
	
	if(!ctx)
	{
		printk(KERN_ALERT "%s: ctx %p fail to init_interface \n", __func__, (void *)ctx);
		return 0;	
	}

        Connected_Ctx[temp_ctx_number-1] = ctx;

	sema_init(&add_newnode_mutex, 1);
	for(i=0;i<MAX_CONNECTION;i++)
	{
		spin_lock_init(&connection_lock[i]);
	}
	
        //Initialize waiting_queue/request list related items
        wq_lock = kmalloc(sizeof(spinlock_t) * QUEUE_NUM_OF_QUEUE, GFP_KERNEL);
        request_list = kmalloc(sizeof(struct send_and_reply_format) * QUEUE_NUM_OF_QUEUE, GFP_KERNEL);
        for(i=0;i<QUEUE_NUM_OF_QUEUE;i++)
        {
        	spin_lock_init(&wq_lock[i]);
        	INIT_LIST_HEAD(&(request_list[i].list));
        }
        
	//Initialize HASHTABLE
	hash_init(MR_HASHTABLE);
	for(i=0;i< 1<<HASH_TABLE_SIZE_BIT;i++)
	{
		spin_lock_init(&(MR_HASHTABLE_LOCK[i]));
	}
	//kthread_run(waiting_queue_handler, NULL, "waiting queue handler");
	thread_handler = kthread_create((void *)waiting_queue_handler, ctx, "wq_handler");
	if(IS_ERR(thread_handler))
	{
		printk(KERN_ALERT "Fail to do handler\n");
		return 0;
	}
        //kthread_bind(thread_handler, NUM_POLLING_THREADS);
	wake_up_process(thread_handler);

	thread_priority_handler = kthread_create((void *)priority_handler, ctx, "priority_handler");
	if(IS_ERR(thread_priority_handler))
	{
		printk(KERN_ALERT "Fail to do priority_handler\n");
		return 0;
	}
	wake_up_process(thread_priority_handler);
	
	//Start handling completion cq
	//This part need to be done on Monday
	
	//thread_poll_cq = (struct task_struct **)kmalloc(NUM_POLLING_THREADS * sizeof(struct task_struct *), GFP_KERNEL);
	thread_poll_cq = (struct task_struct **)kmalloc((NUM_POLLING_THREADS+2) * sizeof(struct task_struct *), GFP_KERNEL);
	for(i=0;i<NUM_POLLING_THREADS;i++)
	{
		char thread_name[32]={};
		struct thread_pass_struct *thread_pass_poll_cq = kmalloc(sizeof(struct thread_pass_struct), GFP_KERNEL);
		sprintf(thread_name, "cq_poller_%d", i);
		thread_pass_poll_cq->ctx = ctx;
		thread_pass_poll_cq->target_cq = ctx->cq[i];
		thread_poll_cq[i] = kthread_create((void *)client_poll_cq_pass, thread_pass_poll_cq, thread_name);
		if(IS_ERR(thread_poll_cq[i]))
		{
			printk(KERN_ALERT "fail to do poll cq %d\n", i);
			return 0;
		}
                //kthread_bind(thread_handler, i);
		wake_up_process(thread_poll_cq[i]);
	}
	//for UD polling
	{
		char thread_name[32]={};
		struct thread_pass_struct *thread_pass_poll_cq = kmalloc(sizeof(struct thread_pass_struct), GFP_KERNEL);
		sprintf(thread_name, "UDcq_poller_%d", i);
		thread_pass_poll_cq->ctx = ctx;
		thread_pass_poll_cq->target_cq = ctx->cqUD;
		thread_poll_cq[NUM_POLLING_THREADS] = kthread_create((void *)client_poll_cq_UD_pass, thread_pass_poll_cq, thread_name);
		if(IS_ERR(thread_poll_cq[NUM_POLLING_THREADS]))
		{
			printk(KERN_ALERT "fail to do UD poll cq %d\n", i);
			return 0;
		}
		wake_up_process(thread_poll_cq[NUM_POLLING_THREADS]);
	}

	//for send-cq poller
        #ifdef SHARE_POLL_CQ_MODEL 
	{
		char thread_name[32]={};
		sprintf(thread_name, "send cq_poller");
		thread_poll_cq[NUM_POLLING_THREADS + 1] = kthread_create((void *)client_send_cq_poller, ctx, thread_name);
		if(IS_ERR(thread_poll_cq[NUM_POLLING_THREADS + 1]))
		{
			printk(KERN_ALERT "fail to do send-cq poller\n");
			return 0;
		}
		wake_up_process(thread_poll_cq[NUM_POLLING_THREADS+1]);
	}
        #endif

	//Initialize ASYIO related things
	hash_init(ASYIO_HASHTABLE);
	for(i=0;i< 1<<HASH_TABLE_SIZE_BIT;i++)
	{
		spin_lock_init(&(ASYIO_HASHTABLE_LOCK[i]));
	}

	hash_init(ASYIO_PAGE_HASHTABLE);
	for(i=0;i< 1<<HASH_TABLE_SIZE_BIT;i++)
	{
		spin_lock_init(&(ASYIO_PAGE_HASHTABLE_LOCK[i]));
	}
	
        //For write-IMM processing (query and future send)
	//EREP
	
	hash_init(LOCAL_MEMORYRING_PORT_HASHTABLE);
	for(i=0;i< 1<<HASH_TABLE_SIZE_BIT;i++)
	{
		spin_lock_init(&(LOCAL_MEMORYRING_PORT_HASHTABLE_LOCK[i]));
	}
	hash_init(REMOTE_MEMORYRING_PORT_HASHTABLE);
	for(i=0;i< 1<<HASH_TABLE_SIZE_BIT;i++)
	{
		spin_lock_init(&(REMOTE_MEMORYRING_PORT_HASHTABLE_LOCK[i]));
	}

	//lock related
	hash_init(LOCK_QUEUE_HASHTABLE);
	for(i=0;i< 1<<HASH_TABLE_SIZE_BIT;i++)
	{
		spin_lock_init(&(LOCK_QUEUE_HASHTABLE_LOCK[i]));
	}

	//ADD askmr table
	hash_init(ADD_ASKMR_TABLE_HASHTABLE);
	for(i=0;i< 1<<HASH_TABLE_SIZE_BIT;i++)
	{
		spin_lock_init(&(ADD_ASKMR_TABLE_HASHTABLE_LOCK[i]));
	}

	memset(&my_dest, 0, sizeof(struct lite_dest));
	memset(&rem_dest, 0, sizeof(struct lite_dest));
	printk(KERN_INFO "establish connection id %d name %s\n", server_id, servername);

	port_buf = (char*)kmalloc(sizeof(char)*16, GFP_KERNEL);
	memset(port_buf, 0, 16);
	/*if(asprintf(&port_buf, "%d", port)<0)
	{
		test_printk(KERN_ALERT "asprintf error\n");
		return NULL;
	}*/
	sprintf(port_buf, "%d", port);

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl((((((ip_a << 8) | ip_b) << 8) | ip_c) << 8) | ip_d);
	printk(KERN_ALERT "establish connection to %x to port %d\n",addr.sin_addr.s_addr, port);
	sockfd = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &excsocket);
	ret = excsocket->ops->connect(excsocket, (struct sockaddr *)&addr, sizeof(addr), 0);
	if(sockfd < 0)
	{
		printk(KERN_ALERT "fail to connect to %d\n", ret);
		return 0;
	}
	client_ktcp_recv(excsocket,(char *)&NODE_ID, sizeof(int));
	printk(KERN_ALERT "Receive %d\n", NODE_ID);
	if(NODE_ID<=0)
	{
		printk(KERN_ALERT "fail to get NODE_ID as %d\n", NODE_ID);
		return 0;
	}
	ctx->node_id = NODE_ID;
	client_ktcp_recv(excsocket, (char *)&ask_number_of_MR_set, sizeof(int));	
	printk(KERN_ALERT "Receive %d\n", ask_number_of_MR_set);
	
	if(ask_number_of_MR_set < 1 || ask_number_of_MR_set > MAX_CONNECTION)
	{
		printk(KERN_ALERT "ask too many required MR set from server %d\n", ask_number_of_MR_set);
		return 0;
	}
	
	//post-recv RC for CD QP
	/*for(i=0;i<ctx->num_parallel_connection;i++)//This part need to be modified into max(num_parallel_connection, ask_number_of_MR_set) in the future.
	{
		int cur_connection = server_id + i;
	}*/
	
	//UD_POST
	client_post_receives_message_UD(ctx, RECV_DEPTH);

	//Send required QP information (future clients) to CD
	for(i=0;i<ask_number_of_MR_set;i++)
	{
		client_gen_msg(ctx, msg, i);
		//printk(KERN_ALERT "%d: %s\n", i, msg);
		memcpy(&my_QPset[i].server_information_buffer, &msg, sizeof(msg));
		client_ktcp_send(excsocket, msg, sizeof(LID_SEND_RECV_FORMAT));
		udelay(100);
	}
	
	//Connect RC to CD
        memset(&recv_ah, 0, sizeof(struct client_ah_combined));
        memset(&send_ah, 0, sizeof(struct client_ah_combined));
	client_ktcp_recv(excsocket, (char *)&recv_ah, sizeof(struct client_ah_combined));
	ctx->ah_attrUD[0].qpn = recv_ah.qpn;
	ctx->ah_attrUD[0].node_id = recv_ah.node_id;
	ctx->ah_attrUD[0].qkey = recv_ah.qkey;
	ctx->ah_attrUD[0].dlid = recv_ah.dlid;
	memcpy(&ctx->ah_attrUD[0].gid, &recv_ah.gid, sizeof(union ib_gid));
	memset(&ah_attr, 0, sizeof(struct ib_ah_attr));
	ah_attr.dlid      = ctx->ah_attrUD[0].dlid;
	ah_attr.sl        = 0;
	ah_attr.src_path_bits = 0;
	ah_attr.port_num = 1;
	if(SGID_INDEX!=-1)
	{
		ah_attr.ah_flags = 1;
		//ah_attr.grh.dgid = ctx->ah_attrUD[0].gid;
		memcpy(&ah_attr.grh.dgid, &ctx->ah_attrUD[0].gid, sizeof(union ib_gid));
		ah_attr.grh.sgid_index = SGID_INDEX;
		ah_attr.grh.hop_limit = 1;
	}
	ctx->ah[0] = ib_create_ah(ctx->pd, &ah_attr);
	if(!ctx->ah[0])
	{
		printk(KERN_CRIT "fail to create ah for CD\n");
	}
	printk(KERN_CRIT "%s: UD message from CD with qpn %d and lid %d: %p\n", __func__, recv_ah.qpn, recv_ah.dlid, ctx->ah[0]);
	
	send_ah.qpn 	= ctx->qpUD->qp_num;
	send_ah.node_id = ctx->node_id;
	send_ah.qkey 	= 0x336;
	send_ah.dlid    = ctx->portinfo.lid;
	if(SGID_INDEX!=-1)
	{
		memcpy(&send_ah.gid, &ctx->gid, sizeof(union ib_gid));
	}
	client_ktcp_send(excsocket, (char *)&send_ah, sizeof(struct client_ah_combined));

	printk(KERN_ALERT "%s: return before establish connection with NODE_ID: %d\n", __func__, NODE_ID);	
	return ctx;
}
EXPORT_SYMBOL(client_establish_conn);

int client_cleanup_module(void)
{
	printk(KERN_INFO "Ready to remove module\n");
	if(thread_poll_cq)
	{
		int i;
		for(i=0;i<NUM_POLLING_THREADS;i++)
		{
			printk(KERN_ALERT "before Kill poll cq thread %d\n", i);
			kthread_stop(thread_poll_cq[i]);
			thread_poll_cq[i]=NULL;
			printk(KERN_ALERT "Kill poll cq thread %d\n", i);
		}
		//kthread_stop(thread_poll_cq);
		//thread_poll_cq = NULL;
		
		printk(KERN_INFO "Kill whole poll cq thread\n");
		
		if(thread_poll_cq[NUM_POLLING_THREADS])//remove UD polling thread
		{
			kthread_stop(thread_poll_cq[NUM_POLLING_THREADS]);
			thread_poll_cq[NUM_POLLING_THREADS] = NULL;
			printk(KERN_ALERT "Kill poll cqUD thread %d\n", i);
		}
		#ifdef SHARE_POLL_CQ_MODEL
		if(thread_poll_cq[NUM_POLLING_THREADS+1])//remove send-cq polling thread
		{
			kthread_stop(thread_poll_cq[NUM_POLLING_THREADS+1]);
			thread_poll_cq[NUM_POLLING_THREADS+1] = NULL;
			printk(KERN_ALERT "Kill poll sendcq thread\n");
		}
                #endif
	}
        
		
	else
	{
		printk(KERN_INFO "Nothing to kill\n");
	}
	if(thread_handler)
	{
		struct send_and_reply_format *recv;
		recv = (struct send_and_reply_format *)kmalloc(sizeof(struct send_and_reply_format), GFP_ATOMIC);
		recv->type = MSG_GET_FINISH;
		//INIT_LIST_HEAD(&recv->list);

		kthread_stop(thread_handler);
		thread_handler = NULL;
		printk(KERN_INFO "Kill handler thread\n");
		spin_lock(&wq_lock[QUEUE_ACK]);
		list_add_tail(&(recv->list), &request_list[QUEUE_ACK].list);
		spin_unlock(&wq_lock[QUEUE_ACK]);
		/*wake_up_interruptible(&wq);*/
	}
	else
	{
		printk(KERN_INFO "Nothing to kill (handler)\n");
	}
	if(thread_priority_handler)
	{
		kthread_stop(thread_priority_handler);
		thread_priority_handler = NULL;
		printk(KERN_INFO "Kill priority handler thread\n");
	}
	else
	{
		printk(KERN_INFO "Nothing to kill (priority handler)\n");
	}

	if(asyIO_handler)
	{
		kthread_stop(asyIO_handler);
		asyIO_handler = NULL;
		printk(KERN_ALERT "Kill asyIO handler\n");
	}
	else
	{
		printk(KERN_INFO "nothing to kill (asyIO_handler)\n");
	}

	/*if(thread_poll_send_cq)
	{
		kthread_stop(thread_poll_send_cq);
		thread_poll_send_cq = NULL;
		printk(KERN_INFO "Kill poll cq thread\n");
	}
	else
	{
		test_printk(KERN_INFO "Nothing to kill\n");
	}*/
	if(post_receive_cache)
		kmem_cache_destroy(post_receive_cache);
	if(header_cache)
		kmem_cache_destroy(header_cache);
	if(header_cache_UD)
		kmem_cache_destroy(header_cache_UD);
	if(s_r_cache)
		kmem_cache_destroy(s_r_cache);
	if(intermediate_cache)
		kmem_cache_destroy(intermediate_cache);
	if(lmr_info_cache)
		kmem_cache_destroy(lmr_info_cache);
	if(lmr_metadata_cache)
		kmem_cache_destroy(lmr_metadata_cache);
	if(asy_page_cache)
		kmem_cache_destroy(asy_page_cache);
	if(asy_hash_page_key_cache)
		kmem_cache_destroy(asy_hash_page_key_cache);
	//if(asy_fence_list_entry_cache)
	//	kmem_cache_destroy(asy_fence_list_entry_cache);
	if(app_reg_cache)
		kmem_cache_destroy(app_reg_cache);
	if(imm_message_metadata_cache)
		kmem_cache_destroy(imm_message_metadata_cache);
	if(imm_header_from_cq_to_port_cache)
		kmem_cache_destroy(imm_header_from_cq_to_port_cache);
	if(imm_copy_userspace_buffer_cache)
		kmem_cache_destroy(imm_copy_userspace_buffer_cache);
	if(imm_wait_userspace_buffer_cache)
		kmem_cache_destroy(imm_wait_userspace_buffer_cache);
	if(lock_queue_element_buffer_cache)
		kmem_cache_destroy(lock_queue_element_buffer_cache);
	return 0;
}
EXPORT_SYMBOL(client_cleanup_module);


static int lite_mmaptest_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long roundup_size = vma->vm_end - vma->vm_start;
	unsigned long u_addr = vma->vm_start;
	unsigned long p_addr = (unsigned long)kzalloc(roundup_size, GFP_KERNEL);
	unsigned long cur_size = 0;
	unsigned long cur_paddr = p_addr;
	unsigned long cur_uaddr = u_addr;
	
	while(cur_size<roundup_size)
	{
		lite_vm_insert_pfn(vma, cur_uaddr, virt_to_phys((void *)cur_paddr), 1);
		cur_size += PAGE_SIZE;
		cur_paddr += PAGE_SIZE;
		cur_uaddr += PAGE_SIZE;
	}
	/*vma->vm_flags |= VM_RESERVED;
	ret = remap_pfn_range(vma, vma->vm_start, virt_to_phys((void *)p_addr), vma->vm_end - vma->vm_start, vma->vm_page_prot);
	if(ret)
	{
		printk(KERN_CRIT "%s:%d\n", __func__, ret);
		return -EFAULT;
	}*/
	printk(KERN_CRIT "%s: uaddr:%lx paddr:%lx size:%lx(%lx) vma:%p\n", __func__, u_addr, p_addr, roundup_size, vma->vm_end - vma->vm_start, vma);
	/*
	unsigned long page,pos;
	unsigned long start = (unsigned long)vma->vm_start; 
	unsigned long size = (unsigned long)(vma->vm_end-vma->vm_start); 
	int ret;

	printk(KERN_INFO "lite_mmaptest_mmap called\n");

        if (size>1024*1024*4)
                return -EINVAL;
 
        pos=(unsigned long)kzalloc(size, GFP_KERNEL);
	//for (page = virt_to_page(pos); page < virt_to_page(pos + size); page++) {
	//	mem_map_reserve(page); 
	//}
 
        while (size > 0) {
                page = virt_to_phys((void *)pos);
                ret = remap_pfn_range(vma, start, page>>PAGE_SHIFT, PAGE_SIZE, vma->vm_page_prot);
		if(ret)
		{
			printk(KERN_CRIT "%s: %d\n", __func__, ret);
                        return -EAGAIN;
		}
                start+=PAGE_SIZE;
                pos+=PAGE_SIZE;
                size-=PAGE_SIZE;
		printk(KERN_CRIT "%s: success %d\n", __func__, ret);
        }*/
        return 0; 
}

static int lite_mmaptest_open(struct inode *inode, struct file *filp)
{
	return 0; 
}
		
static int lite_mmaptest_release(struct inode *inode, struct file *filp)
{
	return 0;
}	

static struct file_operations lite_mmaptest_fops = {
	mmap: 		lite_mmaptest_mmap,
	//munmap:		lite_mmaptest_munmap,
        open: 		lite_mmaptest_open,
	release: 	lite_mmaptest_release,	
}; 

int lite_dev;
dev_t lite_dev_num; // Global variable for the first device number
struct cdev c_dev; // Global variable for the character device structure
struct class *cl; // Global variable for the device class

static int __init lite_internal_init_module(void)
{
        Connected_Ctx = (ltc **)kmalloc(sizeof(ltc*)*MAX_LITE_NUM, GFP_KERNEL);
        atomic_set(&Connected_LITE_Num, 0);


	//lite_dev = register_chrdev(0,"lite_mmaptest",&lite_mmaptest_fops); 	

	if (alloc_chrdev_region(&lite_dev_num, 0, 1, "lite_internal") < 0)
	{
		printk(KERN_CRIT "%s:%d\n", __func__, __LINE__);
		return -1;
	}
	if ((cl = class_create(THIS_MODULE, "lite_class")) == NULL)
	{
		printk(KERN_CRIT "%s:%d\n", __func__, __LINE__);
		unregister_chrdev_region(lite_dev_num, 1);
		return -1;
	}
	if (device_create(cl, NULL, lite_dev_num, NULL, "lite_mmap") == NULL)
	{
		printk(KERN_CRIT "%s:%d\n", __func__, __LINE__);
		class_destroy(cl);
		unregister_chrdev_region(lite_dev_num, 1);
		return -1;
	}
	cdev_init(&c_dev, &lite_mmaptest_fops);
	if (cdev_add(&c_dev, lite_dev_num, 1) == -1)
	{
		device_destroy(cl, lite_dev_num);
		class_destroy(cl);
		unregister_chrdev_region(lite_dev_num, 1);
		return -1;
	}
	printk(KERN_CRIT "%s:%d\n", __func__, lite_dev);
	printk(KERN_CRIT "insmod lite_internal module\n");
	return 0;
}

static void __exit lite_internal_cleanup_module(void)
{
	//unregister_chrdev(lite_dev,"lite_mmaptest"); 
	cdev_del(&c_dev);
	device_destroy(cl, lite_dev_num);
	class_destroy(cl);
	unregister_chrdev_region(lite_dev_num, 1);
	
	printk(KERN_CRIT "rmmod lite_internal module\n");
	return;
}

module_init(lite_internal_init_module);
module_exit(lite_internal_cleanup_module);
