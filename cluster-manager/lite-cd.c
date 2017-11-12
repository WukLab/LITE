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
 *        
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

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

//This is the version modified from 000be840c215d5da3011a2c7b486d5ae122540c4
//It adds LOCKS, sge, and other things  into the system
//Client.h is also modified.
//Server is also modified to match this patch
//Patch SERIAL_VERSION_ID: 04202300
//Please make sure that this version is not fully tested inside dsnvm (interactions are not fully tested)

#define DEBUG 1
#define debug_printf(...) \
        do { if (DEBUG) fprintf(stderr, __VA_ARGS__); fflush(stdout);} while (0)

//#define NO_LOCK_IMPLEMENTATION

#include "client.h"


static const int RDMA_BUFFER_SIZE = 4096;
static const int CIRCULAR_BUFFER  = CIRCULAR_BUFFER_LENGTH;
const int SEND_REPLY_WAIT = -1;
void die(const char *reason)
{
  fprintf(stderr, "%s\n", reason);
  exit(EXIT_FAILURE);
}

#define TEST_NZ(x) do { if ( (x)) die("error: " #x " failed (returned non-zero)." ); } while (0)
#define TEST_Z(x)  do { if (!(x)) die("error: " #x " failed (returned zero/null)."); } while (0)

int num_parallel_connection = NUM_PARALLEL_CONNECTION;

static int page_size;

enum ibv_mtu mtu;
int sl;

struct lite_context *ctx;
int *routs;
int                      rcnt, scnt;

int server_rdma_write(int target_node, struct lmr_info *mr_addr, void *local_addr, int size);
int server_rdma_read(int target_node, struct lmr_info *mr_addr, void *local_addr, int size);

static int server_connect_ctx(int connection_id, int port, int my_psn,
			  enum ibv_mtu mtu, int sl,
			  struct lite_dest *dest)
              //, int sgid_idx)//sgid_idx is set to -1
{
	return 0;
}

static int server_connect_loopback(struct ibv_qp *input_qp, int port, int my_psn,
			  enum ibv_mtu mtu, int sl,
			  struct lite_dest *dest)
              //, int sgid_idx)//sgid_idx is set to -1
{
	struct ibv_qp_attr attr = {
		.qp_state		= IBV_QPS_RTR,
		.path_mtu		= mtu,
		.dest_qp_num		= dest->qpn,
		.rq_psn			= dest->psn,
		.max_dest_rd_atomic	= 10,
		.min_rnr_timer		= 12,
		.ah_attr		= {
			.is_global	= 0,
			.dlid		= dest->lid,
			.sl		= sl,
			.src_path_bits	= 0,
			.port_num	= port
		}
	};
	if (dest->gid.global.interface_id) {
		attr.ah_attr.is_global = 1;
		attr.ah_attr.grh.hop_limit = 1;
		attr.ah_attr.grh.dgid = dest->gid;
		attr.ah_attr.grh.sgid_index = SGID_INDEX;//Always set to -1
	}
	if (ibv_modify_qp(input_qp, &attr,
			  IBV_QP_STATE              |
			  IBV_QP_AV                 |
			  IBV_QP_PATH_MTU           |
			  IBV_QP_DEST_QPN           |
			  IBV_QP_RQ_PSN             |
			  IBV_QP_MAX_DEST_RD_ATOMIC |
			  IBV_QP_MIN_RNR_TIMER)) {
		fprintf(stderr, "Failed to modify QP to RTR\n");
		return 1;
	}
	attr.qp_state	    = IBV_QPS_RTS;
	attr.timeout	    = 14;
	attr.retry_cnt	    = 7;
	attr.rnr_retry	    = 7;
	attr.sq_psn	    = my_psn;
	attr.max_rd_atomic  = 10;
	if (ibv_modify_qp(input_qp, &attr,
			  IBV_QP_STATE              |
			  IBV_QP_TIMEOUT            |
			  IBV_QP_RETRY_CNT          |
			  IBV_QP_RNR_RETRY          |
			  IBV_QP_SQ_PSN             |
			  IBV_QP_MAX_QP_RD_ATOMIC)) {
		fprintf(stderr, "Failed to modify QP to RTS\n");
		return 1;
	}

	return 0;
}


static struct lite_context *server_init_ctx(struct ibv_device *ib_dev,int size,int rx_depth, int port)
{
        int i;
	ctx = calloc(1, sizeof *ctx);
	if (!ctx)
		return NULL;
        int num_connections = MAX_CONNECTION;
	ctx->size       = size;
	ctx->send_flags = IBV_SEND_SIGNALED;
	ctx->rx_depth   = rx_depth;
	ctx->num_connections = num_connections;
        ctx->num_node = MAX_NODE;
        ctx->num_parallel_connection = NUM_PARALLEL_CONNECTION;

	ctx->context = ibv_open_device(ib_dev);
	if (!ctx->context) {
		fprintf(stderr, "Couldn't get context for %s\n",
			ibv_get_device_name(ib_dev));
		goto clean_buffer;
	}
    
        ctx->channel = NULL;

	ctx->pd = ibv_alloc_pd(ctx->context);
	if (!ctx->pd) {
		fprintf(stderr, "Couldn't allocate PD\n");
		goto clean_comp_channel;
	}

	ctx->send_state = (enum s_state *)malloc(num_connections * sizeof(enum s_state));
	ctx->recv_state = (enum r_state *)malloc(num_connections * sizeof(enum r_state));
    
        //Built by Shin-Yeh
        ctx->num_alive_connection = (int*)calloc(ctx->num_node, sizeof(int));
        //ctx->recv_num = (int *)calloc(num_connections, sizeof(int));
        ctx->recv_num = 0;
        ctx->atomic_request_num = (unsigned int*)calloc(ctx->num_node, sizeof(unsigned int));
        ctx->thread_state = (enum t_state *)malloc(MAX_PARALLEL_THREAD * sizeof(enum t_state));
        ctx->parallel_thread_num = 0;
        
        //Send_Reply
        ctx->send_reply_wait_num = 0;

        //Atomic buffer
        ctx->atomic_buffer = (struct atomic_struct **)malloc(num_connections * sizeof(struct atomic_struct *));
        ctx->atomic_buffer_total_length = (int *)malloc(num_connections * sizeof(int));
        ctx->atomic_buffer_cur_length = (int *)malloc(num_connections * sizeof(int));

        //Lock related
        memset((void *)shared_locks, 0, MAX_LOCK * sizeof(uint64_t));
        ctx->num_used_lock = 0;
        ctx->shared_locks_fifo_queue = (struct fifo_t **)malloc(MAX_LOCK * sizeof(struct fifo_t *));
        for(i=0;i<MAX_LOCK;i++)
                ctx->shared_locks_fifo_queue[i] = fifo_new();
  
        //This part should be modified in the future to satisfie multiple CQ
	ctx->cq = ibv_create_cq(ctx->context, rx_depth + 1, NULL, ctx->channel, 0);
	if (!ctx->cq) {
		fprintf(stderr, "Couldn't create CQ\n");
		goto clean_mr;
	}
	
	/*ctx->qp = (struct ibv_qp **)malloc(num_connections * sizeof(struct ibv_qp *)); 
	if (!ctx->pd)
		goto clean_qp;*/

	struct ibv_qp_attr attr;
	struct ibv_qp_init_attr init_attr = 
	{
		.send_cq = ctx->cq,
		.recv_cq = ctx->cq,
		.cap = {
			.max_send_wr  = MAX_ATOMIC_SEND_NUM + 2,
			.max_recv_wr  = rx_depth,
			.max_send_sge = 16,
			.max_recv_sge = 16
		},
		.qp_type = IBV_QPT_UD
	};

 	ctx->qp = ibv_create_qp(ctx->pd, &init_attr);
	if(!ctx->qp)
	{
		fprintf(stderr, "Failed to build UD QP\n");
		return -1;
	}
	ibv_query_qp(ctx->qp, &attr, IBV_QP_CAP, &init_attr);
	if(init_attr.cap.max_inline_data >= size){
		ctx->send_flags |= IBV_SEND_INLINE;
	}

	struct ibv_qp_attr attr1 = {
		.qp_state = IBV_QPS_INIT,
		.pkey_index = 0,
		.port_num = port,
		.qkey = 0x336
	};
	if(ibv_modify_qp(ctx->qp, &attr1,
				IBV_QP_STATE		|
				IBV_QP_PKEY_INDEX	|
				IBV_QP_PORT		|
				IBV_QP_QKEY))
	{
		fprintf(stderr,"Fail to modify UDqp\n");
		ibv_destroy_qp(ctx->qp);
		return -1;
	}
	printf("UD qpn %d\n", ctx->qp->qp_num);
	struct ibv_qp_attr attr2 = {
		.qp_state		= IBV_QPS_RTR
	};

	if(ibv_modify_qp(ctx->qp, &attr2, IBV_QP_STATE)) {
		fprintf(stderr, "Failed to modify QP to RTR\n");
		return -1;
	}

	attr2.qp_state	    = IBV_QPS_RTS;
	attr2.sq_psn	    = lrand48() & 0xffffff;

	if (ibv_modify_qp(ctx->qp, &attr2,
			  IBV_QP_STATE              |
			  IBV_QP_SQ_PSN)) {
		fprintf(stderr, "Failed to modify UDQP to RTS\n");
		return -1;
	}
	ctx->ah = malloc(sizeof(struct ibv_ah *)*ctx->num_node);
	ctx->ah_attrUD = malloc(sizeof(struct client_ah_combined)*ctx->num_node);
	if(SGID_INDEX!=-1)
	{
		if(ibv_query_gid(ctx->context, port, SGID_INDEX, &ctx->gid))
		{
			fprintf(stderr, "Failed to query GID\n");
			return -1;
		}
	}

	return ctx;

clean_qp:

clean_cq:
	ibv_destroy_cq(ctx->cq);

clean_mr:
//	ibv_dereg_mr(ctx->mr);

//clean_pd:
//	ibv_dealloc_pd(ctx->pd);

clean_comp_channel:
	if (ctx->channel)
		ibv_destroy_comp_channel(ctx->channel);

//clean_device:
//	ibv_close_device(ctx->context);

clean_buffer:
//	free(ctx->buf);

//clean_ctx:
//	free(ctx);

	return 0;
}

void server_setup_liteapi_header(uint32_t src_id, uint64_t store_addr, uint64_t store_semaphore, uint32_t length, int priority, int type, struct liteapi_header *output_header)
{
        output_header->src_id = src_id;
        output_header->store_addr = store_addr;
        output_header->store_semaphore = store_semaphore;
        output_header->length = length;
        output_header->priority = priority;
        output_header->type = type;
}

static int server_post_receives_message(int n, int num)
{
        struct ibv_recv_wr wr, *bad_wr = NULL;
        struct ibv_sge sge[2];
        int i,j;
        for(j=0;j<n;j++)
        {
                for(i=0;i<num;i++)
                {
                        char *temp_addr, *temp_header_addr;
                        struct ibv_mr *temp_mr, *temp_header_mr;
                        struct liteapi_post_receive_intermediate_struct *p_r_i_struct;

                        temp_addr = malloc(RDMA_BUFFER_SIZE*2);
                        temp_mr = server_register_memory_api(0, temp_addr, RDMA_BUFFER_SIZE*2, IBV_ACCESS_LOCAL_WRITE);
                        temp_header_addr = malloc(sizeof(struct liteapi_header)+40);
                        temp_header_mr = server_register_memory_api(0, temp_header_addr, sizeof(struct liteapi_header)+40, IBV_ACCESS_LOCAL_WRITE);          
                        p_r_i_struct = malloc(sizeof(struct liteapi_post_receive_intermediate_struct));
                        p_r_i_struct->header = (uintptr_t)temp_header_addr;
                        p_r_i_struct->msg = (uintptr_t)temp_addr;
          
                        sge[0].addr = (uintptr_t)temp_header_mr->addr;
                        sge[0].length = temp_header_mr->length;
                        sge[0].lkey = temp_header_mr->lkey;
                        sge[1].addr = (uintptr_t)temp_mr->addr;
                        sge[1].length = temp_mr->length;
                        sge[1].lkey = temp_mr->lkey;
         
                        wr.wr_id = (uint64_t)p_r_i_struct;
                        wr.next = NULL;
                        wr.sg_list = sge;
                        wr.num_sge = 2;
                        if(ibv_post_recv(ctx->qp, &wr, &bad_wr))
                            break;
                }
        }
        printf("Do a post-receive with %d\n", num);
        return n;
}

int post_receives_message_from_poll_cq(int *ptr)
{
        server_post_receives_message(7, 1024);
        return 0;
}

struct ibv_mr *server_register_memory_api(int connection_id, void *addr, int size, int flag)
{
        return ibv_reg_mr(ctx->pd, addr, size, flag);
}

int server_send_message_sge(int target_node, int type, struct ibv_mr *input_mr, uint64_t store_addr, uint64_t store_semaphore)
{
        pthread_mutex_lock(&connection_lock);
        struct ibv_send_wr wr, *bad_wr = NULL;
    
        int ret;
        int waiting_id = server_get_waiting_id_by_semaphore();
        memset(&wr, 0, sizeof(wr));

        ctx->thread_state[waiting_id] = TS_WAIT;

        struct liteapi_header output_header;
        struct ibv_mr *output_header_mr;
        struct ibv_sge sge[2];
        memset(sge, 0, sizeof(struct ibv_sge)*2);

        wr.wr_id = waiting_id * WRAP_UP_NUM_FOR_WRID + type * WRAP_UP_NUM_FOR_TYPE;
        wr.opcode = IBV_WR_SEND;
        wr.sg_list = sge;
        wr.num_sge = 2;
        wr.send_flags = IBV_SEND_SIGNALED;
        wr.wr.ud.ah = ctx->ah[target_node];
        wr.wr.ud.remote_qpn = ctx->ah_attrUD[target_node].qpn;
        wr.wr.ud.remote_qkey = ctx->ah_attrUD[target_node].qkey;

        server_setup_liteapi_header(NODE_ID, store_addr, store_semaphore, input_mr->length, 0, type, &output_header);
        output_header_mr = server_register_memory_api(0, &output_header, sizeof(struct liteapi_header), IBV_ACCESS_LOCAL_WRITE);

        sge[0].addr = (uint64_t)output_header_mr->addr;
        sge[0].length = output_header_mr->length;
        sge[0].lkey = output_header_mr->lkey;

        sge[1].addr = (uint64_t)input_mr->addr;
        sge[1].length = input_mr->length;
        sge[1].lkey = input_mr->lkey;

        //ret = ibv_post_send(ctx->qp[connection_id], &wr, &bad_wr);   
        ret = ibv_post_send(ctx->qp, &wr, &bad_wr);   

        while(ctx->thread_state[waiting_id] == TS_WAIT);
        pthread_mutex_unlock(&connection_lock);
        return ret;
}

int server_send_message_sge_header_fixed(int target_node, int type, struct ibv_mr *input_mr, uint64_t store_addr, uint64_t store_semaphore, struct ibv_mr *output_header_mr)
{
        pthread_mutex_lock(&connection_lock);
        struct ibv_send_wr wr, *bad_wr = NULL;

        int ret;
        int waiting_id = server_get_waiting_id_by_semaphore();
        memset(&wr, 0, sizeof(wr));

        ctx->thread_state[waiting_id] = TS_WAIT;
        struct ibv_sge sge[2];
        memset(sge, 0, sizeof(struct ibv_sge)*2);

        wr.wr_id = waiting_id * WRAP_UP_NUM_FOR_WRID + type * WRAP_UP_NUM_FOR_TYPE;
        wr.opcode = IBV_WR_SEND;
        wr.sg_list = sge;
        wr.num_sge = 2;
        wr.send_flags = IBV_SEND_SIGNALED;
        wr.wr.ud.ah = ctx->ah[target_node];
        wr.wr.ud.remote_qpn = ctx->ah_attrUD[target_node].qpn;
        wr.wr.ud.remote_qkey = ctx->ah_attrUD[target_node].qkey;

        sge[0].addr = (uint64_t)output_header_mr->addr;
        sge[0].length = output_header_mr->length;
        sge[0].lkey = output_header_mr->lkey;

        sge[1].addr = (uint64_t)input_mr->addr;
        sge[1].length = input_mr->length;
        sge[1].lkey = input_mr->lkey;

        //ret = ibv_post_send(ctx->qp[connection_id], &wr, &bad_wr);   
        ret = ibv_post_send(ctx->qp, &wr, &bad_wr);   

        while(ctx->thread_state[waiting_id] == TS_WAIT);
        pthread_mutex_unlock(&connection_lock);
        return ret;
}

int server_setup_loopback_connections(struct ibv_device *ib_dev,int size,int rx_depth, int port)
{
        struct lite_dest loopback_in, loopback_out;
        char	        		 gid[33];
        //This part is related to loopback_cq
        ctx->loopback_cq = ibv_create_cq(ctx->context, rx_depth + 1, NULL, ctx->channel, 0);
        if (!ctx->loopback_cq) {
		fprintf(stderr, "Couldn't create loopback_CQ\n");
        }    
        {
                struct ibv_qp_attr attr;
		struct ibv_qp_init_attr init_attr = {
                //This part should be modified in the future to satisfie multiple CQ
			.send_cq = ctx->loopback_cq,
                //This part should be modified in the future to satisfie multiple CQ
			.recv_cq = ctx->loopback_cq,
			.cap     = {
				.max_send_wr  = 1,
				.max_recv_wr  = rx_depth,
				.max_send_sge = 2,
				.max_recv_sge = 2
			},
			.qp_type = IBV_QPT_RC
		};
		ctx->loopback_in = ibv_create_qp(ctx->pd, &init_attr);
		if (!ctx->loopback_in)  {
			fprintf(stderr, "Couldn't create loopback in QP\n");
			
		}
		ibv_query_qp(ctx->loopback_in, &attr, IBV_QP_CAP, &init_attr);
		if (init_attr.cap.max_inline_data >= size) {
			ctx->send_flags |= IBV_SEND_INLINE;
		}
		struct ibv_qp_attr attr1 = {
			.qp_state        = IBV_QPS_INIT,
			.pkey_index      = 0,
			.port_num        = port,
			//.qp_access_flags = 0
			//.qp_access_flags = IBV_ACCESS_REMOTE_WRITE|IBV_ACCESS_REMOTE_READ,
			.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_ATOMIC | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE,
                        .path_mtu = LITE_MTU,
                        .retry_cnt = 7,
                        .rnr_retry = 7
		};
		if (ibv_modify_qp(ctx->loopback_in, &attr1,
				  IBV_QP_STATE              |
				  IBV_QP_PKEY_INDEX         |
				  IBV_QP_PORT               |
				  IBV_QP_ACCESS_FLAGS)) {
			fprintf(stderr, "Failed to modify loopback in QP to INIT\n");
			ibv_destroy_qp(ctx->loopback_in);			
		}
        }
        {
                struct ibv_qp_attr attr;
		struct ibv_qp_init_attr init_attr = {
                        //This part should be modified in the future to satisfie multiple CQ
                        .send_cq = ctx->loopback_cq,
                        //This part should be modified in the future to satisfie multiple CQ
			.recv_cq = ctx->loopback_cq,
			.cap     = {
				.max_send_wr  = 1,
				.max_recv_wr  = rx_depth,
				.max_send_sge = 2,
				.max_recv_sge = 2
			},
			.qp_type = IBV_QPT_RC
		};
		ctx->loopback_out = ibv_create_qp(ctx->pd, &init_attr);
		if (!ctx->loopback_out)  {
			fprintf(stderr, "Couldn't create loopback in QP\n");
		}
		ibv_query_qp(ctx->loopback_out, &attr, IBV_QP_CAP, &init_attr);
		if (init_attr.cap.max_inline_data >= size) {
			ctx->send_flags |= IBV_SEND_INLINE;
		}
		struct ibv_qp_attr attr1 = {
			.qp_state        = IBV_QPS_INIT,
			.pkey_index      = 0,
			.port_num        = port,
			//.qp_access_flags = 0
			//.qp_access_flags = IBV_ACCESS_REMOTE_WRITE|IBV_ACCESS_REMOTE_READ,
			.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_ATOMIC | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE,
                        .path_mtu = LITE_MTU,
                        .retry_cnt = 7,
                        .rnr_retry = 7
		};
		if (ibv_modify_qp(ctx->loopback_out, &attr1,
				  IBV_QP_STATE              |
				  IBV_QP_PKEY_INDEX         |
				  IBV_QP_PORT               |
				  IBV_QP_ACCESS_FLAGS)) {
			fprintf(stderr, "Failed to modify loopback in QP to INIT\n");
			ibv_destroy_qp(ctx->loopback_out);
		}
	}
    
        memset(&loopback_in, 0, sizeof(struct lite_dest));
        loopback_in.lid = ctx->portinfo.lid;
        loopback_in.qpn = ctx->loopback_in->qp_num;
        loopback_in.psn = lrand48() & 0xffffff;
        loopback_in.node_id = 0;
        //gid_to_wire_gid(&loopback_in.gid, gid);
        memcpy(&loopback_in.gid, &ctx->gid, sizeof(union ibv_gid));
	inet_ntop(AF_INET6, &loopback_in.gid, gid, sizeof gid);
	printf("  local address:  LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n", loopback_in.lid, loopback_in.qpn, loopback_in.psn, gid);
        memset(&loopback_out, 0, sizeof(struct lite_dest));
        loopback_out.lid = ctx->portinfo.lid;
        loopback_out.qpn = ctx->loopback_out->qp_num;
        loopback_out.psn = lrand48() & 0xffffff;
        loopback_out.node_id = 0;
        //gid_to_wire_gid(&loopback_out.gid, gid);
        memcpy(&loopback_out.gid, &ctx->gid, sizeof(union ibv_gid));
	inet_ntop(AF_INET6, &loopback_out.gid, gid, sizeof gid);
	printf("  local address:  LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n", loopback_out.lid, loopback_out.qpn, loopback_out.psn, gid);
    
        if (server_connect_loopback(ctx->loopback_in, port, loopback_in.psn, mtu, sl, &loopback_out)) 
        {
                fprintf(stderr, "Couldn't connect to loopback out\n");
                die("EXIT during connect QP");
        }
        if (server_connect_loopback(ctx->loopback_out, port, loopback_out.psn, mtu, sl, &loopback_in)) 
        {
                fprintf(stderr, "Couldn't connect to loopback in\n");
                die("EXIT during connect QP");
        }
    
        debug_printf("loopback create successfully \n");
        return 0;
}

int server_init_interface(int ib_port)
{
        //MAX_NODE is defined
	struct ibv_device      **dev_list;
	struct ibv_device      *ib_dev;
	int                    size = 4096;
	int                    rx_depth = RECV_DEPTH;
	int		       i;
        
        mtu = LITE_MTU;
	sl = 0;
	routs = (int *)malloc(MAX_CONNECTION * sizeof(int));

	for (i = 0; i < MAX_CONNECTION; i++) {
		routs[i] = 0;
	}

	srand48(getpid() * time(NULL));

	page_size = sysconf(_SC_PAGESIZE);
	
        rcnt = 0;//How many items you are going to receive
	scnt = 0;//How many items you are going to send

	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		perror("Failed to get IB devices list");
		return 1;
	}
	ib_dev = *dev_list;
	if (!ib_dev) {
		fprintf(stderr, "No IB devices found\n");
		return 1;
	}
        struct ibv_context *t_context;
        struct ibv_device_attr device_attr;
        int rc;
        t_context = ibv_open_device(ib_dev);
        rc = ibv_query_device(t_context, &device_attr);
        if(!rc)
                printf("max qp %d\n", device_attr.max_qp);
        else
                die("Fail to get attribute\n");
        if(rc)
                die("Fail to get attribute\n");
        ctx = server_init_ctx(ib_dev, size, rx_depth, ib_port);
	if (!ctx)
		return 1;

	if (pp_get_port_info(ctx->context, ib_port, &ctx->portinfo)) {
		fprintf(stderr, "Couldn't get port info\n");
		return 1;
	}

        #ifndef NO_LOCK_IMPLEMENTATION
        server_setup_loopback_connections(ib_dev, size, rx_depth, ib_port);
        #endif
	ibv_free_device_list(dev_list);

	return 0;
}

int server_get_send_reply_id_by_semaphore()
{   
        int ret;
        sem_wait(&send_reply_wait_semaphore);
        pthread_mutex_lock(&send_reply_wait_mutex);
        ret = ctx->send_reply_wait_num % MAX_PARALLEL_THREAD;
        ctx->send_reply_wait_num++;
        pthread_mutex_unlock(&send_reply_wait_mutex);
        sem_post(&send_reply_wait_semaphore);
        //debug_printf("target from %d to %d\n", target_node, ret);
        return ret;
}

int server_get_connection_by_atomic_number(int target_node, int priority)
{
        int ret;
        if(ctx->num_alive_connection[target_node]==0)
        {
                debug_printf("Interact with %d\n", target_node);
                die("interact with no connection node");
        }
        pthread_mutex_lock(&atomic_accessing_lock[target_node]);
        ret = ctx->atomic_request_num[target_node]%ctx->num_alive_connection[target_node];
        ctx->atomic_request_num[target_node]++;
        pthread_mutex_unlock(&atomic_accessing_lock[target_node]);
        ret = ctx->num_parallel_connection*target_node + ret;
        return ret;
        //debug_printf("target from %d to %d\n", target_node, ret);
}

int server_get_waiting_id_by_semaphore(void)
{   
        int ret;
        sem_wait(&get_thread_waiting_number_semaphore);
        pthread_mutex_lock(&get_thread_waiting_number_mutex);
        ret = ctx->parallel_thread_num;
        ctx->parallel_thread_num++;
        if(ctx->parallel_thread_num==MAX_PARALLEL_THREAD)
                ctx->parallel_thread_num=0;
        pthread_mutex_unlock(&get_thread_waiting_number_mutex);
        sem_post(&get_thread_waiting_number_semaphore);
        //debug_printf("target from %d to %d\n", target_node, ret);
        return ret;
}

int server_msg_to_lite_dest(char *msg, struct lite_dest *rem_dest)
{
        char gid[33];
        sscanf(msg, "%x:%x:%x:%x:%s", &rem_dest->node_id, &rem_dest->lid, &rem_dest->qpn, &rem_dest->psn, gid);
        wire_gid_to_gid(gid, &rem_dest->gid);
        return 0;
}

int liteapi_send_message(int target_node, char *msg, int size)
{
        int priority = LOW_PRIORITY;
        //int connection_id = server_get_connection_by_atomic_number(target_node, priority);
        struct ibv_mr *ret_mr;
        ret_mr = server_register_memory_api(0, msg, size, IBV_ACCESS_LOCAL_WRITE);
        //return server_send_message_api(connection_id, MSG_SERVER_SEND, ret_mr, 0);
        return server_send_message_sge(target_node, MSG_SERVER_SEND, ret_mr, 0, 0);
}

int liteapi_send_reply(int target_node, char *msg, int size, char *output_msg)
{
        int priority = LOW_PRIORITY;
        int wait_send_reply_id;
        int connection_id = server_get_connection_by_atomic_number(target_node, priority);
        struct ibv_mr *ret_mr;

        wait_send_reply_id = SEND_REPLY_WAIT;
        ret_mr = server_register_memory_api(connection_id, msg, size, IBV_ACCESS_LOCAL_WRITE);
        server_send_message_sge(target_node, MSG_GET_SEND_AND_REPLY_1, ret_mr, (uint64_t)output_msg, (uint64_t)&wait_send_reply_id);
        while(wait_send_reply_id==SEND_REPLY_WAIT);
        return wait_send_reply_id;
}

int server_keep_server_alive(void *ptr)
{
        int ret;
        int listen_fd;
        int connection_fd;
        
        struct liteapi_two_ports *init_ports;
        init_ports = (struct liteapi_two_ports *)ptr;
        //int ib_port = *(int*)ptr;
        int ib_port = init_ports->ib_port;
        int ethernet_port = init_ports->ethernet_port;
        
        struct sockaddr_in myaddr;
        struct sockaddr_in remoteaddr;
        int addrlen = sizeof(remoteaddr);
        char remoteIP[INET_ADDRSTRLEN];
        char recv_buf[sizeof LID_SEND_RECV_FORMAT];
        char send_buf[sizeof LID_SEND_RECV_FORMAT];
        char	        		 gid[33];
        //int			             gidx = -1;
        //char output_buf[SEND_BUF_LENGTH];

        struct server_reply_format server_reply;
        memset(&server_reply, 0, sizeof(struct server_reply_format));
        
        int cur_node = 1;//0 is server itself
        //int ask_number_of_MR_set = ctx->num_node * ctx->num_parallel_connection;
        int ask_number_of_MR_set = FIRST_ASK_MR_SET * ctx->num_parallel_connection;
        int i,j;
        
        //Initialize Configuration
        memset(&myaddr, 0, sizeof(struct sockaddr_in));
        memset(&remoteaddr, 0, sizeof(struct sockaddr_in));
        memset(recv_buf, 0, sizeof(LID_SEND_RECV_FORMAT));
        memset(send_buf, 0, sizeof(LID_SEND_RECV_FORMAT));
        //memset(output_buf, 0, sizeof(output_buf));
        myaddr.sin_family       = AF_INET;
        myaddr.sin_port         = htons(ethernet_port);
        myaddr.sin_addr.s_addr  = htonl(INADDR_ANY);
    
        //Bind socket and start listen
        listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
	error("setsockopt(SO_REUSEADDR) failed");
        if (listen_fd < 0)
        {
                printf("init_rep_service_bak page create failed\n");
                return 1;
        }
        ret = bind(listen_fd, (struct sockaddr *)&myaddr, sizeof(myaddr));
	if (ret < 0) {
		printf("init_rep_service_bak page bind failed ret %d\n", ret);
                printf("Link Port Failed %d\n", ethernet_port);
		return 2;
	}
        ret = listen(listen_fd, LISTEN_BACKLOG);
        struct client_data loop_cache;
        memset(&loop_cache, 0, sizeof(struct client_data));
        
        server_post_receives_message(1, ctx->rx_depth);
        
        while(1)
        {
                //Get local LID information and prepare to send
                struct lite_dest        my_dest;
                struct lite_dest        rem_dest;
                int server_id = 0;
                struct ibv_ah_attr ah_attr;
                //Connect with the remote side
                connection_fd = accept(listen_fd, (struct sockaddr *)&remoteaddr, &addrlen);
        
                inet_ntop(AF_INET, &remoteaddr.sin_addr, remoteIP, INET_ADDRSTRLEN);
                
                //Prepare the local side IB configuration, refer to liteapi_establish_connection
                debug_printf("IB Preparation for the incoming %d connection from %s\n", cur_node,remoteIP);
                /*
                for(i=0;i<ctx->num_parallel_connection;i++)
                {
                        int cur_connection = cur_node*ctx->num_parallel_connection+i;
                        routs[cur_connection] += server_post_receives_message(cur_connection, 2, ctx->rx_depth/2);
                }*/

                //Send NODE ID
                debug_printf("send NODE_ID %d\n", cur_node);
                ret = write(connection_fd, &cur_node, sizeof(int));
                if(ret!= sizeof(int)){
                        die("SEND NODE ID ERROR");
                        return 3;
                }
                //Send require number
                ret = write(connection_fd, &ask_number_of_MR_set, sizeof(int));
                if(ret!= sizeof(int)){
                        die("SEND require MR number ERROR");
                        return 3;
                }
                
                for(i=0;i<ask_number_of_MR_set;i++)
                {
                        ret = read(connection_fd, &recv_buf, sizeof(recv_buf));
                        if(ret != sizeof(recv_buf))
                        {
                                fprintf(stderr, "%d set error %d %d\n", i, ret, sizeof(recv_buf));
                                die("Read remote MR set error");
                        }
                        //debug_printf("%d %s\n", i, recv_buf);
                        memcpy(loop_cache.server_information_buffer[i], recv_buf, ret);
                }
                
                debug_printf("Get Connection from %s: %s\n", remoteIP, loop_cache.server_information_buffer[0]);
                
                
                memcpy(loop_cache.server_name, remoteIP, strlen(remoteIP));
                memcpy(&server_reply.client_list[cur_node], &loop_cache, sizeof(struct client_data));
                
                //Send the local connection information to the remote side
                ret = write(connection_fd, &ctx->ah_attrUD[0], sizeof(struct client_ah_combined));
                ret = read(connection_fd, &ctx->ah_attrUD[cur_node], sizeof(struct client_ah_combined));
        	memset(&ah_attr, 0, sizeof(struct ibv_ah_attr));

                ah_attr.dlid          = ctx->ah_attrUD[cur_node].dlid;
                ah_attr.sl                = 0;
                ah_attr.src_path_bits = 0;
                ah_attr.port_num = 1;
		if(SGID_INDEX!=-1)
		{
			memcpy(&ah_attr.grh.dgid, &ctx->ah_attrUD[cur_node].gid, sizeof(union ibv_gid));
			ah_attr.is_global = 1;
			ah_attr.grh.sgid_index = SGID_INDEX;
			ah_attr.grh.hop_limit = 1;
		}
                ctx->ah[cur_node] = ibv_create_ah(ctx->pd, &ah_attr);
                printf("%s: UD message from %d with qpn %d and lid %d: %p\n", __func__, cur_node, ctx->ah_attrUD[cur_node].qpn, ctx->ah_attrUD[cur_node].dlid, ctx->ah[cur_node]);

                //Send connection requests to all the connected node except the current one
                for(i=1;i<cur_node;i++)//Since 0 is the server itself
                {
                        struct ibv_mr *ah_mr_1, *ah_mr_2;
                        if(strcmp(server_reply.client_list[cur_node].server_name, server_reply.client_list[i].server_name)==0)
                        {
                                continue;
                        }
                        ah_mr_1 = server_register_memory_api(0, &ctx->ah_attrUD[i], sizeof(struct client_ah_combined), IBV_ACCESS_LOCAL_WRITE);
                        ah_mr_2 = server_register_memory_api(0, &ctx->ah_attrUD[cur_node], sizeof(struct client_ah_combined), IBV_ACCESS_LOCAL_WRITE);
                        server_send_message_sge(cur_node, MSG_NODE_JOIN_UD, ah_mr_1, 0, 0);
                        server_send_message_sge(i, MSG_NODE_JOIN_UD, ah_mr_2, 0, 0);
                        for(j=0;j<ctx->num_parallel_connection;j++)
                        {
                                int new_connection_source = cur_node*ctx->num_parallel_connection + j;
                                int new_connection_target = i*ctx->num_parallel_connection+j;
                                //memcpy(ctx->send_msg[new_connection_source]->data.newnode_msg, server_reply.client_list[i].server_information_buffer[new_connection_source], sizeof(LID_SEND_RECV_FORMAT));
                                //server_send_message(new_connection_source, MSG_NODE_JOIN);
                                int connection_id_1 = new_connection_source;//server_get_connection_by_atomic_number(new_connection_source);
                                struct ibv_mr *ret_mr_1;
                                ret_mr_1 = server_register_memory_api(connection_id_1, &server_reply.client_list[i].server_information_buffer[new_connection_source], sizeof(LID_SEND_RECV_FORMAT), IBV_ACCESS_LOCAL_WRITE);
                                //debug_printf("send %s to %d via %d\n", server_reply.client_list[i].server_information_buffer[new_connection_source], new_connection_source, connection_id_1);
                                server_send_message_sge(cur_node, MSG_NODE_JOIN, ret_mr_1, 0, 0);
                                
                                //memcpy(ctx->send_msg[new_connection_target]->data.newnode_msg, server_reply.client_list[cur_node].server_information_buffer[new_connection_target], sizeof(LID_SEND_RECV_FORMAT));
                                //server_send_message(new_connection_target, MSG_NODE_JOIN);
                                
                                int connection_id_2 = new_connection_target;//server_get_connection_by_atomic_number(new_connection_target);
                                struct ibv_mr *ret_mr_2;
                                ret_mr_2 = server_register_memory_api(connection_id_2, &server_reply.client_list[cur_node].server_information_buffer[new_connection_target], sizeof(LID_SEND_RECV_FORMAT), IBV_ACCESS_LOCAL_WRITE);
                                server_send_message_sge(i, MSG_NODE_JOIN, ret_mr_2, 0, 0);
                                
                                //debug_printf("send %s to %d\n", server_reply.client_list[cur_node].server_information_buffer[new_connection_target], new_connection_target);
                                usleep(1000);
                        }
                }
                
                memset(&loop_cache, 0, sizeof(struct client_data));
                memset(recv_buf, 0, sizeof LID_SEND_RECV_FORMAT);
                memset(send_buf, 0, sizeof LID_SEND_RECV_FORMAT);
                cur_node++;

        }
}
int send_handle(char *input_buf, int size)
{
        printf("%s\n", input_buf);
        free(input_buf);
        return 0;
}
int handle_send_reply(char *input_buf, uint32_t size, char *output_buf, uint32_t *output_size)
{
        sprintf(output_buf, "server:%s", input_buf);
        uint32_t ret_length = strlen(output_buf);
        memcpy(output_size, &ret_length, sizeof(uint32_t));
        return 1;

}
int handle_atomic_send(struct atomic_struct *input_list, int length, char *ret, int *ret_size)
{
        ret[0]='o';
        ret[1]='k';
        *ret_size=2;
        return 0;
}

int server_reply_ask_lock_request(struct send_and_reply_format *ptr)
{
        int target_lock;
        
        struct ibv_mr *output_mr;
        int connection_id;
        target_lock = *(ptr->msg);
        pthread_mutex_lock(&num_lock_mutex);
        
        pthread_mutex_unlock(&num_lock_mutex);
        connection_id = server_get_connection_by_atomic_number(ptr->src_id, HIGH_PRIORITY);
        if(target_lock<ctx->num_used_lock)
        {
                output_mr = server_register_memory_api(connection_id, &ctx->shared_locks_mr[target_lock], sizeof(struct lmr_info), IBV_ACCESS_LOCAL_WRITE);
                server_send_message_sge(ptr->src_id, MSG_ASK_LOCK_REPLY, output_mr, ptr->store_addr, ptr->store_semaphore);
        }
        else
        {
                struct ibv_mr empty;
                memset(&empty, 0, sizeof(struct ibv_mr));
                output_mr = server_register_memory_api(connection_id, &empty, sizeof(int), IBV_ACCESS_LOCAL_WRITE);
                server_send_message_sge(ptr->src_id, MSG_ASK_LOCK_REPLY, output_mr, ptr->store_addr, ptr->store_semaphore);
        }
        return 0;
}
int server_reply_create_lock_request(struct send_and_reply_format *ptr)
{
        int connection_id;
        struct ibv_mr *ret_mr, *output_mr;
        //struct lmr_info send_mr;
        pthread_mutex_lock(&num_lock_mutex);
        
        //ret_mr = server_register_memory_api(connection_id, &ctx->shared_locks[2], sizeof(uint64_t), IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC);
        //ctx->shared_locks[2]=(uint64_t)LOCK_USED;
        ret_mr = server_register_memory_api(0, (void *)&shared_locks[ctx->num_used_lock], sizeof(uint64_t), IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC);
        shared_locks[ctx->num_used_lock]=LOCK_USED;
        if(ret_mr==0)
        {
                debug_printf("Oh dear, something went wrong with %d\n", errno);
                die("get zero register\n");
        }
        connection_id = server_get_connection_by_atomic_number(ptr->src_id, HIGH_PRIORITY);
        //Lock related messages are always using high priority
        ctx->shared_locks_mr[ctx->num_used_lock].length = ret_mr->length;
        ctx->shared_locks_mr[ctx->num_used_lock].rkey = ret_mr->rkey;
        ctx->shared_locks_mr[ctx->num_used_lock].lkey = ret_mr->lkey;
        ctx->shared_locks_mr[ctx->num_used_lock].addr = ret_mr->addr;
        ctx->shared_locks_mr[ctx->num_used_lock].node_id = NODE_ID;
        //send_mr.length = ret_mr->length;
        //send_mr.rkey = ret_mr->rkey;
        //send_mr.lkey = ret_mr->lkey;
        //send_mr.addr = ret_mr->addr;
        output_mr = server_register_memory_api(connection_id, &ctx->shared_locks_mr[ctx->num_used_lock], sizeof(struct lmr_info), IBV_ACCESS_LOCAL_WRITE);
        server_send_message_sge(ptr->src_id, MSG_CREATE_LOCK_REPLY, output_mr, ptr->store_addr, ptr->store_semaphore);
        free(ptr->msg);
        free(ptr);
        
        ctx->num_used_lock++;
        pthread_mutex_unlock(&num_lock_mutex);
        return 0;
}
int server_reply_send_request(struct send_and_reply_format *ptr)
{
        char *ret = malloc(RDMA_BUFFER_SIZE*2);
        struct ibv_mr *ret_mr;
        int ret_priority=LOW_PRIORITY;
        uint32_t ret_size;
        int connection_id;
        ctx->send_reply_handler(ptr->msg, ptr->length, ret, &ret_size, ptr->src_id);
        connection_id = server_get_connection_by_atomic_number(ptr->src_id, ret_priority);
        ret_mr = server_register_memory_api(connection_id, ret, ret_size, IBV_ACCESS_LOCAL_WRITE);
        //server_send_message_api(connection_id, MSG_GET_SEND_AND_REPLY_2, ret_mr, ptr->store_addr);
        server_send_message_sge(ptr->src_id, MSG_GET_SEND_AND_REPLY_2, ret_mr, ptr->store_addr, ptr->store_semaphore);
        free(ret);
        free(ptr);
        return 0;
}
int server_reply_atomic_send_request(struct send_and_reply_format *ptr)
{
        char *ret = malloc(RDMA_BUFFER_SIZE*4);
        struct ibv_mr *ret_mr;
        uint32_t ret_size;
        int ret_priority=LOW_PRIORITY;
        int connection_id;
        ctx->atomic_send_handler((struct atomic_struct *)ptr->msg, ptr->length, ret, &ret_size, ptr->src_id);
        connection_id = server_get_connection_by_atomic_number(ptr->src_id, ret_priority);
        ret_mr = server_register_memory_api(connection_id, ret, ret_size, IBV_ACCESS_LOCAL_WRITE);
        server_send_message_sge(ptr->src_id, MSG_GET_ATOMIC_REPLY, ret_mr, ptr->store_addr, ptr->store_semaphore);
        free(ret);
        free(ptr);
        return 0;
}
int server_reply_remote_mr_request(struct send_and_reply_format *ptr)
{        
        int connection_id = server_get_connection_by_atomic_number(ptr->src_id, 0);
        void *addr;
        struct ibv_mr *ret_mr, *output_mr;
        struct lmr_info send_mr;
        int ask_size;
        memcpy(&ask_size, ptr->msg, ptr->length);
        debug_printf("Process ptr->length %d\n", ask_size);
        addr = malloc(ask_size * sizeof(char));
        memset(addr, 0, ask_size * sizeof(char));
        ret_mr = server_register_memory_api(connection_id, addr, ask_size, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC);
        //printf("%x %x %x\n", ret_mr->addr, ret_mr->lkey, ret_mr->length);
        if(ret_mr==0)
        {
                debug_printf("Oh dear, something went wrong with %d\n", errno);
                die("get zero register\n");
        }
        send_mr.length = ret_mr->length;
        send_mr.rkey = ret_mr->rkey;
        send_mr.lkey = ret_mr->lkey;
        send_mr.addr = ret_mr->addr;
        send_mr.node_id = NODE_ID;
        output_mr = server_register_memory_api(connection_id, &send_mr, sizeof(struct lmr_info), IBV_ACCESS_LOCAL_WRITE);
        server_send_message_sge(ptr->src_id, MSG_GET_REMOTEMR_REPLY, output_mr, ptr->store_addr, ptr->store_semaphore);
        free(ptr->msg);
        free(ptr);
        return 0;
}
int server_find_qp_id_by_qpnum(uint32_t qp_num)
{
        return 0;
}
int server_lock_handling(void)
{
        
        int num_lock;
        int i, connection_id;
        unsigned long long int assigned_num, readlock_num;
        struct ibv_mr *assigned_mr, *readlock_mr;
        struct lmr_info readlock_c_mr;
        //struct lmr_info assigned_c_mr;
        struct send_and_reply_format *ptr;
        int length;
        unsigned long long int ret;
        struct liteapi_header output_header;
        struct ibv_mr *output_header_mr;
        
        output_header_mr = server_register_memory_api(connection_id, &output_header, sizeof(struct liteapi_header), IBV_ACCESS_LOCAL_WRITE);
        
        assigned_mr = server_register_memory_api(0, &assigned_num, sizeof(uint64_t), IBV_ACCESS_LOCAL_WRITE);
        //assigned_c_mr.length = assigned_mr->length;
        //assigned_c_mr.rkey = assigned_mr->rkey;
        //assigned_c_mr.lkey = assigned_mr->lkey;
        //assigned_c_mr.addr = assigned_mr->addr;
        //assigned_c_mr.node_id = NODE_ID;
        
        readlock_mr = server_register_memory_api(0, &readlock_num, sizeof(uint64_t), IBV_ACCESS_LOCAL_WRITE);
        readlock_c_mr.length = readlock_mr->length;
        readlock_c_mr.rkey = readlock_mr->rkey;
        readlock_c_mr.lkey = readlock_mr->lkey;
        readlock_c_mr.addr = readlock_mr->addr;
        readlock_c_mr.node_id = NODE_ID;
        
        while(1)
        {
                pthread_mutex_lock(&num_lock_mutex);
                num_lock = ctx->num_used_lock;
                pthread_mutex_unlock(&num_lock_mutex);
                for(i=0;i<num_lock;i++)
                {
                        server_loopback_read(&ctx->shared_locks_mr[i], &readlock_c_mr);
                        pthread_mutex_lock(&fifo_lock_mutex);
                        length = fifo_len(ctx->shared_locks_fifo_queue[i]);
                        if(readlock_num==LOCK_USED&&length==0)
                        {
                                pthread_mutex_unlock(&fifo_lock_mutex);
                                ret = server_loopback_compare_swp(&ctx->shared_locks_mr[i], &readlock_c_mr, (uint64_t)LOCK_USED, (uint64_t)LOCK_AVAILABLE);
                                if(ret || readlock_num!=LOCK_USED)
                                        printf("1-Lock assigned fail in queue %d\n", i);
                        }
                        else if(readlock_num==LOCK_USED&&length>0)
                        {
                                if(readlock_num!=LOCK_USED)
                                {
                                        printf("Special error %llu\n", shared_locks[i]);
                                }
                                ptr = (struct send_and_reply_format *)fifo_remove(ctx->shared_locks_fifo_queue[i]);
                                pthread_mutex_unlock(&fifo_lock_mutex);
                                if(ptr==NULL)
                                {
                                                pthread_mutex_unlock(&fifo_lock_mutex);
                                                debug_printf("recv NULL\n");
                                                continue;
                                }
                                connection_id = server_get_connection_by_atomic_number(ptr->src_id, HIGH_PRIORITY);
                                //assigned_num=(uint64_t)LOCK_ASSIGNED;
                                assigned_num=(uint64_t)LOCK_LOCK;
                                
                                ret = server_loopback_compare_swp(&ctx->shared_locks_mr[i], &readlock_c_mr, (uint64_t)readlock_num, assigned_num);
                                if(ret)
                                        printf("2-Lock assigned fail in queue %d\n", i);
                                else
                                {
                                        server_setup_liteapi_header(NODE_ID, ptr->store_addr, ptr->store_semaphore, assigned_mr->length, 0, MSG_ASSIGN_LOCK, &output_header);
                                        server_send_message_sge_header_fixed(ptr->src_id, MSG_ASSIGN_LOCK, assigned_mr, ptr->store_addr, ptr->store_semaphore, output_header_mr);
                                }
                                free(ptr);
                        }
                        else if(readlock_num==LOCK_AVAILABLE&&length>0)//find potential bug - since the client side is handling faster than server side
                        {
                                //assigned_num=(uint64_t)LOCK_ASSIGNED;
                                assigned_num=(uint64_t)LOCK_LOCK;
                                ret = server_loopback_compare_swp(&ctx->shared_locks_mr[i], &readlock_c_mr, (uint64_t)readlock_num, assigned_num);
                                if(!ret)
                                {
                                        ptr = (struct send_and_reply_format *)fifo_remove(ctx->shared_locks_fifo_queue[i]);
                                        pthread_mutex_unlock(&fifo_lock_mutex);
                                        connection_id = server_get_connection_by_atomic_number(ptr->src_id, HIGH_PRIORITY);
                                        
                                        server_setup_liteapi_header(NODE_ID, ptr->store_addr, ptr->store_semaphore, assigned_mr->length, 0, MSG_ASSIGN_LOCK, &output_header);
                                        server_send_message_sge_header_fixed(ptr->src_id, MSG_ASSIGN_LOCK, assigned_mr, ptr->store_addr, ptr->store_semaphore, output_header_mr);
                                        free(ptr);
                                }
                                else
                                        pthread_mutex_unlock(&fifo_lock_mutex);
                        }
                        else
                                pthread_mutex_unlock(&fifo_lock_mutex);
                        
                }
        }
        return 0;
}
int server_poll_cq(struct ibv_cq *target_cq)
{
        struct ibv_wc wc[2];
        int ne, i;

        int connection_id, waiting_id;
	while (1) 
        {
                do {
                        ne = ibv_poll_cq(target_cq, 1, wc);
                        if (ne < 0) {
                                fprintf(stderr, "poll CQ failed %d\n", ne);
                                return 1;
                        }
                } while (ne < 1);
                for (i = 0; i < ne; ++i) 
                {

                        if (wc[i].status != IBV_WC_SUCCESS) {
                                fprintf(stderr, "Failed status %s (%d) for wr_id %d\n",
                                                ibv_wc_status_str(wc[i].status),
                                                wc[i].status, (int) wc[i].wr_id);
                                die("Failed Status");
                                return 2;
                        }

                        if ((int) wc[i].opcode == IBV_WC_RECV) 
                        {
                                
                                struct liteapi_post_receive_intermediate_struct *p_r_i_struct = (struct liteapi_post_receive_intermediate_struct*)wc[i].wr_id;
                                struct liteapi_header *header_addr;
		struct liteapi_header temp_header;
                                char *addr;
                                int type;
		memcpy(&temp_header, (void *)p_r_i_struct->header + 40, sizeof(struct liteapi_header));
                                header_addr = &temp_header;
                                //header_addr = (struct liteapi_header*)p_r_i_struct->header;
                                addr = (char *)p_r_i_struct->msg;
                                connection_id =  server_find_qp_id_by_qpnum(wc[i].qp_num);
                                ctx->recv_num++;
                                type = header_addr->type;
                                if (type == MSG_CLIENT_SEND)
                                {	
                                        ctx->send_handler(addr, header_addr->length);
                                }
                                else if(type == MSG_GET_SEND_AND_REPLY_1)
                                {
                                        pthread_t thread_reply_send_request;
                                        struct send_and_reply_format *recv;
                                        recv = malloc(sizeof(struct send_and_reply_format));
                                        recv->src_id = header_addr->src_id;
                                        recv->store_addr = header_addr->store_addr;
                                        recv->store_semaphore = header_addr->store_semaphore;
                                        recv->length = header_addr->length;
                                        recv->msg = addr;
                                        printf("MSG_GET_SEND_AND_REPLY_1 from %d\n", recv->src_id);
                                        pthread_create(&thread_reply_send_request, NULL, (void *)server_reply_send_request, recv);
		//	server_reply_send_request(recv);	
                                        free(header_addr);
                                }
                                else if(type == MSG_GET_REMOTEMR)
                                {
                                        pthread_t thread_reply_mr_request;
                                        struct send_and_reply_format *recv;
                                        recv = malloc(sizeof(struct send_and_reply_format));
                                        recv->src_id = header_addr->src_id;
                                        recv->store_addr = header_addr->store_addr;
                                        recv->store_semaphore = header_addr->store_semaphore;
                                        recv->length = header_addr->length;
                                        recv->msg = addr;
                                        pthread_create(&thread_reply_mr_request,NULL, (void *)server_reply_remote_mr_request, recv);
                                        free(header_addr);
                                }
                                else if(type == MSG_GET_ATOMIC_START)
                                {
		        int request_len = 0;
		        memcpy(&request_len, addr, header_addr->length);
                                        ctx->atomic_buffer[connection_id] = (struct atomic_struct *)malloc(request_len * sizeof(struct atomic_struct));
                                        ctx->atomic_buffer_total_length[connection_id] = request_len;
                                        ctx->atomic_buffer_cur_length[connection_id] = 0;
                                        free(header_addr);
                                }
                                else if(type == MSG_GET_ATOMIC_MID)
                                {
                                        int cur_number = ctx->atomic_buffer_cur_length[connection_id];
                                        ctx->atomic_buffer[connection_id][cur_number].vaddr = addr;
                                        ctx->atomic_buffer[connection_id][cur_number].len = header_addr->length;
                                        ctx->atomic_buffer_cur_length[connection_id]++;
                                        if(ctx->atomic_buffer_cur_length[connection_id]==ctx->atomic_buffer_total_length[connection_id])
                                        {
                                                pthread_t thread_reply_send_request;
                                                struct send_and_reply_format *recv;
                                                recv = malloc(sizeof(struct send_and_reply_format));
                                                recv->msg = (void *)ctx->atomic_buffer[connection_id];
                                                recv->src_id = header_addr->src_id;
                                                recv->store_addr = header_addr->store_addr;
                                                recv->store_semaphore = header_addr->store_semaphore;
                                                recv->length = ctx->atomic_buffer_cur_length[connection_id];
                                                pthread_create(&thread_reply_send_request, NULL, (void *)server_reply_atomic_send_request, recv);
                                        }
                                        free(header_addr);
                                }
                                else if(type == MSG_GET_ATOMIC_SINGLE_START)
                                {
                                        int request_len=0;
                                        memcpy(&request_len, addr, header_addr->length);
                                        ctx->atomic_buffer[connection_id] = (struct atomic_struct *)malloc(request_len * sizeof(struct atomic_struct));
                                        ctx->atomic_buffer_total_length[connection_id] = request_len;
                                        ctx->atomic_buffer_cur_length[connection_id] = 0;
                                }
                                else if(type == MSG_GET_ATOMIC_SINGLE_MID)
                                {
                                        int cur_number = ctx->atomic_buffer_cur_length[connection_id];
                                        ctx->atomic_buffer[connection_id][cur_number].vaddr = addr;
                                        ctx->atomic_buffer[connection_id][cur_number].len = header_addr->length;
                                        ctx->atomic_buffer_cur_length[connection_id]++;
                                        if(ctx->atomic_buffer_cur_length[connection_id]==ctx->atomic_buffer_total_length[connection_id])
                                        {
                                                //pthread_t thread_reply_send_request;
                                                struct send_and_reply_format *recv;
                                                recv = malloc(sizeof(struct send_and_reply_format));
                                                recv->msg = (void *)ctx->atomic_buffer[connection_id];
                                                recv->src_id = header_addr->src_id;
                                                recv->length = ctx->atomic_buffer_cur_length[connection_id];
                                                ctx->atomic_single_send_handler((struct atomic_struct *)recv->msg, recv->length, recv->src_id);
                                        }
                                }
                                else if(type == MSG_GET_REMOTEMR_REPLY || type == MSG_GET_SEND_AND_REPLY_2 || type == MSG_GET_ATOMIC_REPLY)
                                {
                                        memcpy((void *)header_addr->store_addr, addr, header_addr->length);
                                        *(int*)header_addr->store_semaphore = header_addr->length;
                                        free(addr);
                                        free(header_addr);
                                }
                                else if(type == MSG_CREATE_LOCK)
                                {
                                        pthread_t thread_reply_create_lock_request;
                                        struct send_and_reply_format *recv;
                                        
                                        recv = malloc(sizeof(struct send_and_reply_format));
                                        recv->src_id = header_addr->src_id;
                                        recv->store_addr = header_addr->store_addr;
                                        recv->store_semaphore = header_addr->store_semaphore;
                                        recv->length = header_addr->length;
                                        recv->msg = addr;
                                        
                                        pthread_create(&thread_reply_create_lock_request, NULL, (void *)server_reply_create_lock_request, recv);
                                        free(header_addr);
                                }
                                else if(type == MSG_RESERVE_LOCK)
                                {
                                        //Get the lock address first
                                        struct send_and_reply_format *recv;
                                        struct lmr_info *temp;
                                        int tar_lock_id;
                                        recv = malloc(sizeof(struct send_and_reply_format));
                                        recv->src_id = header_addr->src_id;
                                        recv->store_addr = header_addr->store_addr;
                                        recv->store_semaphore = header_addr->store_semaphore;
                                        recv->length = header_addr->length;
                                        
                                        temp=(struct lmr_info *)addr;
                                        //transform the lock address into lock id
                                        tar_lock_id = ((uint64_t)temp->addr-(uint64_t)&shared_locks[0]) / sizeof(uint64_t);
                                        pthread_mutex_lock(&fifo_lock_mutex);
                                        fifo_add(ctx->shared_locks_fifo_queue[tar_lock_id], (void *)recv);
                                        pthread_mutex_unlock(&fifo_lock_mutex);
                                        
                                        free(addr);
                                        free(header_addr);
                                }
                                else if(type == MSG_ASK_LOCK)
                                {
                                        pthread_t thread_reply_ask_lock_request;
                                        struct send_and_reply_format *recv;
                                        recv = malloc(sizeof(struct send_and_reply_format));
                                        recv->src_id = header_addr->src_id;
                                        recv->store_addr = header_addr->store_addr;
                                        recv->store_semaphore = header_addr->store_semaphore;
                                        recv->length = header_addr->length;
                                        recv->msg = addr;
                                        
                                        pthread_create(&thread_reply_ask_lock_request, NULL, (void *)server_reply_ask_lock_request, recv);
                                        free(header_addr);
                                }
                                else
                                {
                                        debug_printf("Weird Type Received from connection: %d as %d by src: %d\n", connection_id, type, header_addr->src_id);
                                }
                                //if(ctx->recv_num[connection_id]==ctx->rx_depth/2)
                                if(ctx->recv_num==ctx->rx_depth)
                                {
                                        /*pthread_t thread_receive;
                                        int t_conn = connection_id;
                                        pthread_create(&thread_receive,NULL,(void *)post_receives_message_from_poll_cq, &t_conn);*/
                                        server_post_receives_message(1, RECV_DEPTH);
                                        ctx->recv_num=1;
                                        /*int temp_rou;
                                        for(temp_rou=0;temp_rou<15;temp_rou++)
                                                printf("%d\t", ctx->recv_num[temp_rou]);
                                        printf("\n");*/
                                        //server_post_receives_message(connection_id, 1);
                                        //ctx->recv_num[connection_id]=1;
                                }

                        }
                        else if ((int) wc[i].opcode == IBV_WC_SEND)
                        {
                                connection_id =  (int) wc[i].wr_id % WRAP_UP_NUM_FOR_WRID;
                                waiting_id = (int) (wc[i].wr_id % WRAP_UP_NUM_FOR_TYPE)/ WRAP_UP_NUM_FOR_WRID;
                                int type = wc[i].wr_id/WRAP_UP_NUM_FOR_TYPE;
                                if(type == MSG_GET_SEND_AND_REPLY_1)
                                {
                                        ctx->thread_state[waiting_id]=TS_DONE;
                                }
                                else if(type == MSG_GET_SEND_AND_REPLY_2)
                                {
                                        ctx->thread_state[waiting_id]=TS_DONE;
                                }
                                else if(type == MSG_SERVER_SEND)
                                {                                        
                                        ctx->thread_state[waiting_id]=TS_DONE;
                                }
                                else if(type == MSG_NODE_JOIN || type == MSG_NODE_JOIN_UD)
                                {        
                                        ctx->thread_state[waiting_id]=TS_DONE;
                                }
                                else if (type == MSG_GET_REMOTEMR)
                                {
                                        
                                        ctx->thread_state[waiting_id]=TS_DONE;
                                }
                                else if (type == MSG_GET_REMOTEMR_REPLY)
                                {
                                        
                                        ctx->thread_state[waiting_id]=TS_DONE;
                                }
                                else if (type == MSG_GET_ATOMIC_START)
                                {
                                        ctx->thread_state[waiting_id]=TS_DONE;
                                }
                                else if (type == MSG_GET_ATOMIC_MID)
                                {
                                        ctx->thread_state[waiting_id]=TS_DONE;
                                }
                                else if (type == MSG_GET_ATOMIC_REPLY)
                                {
                                        ctx->thread_state[waiting_id]=TS_DONE;
                                }
                                else if (type == MSG_GET_ATOMIC_SINGLE_START)
                                {
                                        ctx->thread_state[waiting_id]=TS_DONE;
                                }
                                else if (type == MSG_GET_ATOMIC_SINGLE_MID)
                                {
                                        ctx->thread_state[waiting_id]=TS_DONE;
                                }
                                else if (type == MSG_CREATE_LOCK_REPLY)
                                {
                                        ctx->thread_state[waiting_id]=TS_DONE;
                                }
                                else if (type == MSG_ASSIGN_LOCK)
                                {
                                        ctx->thread_state[waiting_id]=TS_DONE;
                                }
                                else if (type == MSG_ASK_LOCK_REPLY)
                                {
                                        ctx->thread_state[waiting_id]=TS_DONE;
                                }
                                else
                                {
                                        debug_printf("Weird send type %d on connection %d\n", type, connection_id);
                                }
                        }
                        else if ((int) wc[i].opcode == IBV_WC_RDMA_READ)
                        {
                                connection_id =  (int) wc[i].wr_id % WRAP_UP_NUM_FOR_WRID;
                                waiting_id = (int) (wc[i].wr_id % WRAP_UP_NUM_FOR_TYPE)/ WRAP_UP_NUM_FOR_WRID;
                                ctx->thread_state[waiting_id]=TS_DONE;
                        }
                        else if ((int) wc[i].opcode == IBV_WC_RDMA_WRITE)
                        {
                                connection_id =  (int) wc[i].wr_id % WRAP_UP_NUM_FOR_WRID;
                                waiting_id = (int) (wc[i].wr_id % WRAP_UP_NUM_FOR_TYPE)/ WRAP_UP_NUM_FOR_WRID;
                                debug_printf("RDMA_WRITE %d %ddone\n", connection_id, waiting_id);
                                
                                ctx->thread_state[waiting_id]=TS_DONE;
                        }
                        else
                        {
                                debug_printf("Recv weird event as %d from %d\n", (int) wc[i].opcode);
                                die("Weird event received");
                        }
                }
                //ibv_ack_cq_events(target_cq, ne);
	}

	return 0;
}
int liteapi_init(int ib_port, int ethernet_port, int option){
         
        server_init_interface(ib_port);
        ctx->send_handler = send_handle;
        ctx->send_reply_handler = handle_send_reply;
        ctx->atomic_send_handler = handle_atomic_send;
        
        //Setup server side Ethernet configuration
        //Now, I am using a naive server/client connection model. This could be modified into select/fork/thread model in the future
        int i;
        int ret;
        struct liteapi_two_ports init_port;
        init_port.ib_port = ib_port;
        init_port.ethernet_port = ethernet_port;
        for(i=0;i<MAX_NODE;i++)
        {
                ret = pthread_mutex_init(&atomic_accessing_lock[i], NULL);
                if(ret!=0)
                        die("mutex error while creating\n");
        }
        /*for(i=0;i<MAX_CONNECTION;i++)
        {
                ret = pthread_mutex_init(&connection_lock[i], NULL);
                if(ret!=0)
                        die("mutex error while creating\n");
        }*/
        ret = pthread_mutex_init(&connection_lock, NULL);
        if(ret!=0)
        	die("mutex error");
        
        ret = sem_init(&get_thread_waiting_number_semaphore, 0, MAX_PARALLEL_THREAD);
        if(ret!=0)
                die("semaphore error while creating\n");
        ret = sem_init(&send_reply_wait_semaphore, 0, MAX_PARALLEL_THREAD);
        if(ret!=0)
                die("semaphore error while creating\n");
        ret = pthread_mutex_init(&send_reply_wait_mutex, NULL);
        if(ret!=0)
                die("mutex error while creating\n");        
                
        ret = pthread_mutex_init(&num_lock_mutex, NULL);
        if(ret!=0)
                die("mutex error while creating num_lock_mutex\n");        
        
        ret = pthread_mutex_init(&fifo_lock_mutex, NULL);
        if(ret!=0)
                die("mutex error while creating fifo_lock_mutex\n");        
                
        
        if(MAX_NODE*NUM_PARALLEL_CONNECTION >=WRAP_UP_NUM_FOR_WRID)
        {
                die("MAX_NODE * NUM_PARALLEL_CONNECTION is larger than WRAP_UP_NUM_FOR_WRID, please modify it\n");
        }
        
        ctx->ah_attrUD[0].qpn = ctx->qp->qp_num;
        ctx->ah_attrUD[0].node_id = 0;
        ctx->ah_attrUD[0].qkey = 0x336;
        ctx->ah_attrUD[0].dlid = ctx->portinfo.lid;
	memcpy(&ctx->ah_attrUD[0].gid, &ctx->gid, sizeof(union ibv_gid));
        
        pthread_t                           thread_server;
        pthread_create(&thread_server, NULL, (void *)&server_keep_server_alive, &init_port);
        pthread_t                           thread_poll_cq;
        struct ibv_cq *target_cq;
        target_cq = ctx->cq;
        pthread_create(&thread_poll_cq, NULL, (void *)&server_poll_cq, target_cq);
        
        //Comment-out lock handling
        #ifndef NO_LOCK_IMPLEMENTATION
        if(option == 0)
        {
                pthread_t                           thread_lock;
                pthread_create(&thread_lock, NULL, (void *)&server_lock_handling, NULL);
        }
        #endif
        return 0;
}
int server_get_remotemr(int target_node, void *addr, int size, struct lmr_info *ret_mr)
{
        int wait_send_reply_id;
        int connection_id = server_get_connection_by_atomic_number(target_node, 0);
        struct ibv_mr *output_mr;
        int request_size = size;
        
        wait_send_reply_id = SEND_REPLY_WAIT;
        output_mr = server_register_memory_api(connection_id, &request_size, sizeof(int), IBV_ACCESS_LOCAL_WRITE);
        server_send_message_sge(target_node, MSG_GET_REMOTEMR, output_mr, (uint64_t)ret_mr, (uint64_t)&wait_send_reply_id);
        while(wait_send_reply_id==SEND_REPLY_WAIT);
        return 0;
}
int server_rdma_write(int target_node, struct lmr_info *mr_addr, void *local_addr, int size)
{
        int connection_id = server_get_connection_by_atomic_number(target_node, 0);
        server_send_request(connection_id, M_WRITE, mr_addr, local_addr, size);
        return 0;
}

int server_rdma_read(int target_node, struct lmr_info *mr_addr, void *local_addr, int size)
{
        int connection_id = server_get_connection_by_atomic_number(target_node, 0);
        server_send_request(connection_id, M_READ, mr_addr, local_addr, size);
        return 0;
}

int server_loopback_compare_swp(struct lmr_info *remote_mr, struct lmr_info *local_mr, unsigned long long guess_value, unsigned long long swp_value)
{
        
        struct ibv_wc wc[2];
	struct ibv_send_wr wr, *bad_wr = NULL;
	struct ibv_sge sge;
        int ne, i;
        
	memset(&wr, 0, sizeof(wr));
	memset(&sge, 0, sizeof(sge));

	wr.wr_id = 1;
	wr.opcode = IBV_WR_ATOMIC_CMP_AND_SWP;
	wr.sg_list = &sge;
	wr.num_sge = 1;
        
	wr.send_flags = IBV_SEND_SIGNALED;
	wr.wr.atomic.remote_addr = (uintptr_t)remote_mr->addr;
	wr.wr.atomic.rkey = remote_mr->rkey;
	wr.wr.atomic.compare_add = guess_value;
	wr.wr.atomic.swap = swp_value;
	sge.addr = (uint64_t)local_mr->addr;
	sge.length = local_mr->length;
	sge.lkey = local_mr->lkey;
	ibv_post_send(ctx->loopback_out, &wr, &bad_wr);
        do {
                ne = ibv_poll_cq(ctx->loopback_cq, 1, wc);
                if (ne < 0) {
                        fprintf(stderr, "poll loopback swp_cmp CQ failed %d\n", ne);
                        return 1;
                }
        } while (ne < 1);
        for (i = 0; i < ne; ++i) 
        {

                if (wc[i].status != IBV_WC_SUCCESS || wc[i].opcode !=IBV_WC_COMP_SWAP) 
                {
                        fprintf(stderr, "Failed status %s (%d) for wr_id %d\n",
                                        ibv_wc_status_str(wc[i].status),
                                        wc[i].status, (int) wc[i].wr_id);
                        fprintf(stderr, "opcode: %d\n", wc[i].opcode);
                        die("Failed Status");
                        return 2;
                }
        }
	if(memcmp(local_mr->addr, &guess_value, sizeof(uint64_t))==0)
		return 0;
	return 1;
}

int server_loopback_read(struct lmr_info *remote_mr, struct lmr_info *local_mr)
{
	struct ibv_send_wr wr, *bad_wr = NULL;
	struct ibv_sge sge;
        struct ibv_wc wc[2];
        int ne, i;
        
	memset(&wr, 0, sizeof(wr));
        memset(&sge, 0, sizeof(sge));

	wr.wr_id = 1;
	wr.opcode = IBV_WR_RDMA_READ;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IBV_SEND_SIGNALED;
        wr.wr.rdma.remote_addr = (uintptr_t)remote_mr->addr;
	wr.wr.rdma.rkey = remote_mr->rkey;
	sge.addr = (uint64_t)local_mr->addr;
	sge.length = local_mr->length;//sizeof(unsigned long long int);//
	sge.lkey = local_mr->lkey;
	ibv_post_send(ctx->loopback_out, &wr, &bad_wr);
        do {
                ne = ibv_poll_cq(ctx->loopback_cq, 1, wc);
                if (ne < 0) {
                        fprintf(stderr, "poll loopback read CQ failed %d\n", ne);
                        return 1;
                }
        } while (ne < 1);
        for (i = 0; i < ne; ++i) 
        {

                if (wc[i].status != IBV_WC_SUCCESS || wc[i].opcode !=IBV_WC_RDMA_READ) 
                {
                        fprintf(stderr, "Failed status %s (%d) for wr_id %d\n",
                                        ibv_wc_status_str(wc[i].status),
                                        wc[i].status, (int) wc[i].wr_id);
                        fprintf(stderr, "opcode: %d\n", wc[i].opcode);
                        die("Failed Status");
                        return 2;
                }
        }
	return 0;
}

int server_send_request(int connection_id, enum mode s_mode, struct lmr_info *remote_mr, void *addr, int size)
{
	struct ibv_send_wr wr, *bad_wr = NULL;
	struct ibv_sge sge;
        struct ibv_mr *ret_mr;
        
        int waiting_id = server_get_waiting_id_by_semaphore();
        ctx->thread_state[waiting_id]=TS_WAIT;
        
	memset(&wr, 0, sizeof(wr));
        memset(&sge, 0, sizeof(sge));

	wr.wr_id = connection_id + waiting_id * WRAP_UP_NUM_FOR_WRID;
	wr.opcode = (s_mode == M_WRITE) ? IBV_WR_RDMA_WRITE : IBV_WR_RDMA_READ;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IBV_SEND_SIGNALED;
	//wr.wr.rdma.remote_addr = (uintptr_t)ctx->peer_mr[connection_id].addr;
	//wr.wr.rdma.rkey = ctx->peer_mr[connection_id].rkey;
        wr.wr.rdma.remote_addr = (uintptr_t)remote_mr->addr;
	wr.wr.rdma.rkey = remote_mr->rkey;
        //Bottleneck

        ret_mr = server_register_memory_api(connection_id, addr, size, IBV_ACCESS_LOCAL_WRITE);
        
	sge.addr = (uint64_t)ret_mr->addr;
	sge.length = ret_mr->length;
	sge.lkey = ret_mr->lkey;

	//TEST_NZ(ibv_post_send(ctx->qp[connection_id], &wr, &bad_wr));
	TEST_NZ(ibv_post_send(ctx->qp, &wr, &bad_wr));
        while(ctx->thread_state[waiting_id]==TS_WAIT);
	return 0;
}
int liteapi_reg_send_handler(int (*input_funptr)(char *addr, uint32_t size))
{
	ctx->send_handler = input_funptr;
	return 0;
}

int liteapi_reg_send_reply_handler(int (*input_funptr)(char *input_addr, uint32_t input_size, char *output_addr, uint32_t *output_size, int sender_id))
{
	ctx->send_reply_handler = input_funptr;
	return 0;
}

int liteapi_reg_atomic_send_handler(int (*input_funptr)(struct atomic_struct *input_list, uint32_t length, char *output_buf, uint32_t *output_size, int sender_id))
{
	ctx->atomic_send_handler = input_funptr;
	return 0;
}

int liteapi_reg_atomic_single_send_handler(int (*input_funptr)(struct atomic_struct *input_list, uint32_t length, int sender_id))
{
        ctx->atomic_single_send_handler = input_funptr;
        return 0;
}

