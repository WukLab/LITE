#ifndef _INCLUDE_FIT_SYS_H
#define _INCLUDE_FIT_SYS_H

#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include "lite.h"

struct lite_hooks
{
	
	uint64_t 	(*lite_alloc_remote)(unsigned int, unsigned int, unsigned int, int);
	int 		(*lite_remote_memset)(uint64_t, int, int);
	int 		(*lite_fetch_add)(uint64_t, void*, unsigned long long, int);
	int 		(*lite_rdma_synwrite)(uint64_t, void*, int, int, int, int);

	int 		(*lite_rdma_asywrite)(uint64_t, void*, int, int, int);
	int 		(*lite_rdma_read)(uint64_t, void*, int, int, int, int);
	uint64_t	(*lite_ask_lmr)(int, uint64_t, uint64_t, int);
	uint64_t	(*lite_dist_barrier)(unsigned int);
	int		(*lite_add_ask_mr_table)(uint64_t, uint64_t, uint64_t, int);
	int		(*lite_compare_swp)(uint64_t, void*, unsigned long long, unsigned long long, int);
	int		(*lite_umap_lmr)(uint64_t);

	int		(*lite_register_application)(unsigned int, unsigned int, unsigned int, char*, uint64_t);
	int		(*lite_unregister_application)(unsigned int);
	int		(*lite_receive_message)(int, void*, void*, void*, int, unsigned int);
	int		(*lite_send_reply_imm)(int, int, void*, void *, void*, unsigned int);
	int             (*lite_reply_message)(void *, int, uintptr_t, unsigned int);
	int		(*lite_get_node_id)(void);
	int		(*lite_get_total_node)(void);
	int      	(*lite_query_port)(int, int, int);
	int		(*lite_alloc_continuous_memory)(unsigned long long, unsigned long);
	uint64_t	(*lite_wrap_alloc_for_remote_access)(void*, unsigned int, uint64_t, int);
	int		(*lite_create_lock)(int, void*);
	int		(*lite_ask_lock)(int, int, void*);
	int		(*lite_lock)(void*);
	int		(*lite_unlock)(void*);
        int             (*lite_reply_and_receive_message)(void *, int, uintptr_t, void *, int, void *);

        int             (*lite_join)(char *, int, int);
};
int register_lite_hooks(const struct lite_hooks *hooks);
void unregister_lite_hooks(void);
#endif
