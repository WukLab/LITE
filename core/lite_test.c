#include <rdma/ib_verbs.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_user_verbs.h>
#include "lite_test.h"


MODULE_AUTHOR("yiying, shinyeh");
MODULE_LICENSE("GPL");
static int __init lite_test_init_module(void)
{
	int node_id;
	node_id = liteapi_establish_conn("192.168.0.1", LISTEN_PORT, 1);

	return node_id;
}

static void __exit lite_test_cleanup_module(void)
{
	printk(KERN_INFO "Ready to remove test module\n");
}

module_init(lite_test_init_module);
module_exit(lite_test_cleanup_module);
