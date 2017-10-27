#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

#include <pthread.h>
#include "mgmt_server.h"
#include "client.h"

#include <getopt.h>


int establish_cluster(int ib_port, int eth_port)
{
    pid_t child_pid;
    network_init(ib_port, eth_port, 0);
    return 0;
}

int application_init(int app_id)
{
	return 0;
}
static void usage(const char *argv0)
{
	printf("Usage:\n");
	printf("  %s            start a server and wait for connection\n", argv0);
	printf("\n");
	printf("Options:\n");
	printf("  -i, --ib-port=<port>   use port <port> of IB device (default 1)\n");
	printf("  -p,    use port <port> of eth (default 18500)\n");
}
int main(int argc, const char* argv[])
{
	
    //	if (pass_argument(argc, argv))
    //		return 1;
    int     ib_port = 1;
    int     eth_port = LISTEN_PORT;
    while (1) {
		int c;

		static struct option long_options[] = {
			{ .name = "ib-port",  .has_arg = 1, .val = 'i' },
			{ .name = "eth-port",  .has_arg = 1, .val = 'p' },
			{ 0 }
		};

		c = getopt_long(argc, argv, "i:p:",
							long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'i':
			ib_port = strtol(optarg, NULL, 0);
			if (ib_port < 0) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'p':
			eth_port = strtol(optarg, NULL, 0);
			if (ib_port < 0) {
				usage(argv[0]);
				return 1;
			}
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}
	//int num_node = argc - 1;
	
    //  =======================================================
    //  Establish cluster as a main API
    //  Which could be found in main.c
    //  Old form: establish_cluster(num_node, argv);
    establish_cluster(ib_port, eth_port);
    //  =======================================================
    return 0;
}



