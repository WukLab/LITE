LITE Local Indirection TiEr
====

LITE - Kernel RDMA Support for Datacenter Applications

LITE stands for Local Indirection TiEr for RDMA in the Linux kernel.
LITE virtualizes native RDMA into a flexible, high-level, easy-to-use abstraction and allows applications to safely share resources.
Despite the widely-held belief that kernel bypassing is essential to RDMA’s low-latency performance, LITE shows that using a kernel-level indirection can achieve both flexibility and lowlatency, scalable performance at the same time.

This version of LITE has been tested for the following configuration:

1. Software
  * OS: CentOS 7.1 (kernel 3.11.1)
  * RDMA drivers: `mlx4` from official libibverbs and verbs.
2. Hardware
  * RNICs:
    * ConnectX-3 354A (InfiniBand)
3. Package (on CentOS7)
  * We didn't install MLNX_OFED
  * `libmthca infiniband-diags perftest qperf opensm libibverbs librdmacm librdmacm-devel libmlx4 libibverbs-utils`
  * add the following two lines to the end of /etc/security/limits.conf
    * `* soft memlock unlimited`
    * `* hard memlock unlimited`

We built LITE as a linux module for the Linux 3.11.1 kernel (patch for syscall is provided).
The LITE kernel module is in `core/`. 
The folder `lite-userspace` contains simple examples of using LITE in user space.
The code `core\lite_test.c` contains simple examples of using LITE in kernel space.

# Caution:
This is a BETA version. We will have our stable version ready soon.
For more information please check [LITE Paper](https://dl.acm.org/citation.cfm?id=3132762) appeared in *SOSP'17*.

## How To Run LITE

### Prerequisites
1. More than two machines connected via InfiniBand.
2. One of the machines (served as cluster manager) has installed InfiniBand OFED user-level library. The rest of the machines serve as LITE clients and need to compile kernel (see below).

### S1: Compile cluster manager
LITE's cluster manager source code is located in `cluster-manager/`, which runs on user space. Assume this machine has installed all IB user libraries, you can go to this directory and simply do `make`. After that, you will have a `mgmt-server`, which is LITE's clueter manager. Also, get the IP address of this CD server, which will be used by all other LITE clients to establish connection.

### S2: Install and boot LITE kernel on LITE clients
1. First, get linux tarball (we used 3.11.1 from `wget https://www.kernel.org/pub/linux/kernel/v3.x/linux-3.11.1.tar.gz`)
2. extract the tarball and cd into the kernel source code (e.g., `cd linux-3.11.1`)
3. apply lite-patch (mainly for syscall) `patch -p1 < ../lite_kernel_patch`
4. Compile the kernel with your machine's old config:                                                        
`cp /boot/config-your-default-kernel-version lite-kernel/.config`  
`make oldconfig` (Recommended to have a special _CONFIG_LOCALVERSION="LITE"_)  
`make && make modules && make modules_install && make install`
5. Reboot the machine and use `uname` to check if the kernel version matches.
<!--
patch is generated by `diff -uNr linux-3.11.1 lite-kernel > lite_kernel_patch`
-->
### S3: Config LITE

LITE has several options that can be configured at compile time at lite.h in `lite/`. The default configurations have been tested to work well for our applications. We will provide a documentation of these configurations soon.

### S4: Compile Modules
After boot into `lite-kernel` successfully (S2), go to `lite` directory and type `make` to compile lite three modules. If the kernel is right, you will have 3 modules compiled: `lite_internal.ko`, `lite_api.ko`, and `lite_test.ko`. `lite_internal.ko` is the LITE core module and `lite_api.ko` is a module includes all LITE API. `lite_test.ko` is a module which shows how to use LITE in kernel space.

### S5: Run
In general, to run LITE, you need to start cluster manager first, which will listen on port 18500. After that, start LITE clients one by one to establish the connection with cluster manager.

#### S5.1 Run cluster manager
You can start cluster manager like this:  
> `./mgmt-server`  
> `./mgmt-server -p [eth_port] -i [ib_port]`  

#### S5.2: Run LITE
Start LITE clients one by one to establish the connection with cluster manager assuming the IP address of cluster manager is `192.168.1.1`. Client needs to install `lite_internal.ko` and `lite_api.ko` first in order. There is a simple script `lite_insmod.sh`, which help you to install these two modules.

##### S5.2.1: Run LITE in userspace
call `userspace_ibapi_join("192.168.1.1", 18500, 1)` if you want to use port 18500 and IB port 1 to build LITE cluster.

##### S5.2.2: Run LITE in kernel space
call `ibapi_establish_conn("192.168.1.1", 18500, 1)` if you want to use port 18500 and IB port 1 to build LITE cluster.

##### S5.3: establish_conn
Even the program which is called ibapi_establish_conn is terminated, the node is still in LITE cluster.
Therefore, I suggest to write an extra program (as lite_join.c) to join the cluster instead of doing join inside your testing program.
How to join a node is illustrated in lite example code.

In detail:  
1. **insmod lite_internal.ko**  
      This will insmod lite_internal module  
2. **insmod lite_api.ko**  
      This will insmod lite_api module
3. **userspace_ibapi_join("192.168.1.1", 18500, 1)**  or **ibapi_establish_connection("192.168.1.1", 18500, 1)**
      This will connect with cluster manager and connent the client to LITE cluster

### S6: Run User Programs
There are several code samples under `lite_userspace/`. Basically, we join LITE with `userspace_ibali_join()` and calling malloc/send/receive/read/write based on `lite_userspace/lite-lib.c`.

### S7: Leave LITE cluster
Currenly, LITE doesn't provide complete instructions for leaving LITE cluster.  
If a node leaves, all nodes have to leave LITE and rebuild the whole cluster. By running `rmmod` `lite_api.ko` and `lite_internal.ko` in order can terminate the LITE module (or running `lite_rmmod.sh`). 
It could re-connect to LITE cluster manager to rebuild the whole LITE cluster again by following Step 5 (also ctrl+c to re-run for cluster manager).

## To cite LITE, please use:

>\@inproceedings{SOSP17-LITE\,  
> author = {Shin-Yeh Tsai and Yiying Zhang},  
> title = {LITE Kernel RDMA Support for Datacenter Applications},  
> booktitle = {Proceedings of the 26th Symposium on Operating Systems Principles (SOSP '17)},  
> year = {2017},  
> address = {Shanghai, China},  
> month = {October}  
>}
 