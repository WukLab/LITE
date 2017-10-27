LITE Local Indirection TiEr - userspace example
====

`lite-lib.c` and `lite-lib.h` contain the code of lite-userspace library call.
`lite-lib.c` mainly interacts with LITE-kernel with syscall.
Syscall definition should match  
1. `lite-syscall/lite_syscall.c`   
2. `kernel_src/arch/x86/syscalls/syscall_64.tbl`.  
Regular example call for send-reply and send are in `lite_example.c` and `lite_send.c` respectively.
 
## How to Run LITE example

### S1: run cluster manager
        ./mgmt_server
### S2: follow step 5.2.2 in README.md to initial userspace_ibapi_join
```
userspace_ibapi_join(IP, eth-port, IB-port) --> change to correct IP and port
```
or you could study `lite_join.c` to find the way to join cluster
### S3: compile by Makefile
make all
### S4: execute RPC example example
on node 1, execute `./lite_rpc.o 0`  
on node 2, execute `./lite_rpc.o 1`  
### S5: execute LITE-Write example
on node 2, execute  ./lite_write.o 1
Remember to rebuild the whole cluster after running examples.
