This is LITE module. More details are in /README.md  
For userspace example, please check `lite-userspace/` for more details.

*current limitation*
1. remote memset doesn't support multiple MR under one LMR now. Only can interact with the first LMR
2. remote memset only does zero to clear the memspace. Currently, it doesn't take any input characters
3. becayse the system is optimized for send-reply, we have limitations in processing send-only (if the receiver is slower than sender for 4096 packets, error will happen)
4. send-reply doesn't support local channel now
5. ibapi_send_reply_imm_multisge (multicast send-reply api) is only available for kernel space application. And this is a wrap-up for our send-reply function. It doesn't optimized significantly. And most of the features of send-reply don't support this api including multiple MR under one LMR, local_send-reply, and send-only request
6. one LMR can only support upto 128MB. It's defined in lite.h
