#obj-y := dsm_syscall.o
obj-y += lite_syscall.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm lite*.o dsm*.o -f
