obj-m := lite_internal.o lite_api.o lite_test.o
lite_internal-objs := lite_core.o lite_internal_tool.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm lite*.o -f
