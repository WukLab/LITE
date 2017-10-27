.PHONY: clean

CFLAGS  := -Wall -g
LD      := gcc
LDLIBS  := ${LDLIBS} -lrdmacm -libverbs -lpthread -ldl
DEPS = client.h fifo.h

APPS    := mgmt-server

all: ${APPS}


mgmt-server: init.o network_handler.o lite-cd.o lite-cd-base.o fifo.o 
	${LD} -o $@ $^ ${LDLIBS} $(DEPS)

clean:
	rm -f *.o ${APPS}

