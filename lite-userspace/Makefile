CFLAGS := -std=gnu11 -Wall -Wmissing-prototypes -Wstrict-prototypes\
	  -fomit-frame-pointer -freg-struct-return -O2

CFLAGS := -fomit-frame-pointer -freg-struct-return

SRCS := $(wildcard example*.c)
SRCS += $(wildcard lite_*.c)
OBJS := $(SRCS:.c=.o)
DEPS := lite-lib.h

all: $(OBJS)

clean:
	rm -f *.o

%.o: %.c 
	gcc lite-lib.c -lpthread -o $@ $(CFLAGS) $<
