TARGET = router

CC = gcc
CFLAGS = -g -Wall -Iinclude
LIBS = -lpthread

SRCS = main.c ip.c arp.c arpcache.c icmp.c ip_base.c rtable.c rtable_internal.c device_internal.c

OBJS = $(patsubst %.c,%.o,$(SRCS))
HDRS = ./include/*.h

all: $(TARGET)

$(OBJS): %.o : %.c $(HDRS)
	$(CC) -c $(CFLAGS) $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LIBS)

clean:
	rm -f *.o $(TARGET)
