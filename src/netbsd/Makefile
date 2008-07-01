S?=             /ext/kern/shisa-netbsd/src/sys
MKMAN=          no
KMOD?=          kbfd
SRCS=           kbfd_main.c kbfd_packet.c kbfd_v4v6_netbsd.c kbfd_interface.c \
		kbfd_memory.c kbfd_queue.c kbfd_log.c kbfd_session.c \
		kbfd_lock.c kbfd_ioctl.c 
WARNS?=         1
CPPFLAGS+=      -nostdinc
CFLAGS+= -g

all: $(SRCS) test
	@echo "Please execute"
	@echo " \"modload -e kbfd_lkmentry -p kbfd_post.sh kbfd.o\""

$(SRCS):
	/bin/ln -s ../*.[ch] ./; \


test: test.c
	$(CC) -g test.c -o test

.include <bsd.kmod.mk>
