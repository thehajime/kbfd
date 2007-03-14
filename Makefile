TARGET=kbfd.o
CFLAGS+=-g -Wall

ifneq ($(KERNELRELEASE),)
obj-m	:=$(TARGET)
kbfd-objs := kbfd_session.o kbfd_packet.o kbfd_main.o kbfd_log.o kbfd_v4v6.o kbfd_netlink.o kbfd_interface.o

else
#KDIR	:= /usr/src/linux/
KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)

default:
	$(MAKE)	-C $(KDIR)	SUBDIRS=$(PWD) modules
endif

clean:
	rm -f *~ ${TARGET}.o ${TARGET}.ko .${TARGET}*
	rm -f .built_in.o.cmd built_in.o
	rm -f .*.cmd *.ko *.mod.c *.mod.o *.o *.ko

nl_test: nl_test.c
	gcc -g -o $@ $@.c
