TARGET=kbfd.o
CFLAGS+=-g -Wall
KVER=$(shell uname -r)
KMISC := /lib/modules/$(KVER)/misc/kbfd/
list-m=kbfd
VERSION=0.1

DIST_FILES := kbfd_session.[ch] kbfd_packet.[ch] kbfd_main.c kbfd_log.[ch]\
	 kbfd_v4v6.[ch] kbfd_netlink.[ch] kbfd_interface.[ch] kbfd.h \
	Makefile README KNOWN_BUGS


ifneq ($(KERNELRELEASE),)
obj-m	:=$(TARGET)
kbfd-objs := kbfd_session.o kbfd_packet.o kbfd_main.o kbfd_log.o kbfd_v4v6.o kbfd_netlink.o kbfd_interface.o

else
KDIR	:= /lib/modules/$(KVER)/build
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

install:
	install -d $(KMISC)
	install -m 644 -c $(addsuffix .ko,$(list-m)) $(KMISC)
	/sbin/depmod -a ${KVER}

zebra:
	wget ftp://ftp.zebra.org/pub/zebra/zebra-0.95a.tar.gz
	tar xfz zebra-0.95a.tar.gz
	cd zebra-0.95a ;\
	patch -p1 < ../patches/kbfd-zebra-0.95a.patch; \
	./update-autotools; \
	./configure --enable-ipv6; \
	make

dist:
	mkdir -p kbfd/patches
	cp -fr $(DIST_FILES) kbfd/
	cp patches/kbfd-zebra-0.95a.patch kbfd/patches/kbfd-$(VERSION)-zebra-0.95a.patch 
	tar cfz kbfd-$(VERSION).tar.gz kbfd/
	rm -rf kbfd/
	cp patches/kbfd-zebra-0.95a.patch kbfd-$(VERSION)-zebra-0.95a.patch 
	gzip kbfd-$(VERSION)-zebra-0.95a.patch