OSNAME = ${shell uname}


#########################################
# Linux Part
#########################################
ifeq ($(OSNAME), Linux)

all:
	cd linux; \
	/bin/ln -s ../*.[ch] ./; \
	make

.PHONY: clean
clean:
	make -C linux clean

#########################################
# NetBSD Part
#########################################
else
 ifeq ($(OSNAME), NetBSD)
all:
	cd netbsd; \
	make

clean:
	cd netbsd; make clean

else
all:
	@echo "No such OS I know"
	echo $(OSNAME)
endif
endif
