KDIR = /lib/modules/`uname -r`/build
obj-m := simple-pt.o
M := make -C ${KDIR} M=`pwd`

CFLAGS_simple-pt.o := -DTRACE_INCLUDE_PATH=${M}

all:
	${M} modules

install:
	${M} modules_install

clean:
	${M} clean
	rm -rf sptdump fastdecode.o sptdump.o fastdecode

sptdump: CFLAGS := -g -Wall
sptdump: sptdump.o

fastdecode: CFLAGS := -g -Wall
fastdecode: fastdecode.o map.o
