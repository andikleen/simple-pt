USER_CFLAGS := -g -Wall
ifneq ($(XED),)
USER_CFLAGS += -DHAVE_XED=1
DIS_LDLIBS += -lxed
endif
LIBIPT_LIB := ../processor-trace/lib
LIBIPT_INCLUDE := ../processor-trace/libipt/include

USER_OBJS := sptdump.o map.o fastdecode.o sptdecode.o dumpkcore.o \
	     elf.o symtab.o dtools.o kernel.o ptfeature.o dwarf.o
USER_EXE := sptdump fastdecode sptdecode ptfeature # dumpkcore
MAN := sptdump.man fastdecode.man sptdecode.man ptfeature.man sptcmd.man \
	sptarchive.man

KDIR = /lib/modules/`uname -r`/build
obj-m := simple-pt.o test-ftrace.o
M := make -C ${KDIR} M=`pwd`

CFLAGS_simple-pt.o := -DTRACE_INCLUDE_PATH=${M}
CFLAGS_test-ftrace.o := -DTRACE_INCLUDE_PATH=${M}

MANHTML := $(MAN:.man=.html)

all:
	${M} modules

modules_install:
	${M} modules_install

clean: user-clean kernel-clean

kernel-clean:
	${M} clean

user-clean:
	rm -rf ${USER_EXE} ${USER_OBJS} loop stest.* ${MANHTML}

${USER_OBJS}: CFLAGS := ${USER_CFLAGS}

user: ${USER_EXE}

sptdump: sptdump.o
sptdump.o: sptdump.c simple-pt.h map.h
map.o: map.c map.h

fastdecode: fastdecode.o map.o

sptdecode.o: CFLAGS += -I ${LIBIPT_INCLUDE}
elf.o: CFLAGS += -I ${LIBIPT_INCLUDE}
dtools.o: CFLAGS += -I ${LIBIPT_INCLUDE}
kernel.o: CFLAGS += -I ${LIBIPT_INCLUDE}
sptdecode: LDFLAGS += -L ${LIBIPT_LIB}
sptdecode: LDFLAGS += ${DIS_LDFLAGS}
sptdecode: LDLIBS += ${DIS_LDLIBS}
sptdecode: LDLIBS += -lipt -lelf -ldwarf
sptdecode: sptdecode.o map.o elf.o symtab.o dtools.o kernel.o dwarf.o

dumpkcore: LDLIBS += -lelf

%.html: %.man
	man -Thtml ./$^ > $@

man-html: ${MANHTML}
