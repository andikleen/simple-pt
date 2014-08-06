KDIR = /lib/modules/`uname -r`/build
obj-m := simple-pt.o
M := make -C ${KDIR} M=`pwd`

all:
	${M} modules

install:
	${M} modules_install

clean:
	${M} clean

