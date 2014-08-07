#include "simple-pt.h"
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>

#define err(x) perror(x), exit(1)

int main(int ac, char **av)
{
	int ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	int pfds[ncpus];
	int bufsize;
	void *pbuf[ncpus];

	int i;
	for (i = 0; i < ncpus; i++) {
		pfds[i] = open("/dev/simple-pt", O_RDONLY);
		if (pfds[i] < 0)
			err("open /dev/simple-pt");

		if (ioctl(pfds[i], SIMPLE_PT_GET_SIZE, &bufsize) < 0)
			err("SIMPLE_PT_GET_SIZE");

		pbuf[i] = mmap(NULL, bufsize, PROT_READ, MAP_PRIVATE, pfds[i], 0);
		if (pbuf[i] == (void*)-1)
			err("mmap on simplept");
	}

	if (ioctl(pfds[0], SIMPLE_PT_START, 0) < 0)
		perror("SIMPLE_PT_START");
}
