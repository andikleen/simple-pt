/* Dump simple-pt buffers to files (ptout.cpu) */
#include "simple-pt.h"
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <sys/wait.h>

#define err(x) perror(x), exit(1)

int main(int ac, char **av)
{
	int ncpus = sysconf(_SC_NPROCESSORS_CONF);
	int pfds[ncpus];
	int bufsize = 0;
	char *pbuf[ncpus];

	int i;
	for (i = 0; i < ncpus; i++) {
		pfds[i] = open("/dev/simple-pt", O_RDONLY | O_CLOEXEC);
		if (pfds[i] < 0)
			err("open /dev/simple-pt");

		if (ioctl(pfds[i], SIMPLE_PT_SET_CPU, i) < 0) {
			close(pfds[i]);
			pfds[i] = -1;
			perror("SIMPLE_PT_SET_CPU");
			/* CPU likely off line */
			continue;
		}

		if (!bufsize && ioctl(pfds[i], SIMPLE_PT_GET_SIZE, &bufsize) < 0)
			err("SIMPLE_PT_GET_SIZE");

		pbuf[i] = mmap(NULL, bufsize, PROT_READ, MAP_PRIVATE, pfds[i], 0);
		if (pbuf[i] == (void*)-1)
			err("mmap on simplept");

		char fn[100];
		snprintf(fn, sizeof fn, "ptout.%d", i);
		int fd = open(fn, O_WRONLY|O_CREAT, 0644);
		if (fd < 0)
			err("Opening output file");
		unsigned offset;
		if (ioctl(pfds[i], SIMPLE_PT_GET_OFFSET, &offset) < 0) {
			perror("SIMPLE_PT_GET_OFFSET");
			continue;
		}
		unsigned len = 0;
		if (*(uint64_t *)(pbuf[i] + offset))
			len += write(fd, pbuf[i] + offset, bufsize - offset);
		len += write(fd, pbuf[i], offset);
		printf("cpu %d offset %u, %u KB, writing to %s\n", i, offset, len >> 10, fn);
		close(fd);
	}

	return 0;
}
