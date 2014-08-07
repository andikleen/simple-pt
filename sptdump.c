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

#define err(x) perror(x), exit(1)

static void handle_usr1(int sig)
{
}

int main(int ac, char **av)
{
	int ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	int pfds[ncpus];
	int bufsize = 0;
	char *pbuf[ncpus];

	signal(SIGUSR1, handle_usr1);
	signal(SIGINT, handle_usr1);

	int i;
	for (i = 0; i < ncpus; i++) {
		pfds[i] = open("/dev/simple-pt", O_RDONLY);
		if (pfds[i] < 0)
			err("open /dev/simple-pt");

		if (ioctl(pfds[i], SIMPLE_PT_SET_CPU, i) < 0)
			err("SIMPLE_PT_SET_CPU");

		if (!bufsize && ioctl(pfds[i], SIMPLE_PT_GET_SIZE, &bufsize) < 0)
			err("SIMPLE_PT_GET_SIZE");

		pbuf[i] = mmap(NULL, bufsize, PROT_READ, MAP_PRIVATE, pfds[i], 0);
		if (pbuf[i] == (void*)-1)
			err("mmap on simplept");
	}

	if (ioctl(pfds[0], SIMPLE_PT_START, 0) < 0)
		perror("SIMPLE_PT_START");
	printf("started, press Ctrl-C or SIGUSR1\n");

	pause();

	printf("stopped\n");
	if (ioctl(pfds[0], SIMPLE_PT_STOP, 0) < 0)
		perror("SIMPLE_PT_STOP");

	for (i = 0; i < ncpus; i++) {
		char fn[100];
		snprintf(fn, sizeof fn, "ptout.%d", i);
		int fd = open(fn, O_WRONLY|O_CREAT, 0644);
		if (fd < 0)
			err("Opening output file");
		unsigned offset;
		if (ioctl(pfds[i], SIMPLE_PT_GET_OFFSET, &offset) < 0)
			err("SIMPLE_PT_GET_OFFSET");
		if (*(uint64_t *)(pbuf[i] + offset))
			write(fd, pbuf[i] + offset, bufsize - offset);
		write(fd, pbuf[i], offset);
		close(fd);
	}

	return 0;
}
