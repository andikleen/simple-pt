/* Dump simple-pt buffers to files (ptout.cpu) */
/* sptdump [filenameprefix] */
/* Always adds .N for the different cpus */

/*
 * Copyright (c) 2015, Intel Corporation
 * Author: Andi Kleen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
*/


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
	int bufsize;
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

		if (ioctl(pfds[i], SIMPLE_PT_GET_SIZE, &bufsize) < 0)
			err("SIMPLE_PT_GET_SIZE");

		pbuf[i] = mmap(NULL, bufsize, PROT_READ, MAP_PRIVATE, pfds[i], 0);
		if (pbuf[i] == (void*)-1)
			err("mmap on simplept");

		char fn[1024];
		snprintf(fn, sizeof fn, "%s.%d", av[1] ? av[1] : "ptout", i);
		int fd = open(fn, O_WRONLY|O_CREAT|O_TRUNC, 0644);
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
		if (len == 0)
			unlink(fn);
	}

	return 0;
}
