/* Decoding tools */
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


#include <intel-pt.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include "dtools.h"
#include "map.h"
#include "elf.h"
#include "symtab.h"

struct pt_insn_decoder *init_decoder(char *fn, char *cpu)
{
	struct pt_config config;
	unsigned zero = 0;

	pt_config_init(&config);
	pt_cpu_parse(&config.cpu, cpu);
	pt_cpu_errata(&config.errata, &config.cpu);
	/* When no bit is set, set all, as libipt does not keep up with newer
	 * CPUs otherwise.
	 */
	if (!memcmp(&config.errata, &zero, 4))
		memset(&config.errata,0xff, sizeof(config.errata));

	size_t len;
	unsigned char *map = mapfile(fn, &len);
	if (!map) {
		fprintf(stderr, "Cannot open PT file %s: %s\n", fn, strerror(errno));
		exit(1);
	}
	config.begin = map;
	config.end = map + len;

	struct pt_insn_decoder *decoder = pt_insn_alloc_decoder(&config);
	if (!decoder) {
		fprintf(stderr, "Cannot create PT decoder\n");
		return NULL;
	}

	return decoder;
}

/* Sideband format:
timestamp pid cr3 load-address off-in-file path-to-binary[:codebin]
 */
void load_sideband(char *fn, struct pt_image *image)
{
	FILE *f = fopen(fn, "r");
	if (!f) {
		fprintf(stderr, "Cannot open %s: %s\n", fn, strerror(errno));
		exit(1);
	}
	char *line = NULL;
	size_t linelen = 0;
	int lineno = 1;
	while (getline(&line, &linelen, f) > 0) {
		uint64_t cr3, addr, off;
		unsigned pid;
		double ts;
		int n;

		if (sscanf(line, "%lf %u %lx %lx %lx %n", &ts, &pid, &cr3, &addr, &off, &n) != 5) {
			fprintf(stderr, "%s:%d: Parse error\n", fn, lineno);
			exit(1);
		}
		if (ts == 0 && !seen_cr3(cr3))
			continue;
		while (isspace(line[n]))
			n++;
		/* timestamp ignored for now. could later be used to distinguish
		   reused CR3s or reused address space. */
		/* pid ignored for now. should use in decoding. */
		char *p = strchr(line + n, '\n');
		if (p) {
			*p = 0;
			while (--p >= line + n && isspace(*p))
				*p = 0;
		}
		if (off != 0)
			fprintf(stderr, "FIXME: mmap %s has non zero offset %lx\n", fn, off);
		if (read_elf(line + n, image, addr, cr3)) {
			fprintf(stderr, "Cannot read %s: %s\n", line + n, strerror(errno));
		}
		lineno++;
	}
	free(line);
	fclose(f);
}
