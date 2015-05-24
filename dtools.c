#include <intel-pt.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include "dtools.h"
#include "map.h"
#include "elf.h"

struct pt_insn_decoder *init_decoder(char *fn)
{
	struct pt_config config;
	pt_config_init(&config);

	/* XXX configure cpu */

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
timestamp cr3 load-address off-in-file path-to-binary[:codebin]
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
		double ts;
		int n;

		if (sscanf(line, "%lf %lx %lx %lx %n", &ts, &cr3, &addr, &off, &n) != 4) {
			fprintf(stderr, "%s:%d: Parse error\n", fn, lineno);
			exit(1);
		}
		while (isspace(line[n]))
			n++;
		/* timestamp ignored for now. could later be used to distinguish
		   reused CR3s or reused address space. */
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

	}
	free(line);
	fclose(f);
}
