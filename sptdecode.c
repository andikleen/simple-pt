/* Decoder using libipt for simple-pt */
#include <intel-pt.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "map.h"
#include "elf.h"
#include "symtab.h"

static void print_event(struct pt_insn *insn)
{
	if (insn->disabled)
		printf("disabled\n");
	if (insn->enabled);
		printf("enabled\n");
	if (insn->resumed)
		printf("resumed\n");
	if (insn->interrupted)
		printf("interrupted\n");
	if (insn->resynced)
		printf("resynced\n");
}

static void print_tsx(struct pt_insn *insn, int *prev_spec, int *indent)
{
	if (insn->speculative != *prev_spec) {
		*prev_spec = insn->speculative;
		printf("%*stransaction\n", *indent, "");
		*indent += 4;
	}
	if (insn->aborted) {
		printf("%*saborted\n", *indent, "");
		*indent -= 4;
	}
	if (insn->committed) {
		printf("%*scommitted\n", *indent, "");
		*indent -= 4;
	}
	if (*indent < 0)
		*indent = 0;
}

static void print_ip(uint64_t ip)
{
	struct sym *sym = findsym(ip);
	if (sym) {
		printf("%s", sym->name);
		if (ip - sym->val > 0)
			printf("+%ld", ip - sym->val);
	} else
		printf("%lx", ip);
}

static bool print_time(struct pt_insn_decoder *decoder, uint64_t *last_ts,
			uint64_t *first_ts, bool inhibit)
{
	uint64_t ts;
	bool printed = false;

	pt_insn_time(decoder, &ts);
	if (*last_ts && ts != *last_ts) {
		char buf[30];
		snprintf(buf, sizeof buf, "[%8lu][+%-lu]", ts - *first_ts, ts - *last_ts);
		printf("%-20s", buf);
		printed = true;
	} else if (!inhibit)
		printf("%*s", 20, "");
	if (ts)
		*last_ts = ts;
	if (!*first_ts && ts)
		*first_ts = ts;
	return printed;
}

static int decode(struct pt_insn_decoder *decoder)
{
	uint64_t last_ts = 0;
	uint64_t first_ts = 0;

	for (;;) {
		uint64_t pos;
		int err = pt_insn_sync_forward(decoder);
		if (err < 0) {
			pt_insn_get_offset(decoder, &pos);
			printf("%lx: sync forward: %s\n", pos, pt_errstr(pt_errcode(err)));
			break;
		}

		struct pt_insn insn;
		int indent = 0;
		int prev_spec = 0;
		while (!err) {
			err = pt_insn_next(decoder, &insn);
			if (err < 0)
				break;
			if (insn.speculative || insn.aborted || insn.committed)
				print_tsx(&insn, &prev_spec, &indent);
			if (insn.disabled || insn.enabled || insn.resumed ||
			    insn.interrupted || insn.resynced)
				print_event(&insn);
			switch (insn.iclass) {
			case ptic_far_call:
			case ptic_call: {
				uint64_t orig_ip = insn.ip;
				print_time(decoder, &last_ts, &first_ts, false);
				err = pt_insn_next(decoder, &insn);
				if (err < 0)
					continue;
				printf("%*scall ", indent, "");
				print_ip(orig_ip);
				printf(" -> ");
				print_ip(insn.ip);
				putchar('\n');
				indent += 4;
				break;
			}
			case ptic_far_return:
			case ptic_return:
				if (print_time(decoder, &last_ts, &first_ts, true)) {
					printf("%*sreturn ", indent, "");
					print_ip(insn.ip);
					putchar('\n');
				}

				indent -= 4;
				if (indent < 0)
					indent = 0;
				break;
			default:
				break;
			}
		}
		if (err) {
			if (err == -pte_eos)
				break;
			pt_insn_get_offset(decoder, &pos);
			printf("%lx:%lx: %s\n", pos, insn.ip,
					pt_errstr(pt_errcode(err)));
		}
	}
	return 0;
}

struct pt_insn_decoder *init_decoder(char *fn)
{
	struct pt_config config = {
		.size = sizeof(struct pt_config)
	};

	if (pt_configure(&config) < 0) {
		fprintf(stderr, "pt configuration failed\n");
		return NULL;
	}
	/* XXX configure cpu */
	size_t len;
	unsigned char *map = mapfile(fn, &len);
	if (!map) {
		perror(fn);
		return NULL;
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

void usage(void)
{
	fprintf(stderr, "sptdecode ptfile .. --elf elffile ...\n");
	exit(1);
}

int main(int ac, char **av)
{
	struct pt_insn_decoder *decoder = NULL;
	while (*++av) {
		if (!strcmp(*av, "--elf")) {
			if (!decoder) {
				fprintf(stderr, "Specify PT file before ELF files\n");
				usage();
			}
			if (!*++av)
				usage();
			read_elf(*av, decoder, 0);
			continue;
		}
		decoder = init_decoder(*av);
	}
	decode(decoder);
	return 0;
}
