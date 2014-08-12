/* Decoder using libipt for simple-pt */

/* Notebook:
   Fast mode on packet level if no ELF file
   Loop detector
   Dwarf decoding
   Multiple aligned input files
   */
#include <intel-pt.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>

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

double tsc_freq;

static double tsc_us(uint64_t t)
{
	if (tsc_freq == 0)
		return t;
	return (t / (tsc_freq*1000));
}

static void print_time_indent(void)
{
	printf("%*s", 20, "");
}

static bool print_time(struct pt_insn_decoder *decoder, uint64_t *last_ts,
			uint64_t *first_ts)
{
	uint64_t ts;
	bool printed = false;

	pt_insn_time(decoder, &ts);
	if (*last_ts && ts != *last_ts) {
		char buf[30];
		snprintf(buf, sizeof buf, "%-9.*f [+%-.*f]", tsc_freq ? 3 : 0,
				tsc_us(ts - *first_ts),
				tsc_freq ? 3 : 0,
				tsc_us(ts - *last_ts));
		printf("%-20s", buf);
		printed = true;
	}
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
		unsigned long insncnt = 0;
		while (!err) {
			bool has_time = false;

			err = pt_insn_next(decoder, &insn);
			if (err < 0)
				break;
			insncnt++;
			if (insn.speculative || insn.aborted || insn.committed)
				print_tsx(&insn, &prev_spec, &indent);
			if (insn.disabled || insn.enabled || insn.resumed ||
			    insn.interrupted || insn.resynced)
				print_event(&insn);
			if (print_time(decoder, &last_ts, &first_ts)) {
				if (insn.iclass != ptic_call || insn.iclass != ptic_far_call) {
					printf("%*s[+%4lu] ", indent, "", insncnt);
					insncnt = 0;
					if (insn.iclass == ptic_return || insn.iclass == ptic_far_return)
						printf("return ");
					print_ip(insn.ip);
					putchar('\n');
				}
				has_time = true;
			}
			switch (insn.iclass) {
			case ptic_far_call:
			case ptic_call: {
				uint64_t orig_ip = insn.ip;
				err = pt_insn_next(decoder, &insn);
				if (err < 0)
					continue;
				if (!has_time)
					print_time_indent();
				printf("[+%4lu] ", insncnt);
				printf("%*scall ", indent, "");
				print_ip(orig_ip);
				printf(" -> ");
				print_ip(insn.ip);
				putchar('\n');
				insncnt = 0;
				indent += 4;
				insncnt++;
				break;
			}
			case ptic_far_return:
			case ptic_return:
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

static void print_header(void)
{
	printf("%-10s %-5s  %7s   %s\n",
		"TIME",
		"DELTA",
		"INSNs",
		"OPERATION");
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
	fprintf(stderr, "sptdecode --pt ptfile .. --elf elffile ...\n");
	fprintf(stderr, "--freq/-f freq  Use frequency to convert time stamps\n");
	exit(1);
}

struct option opts[] = {
	{ "elf", required_argument, NULL, 'e' },
	{ "pt", required_argument, NULL, 'p' },
	{ "freq", required_argument, NULL, 'f' },
	{ }
};

int main(int ac, char **av)
{
	struct pt_insn_decoder *decoder = NULL;
	int c;
	while ((c = getopt_long(ac, av, "e:p:f:", opts, NULL)) != -1) {
		char *end;
		switch (c) {
		case 'e':
			if (!decoder) {
				fprintf(stderr, "Specify PT file before ELF files\n");
				usage();
			}
			read_elf(optarg, decoder, 0);
			break;
		case 'p':
			if (decoder) {
				fprintf(stderr, "Only one PT file supported\n"); /* XXX */
				usage();
			}
			decoder = init_decoder(optarg);
			break;
		case 'f':
			tsc_freq = strtod(optarg, &end);
			if (end == optarg)
				usage();
			break;

		default:
			usage();
		}
	}
	if (ac - optind != 0 || !decoder)
		usage();
	print_header();
	decode(decoder);
	return 0;
}
