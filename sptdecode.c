/* Decoder using libipt for simple-pt */

#define _GNU_SOURCE 1
#include <intel-pt.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>

#include "map.h"
#include "elf.h"
#include "symtab.h"
#include "freq.h"

/* Includes branches and anything with a time. Always
 * flushed on any resyncs.
 */
struct sinsn {
	uint64_t ip;
	uint64_t dst; /* For calls */
	uint64_t ts;
	enum pt_insn_class iclass;
	unsigned insn_delta;
	bool loop_start, loop_end;
	unsigned iterations;
	uint32_t ratio;
	unsigned speculative : 1, aborted : 1, committed : 1, disabled : 1, enabled : 1, resumed : 1,
		 interrupted : 1, resynced : 1;
};
#define NINSN 256

static void transfer_events(struct sinsn *si, struct pt_insn *insn)
{
#define T(x) si->x = insn->x;
	T(speculative);
	T(aborted);
	T(committed);
	T(disabled);
	T(enabled);
	T(resumed);
	T(interrupted);
	T(resynced);
#undef T
}


static void print_event(struct sinsn *insn)
{
	if (insn->disabled)
		printf("disabled\n");
	if (insn->enabled)
		printf("enabled\n");
	if (insn->resumed)
		printf("resumed\n");
	if (insn->interrupted)
		printf("interrupted\n");
	if (insn->resynced)
		printf("resynced\n");
}

static void print_tsx(struct sinsn *insn, int *prev_spec, int *indent)
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
	printf("%*s", 24, "");
}

static void print_time(uint64_t ts, uint64_t *last_ts,uint64_t *first_ts)
{
	char buf[30];
	if (!*first_ts)
		*first_ts = ts;
	if (!*last_ts)
		*last_ts = ts;
	double rtime = tsc_us(ts - *first_ts);
	snprintf(buf, sizeof buf, "%-9.*f [+%-.*f]", tsc_freq ? 3 : 0,
			rtime,
			tsc_freq ? 3 : 0,
			tsc_us(ts - *last_ts));
	*last_ts = ts;
	printf("%-24s", buf);
}

int dump_insn;

static void print_insn(struct pt_insn *insn)
{
	int i;
	printf("%lx insn:", insn->ip);
	for (i = 0; i < insn->size; i++)
		printf(" %02x", insn->raw[i]);
	printf("\n");
}

bool detect_loop = false;

#define NO_ENTRY ((unsigned char)-1)
#define CHASHBITS 8

#define GOLDEN_RATIO_PRIME_64 0x9e37fffffffc0001UL

static int remove_loops(struct sinsn *l, int nr)
{
	int i, j, off;
	unsigned char chash[1 << CHASHBITS];
	memset(chash, NO_ENTRY, sizeof(chash));

	for (i = 0; i < nr; i++) {
		int h = (l[i].ip * GOLDEN_RATIO_PRIME_64) >> (64 - CHASHBITS);

		l[i].iterations = 0;
		l[i].loop_start = l[i].loop_end = false;
		if (chash[h] == NO_ENTRY) {
			chash[h] = i;
		} else if (l[chash[h]].ip == l[i].ip) {
			bool is_loop = true;
			unsigned insn = 0;

			off = 0;
			for (j = chash[h]; j < i && i + off < nr; j++, off++) {
				if (l[j].ip != l[i + off].ip) {
					is_loop = false;
					break;
				}
				insn += l[j].insn_delta;
			}
			if (is_loop) {
				j = chash[h];
				l[j].loop_start = true;
				if (l[j].iterations == 0)
					l[j].iterations++;
				l[j].iterations++;
				printf("loop %lx-%lx %d-%d %u insn iter %d\n", l[j].ip, l[i].ip, j, i,
						insn, l[j].iterations);
				memmove(l + i, l + i + off,
					(nr - (i + off)) * sizeof(struct sinsn));
				l[i-1].loop_end = true;
				nr -= off;
			}
		}
	}
	return nr;
}

struct local_pstate {
	int indent;
	int prev_spec;
};

struct global_pstate {
	uint64_t last_ts;
	uint64_t first_ts;
};

static void print_loop(struct sinsn *si, struct local_pstate *ps)
{
	if (si->loop_start) {
		print_time_indent();
		printf(" %5s  %*sloop start %u iterations ", "", ps->indent, "", si->iterations);
		print_ip(si->ip);
		putchar('\n');
	}
	if (si->loop_end) {
		print_time_indent();
		printf(" %5s  %*sloop end ", "", ps->indent, "");
		print_ip(si->ip);
		putchar('\n');
	}
}

static void print_output(struct sinsn *insnbuf, int sic,
			 struct local_pstate *ps,
			 struct global_pstate *gps)
{
	int i;
	for (i = 0; i < sic; i++) {
		struct sinsn *si = &insnbuf[i];

		if (si->speculative || si->aborted || si->committed)
			print_tsx(si, &ps->prev_spec, &ps->indent);
		if (si->ratio)
			printf("frequency change to %d\n", si->ratio);
		if (si->disabled || si->enabled || si->resumed ||
		    si->interrupted || si->resynced)
			print_event(si);
		if (detect_loop && (si->loop_start || si->loop_end))
			print_loop(si, ps);
		/* Always print if we have a time (for now) */
		if (si->ts) {
			print_time(si->ts, &gps->last_ts, &gps->first_ts);
			if (si->iclass != ptic_call && si->iclass != ptic_far_call) {
				printf("[+%4u] %*s", si->insn_delta, ps->indent, "");
				print_ip(si->ip);
				putchar('\n');
			}
		}
		switch (si->iclass) {
		case ptic_far_call:
		case ptic_call: {
			if (!si->ts)
				print_time_indent();
			printf("[+%4u] %*s", si->insn_delta, ps->indent, "");
			print_ip(si->ip);
			printf(" -> ");
			print_ip(si->dst);
			putchar('\n');
			ps->indent += 4;
			break;
		}
		case ptic_far_return:
		case ptic_return:
			ps->indent -= 4;
			if (ps->indent < 0)
				ps->indent = 0;
			break;
		default:
			break;
		}
	}
}

static int decode(struct pt_insn_decoder *decoder)
{
	struct global_pstate gps = { .first_ts = 0, .last_ts = 0 };
	uint64_t last_ts = 0;

	for (;;) {
		uint64_t pos;
		int err = pt_insn_sync_forward(decoder);
		if (err < 0) {
			pt_insn_get_offset(decoder, &pos);
			printf("%lx: sync forward: %s\n", pos, pt_errstr(pt_errcode(err)));
			break;
		}

		struct local_pstate ps = { .indent = 0, .prev_spec = 0 };

		unsigned long insncnt = 0;
		struct sinsn insnbuf[NINSN];
		uint64_t errip = 0;
		do {
			int sic = 0;
			while (!err && sic < NINSN - 1) {
				struct pt_insn insn;
				struct sinsn *si = &insnbuf[sic];

				insn.ip = 0;
				err = pt_insn_next(decoder, &insn);
				if (err < 0) {
					errip = insn.ip;
					break;
				}
				if (dump_insn)
					print_insn(&insn);
				insncnt++;
				pt_insn_time(decoder, &si->ts);
				uint32_t ratio;
				si->ratio = 0;
				pt_insn_ratio(decoder, &ratio);
				if (ratio != prev_ratio) {
					si->ratio = ratio;
					prev_ratio = ratio;
				}
				if (si->ts && si->ts == last_ts)
					si->ts = 0;
				si->iclass = insn.iclass;
				if (insn.iclass == ptic_call || insn.iclass == ptic_far_call) {
					si->ip = insn.ip;
					err = pt_insn_next(decoder, &insn);
					if (err < 0) {
						si->dst = 0;
						errip = insn.ip;
						break;
					}
					si->dst = insn.ip;
					if (!si->ts) {
						pt_insn_time(decoder, &si->ts);
						if (si->ts && si->ts == last_ts)
							si->ts = 0;
					}
					si->insn_delta = insncnt;
					insncnt = 1;
					sic++;
					transfer_events(si, &insn);
				} else if (insn.iclass == ptic_return || insn.iclass == ptic_far_return || si->ts) {
					si->ip = insn.ip;
					si->insn_delta = insncnt;
					insncnt = 0;
					sic++;
					transfer_events(si, &insn);
				} else
					continue;
				if (si->ts)
					last_ts = si->ts;
			}

			if (detect_loop)
				sic = remove_loops(insnbuf, sic);
			print_output(insnbuf, sic, &ps, &gps);
		} while (err == 0);
		if (err == -pte_eos)
			break;
		pt_insn_get_offset(decoder, &pos);
		printf("%lx:%lx: error %s\n", pos, errip,
				pt_errstr(pt_errcode(err)));
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
static void load_sideband(char *fn, struct pt_insn_decoder *decoder)
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
		if (read_elf(line + n, decoder, addr, cr3)) {
			fprintf(stderr, "Cannot read %s: %s\n", line + n, strerror(errno));
		}

	}
	free(line);
	fclose(f);
}

void usage(void)
{
	fprintf(stderr, "sptdecode --pt ptfile --elf elffile ...\n");
	fprintf(stderr, "-p/--pt ptfile   PT input file. Required and must before --elf/-s\n");
	fprintf(stderr, "-e/--elf binary[:codebin]  ELF input PT files. Can be specified multiple times.\n");
	fprintf(stderr, "                   When codebin is specified read code from codebin\n");
	fprintf(stderr, "-s/--sideband log  Load side band log. Needs access to binaries\n");
	fprintf(stderr, "--freq/-f freq   Use frequency to convert time stamps (Ghz). cur for current system.\n");
	fprintf(stderr, "--insn/-i        dump instruction bytes\n");
	fprintf(stderr, "--loop/-l	  detect loops\n");
	exit(1);
}

struct option opts[] = {
	{ "elf", required_argument, NULL, 'e' },
	{ "pt", required_argument, NULL, 'p' },
	{ "freq", required_argument, NULL, 'f' },
	{ "insn", no_argument, NULL, 'i' },
	{ "sideband", required_argument, NULL, 's' },
	{ "loop", no_argument, NULL, 'l' },
	{ }
};

int main(int ac, char **av)
{
	struct pt_insn_decoder *decoder = NULL;
	int c;
	while ((c = getopt_long(ac, av, "e:p:f:is:l", opts, NULL)) != -1) {
		char *end;
		switch (c) {
		case 'e':
			if (!decoder) {
				fprintf(stderr, "Specify PT file before ELF files\n");
				usage();
			}
			if (read_elf(optarg, decoder, 0, 0) < 0) {
				fprintf(stderr, "Cannot load elf file %s: %s\n",
						optarg, strerror(errno));
			}
			break;
		case 'p':
			if (decoder) {
				fprintf(stderr, "Only one PT file supported\n");
				usage();
			}
			decoder = init_decoder(optarg);
			break;
		case 'f':
			if (!strcmp(optarg, "cur")) {
				tsc_freq = get_freq();
				if (!tsc_freq) {
					fprintf(stderr, "Cannot get frequency\n");
					exit(1);
				}
			} else {
				tsc_freq = strtod(optarg, &end);
				if (end == optarg)
					usage();
			}
			break;
		case 'i':
			dump_insn = 1;
			break;
		case 's':
			if (!decoder) {
				fprintf(stderr, "Specify PT file before sideband\n");
				usage();
			}
			load_sideband(optarg, decoder);
			break;
		case 'l':
			detect_loop = true;
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
