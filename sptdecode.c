/* Decoder using libipt for simple-pt */

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
#include "dtools.h"
#include "kernel.h"

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
	uint64_t cr3;
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

static void print_ip(uint64_t ip, uint64_t cr3);

static void print_ev(char *name, struct sinsn *insn)
{
	printf("%s ", name);
	print_ip(insn->ip, insn->cr3);
	putchar('\n');
}

static void print_event(struct sinsn *insn)
{
	if (insn->disabled)
		print_ev("disabled", insn);
	if (insn->enabled)
		print_ev("enabled", insn);
	if (insn->resumed)
		print_ev("resumed", insn);
	if (insn->interrupted)
		print_ev("interrupted", insn);
	if (insn->resynced)
		print_ev("resynced", insn);
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

static void print_ip(uint64_t ip, unsigned long cr3)
{
	struct sym *sym = findsym(ip, cr3);
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
	unsigned ratio;
};

static void print_loop(struct sinsn *si, struct local_pstate *ps)
{
	if (si->loop_start) {
		print_time_indent();
		printf(" %5s  %*sloop start %u iterations ", "", ps->indent, "", si->iterations);
		print_ip(si->ip, si->cr3);
		putchar('\n');
	}
	if (si->loop_end) {
		print_time_indent();
		printf(" %5s  %*sloop end ", "", ps->indent, "");
		print_ip(si->ip, si->cr3);
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
		if (si->ratio && si->ratio != gps->ratio) {
			printf("frequency %d\n", si->ratio);
			gps->ratio = si->ratio;
		}
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
				print_ip(si->ip, si->cr3);
				putchar('\n');
			}
		}
		switch (si->iclass) {
		case ptic_far_call:
		case ptic_call: {
			if (!si->ts)
				print_time_indent();
			printf("[+%4u] %*s", si->insn_delta, ps->indent, "");
			print_ip(si->ip, si->cr3);
			printf(" -> ");
			print_ip(si->dst, si->cr3);
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
	struct local_pstate ps;

	for (;;) {
		uint64_t pos;
		int err = pt_insn_sync_forward(decoder);
		if (err < 0) {
			pt_insn_get_offset(decoder, &pos);
			printf("%lx: sync forward: %s\n", pos, pt_errstr(pt_errcode(err)));
			break;
		}

		memset(&ps, 0, sizeof(struct local_pstate));

		unsigned long insncnt = 0;
		struct sinsn insnbuf[NINSN];
		uint64_t errip = 0;
		uint32_t prev_ratio = 0;
		do {
			int sic = 0;
			while (!err && sic < NINSN - 1) {
				struct pt_insn insn;
				struct sinsn *si = &insnbuf[sic];

				insn.ip = 0;
				err = pt_insn_next(decoder, &insn, sizeof(struct pt_insn));
				if (err < 0) {
					errip = insn.ip;
					break;
				}
				if (dump_insn)
					print_insn(&insn);
				insncnt++;
				// XXX use lost counts
				pt_insn_time(decoder, &si->ts, NULL, NULL);
				uint32_t ratio;
				si->ratio = 0;
				pt_insn_core_bus_ratio(decoder, &ratio);
				if (ratio != prev_ratio) {
					si->ratio = ratio;
					prev_ratio = ratio;
				}
				pt_insn_get_cr3(decoder, &si->cr3);
				/* This happens when -K is used. Match everything for now. */
				if (si->cr3 == -1L)
					si->cr3 = 0;
				if (si->ts && si->ts == last_ts)
					si->ts = 0;
				si->iclass = insn.iclass;
				if (insn.iclass == ptic_call || insn.iclass == ptic_far_call) {
					si->ip = insn.ip;
					err = pt_insn_next(decoder, &insn, sizeof(struct pt_insn));
					if (err < 0) {
						si->dst = 0;
						errip = insn.ip;
						break;
					}
					si->dst = insn.ip;
					if (!si->ts) {
						pt_insn_time(decoder, &si->ts, NULL, NULL);
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
	printf("%-9s %-5s %13s   %s\n",
		"TIME",
		"DELTA",
		"INSNs",
		"OPERATION");
}

void usage(void)
{
	fprintf(stderr, "sptdecode --pt ptfile --elf elffile ...\n");
	fprintf(stderr, "-p/--pt ptfile   PT input file. Required\n");
	fprintf(stderr, "-e/--elf binary[:codebin]  ELF input PT files. Can be specified multiple times.\n");
	fprintf(stderr, "                   When codebin is specified read code from codebin\n");
	fprintf(stderr, "-s/--sideband log  Load side band log. Needs access to binaries\n");
	fprintf(stderr, "--freq/-f freq   Use frequency to convert time stamps (Ghz). cur for current system.\n");
	fprintf(stderr, "--insn/-i        dump instruction bytes\n");
#if 0 /* needs more debugging */
	fprintf(stderr, "--loop/-l	  detect loops\n");
#endif
	fprintf(stderr, "--cpu/-c cpuname cpu that collected the trace (in family/model/stepping)\n");
	exit(1);
}

struct option opts[] = {
	{ "elf", required_argument, NULL, 'e' },
	{ "pt", required_argument, NULL, 'p' },
	{ "freq", required_argument, NULL, 'f' },
	{ "insn", no_argument, NULL, 'i' },
	{ "sideband", required_argument, NULL, 's' },
	{ "loop", no_argument, NULL, 'l' },
	{ "cpu", required_argument, NULL, 'c' },
	{ }
};

int main(int ac, char **av)
{
	struct pt_insn_decoder *decoder = NULL;
	struct pt_image *image = pt_image_alloc("simple-pt");
	int c;
	char *cpu = NULL;

	while ((c = getopt_long(ac, av, "e:p:f:is:lc:", opts, NULL)) != -1) {
		char *end;
		switch (c) {
		case 'e':
			if (read_elf(optarg, image, 0, 0) < 0) {
				fprintf(stderr, "Cannot load elf file %s: %s\n",
						optarg, strerror(errno));
			}
			break;
		case 'p':
			/* FIXME */
			if (decoder) {
				fprintf(stderr, "Only one PT file supported\n");
				usage();
			}
			decoder = init_decoder(optarg, cpu);
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
			load_sideband(optarg, image);
			break;
		case 'l':
			detect_loop = true;
			break;
		case 'c':
			if (decoder) {
				fprintf(stderr, "--cpu/-c must be before --pt\n");
				exit(1);
			}
			cpu = optarg;
			break;
		default:
			usage();
		}
	}
	if (decoder) {
	  	read_kernel(image);
		pt_insn_set_image(decoder, image);
	}
	if (ac - optind != 0 || !decoder)
		usage();
	print_header();
	decode(decoder);
	return 0;
}
