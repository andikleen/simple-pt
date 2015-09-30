/* Read /proc/kallsyms and map /proc/kcore for decoding */

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
#include <gelf.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libelf.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <assert.h>
#include <intel-pt.h>

#include "kernel.h"
#include "symtab.h"

#define NEW(x) ((x) = calloc(sizeof(*(x)), 1))

struct module {
	struct module *next;
	char *name;
	unsigned long long start, end;
	int numsym;
};

static struct module *modules = NULL;
static struct module *lastmod;

static struct module *newmod(Elf *elf, char *name, bool first)
{
	struct module *mod;
	NEW(mod);
	mod->name = strdup(name);
	if (first) {
		mod->next = modules;
		modules = mod;
	} else {
		if (lastmod)
			lastmod->next = mod;
		if (!modules)
			modules = mod;
		lastmod = mod;
	}
	return mod;
}

static struct module *findmod(char *name)
{
	struct module *mod;
	for (mod = modules; mod; mod = mod->next)
		if (!strcmp(name, mod->name))
			return mod;
	return NULL;
}

static void read_modules(Elf *elf)
{
	FILE *f = fopen("/proc/modules", "r");
	if (!f) {
		perror("/proc/modules");
		return;
	}
	char *line = NULL;
	size_t linelen = 0;
	while (getline(&line, &linelen, f) > 0) {
		char mname[100];
		unsigned long long addr;
		int len;

		// scsi_dh_hp_sw 12895 0 - Live 0xffffffffa005e000
		if (sscanf(line, "%100s %d %*d %*s %*s %llx", mname, &len, &addr) != 3) {
			fprintf(stderr, "failed to parse: %s", line);
			continue;
		}
		struct module *mod = newmod(elf, mname, false);
		mod->start = addr;
		mod->end = addr + len;
	}
	free(line);
	fclose(f);
}

static struct module *kernel_mod(Elf *elf,
				 struct module *mod, char *name,
				 unsigned long long addr)
{
	if (!strcmp(name, "_stext")) {
		assert(mod == NULL);
		mod = newmod(elf, "kernel", true);
		mod->start = addr;
	} else if (!strcmp(name, "_etext")) {
		assert(mod != NULL);
		mod->end = addr;
	}
	return mod;
}

static int cmp_sym(const void *ap, const void *bp)
{
	const struct sym *a = ap;
	const struct sym *b = bp;

	return a->val - b->val;
}

static void read_symbols(Elf *elf)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	if (!f) {
		perror("/proc/kallsyms");
		return;
	}
	struct module *mod;
	unsigned long long addr = 0;
	unsigned long long kend = 0, kstart = -1ULL;
	char name[300], mname[100];
	char type;
	int n;
	struct module *kmod = NULL;

	char *line = NULL;
	size_t linelen = 0;

	/* step 1: count lines and set up kernel_mod */
	int numsyms = 0;
	while (getline(&line, &linelen, f) > 0) {
		if ((n = sscanf(line, "%llx %1c %300s [%100s", &addr, &type, name, mname)) < 3)
			continue;
		/* handle stext,etext */
		kmod = kernel_mod(elf, kmod, name, addr);
		numsyms++;
	}

	if (!kmod) {
		fprintf(stderr, "Cannot find kernel text in kallsyms\n");
		return;
	}
	rewind(f);
	
	// XXX find vmlinux
	struct symtab *ksymtab = add_symtab(numsyms, 0, 0, NULL);

	int sindex = 0;
	while (getline(&line, &linelen, f) > 0 && sindex < numsyms) {
		if ((n = sscanf(line, "%llx %1c %300s [%100s", &addr, &type, name, mname)) < 3)
			continue;

		if (tolower(type) != 't')
			continue;

		if (n > 3) {
			char *p = strchr(mname, ']');
			if (p)
				*p = 0;
			if (!mod) {
				mod = findmod(mname);
				if (!mod) {
					fprintf(stderr, "module %s not found\n", mname);
					continue;
				}
			} else if (strcmp(mod->name, mname)) {
				mod = findmod(mname);
				if (!mod) {
					fprintf(stderr, "module %s not found\n", mname);
					continue;
				}
			}
		} else
			mod = kmod;

		struct sym *sym = &ksymtab->syms[sindex];
		sym->name = strdup(name);
		sym->val = addr;
		sym->size = 0;
		sindex++;
		if (addr > kend)
			kend = addr;
		if (addr < kstart)
			kstart = addr;
	}
	ksymtab->num = sindex;	
	ksymtab->end = kend;
	ksymtab->base = kstart;

	free(line);
	fclose(f);

	/* sort kallsyms */
	qsort(ksymtab->syms, sindex, sizeof(struct sym), cmp_sym);

	/* Compute symbol sizes */
	int i;
	for (i = 1; i < sindex; i++) {
		struct sym *sym = ksymtab->syms + i;
		(sym - 1)->size = sym->val - (sym - 1)->val;
	}
}

static GElf_Phdr *find_phdr(GElf_Phdr *phdrs, int numphdr, unsigned long start, unsigned long end)
{
	int i;
	for (i = 0; i < numphdr; i++) {
		GElf_Phdr *phdr = &phdrs[i];
		if (start >= phdr->p_vaddr && end < phdr->p_vaddr + phdr->p_filesz)
			return phdr;
	}
	return NULL;
}

static GElf_Phdr *read_phdrs(Elf *kelf, size_t *numphdr)
{
	elf_getphdrnum(kelf, numphdr);
	GElf_Phdr *phdr = calloc(*numphdr, sizeof(GElf_Phdr));
	int i;
	for (i = 0; i < *numphdr; i++) {
		if (!gelf_getphdr(kelf, i, &phdr[i])) {
			free(phdr);
			return NULL;
		}
	}
	return phdr;
}

static Elf *open_kcore(int *kfd)
{
	*kfd = open("/proc/kcore", O_RDONLY);
	if (*kfd < 0) {
	       perror("/proc/kcore");
	       return NULL;
	}
	Elf *kelf = elf_begin(*kfd, ELF_C_READ, NULL);
	if (!kelf) {
		fprintf(stderr, "elf_begin ELF_C_READ");
		return NULL;
	}
	return kelf;
}

#define PAGESIZE 4096

/* Create decoder mappings */
static void read_kcore(Elf *kelf, struct pt_image *image)
{
	/* Read phdrs from kcore */
	size_t knumphdr;
	GElf_Phdr *kphdrs = read_phdrs(kelf, &knumphdr);

	if (!kphdrs)
		return;

	int i;
	struct module *mod;
	for (mod = modules, i = 0; mod; mod = mod->next, i++) {
		/* find phdr. assume no overlap */
		GElf_Phdr *ph = find_phdr(kphdrs, knumphdr, mod->start, mod->end);
		if (!ph) {
			fprintf(stderr, "Cannot find kcore mapping for %s %llx-%llx\n",
					mod->name, mod->start, mod->end);
			continue;
		}

		/* Read core from kcore for a module */
		long off = mod->start - ph->p_vaddr;
		assert(off >= 0);
		unsigned long len = mod->end - mod->start;

		int err = pt_image_add_file(image, "/proc/kcore", ph->p_offset + off, len, NULL, mod->start);
		if (err < 0) {
			fprintf(stderr, "reading kernel code from %s: %s (%s)\n",
				"/proc/kcore", pt_errstr(pt_errcode(err)), strerror(errno));
			continue;
		}
	}
	free(kphdrs);
}

void read_kernel(struct pt_image *image)
{
	elf_version(EV_CURRENT);

	int kfd;
	Elf *kelf = open_kcore(&kfd);

	read_modules(kelf);
	read_symbols(kelf);
	read_kcore(kelf, image);

	elf_end(kelf);
}
