/* Resolve and print line numbers using libdwarf */

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

#include <libdwarf/libdwarf.h>
#include <libdwarf/dwarf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include "dwarf.h"

static bool match_line(Dwarf_Line *lines, int num_lines, int i, Dwarf_Addr addr, Dwarf_Addr *addrp)
{
	Dwarf_Error err;
	Dwarf_Addr laddr, next_addr = -1LL;
	dwarf_lineaddr(lines[i], &laddr, &err);
	if (i + 1 < num_lines)
		dwarf_lineaddr(lines[i + 1], &next_addr, &err);
	if (addr >= laddr && addr < next_addr)
		return true;
	*addrp = addr;
	return false;
}

static int find_line(Dwarf_Line *lines, int num_lines, Dwarf_Addr addr)
{
	int start = 0;
	int end = num_lines - 1;

	while (start <= end) {
		Dwarf_Addr laddr;
		int mid = start + (end - start) / 2;

		if (match_line(lines, num_lines, mid, addr, &laddr))
			return mid;
		if (laddr < addr)
			start = mid + 1;
		else
			end = mid - 1;
	}
	return -1;
}

static void print_line(Dwarf_Debug dbg, Dwarf_Line line)
{
	Dwarf_Unsigned lineno;
	Dwarf_Unsigned srcfileno = 0;
	Dwarf_Addr laddr;
	Dwarf_Error err;
	char *filename;

	dwarf_lineno(line, &lineno, &err);
	dwarf_line_srcfileno(line, &srcfileno, &err);
	dwarf_lineaddr(line, &laddr, &err);
	if (srcfileno)
		dwarf_linesrc(line, &filename, &err);
	printf("%lx:%s:%u\n", (unsigned long)laddr, filename, (unsigned)lineno);
	dwarf_dealloc(dbg, filename, DW_DLA_STRING);
}

/* Compilation unit */
struct dw_cu {
	struct dw_cu *next;
	Dwarf_Off off;
	Dwarf_Line *lines;
	Dwarf_Signed num_lines;
};

/* Binary ELF file with dwarf */
struct dw_file {
	struct dw_file *next;
	char *fn;
	int fd;
	bool initialized;
	Dwarf_Debug dbg;
	Dwarf_Arange *all_aranges;
	Dwarf_Signed num_aranges;
	struct dw_cu *cus;
};

// add hash?
// for now just use move-to-front and assume temporal locality
// is good enough.
static struct dw_file *dw_files;

// use sizes instead?
#define MAX_FILES 25

/* Caller must unlink from list */
static void dw_file_free(struct dw_file *dwf)
{
	struct dw_cu *cu, *next;
	Dwarf_Error err;
	for (cu = dwf->cus; cu; cu = next) {
		next = cu->next;
		dwarf_srclines_dealloc(dwf->dbg, cu->lines, cu->num_lines);
		free(cu);
	}

	if (dwf->initialized) {
		dwarf_dealloc(dwf->dbg, dwf->all_aranges, DW_DLA_LIST);
		dwarf_finish(dwf->dbg, &err);
		close(dwf->fd);
	}
	free(dwf->fn);
	free(dwf);
}

static struct dw_file *find_dw_file(char *fn)
{
	struct dw_file *dwf, **pprev;
	int num = 0;
	pprev = &dw_files;
	for (dwf = dw_files; dwf; pprev = &dwf->next, dwf = dwf->next) {
		if (!strcmp(dwf->fn, fn)) {
			/* Move to front */
			if (dwf != dw_files) {
				*pprev = dwf->next;
				dwf->next = dw_files;
				dw_files = dwf;
			}

			/* File not found */
			if (!dwf->initialized)
				return NULL;
			return dwf;
		}
		num++;
		if (!dwf->next)
			break;
	}
	if (num >= MAX_FILES) {
		/* Free the last one to make room */
		assert(dwf->next == NULL);
		dw_file_free(dwf);
		*pprev = NULL;
	}

	dwf = calloc(sizeof(struct dw_file), 1);
	if (!dwf)
		exit(ENOMEM);
	dwf->next = dw_files;
	dw_files = dwf;
	dwf->fn = strdup(fn);
	if (!dwf->fn)
		exit(ENOMEM);
	/* On error leave the dwf around as marker to avoid error floods */
	dwf->fd = open(fn, O_RDONLY);
	if (dwf->fd < 0) {
		perror(fn);
		return NULL;
	}
	int ret;
	Dwarf_Error err;
	ret = dwarf_init(dwf->fd, DW_DLC_READ, NULL, NULL, &dwf->dbg, &err);
	if (ret) {
		printf("dwarf open err on %s: %s\n", fn, dwarf_errmsg(err));
		goto close_fd;
	}
	if (dwarf_get_aranges(dwf->dbg, &dwf->all_aranges, &dwf->num_aranges, &err) != DW_DLV_OK) {
		printf("%s: get_aranges failed: %s\n", fn, dwarf_errmsg(err));
		goto close_dwarf;
	}
	dwf->initialized = true;
	return dwf;

close_dwarf:
	dwarf_finish(dwf->dbg, 0);
close_fd:
	close(dwf->fd);
	dwf->initialized = false;
	return NULL;
}

static struct dw_cu *new_cu(struct dw_file *dwf, Dwarf_Off off, char *fn)
{
	Dwarf_Die cu_die;
	Dwarf_Error err;

	if (dwarf_offdie(dwf->dbg, off, &cu_die, &err) != DW_DLV_OK) {
		printf("%s: off_die failed: %s\n", fn, dwarf_errmsg(err));
		return NULL;
	}
	struct dw_cu *cu = malloc(sizeof(struct dw_cu));
	if (!cu)
		exit(ENOMEM);
	if (dwarf_srclines(cu_die, &cu->lines, &cu->num_lines, &err) != DW_DLV_OK) {
		printf("%s: srclines failed: %s\n", fn, dwarf_errmsg(err));
		free(cu);
		dwarf_dealloc(dwf->dbg, cu_die, DW_DLA_DIE);
		return NULL;
	}
	dwarf_dealloc(dwf->dbg, cu_die, DW_DLA_DIE);
	cu->off = off;
	cu->next = dwf->cus;
	dwf->cus = cu;
	return cu;
}

#define MAX_CU 20

static struct dw_cu *find_cu(struct dw_file *dwf, Dwarf_Off off, char *fn)
{
	struct dw_cu *cu, **pprev;
	int num = 0;
	pprev = &dwf->cus;
	for (cu = dwf->cus; cu; pprev = &cu->next, cu = cu->next) {
		if (cu->off == off) {
			/* Move to front */
			if (cu != dwf->cus) {
				*pprev = cu->next;
				cu->next = dwf->cus;
				dwf->cus = cu;
			}
			return cu;
		}
		num++;
		if (!cu->next)
			break;
	}
	if (num >= MAX_CU) {
		assert(cu->next == NULL);
		dwarf_srclines_dealloc(dwf->dbg, cu->lines, cu->num_lines);
		free(cu);
		*pprev = NULL;
	}
	return new_cu(dwf, off, fn);
}

/* Find offset of CU based on aranges */
static int find_addr_cu_off(struct dw_file *dwf, unsigned long addr, Dwarf_Off *off,
			    char *fn)
{
	Dwarf_Arange arange;
	Dwarf_Error err;
	if (dwarf_get_arange(dwf->all_aranges, dwf->num_aranges, addr, &arange, &err) != DW_DLV_OK) {
		printf("%s: get_arange failed: %s\n", fn, dwarf_errmsg(err));
		return -1;
	}
	if (dwarf_get_cu_die_offset(arange, off, &err) != DW_DLV_OK) {
		printf("%s: get_cu_die_offset failed: %s\n", fn, dwarf_errmsg(err));
		return -1;
	}
	return 0;
}

/* Caller needs to take care of offsets for shared libraries */
int print_addr(char *fn, unsigned long addr)
{
	struct dw_file *dwf = find_dw_file(fn);
	if (!dwf)
		return -1;

	Dwarf_Off off;
	if (find_addr_cu_off(dwf, addr, &off, fn) < 0)
		return -1;
	struct dw_cu *cu = find_cu(dwf, off, fn);
	if (!cu)
		return -1;
	int i = find_line(cu->lines, cu->num_lines, addr);
	if (i < 0)
		return -1;
	print_line(dwf->dbg, cu->lines[i]);
	return 0;
}

#ifdef TEST
int main(int ac, char **av)
{
	while (*++av) {
		unsigned long addr;

		char *dot = strchr(*av, ':');
		if (dot && sscanf(dot + 1, "%lx", &addr) == 1) {
			*dot = 0;
		} else {
			printf("cannot parse %s\n", *av);
			exit(1);
		}
		printf("%s:%lx: ", *av, addr);
		print_addr(*av, addr);
	}
	return 0;
}

#endif
