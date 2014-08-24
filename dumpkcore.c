/* Dump text in /proc/kcore with symbol table from kallsyms */
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

#define err(x) perror(x), exit(1)
#define elferr(x) fprintf(stderr, x ": %s\n", elf_errmsg(-1)), exit(1)
#define NEW(x) ((x) = calloc(sizeof(*(x)), 1))

static void create_strtab(Elf *elf, char *strtab, int len)
{
	Elf_Scn *scn = elf_newscn(elf);
	if (!scn)
		elferr("elf_newscn");

	/* Add strtab elf section */
	Elf_Data *data = elf_newdata(scn);
	if (!data)
		elferr("elf_newdata");
	data->d_align = 1;
	data->d_buf = strtab;
	data->d_off = 0;
	data->d_size = len;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;

	Elf64_Shdr *shdr = elf64_getshdr(scn);
	if (!shdr)
		elferr("elf64_getshdr");
	shdr->sh_type = SHT_STRTAB;
	shdr->sh_flags = SHF_STRINGS;
	shdr->sh_entsize = 0;

	Elf64_Ehdr *ehdr = elf64_getehdr(elf);	
	ehdr->e_shstrndx = elf_ndxscn(scn);
}

static void create_symtab(Elf *elf, Elf64_Sym *symtab, int len)
{
	Elf_Scn *scn = elf_newscn(elf);
	if (!scn)
		elferr("elf_newscn");

	/* Add strtab elf section */
	Elf_Data *data = elf_newdata(scn);
	if (!data)
		elferr("elf_newdata");
	data->d_align = 8;
	data->d_buf = symtab;
	data->d_off = 0;
	data->d_size = len * sizeof(Elf64_Sym);
	data->d_type = ELF_T_SYM;
	data->d_version = EV_CURRENT;

	Elf64_Shdr *shdr = elf64_getshdr(scn);
	if (!shdr)
		elferr("elf64_getshdr");
	shdr->sh_type = SHT_SYMTAB;
	shdr->sh_flags = 0; // XXX
	shdr->sh_entsize = sizeof(Elf64_Sym);
}

#define STRTABINIT (128 * 1024)

void add_strtab(char **strtab, int *strsize, int stroff, char *sym, int len)
{
	if (stroff + len + 1 > *strsize) {
		if (!*strsize)
			*strsize = STRTABINIT;
		else
			*strsize *= 2;
		*strtab = realloc(*strtab, *strsize);
		if (!*strtab) {
			fprintf(stderr, "Out of memory\n");
			exit(ENOMEM);
		}
		if (*strsize == STRTABINIT)
			**strtab = 0;
	}
	strcpy(*strtab + stroff, sym);
}

#define MIN_ADDR 0x100000

struct sym {
	struct sym *next;
	Elf64_Sym sym;
};

struct module {
	struct module *next;
	char *name;
	Elf_Scn *scn;
	unsigned long long start, end;
};

int cmp_sym(const void *ap, const void *bp)
{
	const Elf64_Sym *a = ap;
	const Elf64_Sym *b = bp;
	return a->st_value - b->st_value;
}

Elf64_Sym *collect_syms(struct sym *syms, int numsyms, struct module *modules)
{
	struct sym *next, *sym;

	/* Collect syms into array */
	Elf64_Sym *stab = malloc(numsyms * sizeof(Elf64_Sym));
	int i = 0;
	for (sym = syms; sym; sym = next, i++) {
		next = sym->next;
		memcpy(&stab[i], &sym->sym, sizeof(Elf64_Sym));
		free(sym);
	}

	qsort(stab, numsyms, sizeof(Elf64_Sym), cmp_sym);

	/* Fill in sizes after sorting */
	for (i = 0; i < numsyms - 1; i++) {
		if (!stab[i].st_size)
			stab[i].st_size = stab[i + 1].st_value - stab[i].st_value;
	}
	
	return stab;
}

struct module *modules = NULL;
struct module *lastmod;

struct module *newmod(Elf *elf, char *name, bool first)
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
#if 0
	mod->scn = elf_newscn(elf);
	if (!mod->scn)
		elferr("elf_newscn");
#endif
	return mod;
}

struct module *findmod(char *name)
{
	struct module *mod;
	for (mod = modules; mod; mod = mod->next)
		if (!strcmp(name, mod->name))
			return mod;
	return NULL;
}

struct module *kernel_mod(Elf *elf, 
			  struct module *mod, char *name, struct sym *sym,
			  unsigned long long addr)
{
	if (!strcmp(name, "_stext")) {
		assert(mod == NULL);
		mod = newmod(elf, "[kernel]", true);
		mod->start = addr;
	} else if (!strcmp(name, "_etext")) {
		assert(mod != NULL);
		mod->end = addr;
		mod = NULL;
		if (sym)
			sym->sym.st_size = addr - sym->sym.st_value;
	}
	return mod;
}

void read_modules(Elf *elf)
{
	FILE *f = fopen("/proc/modules", "r");
	if (!f)
		err("/proc/modules");
	char *line = NULL;
	size_t linelen = 0;
	while (getline(&line, &linelen, f) > 0) {
		char mname[100];
		unsigned long long addr;
		int len;

		// scsi_dh_hp_sw 12895 0 - Live 0xffffffffa005e000
		if (sscanf(line, "%100s %d %*d %*s %*s %llx", mname, &len, &addr) != 3)
			continue;
		struct module *mod = newmod(elf, mname, false);
		mod->start = addr;
		mod->end = addr + len;
	}
	free(line);
	fclose(f);
}

void read_symbols(Elf *elf)
{
	int stroff = 1;
	int strsize = 0;
	char *strtab = NULL;
	struct sym *syms = NULL;
	int numsyms = 0;

	FILE *f = fopen("/proc/kallsyms", "r");
	if (!f)
		err("/proc/kallsyms");
	char *line = NULL;
	size_t linelen = 0;
	struct module *mod = NULL;
	unsigned long long addr = 0;
	struct sym *sym = NULL;

	while (getline(&line, &linelen, f) > 0) {
		char type;
		char name[300], mname[100];
		int n;

		if ((n = sscanf(line, "%llx %1c %300s %100s", &addr, &type, name, mname)) < 3)
			continue;

		/* handle stext,etext, modules */
		bool has_module = n > 3;
		mod = kernel_mod(elf, mod, name, syms, addr);

		if (tolower(type) != 't')
			continue;

		if (has_module) {
			if (!mod) { 
				mod = findmod(mname);
				if (!mod) {
					fprintf(stderr, "module %s not found\n", mname);
					exit(1);
				}
			} else if (strcmp(mod->name, mname)) {
				if (sym) 
					sym->sym.st_size = addr - sym->sym.st_value;
				mod = findmod(mname);
				if (!mod) {
					fprintf(stderr, "module %s not found\n", mname);
					exit(1);
				}
			}
		}
		if (!mod)
			continue;

		int len = strlen(name);

		/* Create string tab entry */
		add_strtab(&strtab, &strsize, stroff, name, len);
	
		/* Create symbol table entry */
		NEW(sym);
		sym->sym.st_name = stroff;
		sym->sym.st_value = addr;
		sym->sym.st_info = ELF64_ST_INFO(type == 't' ? STB_LOCAL : STB_GLOBAL, STT_FUNC);
		sym->sym.st_size = 0;
		sym->sym.st_shndx = elf_ndxscn(mod->scn);
		sym->next = syms;

		syms = sym;
		numsyms++;
		stroff += len + 1;
	}
	free(line);
	fclose(f);

	Elf64_Sym *stab = collect_syms(syms, numsyms, modules);
	create_symtab(elf, stab, numsyms);
	create_strtab(elf, strtab, stroff);

	// xxx finalize sections of all modules
	// set sh_link
	for (mod = modules; mod; mod = mod->next)
		printf("%s %llx-%llx\n", mod->name, mod->start, mod->end);
}

void read_kcore(Elf *elf)
{
	int kfd = open("/proc/kcore", O_RDONLY);
	if (kfd < 0)
		err("/proc/kcore");
	Elf *kelf = elf_begin(kfd, ELF_C_READ, NULL);
	if (!kelf)
		elferr("elf_begin ELF_C_READ");
	// walk modules
	// find phdr
	// copy area to elf
	elf_end(kelf);
	close(kfd);
}

void usage(void)
{
	fprintf(stderr, "Usage: dumpkcore file\n");
	exit(1);
}

int main(int ac, char **av)
{
	if (!av[1])
		usage();

	int fd = open(av[1], O_RDWR|O_CREAT|O_TRUNC, 0644);
	if (fd < 0) {
		fprintf(stderr, "Cannot create %s: %s\n", av[1], strerror(errno));
		exit(1);
	}
	elf_version(EV_CURRENT);

	Elf *elf = elf_begin(fd, ELF_C_WRITE, NULL);
	if (elf == NULL)
		elferr("elf_begin");

	Elf64_Ehdr *ehdr = elf64_newehdr(elf);
	if (ehdr == NULL)
		elferr("gelf_newhdr");

	ehdr->e_machine = EM_X86_64;
	ehdr->e_type = ET_CORE;
	ehdr->e_version = 1;
	ehdr->e_ehsize = 1;
	elf_flagehdr (elf, ELF_C_SET, ELF_F_DIRTY);

	read_modules(elf);
	read_symbols(elf);
	read_kcore(elf);

	Elf64_Phdr *phdr = elf64_newphdr(elf, 1);
	if (phdr == NULL)
		elferr("gelf_newphdr");

	phdr->p_type = PT_PHDR;
	phdr->p_offset = ehdr->e_phoff;
	phdr->p_filesz = elf64_fsize(ELF_T_PHDR, 1, EV_CURRENT);

	elf_flagphdr(elf, ELF_C_SET, ELF_F_DIRTY);

	elf_update (elf, ELF_C_NULL);
	if (elf_update(elf, ELF_C_WRITE) < 0)
		elferr("elf_update");

	elf_end(elf);
	close(fd);
	return 0;
}
