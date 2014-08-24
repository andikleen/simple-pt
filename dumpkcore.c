/* Dump text in /proc/kcore with symbol table from kallsyms */
/* Notebook
   convert elf64 to gelf
   generalize string add
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

#define err(x) perror(x), exit(1)
#define elferr(x) fprintf(stderr, x ": %s\n", elf_errmsg(-1)), exit(1)
#define NEW(x) ((x) = calloc(sizeof(*(x)), 1))

Elf_Data *new_bytedata(Elf_Scn *scn, char *buf, int len)
{
	/* Add strtab elf section */
	Elf_Data *data = elf_newdata(scn);
	if (!data)
		elferr("elf_newdata");
	data->d_align = 1;
	data->d_buf = buf;
	data->d_off = 0;
	data->d_size = len;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;

	return data;
}

static void create_strtab(Elf *elf, char *strtab, int len, int *strscn)
{
	Elf_Scn *scn = elf_newscn(elf);
	if (!scn)
		elferr("elf_newscn");

	new_bytedata(scn, strtab, len);

	GElf_Shdr shdr_mem;
	GElf_Shdr *shdr = gelf_getshdr(scn, &shdr_mem);
	if (!shdr)
		elferr("elf64_getshdr");
	shdr->sh_type = SHT_STRTAB;
	shdr->sh_flags = SHF_STRINGS;
	shdr->sh_entsize = 0;
	gelf_update_shdr(scn, shdr);

	GElf_Ehdr ehdr_mem;
	GElf_Ehdr *ehdr = gelf_getehdr(elf, &ehdr_mem);
	*strscn = ehdr->e_shstrndx = elf_ndxscn(scn);
	gelf_update_ehdr(elf, ehdr);
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
int num_modules;

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
	mod->scn = elf_newscn(elf);
	if (!mod->scn)
		elferr("elf_newscn");
	printf("module %s section %lu\n", mod->name, elf_ndxscn(mod->scn));
	num_modules++;
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

void read_symbols(Elf *elf, int *strscn)
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

		if ((n = sscanf(line, "%llx %1c %300s [%100s", &addr, &type, name, mname)) < 3)
			continue;

		/* handle stext,etext, modules */
		bool has_module = n > 3;
		mod = kernel_mod(elf, mod, name, syms, addr);

		if (tolower(type) != 't')
			continue;

		if (has_module) {
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
				if (sym)
					sym->sym.st_size = addr - sym->sym.st_value;
				mod = findmod(mname);
				if (!mod) {
					fprintf(stderr, "module %s not found\n", mname);
					continue;
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
	create_strtab(elf, strtab, stroff, strscn);
}

GElf_Phdr *find_phdr(GElf_Phdr *phdrs, int numphdr, unsigned long start, unsigned long end)
{
	int i;
	for (i = 0; i < numphdr; i++) {
		GElf_Phdr *phdr = &phdrs[i];
		if (start >= phdr->p_vaddr && end < phdr->p_vaddr + phdr->p_filesz)
			return phdr;
	}
	return NULL;
}

GElf_Phdr *read_phdr(Elf *kelf, size_t *numphdr)
{
	elf_getphdrnum(kelf, numphdr);
	GElf_Phdr *phdr = calloc(*numphdr, sizeof(GElf_Phdr));
	int i;
	for (i = 0; i < *numphdr; i++) {
		if (!gelf_getphdr(kelf, i, &phdr[i]))
			elferr("gelf_getphdr");
	}
	return phdr;
}

void read_kcore(Elf *elf, int strscn)
{
	int kfd = open("/proc/kcore", O_RDONLY);
	if (kfd < 0)
		err("/proc/kcore");
	Elf *kelf = elf_begin(kfd, ELF_C_READ, NULL);
	if (!kelf)
		elferr("elf_begin ELF_C_READ");

	gelf_newphdr(elf, num_modules);

	/* Read phdrs */
	size_t knumphdr;
	GElf_Phdr *kphdrs = read_phdr(kelf, &knumphdr);

	GElf_Shdr shdrs[num_modules];

	int i;
	struct module *mod;
	for (mod = modules, i = 0; mod; mod = mod->next, i++) {
		/* find phdr. assume no overlap */
		GElf_Phdr *ph = find_phdr(kphdrs, knumphdr, mod->start, mod->end);
		if (!ph) {
			fprintf(stderr, "Cannot find kcore mapping for %s %llx-%llx\n",
					mod->name, mod->start, mod->end);
			/* Would need to finalize sections anyways to continue */
			exit(1);
		}

		/* Read core from kcore for a module */
		long off = mod->start - ph->p_vaddr;
		assert(off >= 0);
		unsigned long len = mod->end - mod->start;
		char *buf = malloc(len);
		if (!len) {
			fprintf(stderr, "Cannot allocate %ld bytes\n", len);
			exit(ENOMEM);
		}
		if (pread(kfd, buf, len, ph->p_offset + off) != len) {
			fprintf(stderr, "Cannot read %llx-%llx from kcore\n", mod->start, mod->end);
			exit(1);
		}

		/* Set up section */
		(void)new_bytedata(mod->scn, buf, len);
		elf_flagscn(mod->scn, ELF_C_SET, ELF_F_DIRTY);
		//free(buf);

		GElf_Shdr *shdr = gelf_getshdr(mod->scn, &shdrs[i]);
		if (!shdr)
			elferr("gelf_getshdr");
		shdr->sh_flags = SHF_EXECINSTR;
		shdr->sh_link = strscn;
		shdr->sh_type = SHT_PROGBITS;
		gelf_update_shdr(mod->scn, shdr);
	}
	free(kphdrs);

	/* Update PHDRs */
	elf_update (elf, ELF_C_NULL);
	GElf_Phdr tphdr[num_modules];
	for (i = 0; i < num_modules; i++) {
		GElf_Phdr *phdr = gelf_getphdr(elf, i, &tphdr[i]);
		phdr->p_type = PT_PHDR;
		phdr->p_offset = shdrs[i].sh_offset;
		phdr->p_filesz = shdrs[i].sh_size;
		gelf_update_phdr(elf, i, phdr);
	}

	elf_end(kelf);
	close(kfd);
}

void usage(void)
{
	fprintf(stderr, "Usage: dumpkcore file\n");
	fprintf(stderr, "Create a core dump file of all kernel/module text with symbols\n");
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

	gelf_newehdr(elf, ELFCLASS64); /* XXX */
	GElf_Ehdr ehdr_mem;
	GElf_Ehdr *ehdr = gelf_getehdr(elf, &ehdr_mem);
	if (ehdr == NULL)
		elferr("gelf_newhdr");

	ehdr->e_machine = EM_X86_64;
	ehdr->e_type = ET_CORE;
	ehdr->e_version = 1;
	ehdr->e_ehsize = 1;
	gelf_update_ehdr(elf, ehdr);

	int strscn;
	read_modules(elf);
	read_symbols(elf, &strscn);
	read_kcore(elf, strscn);

	elf_update (elf, ELF_C_NULL);
	if (elf_update(elf, ELF_C_WRITE) < 0)
		elferr("elf_update");

	elf_end(elf);
	close(fd);
	return 0;
}
