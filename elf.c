#include <gelf.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <intel-pt.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "symtab.h"
#include "elf.h"

void read_symtab(Elf *elf)
{
	Elf_Scn *section = NULL;

	while ((section = elf_nextscn(elf, section)) != 0) {
		GElf_Shdr shdr, *sh;
		sh = gelf_getshdr(section, &shdr);

		if (sh->sh_type == SHT_SYMTAB || sh->sh_type == SHT_DYNSYM) {
			Elf_Data *data = elf_getdata(section, NULL);
			GElf_Sym *sym, symbol;
			int j;

			unsigned numsym = sh->sh_size / sh->sh_entsize;
			struct symtab *st = add_symtab(numsym);
			for (j = 0; j < numsym; j++) {
				struct sym *s;
				sym = gelf_getsymshndx(data, NULL, j, &symbol, NULL);
				s = &st->syms[j];
				s->name = strdup(elf_strptr(elf, shdr.sh_link, sym->st_name));
				s->val = sym->st_value;
				s->size = sym->st_size;
			}
			sort_symtab(st);
		}
	}
}

void add_progbits(Elf *elf, struct pt_image *image, char *fn, uint64_t base,
		 uint64_t cr3)
{
	int64_t offset = 0;
	size_t numphdr;
	int i;

	elf_getphdrnum(elf, &numphdr);
	if (base) {
		uint64_t minaddr = UINT64_MAX;
		for (i = 0; i < numphdr; i++) {
			GElf_Phdr phdr;
			gelf_getphdr(elf, i, &phdr);
			if (phdr.p_type == PT_LOAD && phdr.p_vaddr < minaddr)
				minaddr = phdr.p_vaddr;
		}
		offset = base - minaddr;
	}
	for (i = 0; i < numphdr; i++) {
		GElf_Phdr phdr;
		gelf_getphdr(elf, i, &phdr);

		if (phdr.p_type == PT_LOAD) {
			struct pt_asid asid;
			int err;

			pt_asid_init(&asid);
			asid.cr3 = cr3;
			err = pt_image_add_file(image, fn, phdr.p_offset, phdr.p_filesz,
					       &asid, phdr.p_vaddr + offset);
			if (err < 0) {
				fprintf(stderr, "reading prog code from %s: %s (%s)\n",
						fn, pt_errstr(pt_errcode(err)), strerror(errno));
				return;
			}
		}
	}
}

static Elf *elf_open(char *fn, int *fd)
{
	*fd = open(fn, O_RDONLY);
	if (*fd < 0) {
		perror(fn);
		return NULL;
	}
	Elf *elf = elf_begin(*fd, ELF_C_READ, NULL);
	if (!elf) {
		fprintf(stderr, "elf_begin failed for %s: %s\n",
				fn, elf_errmsg(-1));
		close(*fd);
	}
	return elf;
}

static void elf_close(Elf *elf, int fd)
{
	elf_end(elf);
	close(fd);
}

int read_elf(char *fn, struct pt_image *image, uint64_t base, uint64_t cr3)
{
	elf_version(EV_CURRENT);

	char *p = strchr(fn, ':');
	if (p) {
		*p = 0;
		p++;
	} else
		p = fn;

	int fd;
	Elf *elf = elf_open(fn, &fd);
	if (elf == NULL)
		return -1;
	read_symtab(elf);
	if (p) {
		elf_close(elf, fd);
		elf = elf_open(p, &fd);
		if (!elf)
			return -1;
	}
	add_progbits(elf, image, p, base, cr3);
	elf_close(elf, fd);
	return 0;
}
