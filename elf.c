#include <gelf.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <intel-pt.h>
#include <string.h>
#include <stdio.h>
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

void add_progbits(Elf *elf, struct pt_insn_decoder *decoder, char *fn, uint64_t base)
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
			int err;
			err = pt_insn_add_file(decoder, fn, phdr.p_offset, phdr.p_filesz,
					       phdr.p_vaddr + offset);
			if (err < 0) {
				fprintf(stderr, "%s: %s\n", fn, pt_errstr(pt_errcode(err)));
				return;
			}
		}
	}
}

int read_elf(char *fn, struct pt_insn_decoder *decoder, uint64_t base)
{
	int ret = -1;

	elf_version(EV_CURRENT);
	int fd = open(fn, O_RDONLY);
	if (fd < 0) {
		perror(fn);
		return -1;
	}

	Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
	if (elf == NULL) {
		fprintf(stderr, "elf_begin failed\n");
		goto out_fd;
	}
	ret = 0;
	read_symtab(elf);
	add_progbits(elf, decoder, fn, base);
out_elf:
	elf_end(elf);
out_fd:
	close(fd);
	return ret;
}
