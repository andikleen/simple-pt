struct pt_insn_decoder;
int read_elf(char *fn, struct pt_insn_decoder *decoder, uint64_t base, uint64_t cr3);
