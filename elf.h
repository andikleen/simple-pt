struct pt_image;
int read_elf(char *fn, struct pt_image *decoder, uint64_t base, uint64_t cr3);
