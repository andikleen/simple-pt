struct pt_image;
int read_elf(char *fn, struct pt_image *decoder, uint64_t base, uint64_t cr3,
		uint64_t file_off, uint64_t map_len);
