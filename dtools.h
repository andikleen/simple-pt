struct pt_insn_decoder;
struct pt_insn_decoder *init_decoder(char *fn);
void load_sideband(char *fn, struct pt_insn_decoder *decoder);
