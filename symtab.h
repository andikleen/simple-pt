struct sym {
	char *name;
	unsigned long val;
	unsigned long size;
};

struct symtab {
	struct symtab *next;
	unsigned num;
	struct sym *syms;
	unsigned long cr3;
};

extern struct symtab *symtabs;

struct sym *findsym(unsigned long val, unsigned long cr3);
struct symtab *add_symtab(unsigned num, unsigned long cr3);
void dump_symtab(struct symtab *st);
void sort_symtab(struct symtab *st);
