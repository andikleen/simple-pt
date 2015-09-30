#include <stdbool.h>
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
	unsigned long base;
	unsigned long end;
	char *fn;
};

extern struct symtab *symtabs;

struct sym *findsym(unsigned long val, unsigned long cr3);
char *find_ip_fn(unsigned long val, unsigned long cr3);
struct symtab *add_symtab(unsigned num, unsigned long cr3, unsigned long base, char *fn);
void dump_symtab(struct symtab *st);
void sort_symtab(struct symtab *st);
bool seen_cr3(unsigned long cr3);
