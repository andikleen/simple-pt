/* Simple PT dumper */
#define _GNU_SOURCE 1
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "map.h"

#define BIT(x) (1U << (x))

typedef unsigned long long u64;


static char psb[16] = {
	0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
	0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82
};

#define LEFT(x) ((end - p) >= (x))

/* Caller must have checked length */
static u64 get_ip_val(unsigned char **pp, unsigned char *end, int len, uint64_t *last_ip)
{
	unsigned char *p = *pp;
	u64 v = *last_ip;
	int i;
	unsigned shift = 0;

	if (len == 0) {
		*last_ip = 0;
		return 0; /* out of context */
	}
	if (len < 4) {
		if (!LEFT(len)) {
			*last_ip = 0;
			return 0; /* XXX error */
		}
		for (i = 0; i < len; i++, shift += 16, p += 2) {
			uint64_t b = *(uint16_t *)p;
			v = (v & ~(0xffffULL << shift)) | (b << shift);
		}
		v = ((int64_t)(v << (64 - 48))) >> (64 - 48); /* sign extension */
	} else {
		return 0; /* XXX error */
	}
	*pp = p;
	*last_ip = v;
	return v;
}

/* Caller must have checked length */
static u64 get_val(unsigned char **pp, int len)
{
	unsigned char *p = *pp;
	u64 v = 0;
	int i;
	unsigned shift = 0;

	for (i = 0; i < len; i++, shift += 8)
		v |= ((uint64_t)(*p++)) << shift;
	*pp = p;
	return v;
}

static void print_unknown(unsigned char *p, unsigned char *end, unsigned char *map)
{
	printf("unknown packet: ");
	unsigned len = end - p;
	int i;
	if (len > 16)
		len = 16;
	for (i = 0; i < len; i++)
		printf("%02x ", p[i]);
	printf("\n");
}

static void print_tnt_byte(unsigned char v, int max)
{
	int i;
	for (i = max - 1; i >= 0; i--)
		if (v & BIT(i))
			putchar('!');
		else
			putchar('.');
}

static void print_tnt_stop(unsigned char v)
{
	int j;
	for (j = 7; j >= 0; j--) {
		if (v & BIT(j))
			break;
	}
	print_tnt_byte(v, j);
}

static void print_multi_tnt(unsigned char *p, int len)
{
	int i;

	for (i = len - 1; i >= 0 && p[i] == 0; i--)
		;
	if (i >= 0) {
		print_tnt_stop(p[i]);
		i--;
	} else {
		printf("??? no stop bit");
		return;
	}
	for (; i >= 0; i--)
		print_tnt_byte(p[i], 8);
}

void decode_buffer(unsigned char *map, size_t len)
{
	unsigned char *end = map + len;
	unsigned char *p;
	size_t skipped = 0;
	size_t overflow = 0;
	uint64_t last_ip = 0;

	for (p = map; p < end; ) {
		unsigned char *prev = p;
		/* look for PSB */
		p = memmem(p, end - p, psb, 16);
		if (!p)
			break;
		skipped += p - prev;
		while (p < end) {
			printf("%lx\t", p - map);

			if (*p == 2 && LEFT(2)) {
				if (p[1] == 0xa3 && LEFT(8)) { /* long TNT */
					printf("tnt64 ");
					print_multi_tnt(p + 2, 6);
					printf("\n");
					p += 8;
					continue;
				}
				if (p[1] == 0x43 && LEFT(8)) { /* PIP */
					p += 2;
					printf("pip\t%llx\n", (get_val(&p, 6) >> 1) << 5);
					continue;
				}
				if (p[1] == 3 && LEFT(4) && p[3] == 0) { /* CBR */
					printf("cbr\t%u\n", p[2]);
					p += 4;
					continue;
				}
				if (p[1] == 0b11110011 && LEFT(8)) { /* OVF */
					printf("ovf\n");
					p += 8;
					overflow++;
					continue;
				}
				if (p[1] == 0x82 && LEFT(16) && !memcmp(p, psb, 16)) { /* PSB */
					printf("psb\n");
					p += 16;
					continue;
				}
				if (p[1] == 0b100011) { /* PSBEND */
					printf("psbend\n");
					p += 2;
					continue;
				}
			}

			if ((*p & BIT(0)) == 0) {
				if (*p == 0) { /* PAD */
					printf("pad\n");
					p++;
					continue;
				}
				printf("tnt8 ");
				print_tnt_stop(*p >> 1);
				printf("\n");
				p++;
				continue;
			}

			char *name = NULL;
			switch (*p & 0x1f) {
			case 0xd:
				name = "tip";
				break;
			case 0x11:
				name = "tip.pge";
				break;
			case 0x1:
				name = "tip.pgd";
				break;
			case 0x1d:
				name = "fup";
				break;
			}
			if (name) {
				int ipl = *p >> 5;
				p++;
				printf("%s\t%d: %llx\n", name, ipl, get_ip_val(&p, end, ipl, &last_ip));
				continue;
			}
			if (*p == 0x99 && LEFT(2)) { /* MODE */
				if ((p[1] >> 5) == 1) {
					printf("mode.tsx");
					if (p[1] & BIT(0))
						printf(" intx");
					if (p[1] & BIT(1))
						printf(" txabort");
					printf("\n");
					p += 2;
					continue;
				} else if ((p[1] >> 5) == 0) {
					printf("mode.exec");
					printf(" lma=%d", (p[1] & BIT(0)));
					printf(" cs.d=%d", !!(p[1] & BIT(1)));
					printf("\n");
					p += 2;
					continue;
				}
			}

			if (*p == 0x19 && LEFT(8)) {  /* TSC */
				p++;
				printf("tsc\t%llx\n", get_val(&p, 7));
				continue;
			}

			print_unknown(p, end, map);
			break;
		}
	}
	if (p < end || skipped)
		printf("%lu bytes undecoded\n", (end - p) + skipped);
	if (overflow)
		printf("%lu overflows\n", overflow);
}

void do_file(char *fn)
{
	size_t len;
	unsigned char *map = mapfile(fn, &len);
	if (!map) {
		perror(fn);
		return;
	}
	decode_buffer(map, len);
	unmapfile(map, len);
}

int main(int ac, char **av)
{
	while (*++av)
		do_file(*av);
	return 0;
}
