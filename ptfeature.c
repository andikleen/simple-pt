/* Check CPUID for different PT features */

#include <stdio.h>
#include <cpuid.h>
#include <string.h>

#define BIT(x) (1ULL << (x))

int main(int ac, char **av)
{
	unsigned a, b, c, d;
	unsigned a1, b1, c1, d1;
	int addr_cfg_max = 0;
	int mtc_freq_mask = 0;
	int cyc_thresh_mask = 0;
	int psb_freq_mask = 0;
	int addr_range_num = 0;
	int has_cr3_match = 0;

	if (__get_cpuid_max(0, NULL) < 0x14) {
		printf("Too old CPU\n");
		return 1;
	}

	/* check cpuid */
	__cpuid_count(0x07, 0, a, b, c, d);
	if ((b & BIT(25)) == 0) {
		printf("No PT support\n");
		return 1;
	}
	__cpuid_count(0x14, 0, a, b, c, d);
	has_cr3_match = !!(b & BIT(0));
	if (b & BIT(2))
		addr_cfg_max = 2;
	a1 = b1 = c1 = d1 = 0;
	if (a >= 1)
		__cpuid_count(0x07, 1, a1, b1, c1, d1);
	if (b & BIT(1)) {
		mtc_freq_mask = (a1 >> 16) & 0xffff;
		cyc_thresh_mask = b1 & 0xffff;
		psb_freq_mask = (b1 >> 16) & 0xffff;
		addr_range_num = a1 & 0x3;
	}

	if (av[1] == NULL) {
		printf("Supports PT\n");
		printf("toPA:				%d\n", !!(c & BIT(0)));
		printf("multiple toPA entries:		%d\n", !!(c & BIT(1)));
		printf("single range:			%d\n", !!(c & BIT(2)));
		printf("payloads are LIP:		%d\n", !!(c & BIT(31)));
		printf("CR3 match:			%d\n", has_cr3_match);
		printf("Number of address ranges:	%d\n", addr_range_num);
		printf("Supports filter ranges:		%d\n", addr_cfg_max >= 1);
		printf("Supports stop ranges:		%d\n", addr_cfg_max >= 2);
		printf("Cycles threshold mask:		%x\n", cyc_thresh_mask);
		printf("PSB freq mask:			%x\n", psb_freq_mask);
		printf("MTC freq mask:			%x\n", mtc_freq_mask);
		return 0;
	}

	while (*++av) {
		if (!strcmp(*av, "pt")) {
			continue; /* Already checked */
		} else if (!strcmp(*av, "filter")) {
			if (addr_range_num == 0 || addr_cfg_max < 1) {
				printf("No filter ranges\n");
				return 1;
			}
		} else if (!strcmp(*av, "stop")) {
			if (addr_range_num == 0 || addr_cfg_max < 2) {
				printf("No stop ranges\n");
				return 1;
			}
		} else if (!strcmp(*av, "cyc")) {
			if (cyc_thresh_mask == 0) {
				printf("No CYC support\n");
				return 1;
			}
		} else if (!strcmp(*av, "psb")) {
			if (psb_freq_mask == 0) {
				printf("No PSB support\n");
				return 1;
			}
		} else if (!strcmp(*av, "mtc")) {
			if (mtc_freq_mask == 0) {
				printf("No MTC support\n");
				return 1;
			}
		} else if (!strcmp(*av, "topa")) {
			if (!(c & BIT(0))) {
				printf("No toPA support\n");
				return 1;
			}
		} else if (!strcmp(*av, "multi_topa")) {
			if (!(c & BIT(0)) || !(c & BIT(1))) {
				printf("No multiple toPA support\n");
				return 1;
			}
		} else if (!strcmp(*av, "single_range")) {
			if (!(c & BIT(2))) {
				printf("No single range support\n");
				return 1;
			}
		} else if (!strcmp(*av, "lip")) {
			if (!(c & BIT(31))) {
				printf("Payloads are not LIP\n");
				return 1;
			}
		} else {
			fprintf(stderr, "Unknown match %s\n", *av);
			fprintf(stderr, "Valid matches: filter, stop, cyc, psb, mtc, pt, topa, multi_topa, single_range, lip\n");
			return 1;
		}
	}
	return 0;
}
