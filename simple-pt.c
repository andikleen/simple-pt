/* Minimal PT driver. */

#define pr_fmt(fmt) KBUILD_MODNAME fmt

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/io.h>
#include <asm/msr.h>
#include <asm/processor.h>

#define MSR_IA32_RTIT_CTL 		0x00000570
#define TRACE_EN (1ULL << 0)
/* os, user, cr3 */
#define TO_PA    (1ULL << 8)
#define TSC_EN   (1ULL << 10)
#define DIS_RETC (1ULL << 11)
#define MSR_IA32_RTIT_STATUS 		0x00000571
#define MSR_IA32_CR3_MATCH 		0x00000572
#define MSR_IA32_RTIT_OUTPUT_BASE 	0x00000560
#define MSR_IA32_RTIT_OUTPUT_MASK_PTRS 	0x00000561

#define TOPA_STOP (1U << 2)
#define TOPA_INT (1U << 1)
#define TOPA_END (1U << 0)
#define TOPA_SIZE_SHIFT 6

static DEFINE_PER_CPU(unsigned long, pt_buffer_cpu);
static DEFINE_PER_CPU(u64 *, topa_cpu);
static DEFINE_PER_CPU(bool, pt_running);
static int pt_buffer_order = 11;
static int pt_error;
module_param(pt_buffer_order, int, 0444);

static u64 rtit_status(void)
{
	u64 status;
	if (rdmsrl_safe(MSR_IA32_RTIT_STATUS, &status) < 0)
		return 0;
	return status;
}

static int start_pt(void)
{
	wrmsrl_safe(MSR_IA32_RTIT_OUTPUT_BASE, __pa(__get_cpu_var(pt_buffer_cpu)));
	wrmsrl_safe(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, 0ULL);
	__get_cpu_var(pt_running) = true;

	return wrmsrl_safe(MSR_IA32_RTIT_CTL, TRACE_EN|TO_PA|TSC_EN);
}

static void simple_pt_cpu_init(void *arg)
{
	int cpu = smp_processor_id();
	u64 *topa;
	unsigned long pt_buffer;
	u64 ctl;

	/* check for pt already active */
	if (rdmsrl_safe(MSR_IA32_RTIT_CTL, &ctl) == 0 && (ctl & TRACE_EN)) {
		pr_err("cpu %d, PT already active\n", cpu);
		pt_error = -EBUSY;
		return;
	}

	/* allocate buffer */
	pt_buffer = __get_free_pages(GFP_KERNEL|__GFP_NOWARN|__GFP_ZERO, pt_buffer_order);
	if (!pt_buffer) {
		pr_err("cpu %d, Cannot allocate order %d KB buffer\n", cpu, pt_buffer_order);
		pt_error = -ENOMEM;
		return;
	}
	__get_cpu_var(pt_buffer_cpu) = pt_buffer;

	/* allocate topa */
	topa = (u64 *)__get_free_page(GFP_KERNEL|__GFP_ZERO);
	if (!topa) {
		pr_err("cpu %d, Cannot allocate topa page\n", cpu);
		pt_error = -ENOMEM;
		goto out_pt_buffer;
	}
	__get_cpu_var(topa_cpu) = topa;

	/* create circular single entry topa table */
	topa[0] = (u64)__pa(pt_buffer) | (pt_buffer_order << TOPA_SIZE_SHIFT);
	topa[1] = (u64)__pa(topa) | TOPA_END; /* circular buffer */

	if (start_pt() < 0) {
		pr_err("cpu %d, Enabling PT failed, status %llx\n", cpu, rtit_status());
		pt_error = -EIO;
		goto out_topa;
	}
	return;
out_topa:
	free_page((unsigned long)topa);
	__get_cpu_var(topa_cpu) = NULL;
out_pt_buffer:
	free_pages(pt_buffer, pt_buffer_order);	
	__get_cpu_var(pt_buffer_cpu) = 0;
}

static void simple_pt_exit(void);
			       
static int simple_pt_init(void)
{
	unsigned a, b, c, d;

	pr_info("Simple PT\n");

	/* check cpuid */
	cpuid_count(0x07, 0, &a, &b, &c, &d);
	if ((b & (1 << 25)) == 0) {
		pr_info("No PT support\n");
		return -EIO;
	}
	cpuid_count(0x14, 0, &a, &b, &c, &d);
	if (!(c & (1 << 0))) {
		pr_info("No ToPA support\n");
		return -EIO;
	}
	
	on_each_cpu(simple_pt_cpu_init, NULL, 1);
	if (pt_error) {
		pr_err("PT initialization failed");
		simple_pt_exit();
		return pt_error;
	}

	/* cpu notifier */
	return 0;
}

static void stop_pt(void *arg)
{
	u64 status;
	if (!__get_cpu_var(pt_running))
		return;
	wrmsrl_safe(MSR_IA32_RTIT_CTL, 0LL);
	status = rtit_status();
	if (status)
		pr_info("cpu %d, rtit status %llx after stopping\n", smp_processor_id(), status);
	__get_cpu_var(pt_running) = false;
}

static void simple_pt_exit(void)
{
	int cpu;

	on_each_cpu(stop_pt, NULL, 1);

	for_each_possible_cpu (cpu) {
		if (per_cpu(topa_cpu, cpu))
			free_page((unsigned long)per_cpu(topa_cpu, cpu));
		if (per_cpu(pt_buffer_cpu, cpu))
			free_pages(per_cpu(pt_buffer_cpu, cpu), pt_buffer_order);		
	}
	pr_info("Exited simple pt");
}

module_init(simple_pt_init);
module_exit(simple_pt_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andi Kleen");
