/* Minimal PT driver. */
/* Open: CPU hotplug */

#define pr_fmt(fmt) KBUILD_MODNAME fmt

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <asm/msr.h>
#include <asm/processor.h>

#include "simple-pt.h"

#define MSR_IA32_RTIT_OUTPUT_BASE 	0x00000560
#define MSR_IA32_RTIT_OUTPUT_MASK_PTRS 	0x00000561
#define MSR_IA32_RTIT_CTL 		0x00000570
#define TRACE_EN 	BIT(0)
/* os, user, cr3 */
#define TO_PA    	BIT(8)
#define TSC_EN   	BIT(10)
#define DIS_RETC 	BIT(11)
#define MSR_IA32_RTIT_STATUS 		0x00000571
#define MSR_IA32_CR3_MATCH 		0x00000572
#define TOPA_STOP 	BIT(2)
#define TOPA_INT  	BIT(1)
#define TOPA_END  	BIT(0)
#define TOPA_SIZE_SHIFT 6

static DEFINE_PER_CPU(unsigned long, pt_buffer_cpu);
static DEFINE_PER_CPU(u64 *, topa_cpu);
static DEFINE_PER_CPU(bool, pt_running);
static DEFINE_PER_CPU(u64, pt_offset);
static int pt_buffer_order = 8;
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

	if (wrmsrl_safe(MSR_IA32_RTIT_CTL, TRACE_EN|TO_PA|TSC_EN) < 0) {
		if (rdmsrl_safe(MSR_IA32_RTIT_CTL, &old) == 0)
			pr_info("ctl %llx\n", old);
		return -1;
	}
	return 0;
}

static void do_start_pt(void *arg)
{
	int cpu = smp_processor_id();
	if (start_pt() < 0)
		pr_err("cpu %d, RTIT_CTL enable failed\n", cpu);
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
		pr_err("cpu %d, Cannot allocate %d KB buffer\n", cpu,
				(pt_buffer_order << PAGE_SHIFT) / 1024);
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
static void stop_pt(void *arg);

static int simple_pt_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long len = vma->vm_end - vma->vm_start;
	int cpu = (int)(long)file->private_data;

	if (len % PAGE_SIZE || len > (PAGE_SHIFT << pt_buffer_order))
		return -EINVAL;

	if (vma->vm_flags & VM_WRITE)
		return -EPERM;

	if (!cpu_online(cpu))
		return -EIO;

	return remap_pfn_range(vma, vma->vm_start, 
			       __pa(per_cpu(pt_buffer_cpu, cpu)),
			       PAGE_SHIFT << pt_buffer_order,
			       vma->vm_page_prot);
}

static long simple_pt_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	switch (cmd) { 
	case SIMPLE_PT_SET_CPU: {
		unsigned long cpu = arg;
		if (cpu > NR_CPUS || !cpu_online(cpu))
			return -EINVAL;
		file->private_data = (void *)cpu;
		return 0;
	}
	case SIMPLE_PT_START:
		on_each_cpu(do_start_pt, NULL, 1);
		return 0;
	case SIMPLE_PT_STOP:
		stop_pt(NULL);
		return 0;
	case SIMPLE_PT_GET_SIZE:
		return put_user(PAGE_SHIFT << pt_buffer_order, (int *)arg);
	case SIMPLE_PT_GET_OFFSET:
		if (per_cpu(pt_running, (long)file->private_data))
			return -EIO;
		return put_user(per_cpu(pt_offset, (long)file->private_data), (int *)arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations simple_pt_fops = {
	.owner = THIS_MODULE,
	.mmap =	simple_pt_mmap,
	.unlocked_ioctl = simple_pt_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice simple_pt_miscdev = { 
	MISC_DYNAMIC_MINOR,
	"simple-pt",
	&simple_pt_fops
};	
			       
static int simple_pt_init(void)
{
	unsigned a, b, c, d;
	int err;

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
		pr_err("PT initialization failed\n");
		simple_pt_exit();
		return pt_error;
	}

 	/* XXX cpu notifier */

	err = misc_register(&simple_pt_miscdev);
	if (err < 0) { 
		pr_err("Cannot register simple-pt device\n");
		simple_pt_exit();
		return err;
	}

	return 0;
}

static void stop_pt(void *arg)
{
	u64 offset;
	u64 status;
	int cpu = smp_processor_id();

	if (!__get_cpu_var(pt_running))
		return;
	wrmsrl_safe(MSR_IA32_RTIT_CTL, 0LL);
	status = rtit_status();
	if (status)
		pr_info("cpu %d, rtit status %llx after stopping\n", cpu, status);
	__get_cpu_var(pt_running) = false;

	rdmsrl_safe(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, &offset);
	__get_cpu_var(pt_offset) = offset >> 32;
	pr_info("cpu %d, table offset %llu output_offset %llu\n", cpu,
			offset & 0xffffffff,
			offset >> 32);
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
	pr_info("exited\n");
}

module_init(simple_pt_init);
module_exit(simple_pt_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andi Kleen");
