/* Minimal PT driver. */
/* Author: Andi Kleen */
/* Notebook:
   Make on/off state per cpu
   Need more locking?
   Add stop-on-kprobe
   Test old kernels
   */

#define DEBUG 1

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/cpu.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <trace/events/sched.h>
#include <asm/msr.h>
#include <asm/processor.h>
#define CREATE_TRACE_POINTS
#include "pttp.h"

#include "compat.h"
#include "simple-pt.h"

#define MSR_IA32_RTIT_OUTPUT_BASE	0x00000560
#define MSR_IA32_RTIT_OUTPUT_MASK_PTRS	0x00000561
#define MSR_IA32_RTIT_CTL		0x00000570
#define TRACE_EN	BIT(0)
#define CTL_OS		BIT(1)
#define CTL_USER	BIT(2)
#define CR3_FILTER	BIT(7)
#define TO_PA		BIT(8)
#define TSC_EN		BIT(10)
#define DIS_RETC	BIT(11)
#define MSR_IA32_RTIT_STATUS		0x00000571
#define MSR_IA32_CR3_MATCH		0x00000572
#define TOPA_STOP	BIT(4)
#define TOPA_INT	BIT(2)
#define TOPA_END	BIT(0)
#define TOPA_SIZE_SHIFT 6

static void restart(void);

static int resync_set(const char *val, const struct kernel_param *kp)
{
	int ret = param_set_int(val, kp);
	restart();
	return ret;
}

static struct kernel_param_ops resync_ops = {
	.set = resync_set,
	.get = param_get_int,
};

static DEFINE_PER_CPU(unsigned long, pt_buffer_cpu);
static DEFINE_PER_CPU(u64 *, topa_cpu);
static DEFINE_PER_CPU(bool, pt_running);
static DEFINE_PER_CPU(u64, pt_offset);
static int pt_error;
static bool initialized;

static int pt_buffer_order = 9;
module_param(pt_buffer_order, int, 0444);
MODULE_PARM_DESC(pt_buffer_order, "Order of PT buffer size per CPU (2^n pages)");
static int start = 0;
module_param_cb(start, &resync_ops, &start, 0644);
MODULE_PARM_DESC(start, "Set to 1 to start trace, or 0 to stop");
static int user = 1;
module_param_cb(user, &resync_ops, &user, 0644);
MODULE_PARM_DESC(user, "Set to 0 to not trace user space");
static int kernel = 1;
module_param_cb(kernel, &resync_ops, &kernel, 0644);
MODULE_PARM_DESC(kernel, "Set to 0 to not trace kernel space");
static int tsc_en = 1;
module_param_cb(tsc, &resync_ops, &tsc_en, 0644);
MODULE_PARM_DESC(tsc, "Set to 0 to not trace timing");
static char comm_filter[100];
module_param_string(comm_filter, comm_filter, sizeof(comm_filter), 0644);
MODULE_PARM_DESC(comm_filter, "Process names to set CR3 filter for");
static int cr3_filter = 0;
module_param_cb(cr3_filter, &resync_ops, &cr3_filter, 0644);
MODULE_PARM_DESC(cr3_filter, "Enable CR3 filter");
static int dis_retc = 0;
module_param_cb(dis_retc, &resync_ops, &dis_retc, 0644);
MODULE_PARM_DESC(dis_retc, "Disable return compression");

static u64 rtit_status(void)
{
	u64 status;
	if (rdmsrl_safe(MSR_IA32_RTIT_STATUS, &status) < 0)
		return 0;
	return status;
}

static int start_pt(void)
{
	u64 val;

	if (__get_cpu_var(pt_running))
		return 0;

	wrmsrl_safe(MSR_IA32_RTIT_OUTPUT_BASE, __pa(__get_cpu_var(topa_cpu)));
	wrmsrl_safe(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, 0ULL);

	if (rdmsrl_safe(MSR_IA32_RTIT_CTL, &val) < 0)
		return -1;
	val |= TRACE_EN | TO_PA;
	if (tsc_en)
		val |= TSC_EN;
	if (kernel)
		val |= CTL_OS;
	if (user)
		val |= CTL_USER;
	if (cr3_filter)
		val |= CR3_FILTER;
	if (dis_retc)
		val |= DIS_RETC;
	if (wrmsrl_safe(MSR_IA32_RTIT_CTL, val) < 0)
		return -1;
	__get_cpu_var(pt_running) = true;
	return 0;
}

static void do_start_pt(void *arg)
{
	int cpu = smp_processor_id();
	if (start_pt() < 0)
		pr_err("cpu %d, RTIT_CTL enable failed\n", cpu);
}

static void stop_pt(void *arg);

static void restart(void)
{
	static DEFINE_MUTEX(restart_mutex);

	if (!initialized)
		return;

	mutex_lock(&restart_mutex);
	on_each_cpu(start ? do_start_pt : stop_pt, NULL, 1);
	pr_info("restarted\n");
	mutex_unlock(&restart_mutex);
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
		pr_err("cpu %d, Cannot allocate %ld KB buffer\n", cpu,
				(PAGE_SIZE << pt_buffer_order) / 1024);
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

	if (start && start_pt() < 0) {
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


static int simple_pt_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long len = vma->vm_end - vma->vm_start;
	int cpu = (int)(long)file->private_data;

	if (len % PAGE_SIZE || len != (PAGE_SIZE << pt_buffer_order) || vma->vm_pgoff)
		return -EINVAL;

	if (vma->vm_flags & VM_WRITE)
		return -EPERM;

	if (!cpu_online(cpu))
		return -EIO;

	return remap_pfn_range(vma, vma->vm_start,
			       __pa(per_cpu(pt_buffer_cpu, cpu)) >> PAGE_SHIFT,
			       PAGE_SIZE << pt_buffer_order,
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
		on_each_cpu(stop_pt, NULL, 1);
		return 0;
	case SIMPLE_PT_GET_SIZE:
		return put_user(PAGE_SIZE << pt_buffer_order, (int *)arg);
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

static void free_all_buffers(void);

static void set_cr3_filter(void *arg)
{
	if (wrmsrl_safe(MSR_IA32_CR3_MATCH, *(u64 *)arg) < 0)
		pr_err("cpu %d, cannot set cr3 filter\n", smp_processor_id());
}

static void probe_sched_process_exec(void *arg,
				     struct task_struct *p, pid_t old_pid,
				     struct linux_binprm *bprm)
{
	u64 cr3;

	asm volatile("mov %%cr3,%0" : "=r" (cr3));
	trace_exec_cr3(cr3);

	if (comm_filter[0] == 0)
		return;
	if (!strcmp(current->comm, comm_filter)) {
		pr_debug("arming cr3 filter %llx for %s\n", cr3, current->comm);
		on_each_cpu(set_cr3_filter, &cr3, 1);
	}
}

static int simple_pt_cpu(struct notifier_block *nb, unsigned long action,
			 void *v)
{
	switch (action) {
	case CPU_STARTING:
		simple_pt_cpu_init(NULL);
		break;
	case CPU_DYING:
		stop_pt(NULL);
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block cpu_notifier = {
	.notifier_call = simple_pt_cpu,
};

static int simple_pt_init(void)
{
	unsigned a, b, c, d;
	int err;

	/* check cpuid */
	cpuid_count(0x07, 0, &a, &b, &c, &d);
	if ((b & BIT(25)) == 0) {
		pr_info("No PT support\n");
		return -EIO;
	}
	cpuid_count(0x14, 0, &a, &b, &c, &d);
	if (!(c & BIT(0))) {
		pr_info("No ToPA support\n");
		return -EIO;
	}

	err = misc_register(&simple_pt_miscdev);
	if (err < 0) {
		pr_err("Cannot register simple-pt device\n");
		return err;
	}

	get_online_cpus();
	on_each_cpu(simple_pt_cpu_init, NULL, 1);
	register_cpu_notifier(&cpu_notifier);
	put_online_cpus();
	if (pt_error) {
		pr_err("PT initialization failed\n");
		err = pt_error;
		goto out_buffers;
	}

	err = compat_register_trace_sched_process_exec(probe_sched_process_exec, NULL);
	if (err)
		pr_info("Cannot register exec tracepoint: %d\n", err);

	pr_info("%s with %ld KB buffer\n",
				start ? "running" : "loaded",
				(PAGE_SIZE << pt_buffer_order) / 1024);

	initialized = true;
	return 0;

out_buffers:
	free_all_buffers();
	misc_deregister(&simple_pt_miscdev);
	return err;
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
			(offset & 0xffffffff) >> (7 - 3),
			offset >> 32);
}

static void free_all_buffers(void)
{
	int cpu;

	unregister_cpu_notifier(&cpu_notifier);
	get_online_cpus();
	for_each_possible_cpu (cpu) {
		if (per_cpu(topa_cpu, cpu))
			free_page((unsigned long)per_cpu(topa_cpu, cpu));
		if (per_cpu(pt_buffer_cpu, cpu))
			free_pages(per_cpu(pt_buffer_cpu, cpu), pt_buffer_order);
	}
	put_online_cpus();
}

static void simple_pt_exit(void)
{
	on_each_cpu(stop_pt, NULL, 1);
	free_all_buffers();
	misc_deregister(&simple_pt_miscdev);
	compat_unregister_trace_sched_process_exec(probe_sched_process_exec, NULL);
	pr_info("exited\n");
}

module_init(simple_pt_init);
module_exit(simple_pt_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andi Kleen");
