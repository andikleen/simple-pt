/* Minimal Linux Intel Processor Trace driver. */

/*
 * Copyright (c) 2015, Intel Corporation
 * Author: Andi Kleen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Alternatively you can use this file under the GPLv2.
 */


/* Notebook:
   Auto probe largest buffer
   Test old kernels
   Test 32bit
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
#include <linux/nodemask.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/dcache.h>
#include <linux/ctype.h>
#include <linux/syscore_ops.h>
#include <trace/events/sched.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/processor-flags.h>
#define CREATE_TRACE_POINTS
#include "pttp.h"

#include "compat.h"
#include "simple-pt.h"

#define MSR_IA32_RTIT_OUTPUT_BASE	0x00000560
#define MSR_IA32_RTIT_OUTPUT_MASK_PTRS	0x00000561
#define MSR_IA32_RTIT_CTL		0x00000570
#define TRACE_EN	BIT_ULL(0)
#define CYC_EN		BIT_ULL(1)
#define CTL_OS		BIT_ULL(2)
#define CTL_USER	BIT_ULL(3)
#define PT_ERROR	BIT_ULL(4)
#define CR3_FILTER	BIT_ULL(7)
#define PWR_EVT_EN	BIT_ULL(4)
#define FUP_ON_PTW_EN	BIT_ULL(5)
#define TO_PA		BIT_ULL(8)
#define MTC_EN		BIT_ULL(9)
#define TSC_EN		BIT_ULL(10)
#define DIS_RETC	BIT_ULL(11)
#define PTW_EN		BIT_ULL(12)
#define BRANCH_EN	BIT_ULL(13)
#define MTC_MASK	(0xf << 14)
#define CYC_MASK	(0xf << 19)
#define PSB_MASK	(0xf << 24)
#define ADDR0_SHIFT	32
#define ADDR1_SHIFT	36
#define ADDR0_MASK	(0xfULL << ADDR0_SHIFT)
#define ADDR1_MASK	(0xfULL << ADDR1_SHIFT)
#define MSR_IA32_RTIT_STATUS		0x00000571
#define MSR_IA32_CR3_MATCH		0x00000572
#define TOPA_STOP	BIT_ULL(4)
#define TOPA_INT	BIT_ULL(2)
#define TOPA_END	BIT_ULL(0)
#define TOPA_SIZE_SHIFT 6
#define MSR_IA32_ADDR0_START		0x00000580
#define MSR_IA32_ADDR0_END		0x00000581
#define MSR_IA32_ADDR1_START		0x00000582
#define MSR_IA32_ADDR1_END		0x00000583

static bool delay_start;

static void restart(void);
static void stop_pt_all(void);

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

static int start_set(const char *val, const struct kernel_param *kp)
{
	int ret = resync_set(val, kp);
	delay_start = false;
	return ret;
}
static struct kernel_param_ops start_ops = {
	.set = start_set,
	.get = param_get_int,
};

static void do_enumerate_all(void);
static int enumerate_all;

static int enumerate_set(const char *val, const struct kernel_param *kp)
{
	int ret = param_set_int(val, kp);
	if (enumerate_all)
		do_enumerate_all();
	return ret;
}

static struct kernel_param_ops enumerate_ops = {
	.set = enumerate_set,
	.get = param_get_int,
};

static unsigned addr_range_num;

static int symbol_set(const char *val, const struct kernel_param *kp)
{
	int ret = -EIO;
	if (!isdigit(val[0])) {
		pr_err("Symbols are not supported anymore. Please resolve through /proc/kallsyms");
	} else {
		ret = param_set_ulong(val, kp);
	}
	return ret;
}

static int start = 0;

static int addr_set(const char *val, const struct kernel_param *kp)
{
	int ret;
	if (addr_range_num == 0)
		return -EINVAL;

	ret = symbol_set(val, kp);
	if (start)
		restart();
	return ret;
}

static struct kernel_param_ops addr_ops = {
	.set = addr_set,
	.get = param_get_ulong,
};

/* Protects start/stop_kprobe_set and the kprobes */

/* If you are porting this driver this kprobes related code is all
 * optional and can be removed.
 */
static DEFINE_MUTEX(kprobe_mutex);

static int probe_start(struct kprobe *kp, struct pt_regs *regs);
static int probe_stop(struct kprobe *kp, struct pt_regs *regs);

static struct kprobe start_kprobe = {
	.pre_handler = probe_start
};
static struct kprobe stop_kprobe = {
	.pre_handler = probe_stop
};

static int kprobe_set(const char *val, const struct kernel_param *kp,
		      struct kprobe *kprobe)
{
	int ret;
	unsigned long addr;
	char sym[128];

	if (!isdigit(val[0])) {
		int syml = strcspn(val, "+");
		if (syml >= sizeof(sym) - 1) {
			pr_err("Symbol too large %s\n", sym);
			return -EIO;
		}
		memcpy(sym, val, syml);
		sym[syml] = 0;
		kprobe->symbol_name = sym;
		if (val[syml] == '+')
			syml++;
		if (kstrtouint(val + syml, 0, &kprobe->offset) < 0) {
			pr_err("Invalid offset in %s\n", val);
			return -EIO;
		}
	}
	ret = symbol_set(val, kp);
	addr = *(unsigned long *)(kp->arg);
	mutex_lock(&kprobe_mutex);
	if (kprobe->addr) {
		unregister_kprobe(kprobe);
		kprobe->addr = NULL;
	}
	if (addr) {
		int (*handler)(struct kprobe *kp, struct pt_regs *regs);
		handler = kprobe->pre_handler;
		/* Linux doesn't like reusing an old kprobes structure.
		 * Always clear and reinitialize.
		 */
		memset(kprobe, 0, sizeof(struct kprobe));
		kprobe->addr = (kprobe_opcode_t *)addr;
		kprobe->pre_handler = handler;
		ret = register_kprobe(kprobe);
		if (ret)
			pr_err("registering kprobe failed\n");
	}
	mutex_unlock(&kprobe_mutex);

	return ret;
}

static int trace_start_set(const char *val, const struct kernel_param *kp)
{
	int ret = kprobe_set(val, kp, &start_kprobe);
	if (start_kprobe.addr)
		delay_start = true;
	return ret;
}

static int trace_stop_set(const char *val, const struct kernel_param *kp)
{
	return kprobe_set(val, kp, &stop_kprobe);
}

static struct kernel_param_ops trace_start_ops = {
	.set = trace_start_set,
	.get = param_get_ulong,
};

static struct kernel_param_ops trace_stop_ops = {
	.set = trace_stop_set,
	.get = param_get_ulong,
};

/* Support for Linux panic dumps (optional) */

static int pt_num_buffers = 1;
static int log_dump = 0;
static void print_last_branches(int num_psbs);

static int log_dump_set(const char *val, const struct kernel_param *kp)
{
	int ret = param_set_int(val, kp);
	if (start && log_dump && pt_num_buffers == 1) {
		stop_pt_all();
		print_last_branches(log_dump);
	}
	return ret;
}

static struct kernel_param_ops log_dump_ops = {
	.set = log_dump_set,
	.get = param_get_ulong,
};

/* End of optional code */

static DEFINE_PER_CPU(unsigned long, pt_buffer_cpu);
static DEFINE_PER_CPU(u64 *, topa_cpu);
static DEFINE_PER_CPU(bool, pt_running);
static DEFINE_PER_CPU(u64, pt_offset);
static bool initialized;
static bool has_cr3_match;
static bool has_ptw;
static bool has_pwr_evt;
static unsigned psb_freq_mask;
static unsigned cyc_thresh_mask;
static unsigned mtc_freq_mask;
static unsigned addr_cfg_max;

static bool disable_branch;
module_param(disable_branch, bool, 0644);
MODULE_PARM_DESC(disable_branch, "Don't enable branch tracing (if supported)");
static int pt_buffer_order = 9;
module_param(pt_buffer_order, int, 0444);
MODULE_PARM_DESC(pt_buffer_order, "Order of PT buffer size per CPU (2^n pages)");
module_param(pt_num_buffers, int, 0444);
MODULE_PARM_DESC(pt_num_buffers, "Number of PT buffers per CPU (if supported)");
module_param_cb(start, &start_ops, &start, 0644);
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
MODULE_PARM_DESC(comm_filter, "Process name to set CR3 filter for");
static int cr3_filter = 0;
module_param_cb(cr3_filter, &resync_ops, &cr3_filter, 0644);
MODULE_PARM_DESC(cr3_filter, "Enable CR3 filter");
static int dis_retc = 0;
module_param_cb(dis_retc, &resync_ops, &dis_retc, 0644);
MODULE_PARM_DESC(dis_retc, "Disable return compression");
static int ptw = 0;
module_param_cb(ptw, &resync_ops, &ptw, 0644);
MODULE_PARM_DESC(ptw, "Enable PTWRITE (if supported)");
static int fup_on_ptw = 0;
module_param_cb(fup_on_ptw, &resync_ops, &fup_on_ptw, 0644);
MODULE_PARM_DESC(fup_on_ptw, "Report IP on each PTWRITE (with ptw=1)");
static int pwr_evt = 0;
module_param_cb(pwr_evt, &resync_ops, &pwr_evt, 0644);
MODULE_PARM_DESC(pwr_evt, "Enable power tracing (if supported)");
static bool clear_on_start = true;
module_param(clear_on_start, bool, 0644);
MODULE_PARM_DESC(clear_on_start, "Clear PT buffer before start");
static bool single_range = false;
module_param(single_range, bool, 0444);
MODULE_PARM_DESC(single_range, "Use single range output");
static int num_sro_bases;
static unsigned long sro_bases[1<<NODES_SHIFT];
module_param_array(sro_bases, ulong, &num_sro_bases, 0444);
MODULE_PARM_DESC(sro_bases, "physical addresses of SRO buffers");
static int enumerate_all = 0;
module_param_cb(enumerate_all, &enumerate_ops, &enumerate_all, 0644);
MODULE_PARM_DESC(enumerate_all, "Enumerate all processes CR3s (only use after initialization)");
static int cyc_thresh = 0;
module_param_cb(cyc_thresh, &resync_ops, &cyc_thresh, 0644);
MODULE_PARM_DESC(cyc_thresh, "Send cycle packets at every 2^(n-1) cycles (if supported)");
static int mtc_freq = 0;
module_param_cb(mtc_freq, &resync_ops, &mtc_freq, 0644);
MODULE_PARM_DESC(mtc_freq, "Enable MTC packets at frequency 2^(n-1) (if supported)");
static int psb_freq = 0;
module_param_cb(psb_freq, &resync_ops, &psb_freq, 0644);
MODULE_PARM_DESC(psb_freq, "Send PSB packets every 2K^n bytes (if supported)");
static u64 addr0_start;
module_param_cb(addr0_start, &addr_ops, &addr0_start, 0644);
MODULE_PARM_DESC(addr0_start, "Virtual start address of address range 0. Hex or kernel symbol+offset");
static u64 addr0_end;
module_param_cb(addr0_end, &addr_ops, &addr0_end, 0644);
MODULE_PARM_DESC(addr0_end, "Virtual end address of address range 0. Hex or kernel symbol+offset");
static unsigned addr0_cfg;
module_param_cb(addr0_cfg, &resync_ops, &addr0_cfg, 0644);
MODULE_PARM_DESC(addr0_end, "Mode of address range 0: 0 = off, 1 = filter, 2 = trace-stop (if supported)");
static u64 addr1_start;
module_param_cb(addr1_start, &addr_ops, &addr1_start, 0644);
MODULE_PARM_DESC(addr1_start, "Virtual start address of address range 1. Hex or kernel symbol+offset");
static u64 addr1_end;
module_param_cb(addr1_end, &addr_ops, &addr1_end, 0644);
MODULE_PARM_DESC(addr1_end, "Virtual end address of address range 1. Hex or kernel symbol+offset");
static unsigned addr1_cfg;
module_param_cb(addr1_cfg, &resync_ops, &addr1_cfg, 0644);
MODULE_PARM_DESC(addr1_end, "Mode of address range 1: 0 = off, 1 = filter, 2 = trace-stop (if supported)");
static unsigned long trace_stop;
module_param_cb(trace_stop, &trace_stop_ops, &trace_stop, 0644);
MODULE_PARM_DESC(trace_stop, "Stop trace when reaching kernel address. Can be kernel symbol+offset or 0 to disable");
static unsigned long trace_start;
module_param_cb(trace_start, &trace_start_ops, &trace_start, 0644);
MODULE_PARM_DESC(trace_start, "Start trace when reaching kernel address. Can be kernel symbol+offset or 0 to disable");
static bool force = false;
module_param(force, bool, 0644);
MODULE_PARM_DESC(force, "Force PT initialization even when already active");
static unsigned long tasklist_lock_ptr;
module_param(tasklist_lock_ptr, ulong, 0400);
MODULE_PARM_DESC(tasklist_lock_ptr, "Set address of tasklist_lock (for kernels without CONFIG_KALLSYMS_ALL)");
static int print_panic_psbs = 0;
module_param(print_panic_psbs, int, 0644);
MODULE_PARM_DESC(print_panic_psbs, "Print as many PSBs from PT log into kernel log on panic");
module_param_cb(log_dump, &log_dump_ops, &log_dump, 0644);

static DEFINE_MUTEX(restart_mutex);

static atomic_long_t sro_bases_curr[1<<NODES_SHIFT];

static inline int pt_wrmsrl_safe(unsigned msr, u64 val)
{
	int ret = wrmsrl_safe(msr, val);
	trace_msr(msr, val, ret != 0, 0);
	return ret;
}

static inline int pt_rdmsrl_safe(unsigned msr, u64 *val)
{
	int ret = rdmsrl_safe(msr, val);
	trace_msr(msr, *val, ret != 0, 1);
	return ret;
}

static void init_mask_ptrs(void)
{
	if (single_range)
		pt_wrmsrl_safe(MSR_IA32_RTIT_OUTPUT_MASK_PTRS,
			((1ULL << (PAGE_SHIFT + pt_buffer_order)) - 1));
	else
		pt_wrmsrl_safe(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, 0ULL);
}

// https://carteryagemann.com/pid-to-cr3.html
static u64 pid_to_cr3(int const pid)
{
	unsigned long cr3_phys = 0;
	rcu_read_lock();
	{
		struct pid *pidp = find_vpid(pid);
		struct task_struct * task;
		struct mm_struct *mm;

		if (!pidp)
			goto out;
		task = pid_task(pidp, PIDTYPE_PID);
		if (task == NULL)
			goto out; // pid has no task_struct
		mm = task->mm;

		// mm can be NULL in some rare cases (e.g. kthreads)
		// when this happens, we should check active_mm
		if (mm == NULL) {
			mm = task->active_mm;
			if (mm == NULL)
				goto out; // this shouldn't happen, but just in case
		}

		cr3_phys = virt_to_phys((void*)mm->pgd);
	}
out:
	rcu_read_unlock();
	return cr3_phys;
}

static inline void set_cr3_filter0(u64 cr3)
{
	if(pt_wrmsrl_safe(MSR_IA32_CR3_MATCH, cr3) < 0)
		pr_err("cpu %d, cannot set CR3 filter\n", smp_processor_id());
}

static int start_pt(void)
{
	u64 val, oldval;

	if (pt_rdmsrl_safe(MSR_IA32_RTIT_CTL, &val) < 0)
		return -1;

	oldval = val;
	/* Disable trace for reconfiguration */
	if (val & TRACE_EN)
		pt_wrmsrl_safe(MSR_IA32_RTIT_CTL, val & ~TRACE_EN);

	if (clear_on_start && !(val & TRACE_EN)) {
		memset((void *)__this_cpu_read(pt_buffer_cpu), 0, PAGE_SIZE << pt_buffer_order);
		init_mask_ptrs();
		pt_wrmsrl_safe(MSR_IA32_RTIT_STATUS, 0ULL);
	}

	val &= ~(TSC_EN | CTL_OS | CTL_USER | CR3_FILTER | DIS_RETC | TO_PA |
		 CYC_EN | TRACE_EN | BRANCH_EN | CYC_EN | MTC_EN |
		 MTC_EN | MTC_MASK | CYC_MASK | PSB_MASK | ADDR0_MASK | ADDR1_MASK);
	/* Otherwise wait for start trigger */
	if (!delay_start)
		val |= TRACE_EN;
	if (!disable_branch)
		val |= BRANCH_EN;
	if (!single_range)
		val |= TO_PA;
	if (tsc_en)
		val |= TSC_EN;
	if (kernel)
		val |= CTL_OS;
	if (user)
		val |= CTL_USER;
	if (cr3_filter && has_cr3_match) {
		if(cr3_filter > 1) {
			u64 cr3 = pid_to_cr3(cr3_filter) & ~CR3_PCID_MASK;
#ifdef CONFIG_PAGE_TABLE_ISOLATION
			if (IS_ENABLED(CONFIG_PAGE_TABLE_ISOLATION) && static_cpu_has(X86_FEATURE_PTI)) {
				if(user) {
					cr3 |= 1 << PAGE_SHIFT;
					if(kernel) {
						pr_warn("Cannot trace kernel along with user space using CR3 filter in PTI-enabled kernel.\n");
					}
				}
			}
#endif
			set_cr3_filter0(cr3);
			comm_filter[0] = '\0';	// Do not re-target on exec()
		} else if(!(oldval & CR3_FILTER)) {
			set_cr3_filter0(0ULL);
		}
		val |= CR3_FILTER;
	}
	if (dis_retc)
		val |= DIS_RETC;
	if (cyc_thresh && ((1U << (cyc_thresh-1)) & cyc_thresh_mask))
		val |= ((cyc_thresh - 1) << 19) | CYC_EN;
	if (mtc_freq && ((1U << (mtc_freq-1)) & mtc_freq_mask))
		val |= ((mtc_freq - 1) << 14) | MTC_EN;
	if (psb_freq && ((1U << (psb_freq-1)) & psb_freq_mask))
		val |= (psb_freq - 1) << 24;
	if (ptw && has_ptw) {
		val |= PTW_EN;
		if (fup_on_ptw)
			val |= FUP_ON_PTW_EN;
	}
	if (pwr_evt && has_pwr_evt)
		val |= PWR_EVT_EN;
	if (addr0_cfg && (addr0_cfg <= addr_cfg_max) && addr_range_num >= 1) {
		val |= ((u64)addr0_cfg << ADDR0_SHIFT);
		pt_wrmsrl_safe(MSR_IA32_ADDR0_START, addr0_start);
		pt_wrmsrl_safe(MSR_IA32_ADDR0_END, addr0_end);
	}
	if (addr1_cfg && (addr1_cfg <= addr_cfg_max) && addr_range_num >= 2) {
		val |= ((u64)addr1_cfg << ADDR1_SHIFT);
		pt_wrmsrl_safe(MSR_IA32_ADDR1_START, addr1_start);
		pt_wrmsrl_safe(MSR_IA32_ADDR1_END, addr1_end);
	}

	if (pt_wrmsrl_safe(MSR_IA32_RTIT_CTL, val) < 0)
		return -1;
	__this_cpu_write(pt_running, true);
	return 0;
}

static void do_start_pt(void *arg)
{
	int cpu = smp_processor_id();
	if (start_pt() < 0)
		pr_err("cpu %d, RTIT_CTL enable failed\n", cpu);
}

static void stop_pt(void *arg)
{
	u64 offset;
	u64 ctl, status, extra;

	if (!__this_cpu_read(pt_running))
		return;
	pt_rdmsrl_safe(MSR_IA32_RTIT_CTL, &ctl);
	pt_rdmsrl_safe(MSR_IA32_RTIT_STATUS, &status);
	if (!(ctl & TRACE_EN))
		pr_debug("cpu %d, trace was not enabled on stop, ctl %llx, status %llx\n",
				raw_smp_processor_id(), ctl, status);
	if (status & PT_ERROR) {
		pr_info("cpu %d, error happened: status %llx\n",
				raw_smp_processor_id(), status);
		pt_wrmsrl_safe(MSR_IA32_RTIT_STATUS, 0);
	}
	pt_wrmsrl_safe(MSR_IA32_RTIT_CTL, 0LL);
	pt_rdmsrl_safe(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, &offset);
	extra = 0;
	if (!single_range)
		extra = ((offset & 0xffffffff) >> 7) <<
			(pt_buffer_order + PAGE_SHIFT);
	__this_cpu_write(pt_offset, (offset >> 32) + extra);
	__this_cpu_write(pt_running, false);
}

static void stop_pt_all(void)
{
	mutex_lock(&restart_mutex);
	on_each_cpu(stop_pt, NULL, 1);
	start = 0;
	mutex_unlock(&restart_mutex);
}

static void restart(void)
{
	if (!initialized)
		return;

	mutex_lock(&restart_mutex);
	on_each_cpu(start ? do_start_pt : stop_pt, NULL, 1);
	mutex_unlock(&restart_mutex);
}

static int probe_start(struct kprobe *kp, struct pt_regs *regs)
{
	if (__this_cpu_read(pt_running)) {
		u64 val;
		pt_rdmsrl_safe(MSR_IA32_RTIT_CTL, &val);
		val |= TRACE_EN;
		pt_wrmsrl_safe(MSR_IA32_RTIT_CTL, val);
	}
	return 0;
}

static int probe_stop(struct kprobe *kp, struct pt_regs *regs)
{
	if (__this_cpu_read(pt_running)) {
		u64 val;
		pt_rdmsrl_safe(MSR_IA32_RTIT_CTL, &val);
		val &= ~TRACE_EN;
		pt_wrmsrl_safe(MSR_IA32_RTIT_CTL, val);
	}
	return 0;
}

/* Log CR3 of all already running processes. */
static void do_enumerate_all(void)
{
	struct task_struct *t;
	rwlock_t *my_tasklist_lock = (rwlock_t *)tasklist_lock_ptr;
	if (!my_tasklist_lock) {
		pr_err("Specify tasklist_lock_ptr parameter at load to support enumeration of running processes\n");
		return;
	}

	read_lock(my_tasklist_lock);
	for_each_process (t) {
		if ((t->flags & PF_KTHREAD) || !t->mm)
			continue;
		/* Cannot get the file name here, leave that to user space */
		trace_process_cr3(t->pid, __pa(t->mm->pgd), t->comm);
	}
	read_unlock(my_tasklist_lock);
}

static void simple_pt_init_msrs(void)
{
	if (!single_range) {
		u64 *topa;
		topa = __this_cpu_read(topa_cpu);
		pt_wrmsrl_safe(MSR_IA32_RTIT_OUTPUT_BASE, __pa(topa));
	} else {
		unsigned long pt_buffer;
		pt_buffer = __this_cpu_read(pt_buffer_cpu);
		pt_wrmsrl_safe(MSR_IA32_RTIT_OUTPUT_BASE, __pa(pt_buffer));
	}
	init_mask_ptrs();
	pt_wrmsrl_safe(MSR_IA32_RTIT_STATUS, 0ULL);
}

static int simple_pt_buffer_init(int cpu)
{
	unsigned long pt_buffer;
	u64 *topa;
	int node;

	/* allocate buffer */
	pt_buffer = per_cpu(pt_buffer_cpu, cpu);
	if (!pt_buffer) {
		if (num_sro_bases) {
			node = cpu_to_node(cpu);
			pt_buffer = (long)__va(atomic_long_add_return(
					1UL << pt_buffer_order,
					&sro_bases_curr[node]) << PAGE_SHIFT);
		} else {
			pt_buffer = __get_free_pages(GFP_KERNEL|__GFP_NOWARN|__GFP_ZERO, pt_buffer_order);
			if (!pt_buffer) {
				pr_err("cpu %d, Cannot allocate %ld KB buffer\n", cpu,
						(PAGE_SIZE << pt_buffer_order) / 1024);
				return -ENOMEM;
			}
		}
		per_cpu(pt_buffer_cpu, cpu) = pt_buffer;
	}

	if (!single_range) {
		/* allocate topa */
		topa = per_cpu(topa_cpu, cpu);
		if (!topa) {
			int n;

			topa = (u64 *)__get_free_page(GFP_KERNEL|__GFP_ZERO);
			if (!topa) {
				pr_err("cpu %d, Cannot allocate topa page\n", cpu);
				goto out_pt_buffer;
			}
			per_cpu(topa_cpu, cpu) = topa;

			/* create circular topa table */
			n = 0;
			topa[n++] = (u64)__pa(pt_buffer) |
				(pt_buffer_order << TOPA_SIZE_SHIFT);
			for (; n < pt_num_buffers; n++) {
				void *buf = (void *)__get_free_pages(
					GFP_KERNEL|__GFP_NOWARN|__GFP_ZERO,
					pt_buffer_order);
				if (!buf) {
					pr_warn("Cannot allocate %d'th PT buffer\n", n);
					break;
				}
				topa[n] = __pa(buf) |
					(pt_buffer_order << TOPA_SIZE_SHIFT);
			}
			topa[n] = (u64)__pa(topa) | TOPA_END; /* circular buffer */
		}
	}
	return 0;

out_pt_buffer:
	free_pages(pt_buffer, pt_buffer_order);
	per_cpu(pt_buffer_cpu, cpu) = 0;
	return -ENOMEM;
}

static unsigned topa_entries(int cpu)
{
	u64 *topa = per_cpu(topa_cpu, cpu);
	int n;

	if (single_range)
		return 1;
	if (!topa)
		return 0;
	for (n = 0; !(topa[n] & TOPA_END); n++)
		;
	return n;
}

static int simple_pt_cpu_init(void *arg)
{
	int cpu = smp_processor_id();
	u64 ctl;

	/* check for pt already active */
	if (pt_rdmsrl_safe(MSR_IA32_RTIT_CTL, &ctl) < 0) {
		pr_err("cpu %d, Cannot access RTIT_CTL\n", cpu);
		return -EIO;
	}

	if (ctl & TRACE_EN) {
		if (!force) {
			pr_err("cpu %d, PT already active: %llx\n", cpu, ctl);
			return -EBUSY;
		}
		pr_info("forcibly taking over PT on %d: %llx\n", cpu, ctl);
	}

	simple_pt_init_msrs();
	return 0;
}

static inline int file_get_cpu(struct file *file)
{
	return (long)file->private_data;
}

static int simple_pt_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long len = vma->vm_end - vma->vm_start;
	int cpu = file_get_cpu(file);
	unsigned num = topa_entries(cpu);
	int i, err;
	u64 *topa;
	unsigned long buffer_size = PAGE_SIZE << pt_buffer_order;

	vma->vm_flags &= ~VM_MAYWRITE;

	if (len % PAGE_SIZE || len != num * buffer_size || vma->vm_pgoff)
		return -EINVAL;

	if (vma->vm_flags & VM_WRITE)
		return -EPERM;

	if (!cpu_online(cpu))
		return -EIO;

	if (num <= 1) {
		return remap_pfn_range(vma, vma->vm_start,
			       __pa(per_cpu(pt_buffer_cpu, cpu)) >> PAGE_SHIFT,
			       buffer_size,
			       vma->vm_page_prot);
	}
	topa = per_cpu(topa_cpu, cpu);
	err = 0;
	for (i = 0; i < num; i++) {
		err = remap_pfn_range(vma,
				vma->vm_start + i*buffer_size,
				topa[i] >> PAGE_SHIFT,
				buffer_size,
				vma->vm_page_prot);
		if (err)
			break;
	}
	return err;
}

static long simple_pt_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	switch (cmd) {
	case SIMPLE_PT_SET_CPU: {
		unsigned long cpu = arg;
		if (cpu >= NR_CPUS || !cpu_online(cpu))
			return -EINVAL;
		file->private_data = (void *)cpu;
		return 0;
	}
	case SIMPLE_PT_GET_SIZE: {
		int num = topa_entries(file_get_cpu(file));
		return put_user(num * (PAGE_SIZE << pt_buffer_order),
				(int *)arg);
	}
	case SIMPLE_PT_GET_OFFSET: {
		unsigned offset;
		int ret = 0;
		mutex_lock(&restart_mutex);
		if (per_cpu(pt_running, file_get_cpu(file)))
			ret = -EIO;
		else
			offset = per_cpu(pt_offset, file_get_cpu(file));
		mutex_unlock(&restart_mutex);
		if (!ret)
			ret = put_user(offset, (int *)arg);
		return ret;
	}
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

static void set_cr3_filter(void *arg)
{
	u64 val;

	if (pt_rdmsrl_safe(MSR_IA32_RTIT_CTL, &val) < 0)
		return;
	if ((val & TRACE_EN) && pt_wrmsrl_safe(MSR_IA32_RTIT_CTL, val & ~TRACE_EN) < 0)
		return;
	set_cr3_filter0(*(u64*)arg);
	if ((val & TRACE_EN) && pt_wrmsrl_safe(MSR_IA32_RTIT_CTL, val) < 0)
		return;
}

static bool match_comm(void)
{
	char *s;

	s = strchr(comm_filter, '\n');
	if (s)
		*s = 0;
	if (comm_filter[0] == 0)
		return true;
	return !strcmp(current->comm, comm_filter);
}

static u64 retrieve_cr3(void)
{
	u64 cr3;

	asm volatile("mov %%cr3,%0" : "=r" (cr3));
	return cr3 & ~0xfff; // mask out the PCID
}

static int probe_exec(struct kprobe *kp, struct pt_regs *regs)
{
	u64 cr3;
	char *pathbuf, *path;

	if (!match_comm())
		return 0;

	pathbuf = (char *)__get_free_page(GFP_KERNEL);
	if (!pathbuf)
		return 0;

	/* mmap_sem needed? */
	path = d_path(&current->mm->exe_file->f_path, pathbuf, PAGE_SIZE);
	if (IS_ERR(path))
		goto out;

	cr3 = retrieve_cr3();
	trace_exec_cr3(cr3, path, current->pid);
	if (comm_filter[0] && has_cr3_match) {
		mutex_lock(&restart_mutex);
		on_each_cpu(set_cr3_filter, &cr3, 1);
		mutex_unlock(&restart_mutex);
	}
out:
	free_page((unsigned long)pathbuf);
	return 0;
}

static int probe_mmap_region(struct kprobe *kp, struct pt_regs *regs)
{
#ifdef CONFIG_X86_64
	struct file *file = (struct file *)regs->di;
	unsigned long addr = regs->si;
	unsigned long len = regs->dx;
	unsigned long vm_flags = regs->cx;
	unsigned long pgoff = regs->r8;
#else
	/* Assume regparm(3) */
	struct file *file = (struct file *)regs->ax;
	unsigned long addr = regs->dx;
	unsigned long len = regs->cx;
	unsigned long vm_flags = ((u32 *)(regs->sp))[1];
	unsigned long pgoff = ((u32 *)(regs->sp))[2];
#endif
	char *pathbuf, *path;

	if (!(vm_flags & VM_EXEC) || !file)
		return 0;

	if (!match_comm())
		return 0;

	pathbuf = (char *)__get_free_page(GFP_ATOMIC);
	if (!pathbuf)
		return 0;

	path = d_path(&file->f_path, pathbuf, PAGE_SIZE);
	if (IS_ERR(path))
		goto out;

	trace_mmap_cr3(retrieve_cr3(), path, pgoff, addr, len,
		       current->pid);
out:
	free_page((unsigned long)pathbuf);
	return 0;
}

static struct kprobe mmap_kp = {
	.symbol_name = "mmap_region",
	.pre_handler = probe_mmap_region,
};

/* Arbitrary symbol in the exec*() path that is called after the new mm/CR3 is set up */
static struct kprobe finalize_exec_kp = {
	.symbol_name = "finalize_exec",
	.pre_handler = probe_exec,
};

static bool is_psb(void *p)
{
	return *(u64 *)p == 0x8202820282028202ULL && ((u64 *)p)[1] == 0x8202820282028202ULL;
}

static const char base64[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define LINELEN 75

static void print_base64(char *start, char *end)
{
	char line[LINELEN + 1];
	char *o = line;

	while (start < end) {
		unsigned b;

		*o++ = base64[(start[0] & 0xfc) >> 2];
		b = (start[0] & 3) << 4;
		if (start + 1 < end) {
			b |= (start[1] & 0xf0) >> 4;
			*o++ = base64[b];
			b = (start[1] & 0xf) << 2;
			if (start + 2 < end) {
				b |= (start[2] & 0xc0) >> 6;
				*o++ = base64[b];
				b = start[2] & 0x3f;
				*o++ = base64[b];
			} else {
				*o++ = base64[b];
				*o++ = '=';
			}
		} else {
			*o++ = base64[b];
			*o++ = '=';
			*o++ = '=';
		}
		if (o - line >= LINELEN) {
			*o = 0;
			printk("%s\n", line);
			o = line;
		}
		start += 3;
	}
	if (o > line) {
		*o = 0;
		printk("%s\n", line);
	}
}

/*
 * This should rather go into pstore, but pstore doesn't support
 * writing from modules currently, so we just write it to the
 * kernel log.
 */
static void print_last_branches(int num_psbs)
{
	u64 offset = __this_cpu_read(pt_offset);
	char *base = (char *)__this_cpu_read(pt_buffer_cpu);
	u64 end;

	end = offset;
	if (offset <= 16)
		return;
	offset -= 16;
	printk(KERN_INFO "PT DUMP START OFF %llx CPU %d BUF %p\n", offset,
			raw_smp_processor_id(), base);
	for (;;) {
		if (is_psb(base + offset) &&
			--num_psbs <= 0)
			break;
		if (offset == 0)
			break;
		offset--;
	}
	print_base64(base + offset, base + end);
	printk(KERN_INFO "PT DUMP END %llx\n", offset);
}

/* Stop PT on all CPUs so that a crash dump has a good log */
static int simple_pt_panic(struct notifier_block *nb, unsigned long action,
			   void *v)
{
	/* Assumes the interrupts are still on. Should send a NMI?
	 * We don't wait to avoid any deadlocks.
	 * Could also only stop on the current CPU.
	 */
	if (!start)
		return NOTIFY_OK;
	on_each_cpu(stop_pt, NULL, 0);
	if (print_panic_psbs && pt_num_buffers == 1)
		print_last_branches(print_panic_psbs);
	return NOTIFY_OK;
}

static struct notifier_block panic_notifier = {
	.notifier_call = simple_pt_panic,
};

/* No tracing over suspend for now. */

static int simple_pt_suspend(void)
{
	stop_pt(NULL);
	start = 0;
	return 0;
}

static void simple_pt_resume(void)
{
	simple_pt_cpu_init(NULL);
}

static struct syscore_ops simple_pt_syscore = {
	.suspend = simple_pt_suspend,
	.resume = simple_pt_resume,
};

static int simple_pt_cpuid(void)
{
	unsigned a, b, c, d;
	unsigned a1, b1, c1, d1;

	cpuid(0, &a, &b, &c, &d);
	if (a < 0x14) {
		pr_info("Not enough CPUID support for PT\n");
		return -EIO;
	}
	cpuid_count(0x07, 0, &a, &b, &c, &d);
	if ((b & BIT(25)) == 0) {
		pr_info("No PT support\n");
		return -EIO;
	}
	cpuid_count(0x14, 0, &a, &b, &c, &d);
	if (!single_range && !(c & BIT(0))) {
		pr_info("No ToPA support\n");
		return -EIO;
	}
	has_cr3_match = !!(b & BIT(0));
	has_ptw = !!(b & BIT(4));
	has_pwr_evt = !!(b & BIT(5));
	if (b & BIT(2))
		addr_cfg_max = 2;
	if (!(c & BIT(1)))
		pt_num_buffers = 1;
	pt_num_buffers = min_t(unsigned, pt_num_buffers,
			       (PAGE_SIZE / 8) - 1);
	a1 = b1 = c1 = d1 = 0;
	if (a >= 1)
		cpuid_count(0x14, 1, &a1, &b1, &c1, &d1);
	if (b & BIT(1)) {
		mtc_freq_mask = (a1 >> 16) & 0xffff;
		cyc_thresh_mask = b1 & 0xffff;
		psb_freq_mask = (b1 >> 16) & 0xffff;
		addr_range_num = a1 & 0x3;
	}
	return 0;
}

static int spt_hotplug_state = -1;

static void free_topa(u64 *topa)
{
	int j;

	for (j = 1; j < pt_num_buffers; j++) {
		if (topa[j] & TOPA_END)
			break;
		free_pages((unsigned long)__va(topa[j] & PAGE_MASK),
				pt_buffer_order);
	}
}

static int spt_cpu_startup(unsigned int cpu)
{
	int err;
	err = simple_pt_buffer_init(cpu);
	if (err)
		return err;
	return simple_pt_cpu_init(NULL);
}

static int spt_cpu_teardown(unsigned int cpu)
{
	stop_pt(NULL);
	if (per_cpu(topa_cpu, cpu)) {
		u64 *topa = per_cpu(topa_cpu, cpu);
		free_topa(topa);
		free_page((unsigned long)topa);
		per_cpu(topa_cpu, cpu) = NULL;
	}
	if (per_cpu(pt_buffer_cpu, cpu) && !num_sro_bases) {
		/*
		 * With SRO Bases specified, keep existing pt_buffer_cpu,
		 * as it's considered constant for the life time of
		 * the module, not the life time of the CPU.
		 */
		free_pages(per_cpu(pt_buffer_cpu, cpu), pt_buffer_order);
		per_cpu(pt_buffer_cpu, cpu) = 0;
	}
	return 0;
}

static int simple_pt_init(void)
{
	int err, i;

	if (THIS_MODULE->taints)
		fix_tracepoints();

	err = simple_pt_cpuid();
	if (err < 0)
		return err;

	err = misc_register(&simple_pt_miscdev);
	if (err < 0) {
		pr_err("Cannot register simple-pt device\n");
		return err;
	}

	if (!single_range)
		num_sro_bases = 0;
	else if (num_sro_bases) {
		if (num_sro_bases != num_possible_nodes()) {
			pr_err("sro_bases should be provided for %u nodes",
					num_possible_nodes());
			err = -EINVAL;
			goto out_buffers;
		}
		for (i = 0; i != num_sro_bases; ++i) {
			if (sro_bases[i] & ((1UL << pt_buffer_order) - 1)) {
				pr_err("sro_bases must be aligned to 2^pt_buffer_order");
				err = -EINVAL;
				goto out_buffers;
			}
			atomic_long_set(&sro_bases_curr[i],
					sro_bases[i] - (1UL << pt_buffer_order));
		}
	}
	err = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "simple-pt",
				       spt_cpu_startup,
				       spt_cpu_teardown);
	if (err < 0)
		goto out_buffers;
	spt_hotplug_state = err;

	/* Trace exec->cr3 */
	/* This used to use the sched_exec trace point, but Linux doesn't
	 * export trace points anymore.
	 */
	err = register_kprobe(&finalize_exec_kp);
	if (err) {
		pr_info("Cannot register exec kprobe on finalize_exec: %d\n", err);
		/* Ignore error */
	}

	/* Trace mmap */
	err = register_kprobe(&mmap_kp);
	if (err < 0) {
		pr_err("registering mmap_region kprobe failed: %d\n", err);
		/* Ignore error */
	}

	/* Optional code */
	atomic_notifier_chain_register(&panic_notifier_list, &panic_notifier);

	/* Optional suspend/resume hooks. */
	register_syscore_ops(&simple_pt_syscore);

	initialized = true;
	if (start)
		restart();

	pr_info("%s\n", start ? "running" : "loaded");
	return 0;

out_buffers:
	misc_deregister(&simple_pt_miscdev);
	return err;
}

static void simple_pt_exit(void)
{
	if (start_kprobe.addr)
		unregister_kprobe(&start_kprobe);
	if (stop_kprobe.addr)
		unregister_kprobe(&stop_kprobe);
	if (spt_hotplug_state >= 0)
		cpuhp_remove_state(spt_hotplug_state);
	misc_deregister(&simple_pt_miscdev);
	unregister_kprobe(&finalize_exec_kp);
	unregister_kprobe(&mmap_kp);
	atomic_notifier_chain_unregister(&panic_notifier_list, &panic_notifier);
	unregister_syscore_ops(&simple_pt_syscore);
	pr_info("exited\n");
}

module_init(simple_pt_init);
module_exit(simple_pt_exit);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Andi Kleen");
