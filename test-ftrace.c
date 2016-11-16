/*
 * Tester for ftrace. ftrace from modules appears to be broken in
 * various older kernels.  This kernel module allows testing it
 * without using a PT capable system.
 *
 * Cannot be loaded at the same time as simple-pt.ko
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#define CREATE_TRACE_POINTS
#include "pttp.h"
#include "compat.h"

static int trace_set(const char *val, const struct kernel_param *kp)
{
	trace_msr(0x123, 0xdeadbeef, 1, 1);
	trace_process_cr3(123, 0x12345678, "foo");
	trace_exec_cr3(0xdeadbeef, "bar", 789);
	trace_mmap_cr3(0xdeadbeef, "bar", 1, 2, 4096, 789);
	return 0;
}

static struct kernel_param_ops trace_ops = {
	.set = trace_set,
	.get = param_get_int,
};

static int trace;
module_param_cb(trace, &trace_ops, &trace, 0644);

static int test_ftrace_init(void)
{
	if (THIS_MODULE->taints)
		fix_tracepoints();
	pr_info("test-ftrace loaded\n");
	return 0;
}

static void test_ftrace_exit(void)
{
	pr_info("test-ftrace unloaded\n");
}

module_init(test_ftrace_init);
module_exit(test_ftrace_exit);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Andi Kleen");
