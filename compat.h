
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
static struct tracepoint *exec_tp;

static int compat_register_trace_sched_process_exec(void (*probe)(void *, struct task_struct *, pid_t, struct linux_binprm *),
						void *arg)
{
	/* Workaround for newer kernels which use non exported symbols */
	exec_tp = (struct tracepoint *)kallsyms_lookup_name("__tracepoint_sched_process_exec");
	if (!exec_tp)
		return -EIO;
	return tracepoint_probe_register(exec_tp, (void *)probe, NULL);
}

static void compat_unregister_trace_sched_process_exec(void (*probe)(void *, struct task_struct *, pid_t, struct linux_binprm *),
						void *arg)
{
	if (exec_tp)
		tracepoint_probe_unregister(exec_tp, probe, arg);
}

#else
#define compat_register_trace_sched_process_exec register_trace_sched_process_exec
#define compat_unregister_trace_sched_process_exec unregister_trace_sched_process_exec
#endif
