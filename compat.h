
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
static struct tracepoint *exec_tp;

static inline int compat_register_trace_sched_process_exec(void (*probe)(void *, struct task_struct *, pid_t, struct linux_binprm *),
						void *arg)
{
	/* Workaround for newer kernels which use non exported symbols */
	exec_tp = (struct tracepoint *)kallsyms_lookup_name("__tracepoint_sched_process_exec");
	if (!exec_tp)
		return -EIO;
	return tracepoint_probe_register(exec_tp, (void *)probe, NULL);
}

static inline void compat_unregister_trace_sched_process_exec(void (*probe)(void *, struct task_struct *, pid_t, struct linux_binprm *),
						void *arg)
{
	if (exec_tp)
		tracepoint_probe_unregister(exec_tp, probe, arg);
}

#else
#define compat_register_trace_sched_process_exec register_trace_sched_process_exec
#define compat_unregister_trace_sched_process_exec unregister_trace_sched_process_exec
#endif

/* arbitrary cut-off point. 3.19 is known to work, 3.13 is known broken. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)

/*
 * Work around bug in older kernels that unsigned or out of tree
 * modules disable trace points. Thanks to Mathieu Desnoyers
 * and Ben Porter.
 */
static void fix_tracepoints(void)
{
	/*
	 * Force tracepoints to load by spoofing this module's taint
	 * and calling trace_module_notify and tracepoint_module_notify
	 * manually.
	 * Will duplicate calls to trace/tracepoint notify cause
	 * issues? perhaps detect if notify has already succeeded, and
	 * if so break before calling again.
	 */
	int (*tracepoint_module_notify_sym)(struct notifier_block *nb,
					unsigned long val, struct module *mod);
	int (*trace_module_notify_sym)(struct notifier_block * nb,
		    unsigned long val, struct module * mod);

	trace_module_notify_sym = (void*)kallsyms_lookup_name("trace_module_notify");
	tracepoint_module_notify_sym = (void*)kallsyms_lookup_name("tracepoint_module_notify");

	if (trace_module_notify_sym && tracepoint_module_notify_sym) {
		unsigned old_taint = THIS_MODULE->taints;
		THIS_MODULE->taints = 0;
		trace_module_notify_sym(NULL, MODULE_STATE_COMING, THIS_MODULE);
		tracepoint_module_notify_sym(NULL, MODULE_STATE_COMING, THIS_MODULE);
		THIS_MODULE->taints = old_taint;
	}
}

#else
static inline void fix_tracepoints(void) {}
#endif
