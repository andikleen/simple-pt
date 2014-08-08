#undef TRACE_SYSTEM
#define TRACE_SYSTEM pttp

#if !defined(_TRACE_PEBS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_PT_TP_H

#include <linux/tracepoint.h>

/* Trace point mapping exec to CR3 to match to PIPs */

TRACE_EVENT(exec_cr3,
	    TP_PROTO(u64 cr3),
	    TP_ARGS(cr3),
	    TP_STRUCT__entry(
		    __field(u64, cr3)),
	    TP_fast_assign(
		    __entry->cr3 = cr3;),
	    TP_printk("cr3=%llx", __entry->cr3));

#endif

#include <trace/define_trace.h>
	    
		    
		    
