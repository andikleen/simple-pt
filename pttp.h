#undef TRACE_SYSTEM
#define TRACE_SYSTEM pttp

#if !defined(_TRACE_PEBS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_PT_TP_H

#include <linux/tracepoint.h>

/* Map exec to CR3 to match to PIPs */

TRACE_EVENT(exec_cr3,
	    TP_PROTO(u64 cr3, char *fn),
	    TP_ARGS(cr3, fn),
	    TP_STRUCT__entry(
		    __string(filename, fn)
		    __field(u64, cr3)),
	    TP_fast_assign(
		    __assign_str(filename, fn);
		    __entry->cr3 = cr3;),
	    TP_printk("cr3=%llx, fn=%s", __entry->cr3, __get_str(filename)));

/* Map mmap file names to address, CR3 */

TRACE_EVENT(mmap_cr3,
	    TP_PROTO(u64 cr3, char *fn, unsigned long pgoff, unsigned long addr, unsigned long len),
	    TP_ARGS(cr3, fn, pgoff, addr, len),
	    TP_STRUCT__entry(
		    __field(u64, cr3)
		    __string(filename, fn)
		    __field(unsigned long, pgoff)
		    __field(unsigned long, addr)
		    __field(unsigned long, len)),
	    TP_fast_assign(
		    __entry->cr3 = cr3;
		    __assign_str(filename, fn);
		    __entry->pgoff = pgoff;
		    __entry->addr = addr;
		    __entry->len = len;),
	    TP_printk("cr3=%llx, pgoff=%lx, addr=%lx, len=%lx, fn=%s",
		      __entry->cr3,
		      __entry->pgoff,
		      __entry->addr,
		      __entry->len,
		      __get_str(filename)));

#endif

#include <trace/define_trace.h>
	    
		    
		    
