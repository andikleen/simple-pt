![simple-pt] (http://halobates.de/simple-pt.png)

# Introduction

simple-pt is a simple experimental reference implementation of Intel Processor Trace (PT) on
Linux. PT can trace all branches executed by the CPU at the hardware level
with moderate overhead. A PT decoder then uses sideband data to decode the branch
traces. 

PT is supported on Intel 5th generation Code (Broadwell) and 6th generation Code (Skylake) CPUs.

simple pt consists of a 
	* kernel driver
	* sptcmd to collect data from the kernel driver
	* sptdecode to decode PT information
	* fastdecode to dump raw PT traces

It uses the [libipt](https://github.com/01org/processor-trace) PT decoding library

Note that Linux 4.1 and later has an [integrated PT implementation](http://lwn.net/Articles/648154/) as part 
of Linux perf. gdb 7.10 also supports full debugging on top of PT.

Simple PT does *NOT* support:

	* It does not support long term tracing of more data than fits in the buffer (no interrupt)
	* It does not support any sampling (use perf or VTune)
	* It requires root rights to collect data (use perf)
	* It does not support interactive debugging (use gdb or hardware debuggers)

Simple PT has the following functionality
	* set up hardware to processor trace
	* supports a ring buffer of branch data, stopped on events
	* supports flushing buffer on panic
	* does not require patching the kernel
	* set up PT filters, such as kernel filter
	* start and stop traces at specific kernel addresses
	* support tracing multiple processes
	* print all function calls
	* simple driver that can be ported to older kernel releases or other operating systems
	* simple code base that is easily changed.

# Installation

Build and install libipt. This currently requires a patched version of libipt.

	git clone -b cr3-callback https://github.com/01org/processor-trace
	cd processor-trace
	cmake .
	make
	cp lib/libipt.so* /usr/local/lib64      # or lib depending on your system
	ldconfig

Clone simple-pt

	git clone https://github.com/andikleen/simple-pt
	cd simple-pt

Build the kernel module. May require installing kernel includes from your distribution.

	make 

Build the user tools

	make user

Run test

	sudo ./sptcmd -c ls ls
	sudo ./sptdecode --sideband ptout.sideband --pt ptout.0 | less
	
sptcmd loads and configures the kernel driver. It runs a program with trace. It always 
does a global trace. It writes the pt trace data to trace files for each CPU
(ptout.N where N is the CPU number). It also writes side band information needed
to decode the trace into the ptout.sideband file. 

-c sets a command filter, tracing only commands with that name. Otherwise
everything global is traced.

sptdecode then decodes the trace for a CPU using the side band information.
When it should decode kernel code it needs to run 

Limitations:

	* When kernel tracing is disabled (-K) multiple processes cannot be distinguished by the decoder.
	
	* sptcmd does not continuously save side band data, so events at the beginning
of a trace may not be saved. For complex workloads it may be needed to increase the trace buffers 
in /sys/kernel/debug/tracing/buffer_size_kb


Contact: simple-pt@halobates.de

For bugs please file a github issue.

Andi Kleen
