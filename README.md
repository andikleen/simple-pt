![simple-pt](http://halobates.de/spt-logo.png)

# Introduction

simple-pt is a simple implementation of Intel Processor Trace (PT) on
Linux. PT can trace all branches executed by the CPU at the hardware level
with moderate overhead. simple-pt then decodes the branch trace and
displays a function or instruction level trace.

PT is supported on Intel 5th generation Core (Broadwell), 6th generation Core (Skylake) CPUs,
and later, as well as Goldmont based Atom CPUs (Intel Joule, Apollo Lake) and later.

# Example

	% sptcmd  -c tcall taskset -c 0 ./tcall
	cpu   0 offset 1027688,  1003 KB, writing to ptout.0
	...
	Wrote sideband to ptout.sideband
	% sptdecode --sideband ptout.sideband --pt ptout.0 | less
	TIME      DELTA	 INSNs   OPERATION
	frequency 32
	0        [+0]     [+   1] _dl_aux_init+436
	                  [+   6] __libc_start_main+455 -> _dl_discover_osversion
	...
	                  [+  13] __libc_start_main+446 -> main
	                  [+   9]     main+22 -> f1
	                  [+   4]	      f1+9 -> f2
	                  [+   2]	      f1+19 -> f2
	                  [+   5]     main+22 -> f1
	                  [+   4]	      f1+9 -> f2
	                  [+   2]	      f1+19 -> f2
	                  [+   5]     main+22 -> f1
	...

# Overview

simple-pt consists of a
* kernel driver
* sptcmd to collect data from the kernel driver
* sptdecode to display function or instruction traces
* fastdecode to dump raw PT traces

It uses the [libipt](https://github.com/01org/processor-trace) PT decoding library

Note that Linux 4.1 and later has an [integrated PT implementation](http://lwn.net/Articles/648154/) as part 
of Linux perf. gdb 7.10 also supports full debugging on top of PT. [Intel VTune](https://software.intel.com/en-us/intel-vtune-amplifier-xe)
also supports PT.

If you want a full production system please use one of these. simple-pt is an experimental implementation.

Simple PT does *NOT* support:

* It does not support long term tracing of more data than fits in the buffer (no interrupt) (use perf or VTune)
* It does not support any sampling (use perf or VTune)
* It requires root rights to collect data (use perf)
* It does not support interactive debugging (use gdb or hardware debuggers)

Simple PT has the following functionality:
* set up hardware to processor trace
* supports a ring buffer of branch data, stopped on events
* supports flushing buffer on panic
* does not require patching the kernel (although it cheats a bit using kprobes)
* set up PT filters, such as kernel filter, or filter ranges
* start and stop traces at specific kernel addresses, with unlimited number
* support tracing multiple processes
* print all function calls in "ftrace" style
* disassembling all executed instructions (requires xed library, optional)
* simple driver that could be ported to older kernel releases or other operating systems
* simple code base that is easily changed.
* modular "unix style" design with simple tools that do only one thing
* can dump branches before panic to kernel log and decode

# Installation

__Note: simple-pt now requires a new version of libipt (2.x), which has
an incompatible API. Please update.__

__Note: The installation requirements for simple-pt have changed. It now requires
the upstream version of libipt. No special branches needed anymore.
Also udis86 has been replaced with xed.__

Build and install libipt

	git clone https://github.com/01org/processor-trace -b stable/v2.0
	cd processor-trace
	cmake .
	make
	sudo make install
	sudo ldconfig

Install libelf-elf-devel or elfutils-devel or similar depending on your distribution.

Optionally install xed if you want to see disassembled instructions:

	git clone https://github.com/intelxed/mbuild.git mbuild
	git clone https://github.com/intelxed/xed
	cd xed
	mkdir obj
	cd obj
	../mfile.py
	sudo ../mfile.py --prefix=/usr/local install

Clone simple-pt

	git clone https://github.com/andikleen/simple-pt
	cd simple-pt

Build the kernel module. May require installing kernel includes from your distribution.

	make 

Install the kernel module

	sudo make modules_install

Build the user tools

	make user

If you installed xed use

	make user XED=1

Check if your system supports PT

	./ptfeature

Run a trace

	sudo ./sptcmd -c ls ls
	sudo ./sptdecode --sideband ptout.sideband --pt ptout.0 | less

On recent kernels it may be needed to separate page table separation, if you
want to use process filtering

	Boot the kernel with the "nopti" argument

sptcmd loads and configures the kernel driver. It runs a program with trace. It always 
does a global trace. It writes the pt trace data to trace files for each CPU
(ptout.N where N is the CPU number). It also writes side band information needed
to decode the trace into the ptout.sideband file. 

-c sets a command filter, tracing only commands with that name. Otherwise
everything global is traced.

sptdecode then decodes the trace for a CPU using the side band information.
When it should decode kernel code it needs to run as root to be able to
read /proc/kcore. If it's not run as root kernel code will not be shown.

Another way to use simple-pt is to run the workload with PT running
in the background and only dump on an event.

Start trace and dump trace on event:

	sudo ./sptcmd --enable
	<run workload>
	<some event of interest happens and triggers:>
	sudo ./sptcmd --dump
	sudo ./sptdecode --sideband ptout.sideband --pt ptout.0 | less

Another way is to use --stop-address or --stop-range to stop the trace
on specific kernel symbols being executed. Note that these options
only affect the trace on their current CPU.

Run test suite

	sudo ./tester

# Design overview

The kernel driver manages the PT hardware and allocates the trace buffers.
It also sets up some custom trace points for the sideband data.

The simple-pt kernel driver is configured using module parameters. Many can be changed
at runtime through /sys/module/simple_pt/parameters. A few need a driver reload

Use
	modinfo simple-pt.ko

to show all allowed parameters. For most parameters sptcmd has options to
set them up. That is the recommended interface.

sptcmd configures the driver, starts the trace and runs the trace command.
The driver sets up a ring buffer and runs the the processor trace
for each CPU until stopped.  Then it calls sptdump to write the buffer
for each CPU to a ptout.N file (N is the number of the CPU)

For the side band information ftrace with some custom trace points defined
by the driver is used. sptsideband converts the ftrace output into
the .sideband files used by the decoder.

sptdecode then reads the PT data, the sideband data, the executables, the kernel code
through /proc/kcore, and uses the libipt decoder to reconstruct the
trace.

# Manpages

* [sptcmd](http://halobates.de/spt-man/sptcmd.html)
* [sptdecode](http://halobates.de/spt-man/sptdecode.html)
* [ptfeature](http://halobates.de/spt-man/ptfeature.html)
* [sptarchive](http://halobates.de/spt-man/sptarchive.html)
* [fastdecode](http://halobates.de/spt-man/fastdecode.html)
* [sptdump](http://halobates.de/spt-man/sptdump.html)

# Changing the PT buffer sizes

To change the PT buffer size the driver needs to be loaded manually. The PT
buffer size can be changed with the pt_buffer_order parameter.

	rmmod simple_pt # if it was loaded
	modprobe simple_pt pt_buffer_order=10

The size is specified in 2^n 4K pages. The default is 9 (2MB). The maximum limit
is the kernel's MAX_ORDER limit, typically 8MB. The allocation may also fail
if the kernel memory is too fragmented. In this case quitting a large process
may help.

When ptfeature shows the "multiple toPA entries" feature it is possible to
allocate multiple PT buffers with the pt_num_buffers parameter. All the buffers
are logically concatenated. The default is one buffer. The maximum is 511
buffers.

# Using simple-pt for panic debugging

simple-pt can be used to print a number of branches before a panic.

	insmod simple-pt.ko start=1 print_panic_psbs=4
	<panic system>
	<collect log from serial console>

The number after print_panic_psbs specifies the length of the logged trace
(expressed in number of PT sync points)

The PT information is logged in base64 format to the kernel log.  It can be recovered
with the base64log.py utility

	base64log.py < log > ptlog
	sptdecode --elf vmlinux --pt ptlog

This method currently does not support modules or ring 3 code, or multiple
PT buffers.

# Notes

* To limit the program to one CPU use sptcmd taskset -c CPU ..
* To demangle C++ symbols pipe output through c++filt
* To start/stop around specific user code bracket it with dummy syscalls that you
  can then put a kernel trigger on. The test suite uses personality(21212212) and prctl(12341234).
  This will be improved in the future.
* perf or the BIOS may be already using the PT hardware. If you know it's safe you can take
  over the PT hardware with --force -d.
* When configuring the driver manually you need to manually reset any parameters you do not want anymore.
  sptcmd takes care of that automatically.
* Some Debian kernels are built without CONFIG_KALLSYMS_ALL. When you see an "Cannot find task_lock"
error message load the simple_pt module like this

	insmod simple_pt.ko tasklist_lock_ptr=0x$(grep tasklist_lock /boot/System.map-$(uname -r) | awk ' {print $1}')
* Various older Linux kernels have problems with ftrace in kernel modules. simple-pt relies on ftrace
output for its sideband. "tester" has a special test. If there are problems likely the workarounds
in "compat.h" (e.g. the ifdefs) need to be adjusted. Upgrading to a newer kernel should fix the problem too.
* The time in different ptout files collected on the same system without reboot is synchronized.
However the synchronization is not fine grained enough to directly determine causality of nearby memory accesses.

# Current limitations:

* When kernel tracing is disabled (-K) multiple processes cannot be distinguished by the decoder.

* Enabling/Disabling tracing causes the kernel to modify itself, which can cause the PT decoder
  to lose synchronization. sptcmd disables trace points. Workaround is to keep trace points
  running after the trace ends with -k, or disable kernel tracing. This can sometimes affect the
  test suite. If this happens try "tester -k"

* sptcmd does not continuously save side band data, so events at the beginning
  of a trace may not be saved. For complex workloads it may be needed to increase the trace buffers 
  in /sys/kernel/debug/tracing/buffer_size_kb.

* The decoder does not (currently) support reusing the same address region in a process for
  different code (for example after dlclose/dlopen)

* Tracing JITed code is not supported.

* On Skylake the trace time occasionally jumps backwards after frequency changes.

* Decoder loses synchronization in some cases where it shouldn't.

* Binaries with spaces in the name are not supported (due to limitations in sptsideband.py)

* On 5.7+ kernels using symbol names located in modules in --start/stop-addr will leak the module count
  of the module.

* On systems with page table isolation active the -C filter can only filter on user code or kernel code,
  but not both at the same time. To avoid this boot with pti=off. Note this may make the system
  suspectible to Meltdown.

# Porting simple-pt

There is some Linux specific code in the driver, but the basic PT hardware configuration
should be straight forward to adapt to other environments. The minimum support needed
is memory allocation, a mechanism to call a callback on all CPUs (IPIs), and a mechanism
to establish a shared buffer with the decoding tool (implemented using mmap on a character device).
When suspend-to-ram is supported it's also useful to have a callback after resume
to reinitialize the hardware.

The kernel driver is configured using global variables with Linux's moduleparams mechanism.
This can be replaced with simple hard coded variables.

The driver supports Linux "kprobes" and "kallsyms" to set custom triggers. That code
is all optional and can be removed. Such optional code is generally marked as
optional.

The user tools should be portable to POSIX C99 based systems. The code to access the kernel
image will need to be adapted.  Porting to non DWARF/ELF based systems will need more work.

# Contact
simple-pt@halobates.de

For bugs please file a github issue.

Andi Kleen
