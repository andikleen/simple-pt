#!/usr/bin/python
# convert spt sideband .trace and .maps files to .sideband for sptdecode
# sptsideband.py ptout.trace [ptout.maps] [ptout.cpuid] [mtc_freq] > ptout.sideband

#*
#* Copyright (c) 2015, Intel Corporation
#* All rights reserved.
#* Author: Andi Kleen
#*
#* Redistribution and use in source and binary forms, with or without
#* modification, are permitted provided that the following conditions are met:
#*
#* 1. Redistributions of source code must retain the above copyright notice,
#* this list of conditions and the following disclaimer.
#*
#* 2. Redistributions in binary form must reproduce the above copyright
#* notice, this list of conditions and the following disclaimer in the
#* documentation and/or other materials provided with the distribution.
#*
#* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
#* FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
#* COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
#* INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
#* OF THE POSSIBILITY OF SUCH DAMAGE.


import argparse
import re
import sys

# Sideband format:
# timestamp pid cr3 load-address off-in-file path-to-binary

ap = argparse.ArgumentParser(usage='convert spt sideband .trace and .maps files to .sideband for sptdecode')
ap.add_argument('trace', help='trace file', type=argparse.FileType('r'))
ap.add_argument('maps', nargs='?', help='maps file', type=argparse.FileType('r'))
ap.add_argument('cpuid', nargs='?', help='cpuid file', type=argparse.FileType('r'))
ap.add_argument('mtcfreq', nargs='?', help='mtc frequency')
arguments = ap.parse_args()

if arguments.cpuid:
    for l in arguments.cpuid:
	n = l.split()
	if n[0] == "Family:":
	    print "meta", "family", n[1]
	elif n[0] == "Model:":
	    print "meta", "model", n[1]
	elif n[0] == "Stepping:":
	    print "meta", "stepping", n[1]
	elif n[0] == "TSC" and n[1] == "Ratio:":
	    print "meta", "tsc_ratio", n[2], n[3]
        elif n[0] == "Max" and n[1] == "non" and n[2] == "Turbo" and n[3] == "Ratio:":
            print "meta", "nom_freq", n[4]

if arguments.mtcfreq:
    print "meta", "mtc_freq", arguments.mtcfreq

cr3s = dict()

for l in arguments.trace:
    if l.startswith('#'):
        continue
    # handle fn= and comm= with spaces
    l = re.sub(r'(fn|comm)=(.*)', lambda x: x.group(0).replace(" ", "_"), l)
    f = l.split()
    try:
        proc, cpu, flags, ts, tp = f[:5]
    except ValueError:
        print >>sys.stderr, "Cannot parse", l,
    ts = ts.replace(":", "")
    if tp not in ("process_cr3:", "exec_cr3", "mmap_cr3:"):
        continue
    args = dict([x.replace(",", "").split('=') for x in f[5:]])
    pid = 0
    if 'pid' in args:
	pid = int(args['pid'])
    if tp == "process_cr3:":
        cr3s[pid] = args['cr3']
        continue
    if tp == "exec_cr3:":
        continue
    if tp != "mmap_cr3:":
        continue
    if not args['fn'].startswith("/"):
        continue
    if not 'addr' in args:
        args['addr'] = '0'
    if not 'pgoff' in args:
        args['pgoff'] = '0'
    if not 'len' in args:
        args['len'] = '0'
    args['pgoff'] = int(args['pgoff'], 16) * 4096
    print ts, pid, args['cr3'], args['addr'], "%d" % (args['pgoff']), args['len'] + "\t" + args['fn']

if arguments.maps:
    # /proc/1/maps:7ff4d5751000-7ff4d5950000 ---p 0000b000 08:02 266205                     /lib/x86_64-linux-gnu/libnss_files-2.19.so
    for l in arguments.maps:
        m = re.match(r"""
        /proc/(?P<pid>\d+)/maps:
        (?P<start>[0-9a-f]+)-(?P<end>[0-9a-f]+) \s+
        (?P<perm>\S+) \s+ 
        (?P<pgoff>[0-9a-f]+) \s+ 
        ([0-9a-f]+):([0-9a-f]+) \s+ 
        (?P<inode>\d+) \s+ 
        (?P<fn>.*)""", l, re.X)
	if int(m.group('pid')) not in cr3s.keys():
	    continue
        if not m:
            print >>sys.stderr, "no match", l,
            continue
        if not m.group('fn').startswith("/"):
            continue
        if m.group('perm').find('x') < 0:
            continue
        map_len = int(m.group('end'), 16)  - int(m.group('start'), 16)
        print "0.0", m.group('pid'), cr3s[int(m.group('pid'))], m.group('start'), m.group('pgoff'), map_len, "\t" + m.group('fn')
