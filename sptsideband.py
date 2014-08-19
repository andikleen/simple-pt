#!/usr/bin/python
# convert spt sideband .trace and .maps files to .sideband for sptdecode
# sptsideband.py ptout.trace [ptout.maps] > ptout.sideband
import argparse
import re
import sys

# Sideband format:
# timestamp cr3 load-address off-in-file path-to-binary

ap = argparse.ArgumentParser(usage='convert spt sideband .trace and .maps files to .sideband for sptdecode')
ap.add_argument('trace', help='trace file', type=argparse.FileType('r'))
ap.add_argument('maps', nargs='?', help='trace file', type=argparse.FileType('r'))
arguments = ap.parse_args()

cr3s = dict()

for l in arguments.trace:
    if l.startswith('#'):
        continue
    f = l.split()
    proc, cpu, flags, ts, tp = f[:5]
    ts = ts.replace(":", "")
    args = dict([x.replace(",", "").split('=') for x in f[5:]])
    if tp == "process_cr3:":
        cr3s[int(args['pid'])] = args['cr3']
        continue
    if not args['fn'].startswith("/"):
        continue
    if not 'addr' in args:
        args['addr'] = '0'
    if not 'pgoff' in args:
        args['pgoff'] = '0'
    args['pgoff'] = int(args['pgoff']) * 4096
    print ts,args['cr3'],args['addr'],"%d" % (args['pgoff']) + "\t" + args['fn']

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
        if not m:
            print >>sys.stderr, "no match", l,
            continue
        if not m.group('fn').startswith("/"):
            continue
        if m.group('perm').find('x') < 0:
            continue
        print "0.0", cr3s[int(m.group('pid'))], m.group('start'), m.group('pgoff') + "\t" + m.group('fn')
