#!/usr/bin/python
# add symbols to ptxed output
# ptxed --pt .. --elf ELFFILE | symoffset.py ELFFILE 

import bisect
import subprocess
import sys
import re

if len(sys.argv) < 2:
   print "usage symoffset elf-executable < ptxedlog"
   sys.exit(1)

pipe = subprocess.Popen("nm " + sys.argv[1], shell=True, stdout=subprocess.PIPE).stdout
symtab = []
adresses = []
max = 0
for l in pipe:
	m = re.match(r"^([0-9a-f]+) \S (\w+)", l)
	if m:
                val = int(m.group(1), 16)
                if val > max:
                    max = val
                pos = bisect.bisect_left(adresses, val)
                adresses.insert(pos, val)
		symtab.insert(pos, m.group(2))

for l in sys.stdin:
	n = l.split()
        try:
            adr = int(n[0], 16)
        except:
            print l,
            continue
	n = bisect.bisect_left(adresses, adr)
	if n >= len(adresses):
		#print "%u not found %d/%d" % (adr,n,len(symtab))
		print l,
		continue
	sym = symtab[n]
	print "%-30s" % ("%s+%d" % (symtab[n], -(adr - adresses[n]))),
        print l.rstrip(),
        m = re.search(r'\[rip\+(0x[0-9a-f]+)\]', l)
        if m:
            saddr = adr + int(m.group(1), 16)
            n = bisect.bisect_left(adresses, saddr)
            if n < len(adresses):
                # XXX really need to use next IP
                print "\t# %s" % (symtab[n]),
        print
