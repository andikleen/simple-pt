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
addresses = []
max = 0
for l in pipe:
   m = re.match(r"^([0-9a-f]+) \S (\w+)", l)
   if m:
      val = int(m.group(1), 16)
      if val > max:
         max = val
         pos = bisect.bisect_left(addresses, val)
         addresses.insert(pos, val)
         symtab.insert(pos, m.group(2))

last_ndx = None
for l in sys.stdin:
   n = l.split()
   try:
      adr = int(n[0], 16)
   except:
      print l,
      continue
      # last hit cache
      if (last_ndx and adr >= addresses[last_ndx] and
          (last_ndx == len(addresses)-1 or adr < addresses[last_ndx + 1])):
         n = last_ndx
      else:
         n = bisect.bisect_left(addresses, adr)
         if n >= len(addresses):
            #print "%u not found %d/%d" % (adr,n,len(symtab))
            print l,
            continue
            last_ndx = n
            sym = symtab[n]
            print "%-40s" % ("%s+%d" % (symtab[n], -(adr - addresses[n]))),
            print l.rstrip(),
            m = re.search(r'\[rip\+(0x[0-9a-f]+)\]', l)
            if m:
               saddr = adr + int(m.group(1), 16)
               n = bisect.bisect_left(addresses, saddr)
               if n < len(addresses):
                  # XXX really need to use next IP
                  print "\t# %s" % (symtab[n]),
                  print
