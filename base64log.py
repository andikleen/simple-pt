#!/usr/bin/python
# extract base64 encoded PT snippets in a kernel log
# base64log logfile > ptfile
import sys
import re
import base64

dump = False
for l in sys.stdin:
    l = re.sub(r'\s*(\[.*?\])?\s*(<.*?>)?\s*', '', l)
    if l.startswith("PTDUMPSTART"):
        dump = True
        continue
    if l.startswith("PTDUMPEND"):
        dump = False
    if dump:
        sys.stdout.write(base64.b64decode(l))
