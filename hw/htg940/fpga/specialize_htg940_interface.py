#!/usr/bin/env python3
"""Resolve ONLY HTG940_ENTROPY_CONTROL=True in generated hardware copies.
All other preprocessor directives stay intact; never preprocess arbitrary macros.
"""
import re
import sys
from pathlib import Path

def specialize(text):
    stack=[]; out=[]; targets=0
    pattern=re.compile(r'^\s*`(ifdef|ifndef|else|elsif|endif)\b(?:\s+(\w+))?')
    for line in text.splitlines(keepends=True):
        m=pattern.match(line)
        active=all(flag for _,flag in stack)
        if not m:
            if active:out.append(line)
            continue
        kind,name=m.groups()
        if kind in ('ifdef','ifndef'):
            target=name=='HTG940_ENTROPY_CONTROL'
            if target:targets+=1
            if active and not target:out.append(line)
            stack.append((target, kind=='ifdef' if target else True))
        else:
            if not stack:raise ValueError('Unbalanced preprocessor directive: '+line.strip())
            target,flag=stack[-1]
            if kind=='endif':
                stack.pop()
                if not target and all(f for _,f in stack):out.append(line)
            elif kind=='else':
                if target:stack[-1]=(True,not flag)
                elif active:out.append(line)
            elif target:
                raise ValueError('Targeted conditional contains unsupported elsif')
            elif active:out.append(line)
    if stack:raise ValueError('Unclosed conditional')
    if not targets:raise ValueError('No HTG940_ENTROPY_CONTROL conditional found')
    return '// HTG940 hardware-only generated interface; do not edit.\n'+''.join(out)

if __name__=='__main__':
    if len(sys.argv)!=3:raise SystemExit('Usage: specialize_htg940_interface.py INPUT OUTPUT')
    source,dest=map(Path,sys.argv[1:])
    result=specialize(source.read_text())
    dest.write_text(result)
    print(f'HTG940_INTERFACE_SPECIALIZED: {dest}')
