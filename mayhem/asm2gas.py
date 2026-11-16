#!/usr/bin/env python3
"""Translate the fastop section of assembly/x64/assembly.asm (MASM) to GNU as intel syntax.

Only the em_* ALU/shift/setcc/cmp routines are translated; the Win64-only parts (VMX/SVM entry,
control-register accessors, the __asm_fastop trampoline) are replaced by mayhem/fuzz_emulate.c.
"""
import re
import sys

src, dst = sys.argv[1], sys.argv[2]
lines = open(src, encoding="latin-1").read().splitlines()
start = next(i for i, l in enumerate(lines) if re.match(r"\s*public\s+em_setcc\b", l))
end = next(i for i, l in enumerate(lines) if re.match(r"\s*__cmpq_rdx_rax\s+endp\b", l))

out = [".intel_syntax noprefix", ".text"]
for l in lines[start:end + 1]:
    l = l.split(";")[0].rstrip()
    if not l.strip():
        continue
    m = re.match(r"\s*public\s+(\w+)$", l)
    if m:
        out.append(".globl %s" % m.group(1))
        continue
    m = re.match(r"\s*(\w+)\s+proc\b", l)
    if m:
        out.append("%s:" % m.group(1))
        continue
    if re.match(r"\s*\w+\s+endp\b", l):
        continue
    m = re.match(r"\s*align\s+(\d+)$", l)
    if m:
        out.append(".balign %s" % m.group(1))
        continue
    out.append("\t" + l.strip())
out.append('.section .note.GNU-stack,"",@progbits')
open(dst, "w").write("\n".join(out) + "\n")
