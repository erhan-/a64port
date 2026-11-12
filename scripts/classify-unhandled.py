#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Classify unhandled-instruction output from tools/recomp/a64recomp.

Accepts either CSV that `a64recomp` writes:

  --dump-exact      -> "count,encoding"
  --dump-signatures -> "signature,count,group,example_insn,example_pc"

Each distinct encoding is assembled as `.inst 0x...` and disassembled with the real AArch64
binutils. That separates three very different things that all look like "unhandled" from the
emitter's point of view:

  * a named mnemonic      -> a genuine decoder gap
  * ".inst ...; undefined" -> data that block discovery walked (pointer tables, literal pools)
  * "udf"                 -> a trap/padding word

Needs: aarch64-linux-gnu-as and aarch64-linux-gnu-objdump on PATH.

Usage: classify-unhandled.py <dump.csv>
"""
import collections
import csv
import pathlib
import re
import subprocess
import sys
import tempfile

AS = "aarch64-linux-gnu-as"
OBJDUMP = "aarch64-linux-gnu-objdump"


def load(path):
    """-> list of (count, encoding, note) where note is optional context."""
    rows = list(csv.DictReader(open(path)))
    if not rows:
        sys.exit("empty csv")
    if "encoding" in rows[0]:
        return [(int(r["count"]), r["encoding"], "") for r in rows]
    if "example_insn" in rows[0]:
        return [(int(r["count"]), r["example_insn"],
                 f"{r.get('example_pc', '')} {r.get('group', '')}") for r in rows]
    sys.exit(f"unrecognised csv header: {list(rows[0])}")


def disassemble(encodings):
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="a64port-classify"))
    asm = ["\t.text", "\t.globl _start", "_start:"]
    for i, e in enumerate(encodings):
        asm += [f".L{i}:", f"\t.inst {e}"]
    (tmp / "s.s").write_text("\n".join(asm) + "\n")
    subprocess.run([AS, "-o", str(tmp / "s.o"), str(tmp / "s.s")], check=True)
    dis = subprocess.run([OBJDUMP, "-d", str(tmp / "s.o")], capture_output=True, text=True,
                         check=True).stdout
    out = {}
    for line in dis.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\t([0-9a-f]{8})\s*\t?(.*)$", line)
        if m:
            out[int(m.group(1), 16) // 4] = m.group(3).strip()
    return out


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    rows = load(sys.argv[1])
    text_of = disassemble([e for _, e, _ in rows])

    classes = collections.Counter()
    families = collections.Counter()
    examples = {}
    real_rows = []
    for i, (count, enc, note) in enumerate(rows):
        body = text_of.get(i, "")
        if "undefined" in body:
            cls, mn = "data / unallocated", "(data)"
        elif body.startswith("udf"):
            cls, mn = "trap (udf)", "udf"
        else:
            mn = body.split()[0] if body else "?"
            cls = "real instruction"
            families[mn] += count
            examples.setdefault(mn, (enc, body))
            real_rows.append((count, mn, enc, note))
        classes[cls] += count

    total = sum(classes.values())
    print(f"file: {sys.argv[1]}")
    print(f"unhandled total {total} over {len(rows)} distinct encodings\n")
    for cls, n in classes.most_common():
        print(f"  {cls:<20} {n:7}  {100 * n / total:6.2f}%")

    if families:
        print("\nreal gaps by mnemonic:")
        for mn, n in families.most_common(40):
            enc, body = examples[mn]
            print(f"  {n:7}  {mn:<10} e.g. {enc}  {body}")
        print("\nlargest individual real gaps:")
        for n, mn, enc, note in sorted(real_rows, reverse=True)[:25]:
            print(f"  {n:7}  {mn:<10} {enc}  {note}")


if __name__ == "__main__":
    main()
