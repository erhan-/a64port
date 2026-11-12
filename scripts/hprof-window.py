#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""hprof-window.py <start.bin> <end.bin> <out.bin>: the samples taken between two snapshots of the
same A64PORT_HPROF file (records are appended in time order; the maps/threads trailer of <end> is kept),
so a profile covers one phase of a run (e.g. the steady state only).  Analyse <out> with hprof.py."""
import struct, sys
a = open(sys.argv[1], "rb").read(); b = open(sys.argv[2], "rb").read()
ma, na, us = struct.unpack_from("<QQQ", a, 0); mb, nb, usb = struct.unpack_from("<QQQ", b, 0)
assert ma == mb == 0x31464F5250484252 and us == usb and nb >= na, "not two snapshots of one RBHPROF1 file"
assert b[24:24 + 24 * na] == a[24:24 + 24 * na], "<start> is not a prefix of <end> (different runs?)"
recs = b[24 + 24 * na:24 + 24 * nb]
open(sys.argv[3], "wb").write(struct.pack("<QQQ", mb, nb - na, us) + recs + b[24 + 24 * nb:])
print(f"{nb - na} samples ({(nb - na) * us / 1e6:.1f} s of thread CPU) between the snapshots")
