#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""gen_mods.py — build mods.h for the multi-module a64port loader.

Reads, for each module (the main executable plus every DSO it needs):
  * the original AArch64 ELF  -> .dynsym (names) and .rela.dyn/.rela.plt
  * the emitted project       -> a64port/layout.h (segment file names + VAs)
and writes one C header describing the whole image: load bases, segments,
the full dynamic symbol table (index-aligned with .dynsym, so relocation
symbol indices stay valid), and every relocation with its symbol name.

The loader uses it to place the executable and the dynamic linker and to map
guest code addresses to the translated blocks of each module; the guest's own
translated ld.so then loads the libraries and applies their relocations.

  gen_mods.py [--modules-only] <root> <work-dir>      (A64PORT_PROFILE=<profile.json>, else <app dir>/profile.json)
"""
import os
import re
import struct
import sys

# ── ELF ──────────────────────────────────────────────────────────────────────
def elf_sections(b):
    shoff = struct.unpack_from('<Q', b, 40)[0]
    shent = struct.unpack_from('<H', b, 58)[0]
    shnum = struct.unpack_from('<H', b, 60)[0]
    shstr = struct.unpack_from('<H', b, 62)[0]
    shs = []
    for i in range(shnum):
        o = shoff + i * shent
        name, typ, flags, addr, off, size, link, info, align, entsz = \
            struct.unpack_from('<IIQQQQIIQQ', b, o)
        shs.append(dict(name=name, typ=typ, addr=addr, off=off, size=size,
                        entsz=entsz))
    st = shs[shstr]['off']
    def nm(x):
        e = b.index(b'\0', st + x)
        return b[st + x:e].decode()
    for s in shs:
        s['n'] = nm(s['name'])
    return shs


def parse_elf(path):
    b = open(path, 'rb').read()
    shs = elf_sections(b)
    byname = {s['n']: s for s in shs}

    # PT_TLS: static TLS init image + block size (all zero when the module has none)
    phoff = struct.unpack_from('<Q', b, 32)[0]
    phent = struct.unpack_from('<H', b, 54)[0]
    phnum = struct.unpack_from('<H', b, 56)[0]
    tls = (0, 0, 0, 0)
    for i in range(phnum):
        o = phoff + i * phent
        if struct.unpack_from('<I', b, o)[0] != 7:      # PT_TLS
            continue
        tls = (struct.unpack_from('<Q', b, o + 16)[0],   # p_vaddr
               struct.unpack_from('<Q', b, o + 32)[0],   # p_filesz
               struct.unpack_from('<Q', b, o + 40)[0],   # p_memsz
               struct.unpack_from('<Q', b, o + 48)[0])   # p_align

    syms = []
    ds, dstr = byname.get('.dynsym'), byname.get('.dynstr')
    if ds:
        for o in range(0, ds['size'], 24):
            name, info, other, shndx, value, size = struct.unpack_from(
                '<IBBHQQ', b, ds['off'] + o)
            e = b.index(b'\0', dstr['off'] + name)
            s = b[dstr['off'] + name:e].decode()
            syms.append((s, info & 0xf, value, shndx, size))

    rels = []
    for s in shs:
        if s['typ'] != 4:                      # SHT_RELA
            continue
        for o in range(0, s['size'], 24):
            off, info, add = struct.unpack_from('<QQq', b, s['off'] + o)
            rels.append((off, info & 0xffffffff, info >> 32, add))
    return syms, rels, tls


def parse_layout(path):
    txt = open(path).read()
    segs, nobs = [], []
    m = re.search(r'A64PORT_SEGMENTS\[\] = \{(.*?)\};', txt, re.S)
    if m:
        for nm, f, va, sz in re.findall(
                r'\{"([^"]*)",\s*"([^"]*)",\s*0x([0-9a-f]+)ull,\s*0x([0-9a-f]+)ull\}', m.group(1)):
            segs.append((nm, f, int(va, 16), int(sz, 16)))
    m = re.search(r'A64PORT_NOBITS\[\] = \{(.*?)\};', txt, re.S)
    if m:
        for nm, va, sz in re.findall(
                r'\{"([^"]*)",\s*0x([0-9a-f]+)ull,\s*0x([0-9a-f]+)ull\}', m.group(1)):
            nobs.append((nm, int(va, 16), int(sz, 16)))
    ent = int(re.search(r'A64PORT_ENTRY\s+0x([0-9a-f]+)ull', txt).group(1), 16)
    return segs, nobs, ent


def default_app_dir(root):
    """A64PORT_APP_DIR, else the only directory under <root>/apps (empty string if there is none or several)."""
    d = os.environ.get("A64PORT_APP_DIR")
    if d:
        return d
    apps = os.path.join(root, "apps")
    subs = [os.path.join(apps, n) for n in sorted(os.listdir(apps))] if os.path.isdir(apps) else []
    subs = [p for p in subs if os.path.isdir(p)]
    return subs[0] if len(subs) == 1 else ""


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    modules_only = '--modules-only' in sys.argv
    root, work = os.path.abspath(args[0]), os.path.abspath(args[1])
    # A/B emit trees live under app<suffix>/ libs<suffix>/ (reemit.sh's
    # A64PORT_EMIT_SUFFIX); mods.h only depends on the ELF + layout, which are
    # identical across suffixes, so honour the suffix rather than demanding the
    # default tree exist.
    esuf = os.environ.get('A64PORT_EMIT_SUFFIX', '')
    libs = os.path.join(work, 'libs' + esuf)
    R = os.path.join(root, 'rootfs')

    # (mod, elf, emitted dir, load base). A non-PIE executable is ET_EXEC: base 0, link addresses.
    # Other executables of the rootfs (e.g. helper daemons): A64PORT_EXE_ELF/A64PORT_EXE_DIR name the
    # executable and its emit tree (it is still module "app" in the generated
    # symbols), A64PORT_DSO_LIST a file of `mod<TAB>file` lines replacing the
    # default list, A64PORT_MULTI_OUT the output directory.
    import json
    prof_path = os.environ.get('A64PORT_PROFILE') or os.path.join(default_app_dir(root), 'profile.json')
    if not os.path.exists(prof_path):
        sys.exit(f'gen_mods: no application profile at {prof_path} (set A64PORT_PROFILE or A64PORT_APP_DIR; the profile format is in docs/TUTORIAL.md)')
    prof = json.load(open(prof_path))
    exe_elf = os.environ.get('A64PORT_EXE_ELF') or os.path.join(R, prof['exe'])
    exe_mod = prof.get('module', 'exe')
    exe_dir = os.environ.get('A64PORT_EXE_DIR') or os.path.join(work, exe_mod + esuf)
    mods = [(exe_mod, exe_elf, exe_dir, 0)]
    dsos = [tuple(p) for p in prof['dsos']]
    dso_list = os.environ.get('A64PORT_DSO_LIST')
    if dso_list:
        dsos = [tuple(l.rstrip('\n').split('\t')) for l in open(dso_list) if l.strip()]
    # The interpreter (PT_INTERP). In the kernel-faithful model this is the only
    # module whose load address we choose; ld.so maps every other DSO through our
    # mmap hook and we learn each base from the mapping itself.
    mods.append(('ld', os.path.join(R, prof['interp']), os.path.join(libs, 'ld'), 0x3fe000000))
    # DSO bases below are a first guess only: ld.so picks the real ones at run
    # time via our mmap, and `basevar` is updated from that mapping.
    for i, (mod, f) in enumerate(dsos):
        mods.append((mod, os.path.join(R, prof['dso_dir'], f), os.path.join(libs, mod),
                     0x20000000 + i * 0x1000000))

    if modules_only:
        # Only the module list (module<TAB>ELF path relative to the root), from the profile: what emit-gen.sh needs before
        # anything is emitted.  The full run (without this flag) needs the emitted trees for their layouts.
        dst = os.environ.get('A64PORT_MULTI_OUT') or os.path.join(work, 'multi')
        os.makedirs(dst, exist_ok=True)
        with open(os.path.join(dst, 'modules.txt'), 'w') as fh:
            for mod, elf, edir, base in mods:
                fh.write(f'{mod}\t{os.path.relpath(elf, root)}\n')
        print(f'wrote {dst}/modules.txt ({len(mods)} modules)')
        return

    out = []
    out.append('/* auto-generated by gen_mods.py - DO NOT EDIT */')
    out.append('#pragma once')
    out.append('#include <stdint.h>')
    out.append('#include "recomp_runtime.h"')
    out.append('typedef struct { const char* name; const char* file; uint64_t va, size; } RModSeg;')
    out.append('typedef struct { const char* name; uint64_t value; uint64_t size;')
    out.append('                 uint32_t type, shndx; } RModSym;')
    out.append('typedef struct { uint64_t off; uint32_t type, sym; int64_t addend; } RModRel;')
    out.append('typedef struct {')
    out.append('  const char* name; const char* file; const char* dir;')
    out.append('  uint64_t base, entry;')
    out.append('  const RModSeg *segs; unsigned nseg;')
    out.append('  const RModSeg *nobits; unsigned nnobits;')
    out.append('  const RModSym *syms; unsigned nsym;')
    out.append('  const RModRel *rels; unsigned nrel;')
    out.append('  uint64_t tls_vaddr, tls_filesz, tls_memsz, tls_align;')
    out.append('  uint64_t* basevar;')
    out.append('  void (*build_index)(void);')
    out.append('  int  (*index_view)(uint64_t*, uint64_t*, BlockFn**);')
    out.append('} RModule;')

    stats = []
    counts = {}
    tlsinfo = {}
    entries = {}
    for mod, elf, edir, base in mods:
        syms, rels, tls = parse_elf(elf)
        tlsinfo[mod] = tls
        segs, nobs, ent = parse_layout(os.path.join(edir, 'a64port', 'layout.h'))
        entries[mod] = ent
        counts[mod] = (len(segs), len(nobs), len(syms), len(rels))
        out.append(f'\n/* ---- {mod} ---- */')
        out.append(f'extern uint64_t g_mb_{mod};')
        # The emitted code passes its own guard-version global to
        # recomp_code_guard(); a host that installs a page table must set it to 2
        # or the guard aborts on the first block.  The executable's guard is
        # not renamed, every DSO is.
        gsym = 'g_recomp_guard_host_v2' if mod == exe_mod else f'g_guard_{mod}'
        out.append(f'extern int {gsym};')
        if mod == exe_mod:
            out.append('extern void recomp_build_index(void);')
            out.append('extern int _recomp_index_view(uint64_t*,uint64_t*,BlockFn**);')
        else:
            out.append(f'extern void recomp_build_index_{mod}(void);')
            out.append(f'extern int _recomp_index_view_{mod}(uint64_t*,uint64_t*,BlockFn**);')
        out.append(f'static const RModSeg s_{mod}[] = {{')
        for nm, f, va, sz in segs:
            out.append(f'  {{"{nm}", "{f}", 0x{va:x}ull, 0x{sz:x}ull}},')
        out.append('};')
        out.append(f'static const RModSeg n_{mod}[] = {{')
        for nm, va, sz in nobs:
            out.append(f'  {{"{nm}", 0, 0x{va:x}ull, 0x{sz:x}ull}},')
        out.append('};')
        out.append(f'static const RModSym y_{mod}[] = {{')
        for s, t, v, sh, sz in syms:
            out.append(f'  {{"{s}", 0x{v:x}ull, 0x{sz:x}ull, {t}u, {sh}u}},')
        out.append('};')
        out.append(f'static const RModRel r_{mod}[] = {{')
        for off, t, sym, add in rels:
            out.append(f'  {{0x{off:x}ull, {t}u, {sym}u, {add}LL}},')
        out.append('};')
        nglob = sum(1 for s, t, v, sh, sz in syms if sh != 0 and s)
        stats.append((mod, base, len(segs), len(syms), len(rels), nglob))

    out.append('\nstatic const RModule R_MODULES[] = {')
    for mod, elf, edir, base in mods:
        if mod == exe_mod:
            bi, iv = 'recomp_build_index', '_recomp_index_view'
        else:
            bi, iv = f'recomp_build_index_{mod}', f'_recomp_index_view_{mod}'
        out.append(f'  {{"{mod}", "{os.path.basename(elf)}", "{edir}", '
                   f'0x{base:x}ull, 0x{base + entries[mod]:x}ull,')
        ns, nnob, nsym, nrel = counts[mod]
        out.append(f'   s_{mod}, {ns}, n_{mod}, {nnob}, '
                   f'y_{mod}, {nsym}, r_{mod}, {nrel}, '
                   f'0x{tlsinfo[mod][0]:x}ull, 0x{tlsinfo[mod][1]:x}ull, '
                   f'0x{tlsinfo[mod][2]:x}ull, {tlsinfo[mod][3]},'
                   f' &g_mb_{mod}, {bi}, {iv}}},')
    out.append('};')
    out.append('#define R_NMODULES (sizeof(R_MODULES)/sizeof(R_MODULES[0]))')
    out.append(f'/* the main executable: its module name and its load-address variable */')
    out.append(f'#define R_EXE_MODULE "{exe_mod}"')
    out.append(f'#define R_EXE_BASE g_mb_{exe_mod}')
    out.append('/* the load-address variable of every module, for the host to define */')
    out.append('#define R_MODULE_BASE_VARS ' + ', '.join(f'g_mb_{mod}' for mod, elf, edir, base in mods))
    out.append('\nstatic int* const R_GUARDS[] = {')
    for mod, elf, edir, base in mods:
        gsym = 'g_recomp_guard_host_v2' if mod == exe_mod else f'g_guard_{mod}'
        out.append(f'  &{gsym},')
    out.append('};')
    out.append('#define R_NGUARDS (sizeof(R_GUARDS)/sizeof(R_GUARDS[0]))')
    txt = '\n'.join(out)

    dst = os.environ.get('A64PORT_MULTI_OUT') or os.path.join(work, 'multi')
    os.makedirs(dst, exist_ok=True)
    open(os.path.join(dst, 'mods.h'), 'w').write(txt + '\n')

    # One canonical module list, consumed by the build and re-emit scripts so
    # the three places that need it can never drift apart.
    with open(os.path.join(dst, 'modules.txt'), 'w') as fh:
        for mod, elf, edir, base in mods:
            fh.write(f'{mod}\t{os.path.relpath(elf, root)}\n')

    print(f'wrote {dst}/mods.h')
    print(f'{"mod":<12}{"base":>12}{"segs":>6}{"syms":>8}{"relocs":>8}{"defined":>9}')
    tot = 0
    for mod, base, ns, nsym, nrel, ng in stats:
        print(f'{mod:<12}0x{base:<10x}{ns:>6}{nsym:>8}{nrel:>8}{ng:>9}')
        tot += nrel
    print(f'{"TOTAL":<12}{"":>12}{"":>6}{"":>8}{tot:>8}')


if __name__ == '__main__':
    main()
