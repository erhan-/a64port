/* SPDX-License-Identifier: GPL-2.0-or-later */
// a64recomp — AArch64 ELF -> portable C, via suyu's arm64_to_c.h engine.
//
// This is a64port's retargetable frontend driver. It reads a real AArch64 ELF
// (not a Switch NSO), collects block-discovery roots, and either reports the
// decoder's unhandled-instruction histogram (--stats-only, cheap) or emits a
// buildable C project with suyu::recomp::EmitProject.
//
// The emitted C is the intermediate artifact: compile it with any host C
// compiler to get a native binary for that host.
//
// Build:
//   g++ -std=c++20 -O2 -Ithird_party/mk8-recomp tools/recomp/a64recomp.cpp
//       -o tools/recomp/a64recomp
//
// Use:
//   tools/recomp/a64recomp <aarch64-elf> <out-dir> [options]
//     --mod NAME        module name used in generated symbols (default: input stem)
//     --entry HEX       override the ELF entry point
//     --roots FILE      extra roots, one hex absolute address per line
//     --no-eh-frame     do not seed roots from .eh_frame_hdr
//     --stats-only      do not write output; just print the histogram
//     --examples N      rows in the histogram report (default 12)

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <filesystem>
#include <algorithm>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "arm64_to_c.h"

using namespace suyu::recomp;

namespace {

struct Section {
    std::string name;
    uint64_t addr = 0, off = 0, size = 0;
    uint32_t type = 0;
    uint32_t link = 0;   // sh_link: the string table of a SYMTAB/DYNSYM
    uint64_t flags = 0;
    bool alloc() const { return (flags & 0x2) != 0; }        // SHF_ALLOC
    bool nobits() const { return type == 8; }                // SHT_NOBITS
    bool rela() const { return type == 4; }                  // SHT_RELA
};

template <typename T>
T rd(const std::vector<uint8_t>& b, size_t o) {
    T v{};
    std::memcpy(&v, b.data() + o, sizeof(T));
    return v;
}

struct Elf {
    struct Load {
        uint64_t vaddr = 0, memsz = 0, filesz = 0, off = 0;
    };
    std::vector<uint8_t> bytes;
    uint64_t entry = 0;
    std::vector<Section> sections;
    std::vector<Load> loads;

    const Section* find(const std::string& n) const {
        for (const auto& s : sections)
            if (s.name == n) return &s;
        return nullptr;
    }
    const uint8_t* ptr(const Section& s) const { return bytes.data() + s.off; }
};

bool ReadElf(const char* path, Elf& e) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "cannot open %s\n", path);
        return false;
    }
    e.bytes.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    const auto& b = e.bytes;
    if (b.size() < 64 || std::memcmp(b.data(), "\x7f" "ELF", 4) != 0) {
        std::fprintf(stderr, "%s: not an ELF\n", path);
        return false;
    }
    // The misdecode gate. An AArch32 (or x86) input must be rejected here: the
    // AArch64 decoder never fails on a wrong-ISA word, it emits unhandled
    // fallbacks, so a silent wrong input looks like a successful export.
    if (b[4] != 2) {
        std::fprintf(stderr, "%s: not ELF64 (EI_CLASS=%u)\n", path, b[4]);
        return false;
    }
    if (b[5] != 1) {
        std::fprintf(stderr, "%s: not little-endian\n", path);
        return false;
    }
    const uint16_t machine = rd<uint16_t>(b, 18);
    if (machine != 183) {
        std::fprintf(stderr, "%s: e_machine=%u, not AArch64 (183) — refusing\n", path, machine);
        return false;
    }
    e.entry = rd<uint64_t>(b, 24);
    const uint64_t shoff = rd<uint64_t>(b, 40);
    const uint16_t shentsize = rd<uint16_t>(b, 58);
    const uint16_t shnum = rd<uint16_t>(b, 60);
    const uint16_t shstrndx = rd<uint16_t>(b, 62);
    if (shoff == 0 || shnum == 0) {
        std::fprintf(stderr, "%s: no section headers\n", path);
        return false;
    }
    auto sh = [&](int i, int field) -> uint64_t {
        const size_t o = shoff + (size_t)i * shentsize;
        // Elf64_Shdr: name+0, type+4, flags+8, addr+16, offset+24, size+32.
        switch (field) {
            case 0: return rd<uint32_t>(b, o + 0);   // sh_name
            case 1: return rd<uint32_t>(b, o + 4);   // sh_type
            case 2: return rd<uint64_t>(b, o + 16);  // sh_addr
            case 3: return rd<uint64_t>(b, o + 24);  // sh_offset
            case 4: return rd<uint64_t>(b, o + 32);  // sh_size
            case 5: return rd<uint64_t>(b, o + 8);   // sh_flags
            case 6: return rd<uint32_t>(b, o + 40);  // sh_link
        }
        return 0;
    };
    const uint64_t stroff = sh(shstrndx, 3);
    for (int i = 0; i < shnum; ++i) {
        Section s;
        const char* nm = reinterpret_cast<const char*>(b.data() + stroff + sh(i, 0));
        s.name = nm ? nm : "";
        s.type = (uint32_t)sh(i, 1);
        s.addr = sh(i, 2);
        s.off = sh(i, 3);
        s.size = sh(i, 4);
        s.flags = sh(i, 5);
        s.link = (uint32_t)sh(i, 6);
        e.sections.push_back(s);
    }
    // PT_LOAD layout: the guest's real address span, used to size and place the
    // flat guest memory the standalone runtime hands to the recompiled code.
    const uint64_t phoff = rd<uint64_t>(b, 32);
    const uint16_t phentsize = rd<uint16_t>(b, 54);
    const uint16_t phnum = rd<uint16_t>(b, 56);
    for (int i = 0; i < phnum; ++i) {
        const size_t o = phoff + (size_t)i * phentsize;
        if (rd<uint32_t>(b, o) != 1) continue;  // PT_LOAD
        Elf::Load l;
        l.off = rd<uint64_t>(b, o + 8);
        l.vaddr = rd<uint64_t>(b, o + 16);
        l.filesz = rd<uint64_t>(b, o + 32);
        l.memsz = rd<uint64_t>(b, o + 40);
        e.loads.push_back(l);
    }
    return true;
}

// A real binary's executable code is not all in .text: .init, .plt and .fini
// are separate SHF_EXECINSTR sections, and a static binary routes its
// IFUNC-resolved calls (memcpy, memset, ...) through the PLT. Recompiling only
// .text leaves every PLT stub undiscovered, which surfaces as "no block at
// <plt address>" the first time such a function is called.
//
// So build one synthetic code image spanning every executable section, copy
// each in at its offset (gaps stay zero, which block discovery skips), and
// recompile that. Section placement for the guest comes from WriteLayout, so
// the guards still verify against the real bytes at their real addresses.
struct CodeImage {
    std::vector<uint8_t> bytes;
    uint64_t base = 0;
};

CodeImage BuildCodeImage(const Elf& elf) {
    CodeImage img;
    uint64_t lo = UINT64_MAX, hi = 0;
    for (const auto& s : elf.sections) {
        if (!s.alloc() || s.nobits() || s.size == 0) continue;
        if (!(s.flags & 0x4)) continue;  // SHF_EXECINSTR
        lo = std::min(lo, s.addr);
        hi = std::max(hi, s.addr + s.size);
    }
    if (lo == UINT64_MAX) {
        const Section* t = elf.find(".text");
        lo = t ? t->addr : 0;
        hi = t ? t->addr + t->size : 0;
    }
    img.base = lo;
    img.bytes.assign((size_t)(hi - lo), 0);
    for (const auto& s : elf.sections) {
        if (!s.alloc() || s.nobits() || s.size == 0) continue;
        if (!(s.flags & 0x4)) continue;
        std::memcpy(img.bytes.data() + (size_t)(s.addr - lo), elf.bytes.data() + s.off,
                    (size_t)s.size);
    }
    return img;
}

std::vector<uint64_t> ReadHexLines(const char* path) {
    std::vector<uint64_t> out;
    std::ifstream in(path);
    if (!in) {
        std::fprintf(stderr, "warning: cannot open roots file %s\n", path);
        return out;
    }
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        out.push_back(std::strtoull(line.c_str(), nullptr, 16));
    }
    return out;
}

// ---- root sources -----------------------------------------------------------

// .dynsym STT_FUNC values. Exported functions are reached indirectly (GOT/PLT,
// vtables) and are not otherwise discoverable from .text alone.
void AddDynsymRoots(const Elf& e, std::vector<uint64_t>& roots) {
    const Section* sym = e.find(".dynsym");
    if (!sym || sym->size < 24) return;
    const uint8_t* p = e.ptr(*sym);
    for (size_t o = 0; o + 24 <= sym->size; o += 24) {
        uint8_t info = p[o + 4];
        uint64_t value = 0;
        std::memcpy(&value, p + o + 8, 8);
        if ((info & 0xf) == 2 && value != 0) roots.push_back(value);
    }
}

// .eh_frame_hdr binary search table -> FDE initial locations (function starts).
// This is the precise, complete function list for gcc/clang output and is what
// makes an indirectly-called function visible to block discovery.
bool AddEhFrameRoots(const Elf& e, std::vector<uint64_t>& roots, size_t* decoded) {
    const Section* hdr = e.find(".eh_frame_hdr");
    if (!hdr || hdr->size < 4) return false;
    const uint8_t* p = e.ptr(*hdr);
    const size_t n = hdr->size;
    if (p[0] != 1) {
        std::fprintf(stderr, "warning: .eh_frame_hdr version %u unsupported\n", p[0]);
        return false;
    }
    const uint8_t enc_frame = p[1], enc_count = p[2], enc_tab = p[3];
    size_t pos = 4;
    const uint64_t hdr_addr = hdr->addr;

    auto read_enc = [&](uint8_t enc, uint64_t* out) -> bool {
        const uint64_t field_addr = hdr_addr + pos;
        uint64_t base = 0;
        switch (enc & 0x70) {
            case 0x10: base = field_addr; break;   // pcrel
            case 0x30: base = hdr_addr; break;     // datarel (base = .eh_frame_hdr)
            case 0x00: base = 0; break;            // absptr
            default:
                std::fprintf(stderr, "warning: .eh_frame_hdr application 0x%02x unsupported\n",
                             enc & 0x70);
                return false;
        }
        uint64_t raw = 0;
        switch (enc & 0x0f) {
            case 0x00: if (pos + 8 > n) return false; std::memcpy(&raw, p + pos, 8); pos += 8; break;
            case 0x02: { if (pos + 2 > n) return false; uint16_t v; std::memcpy(&v, p + pos, 2); raw = v; pos += 2; break; }
            case 0x03: { if (pos + 4 > n) return false; uint32_t v; std::memcpy(&v, p + pos, 4); raw = v; pos += 4; break; }
            case 0x04: if (pos + 8 > n) return false; std::memcpy(&raw, p + pos, 8); pos += 8; break;
            case 0x09: {  // sleb128
                int64_t v = 0; int shift = 0; uint8_t byte;
                do { if (pos >= n) return false; byte = p[pos++]; v |= (int64_t)(byte & 0x7f) << shift; shift += 7; } while (byte & 0x80);
                if (shift < 64 && (byte & 0x40)) v |= -((int64_t)1 << shift);
                raw = (uint64_t)v; break;
            }
            case 0x0a: { if (pos + 2 > n) return false; int16_t v; std::memcpy(&v, p + pos, 2); raw = (uint64_t)(int64_t)v; pos += 2; break; }
            case 0x0b: { if (pos + 4 > n) return false; int32_t v; std::memcpy(&v, p + pos, 4); raw = (uint64_t)(int64_t)v; pos += 4; break; }
            case 0x0c: if (pos + 8 > n) return false; std::memcpy(&raw, p + pos, 8); pos += 8; break;
            case 0x01: {  // uleb128
                uint64_t v = 0; int shift = 0; uint8_t byte;
                do { if (pos >= n) return false; byte = p[pos++]; v |= (uint64_t)(byte & 0x7f) << shift; shift += 7; } while (byte & 0x80);
                raw = v; break;
            }
            default:
                std::fprintf(stderr, "warning: .eh_frame_hdr format 0x%02x unsupported\n", enc & 0x0f);
                return false;
        }
        if ((enc & 0x0f) == 0x0b || (enc & 0x0f) == 0x0c || (enc & 0x0f) == 0x09 ||
            (enc & 0x0f) == 0x0a) {
            *out = base + raw;  // signed: wrapping add is correct for pcrel/datarel
        } else {
            *out = base + raw;
        }
        return true;
    };

    uint64_t ignored = 0, count = 0;
    if (!read_enc(enc_frame, &ignored)) return false;
    if (!read_enc(enc_count, &count)) return false;
    if (count == 0 || count > (1u << 24)) {
        std::fprintf(stderr, "warning: .eh_frame_hdr fde_count=%llu implausible\n",
                     (unsigned long long)count);
        return false;
    }
    size_t got = 0;
    for (uint64_t i = 0; i < count; ++i) {
        uint64_t loc = 0, fde = 0;
        if (!read_enc(enc_tab, &loc)) break;
        if (!read_enc(enc_tab, &fde)) break;
        roots.push_back(loc);
        ++got;
    }
    if (decoded) *decoded = got;
    return got > 0;
}

// ---- extra root sources (R2/R4) ------------------------------------------------
//
// Block discovery seeds from the entry, .dynsym FUNC values and .eh_frame_hdr FDE
// starts. Two classes of code pointer are invisible to all three:
//
//   * an address a relocation stores in .data.rel.ro/.got - a vtable slot or an
//     absolute jump-table entry. R_AARCH64_RELATIVE/ABS64 carries it verbatim, so
//     no instruction has to be decoded.
//   * LLVM/GCC switch lookup tables, which live in .rodata as *relative* offsets
//     and are reached only through a computed `br`. Nothing branches to the case
//     bodies and they have no FDE.
//
// Both are recovered statically here and appended to the root list. Over-seeding
// is harmless: a wrong root only costs one never-executed block, and recomp_lookup
// matches exact starts, so it cannot redirect correct execution.

inline int64_t SignExtend(uint64_t v, int bits) {
    const uint64_t m = 1ULL << (bits - 1);
    return (int64_t)((v ^ m) - m);
}

bool IsExec(const Elf& e, uint64_t vaddr) {
    for (const auto& s : e.sections)
        if ((s.flags & 0x4) && vaddr >= s.addr && vaddr < s.addr + s.size) return true;
    return false;
}

// Read n bytes at a virtual address, from whichever section or PT_LOAD covers it.
bool ReadVaddr(const Elf& e, uint64_t vaddr, void* dst, size_t n) {
    for (const auto& s : e.sections) {
        if (!s.alloc() || s.nobits() || s.size == 0) continue;
        if (vaddr >= s.addr && vaddr + n <= s.addr + s.size) {
            std::memcpy(dst, e.bytes.data() + s.off + (size_t)(vaddr - s.addr), n);
            return true;
        }
    }
    for (const auto& l : e.loads) {
        if (vaddr >= l.vaddr && vaddr + n <= l.vaddr + l.filesz) {
            std::memcpy(dst, e.bytes.data() + l.off + (size_t)(vaddr - l.vaddr), n);
            return true;
        }
    }
    return false;
}

// ---- AArch64 decode, only the shapes the two passes below need ----------------

bool DecodeAdrp(uint32_t w, uint64_t pc, uint32_t& rd, uint64_t& page) {
    if ((w & 0x9F000000u) != 0x90000000u) return false;
    const uint64_t immlo = (w >> 29) & 3u;
    const uint64_t immhi = (w >> 5) & 0x7FFFFu;
    rd = w & 31u;
    page = (pc & ~0xFFFULL) + (uint64_t)(SignExtend((immhi << 2) | immlo, 21) << 12);
    return true;
}

bool DecodeAdr(uint32_t w, uint64_t pc, uint32_t& rd, uint64_t& target) {
    if ((w & 0x9F000000u) != 0x10000000u) return false;
    const uint64_t immlo = (w >> 29) & 3u;
    const uint64_t immhi = (w >> 5) & 0x7FFFFu;
    rd = w & 31u;
    target = pc + (uint64_t)SignExtend((immhi << 2) | immlo, 21);
    return true;
}

// ADD (immediate), 64-bit: add xD, xN, #imm12
bool DecodeAddImm(uint32_t w, uint32_t& rd, uint32_t& rn, uint32_t& imm) {
    if ((w & 0xFFC00000u) != 0x91000000u) return false;
    rd = w & 31u;
    rn = (w >> 5) & 31u;
    imm = (w >> 10) & 0xFFFu;
    return true;
}

// ADD (extended register), 64-bit: add xD, xN, wM, <ext> #shift
// `ext` selects the table entry width: sxtb -> int8, sxth -> int16, sxtw -> int32.
bool DecodeAddExt(uint32_t w, uint32_t& rd, uint32_t& rn, uint32_t& rm, uint32_t& option,
                  uint32_t& shift) {
    if ((w & 0xFFE00000u) != 0x8B200000u) return false;
    rd = w & 31u;
    rn = (w >> 5) & 31u;
    rm = (w >> 16) & 31u;
    option = (w >> 13) & 7u;
    shift = (w >> 10) & 7u;
    return true;
}

bool DecodeCmpImm(uint32_t w, uint32_t& rn, uint32_t& imm) {
    // SUBS (immediate) with Rd=31 (the CMP alias), 32- or 64-bit, shift 0.
    if ((w & 0xFF000000u) == 0x71000000u && (w & 31u) == 31u) {
        rn = (w >> 5) & 31u; imm = (w >> 10) & 0xFFFu; return true;
    }
    if ((w & 0xFF000000u) == 0xF1000000u && (w & 31u) == 31u) {
        rn = (w >> 5) & 31u; imm = (w >> 10) & 0xFFFu; return true;
    }
    return false;
}

bool DecodeBCond(uint32_t w) { return (w & 0xFF000010u) == 0x54000000u; }
bool DecodeBr(uint32_t w, uint32_t& rn) {
    if ((w & 0xFFFFFC1Fu) != 0xD61F0000u) return false;
    rn = (w >> 5) & 31u;
    return true;
}

// LDR/LDRB/LDRH (register offset), plain opc=01 (not the signed variants).
// Returns the size in bytes, the base register Rn, and the index register Rm.
bool DecodeLoadReg(uint32_t w, uint32_t& size_bytes, uint32_t& rn, uint32_t& rm) {
    if ((w & 0xFFE00C00u) == 0x38600800u) { size_bytes = 1; rn = (w >> 5) & 31u; rm = (w >> 16) & 31u; return true; }
    if ((w & 0xFFE00C00u) == 0x78600800u) { size_bytes = 2; rn = (w >> 5) & 31u; rm = (w >> 16) & 31u; return true; }
    if ((w & 0xFFE00C00u) == 0xB8600800u) { size_bytes = 4; rn = (w >> 5) & 31u; rm = (w >> 16) & 31u; return true; }
    return false;
}

// ---- R2: switch lookup tables -------------------------------------------------
//
// The LLVM form is:
//     adrp xT, .rodata_page ; add xT, xT, #imm
//     ldrb wI, [xT, wIdx, uxtw]
//     adr  xB, .Lbase
//     add  xD, xB, wI, sxtb #2     ; target = base + (int8)entry * 4
//     br   xD
// GCC uses a word table with sxtw #2. The table length comes from the guard
// `cmp wIdx, #N` + conditional branch just before it; without one, entries are
// walked until they stop pointing into an executable section.
void AddLookupTableRoots(const Elf& e, const CodeImage& code, std::vector<uint64_t>& roots,
                         size_t& dispatches, size_t& from_tables) {
    const uint32_t* p = reinterpret_cast<const uint32_t*>(code.bytes.data());
    const int n = (int)(code.bytes.size() / 4);
    const uint64_t base = code.base;
    std::unordered_set<uint64_t> added_here;

    for (int i = 6; i < n; ++i) {
        uint32_t brn;
        if (!DecodeBr(p[i], brn)) continue;
        // add xD, xB, wI, <ext> #s  immediately before the br, xD == brn
        uint32_t rd, rn, rm, option, shift;
        if (!DecodeAddExt(p[i - 1], rd, rn, rm, option, shift) || rd != brn) continue;
        if (shift > 4) continue;
        const uint32_t scale = 1u << shift;
        // The window is fixed and contiguous: adrp i-5, add i-4, ldrb i-3,
        // adr i-2, add-ext i-1, br i. Requiring it exactly (a stale ADRP from
        // earlier in the function resolves to a misaligned "table" and then
        // reads hundreds of arbitrary .rodata bytes as offsets) is what keeps
        // the pass precise; the emitted pattern is this shape in practice.
        // base from the adr on xB
        uint64_t tblbase;
        uint32_t adr_rd;
        if (!DecodeAdr(p[i - 2], base + (uint64_t)(i - 2) * 4, adr_rd, tblbase)) continue;
        if (adr_rd != rn) continue;
        if (!IsExec(e, tblbase)) continue;
        // table pointer: resolve the load's base register from its contiguous
        // adrp+add. The load's index register must be the one the add scales -
        // otherwise this is an ordinary `add base, table, index` followed by an
        // indirect call/return, not a switch dispatch.
        uint32_t ld_size, ld_base, ld_rm;
        if (!DecodeLoadReg(p[i - 3], ld_size, ld_base, ld_rm)) continue;
        if (ld_rm != rm) continue;
        uint32_t t_rd;
        uint64_t page;
        if (!DecodeAdrp(p[i - 5], base + (uint64_t)(i - 5) * 4, t_rd, page) || t_rd != ld_base) continue;
        uint32_t a_rd, a_rn, a_imm;
        if (!DecodeAddImm(p[i - 4], a_rd, a_rn, a_imm) || a_rd != ld_base || a_rn != ld_base) continue;
        const uint64_t table = page + a_imm;
        if (IsExec(e, table)) continue;  // tables live in .rodata/.data

        // guard: nearest cmp on the index register before the load, with a
        // conditional branch after it. Without one, entries are walked until
        // one leaves executable memory (3dsrecomp's address_table heuristic).
        int64_t count = -1;
        for (int j = i - 3; j >= 0 && j >= i - 60; --j) {
            uint32_t crn, cimm;
            if (DecodeCmpImm(p[j], crn, cimm) && crn == rm) {
                bool branch_follows = false;
                for (int k = j + 1; k <= i && k < n; ++k)
                    if (DecodeBCond(p[k]) || (p[k] & 0x7E000000u) == 0x34000000u) { branch_follows = true; break; }
                if (branch_follows) { count = (int64_t)cimm + 1; break; }
            }
        }
        const bool guarded = count > 0 && count <= 4096;
        // Only a table whose length a guard states outright is trusted. An
        // unguarded dispatch (a `subs` the pass does not recognise, or an index
        // transformed before the load) would otherwise have hundreds of
        // arbitrary .rodata bytes read as offsets, and since a signed byte
        // offset from a .text base usually lands in .text, most of them look
        // valid. Every target in the gaps measured on a large program was in a guarded
        // table, so this loses nothing that is known to matter.
        if (!guarded) continue;
        const int64_t limit = count;

        ++dispatches;
        int miss_run = 0;
        for (int64_t k = 0; k < limit; ++k) {
            const uint64_t slot = table + (uint64_t)k * ld_size;
            uint8_t raw[4] = {0, 0, 0, 0};
            if (!ReadVaddr(e, slot, raw, ld_size)) break;
            int64_t entry = 0;
            if (ld_size == 1) entry = (int8_t)raw[0];
            else if (ld_size == 2) entry = (int16_t)(raw[0] | (raw[1] << 8));
            else entry = (int32_t)(raw[0] | (raw[1] << 8) | (raw[2] << 16) | ((uint32_t)raw[3] << 24));
            const uint64_t target = tblbase + (uint64_t)(entry * (int64_t)scale);
            if (IsExec(e, target) && (target & 3u) == 0) {
                miss_run = 0;
                if (added_here.insert(target).second) { roots.push_back(target); ++from_tables; }
            } else if (++miss_run >= 8) {
                break;  // a run that is not code: the bound was wrong, or the end
            }
        }
    }
}

// ---- R4: relocation-derived code pointers -------------------------------------
//
// R_AARCH64_RELATIVE and symbol-less R_AARCH64_ABS64 store an absolute address
// verbatim; if it lands in an executable section it is a function pointer in a
// vtable or an absolute jump table, and nothing else necessarily reaches it.
void AddRelocRoots(const Elf& e, std::vector<uint64_t>& roots, size_t& added) {
    for (const auto& s : e.sections) {
        if (!s.rela() || s.size < 24) continue;
        const uint8_t* rp = e.bytes.data() + s.off;
        for (size_t o = 0; o + 24 <= s.size; o += 24) {
            const uint64_t info = rd<uint64_t>(e.bytes, s.off + o + 8);
            const uint64_t add = rd<uint64_t>(e.bytes, s.off + o + 16);
            const uint32_t type = (uint32_t)(info & 0xFFFFFFFFu);
            const uint64_t sym = info >> 32;
            (void)rp;
            if (type == 1027u || (type == 257u && sym == 0)) {
                if (IsExec(e, add) && (add & 3u) == 0) { roots.push_back(add); ++added; }
            }
        }
    }
}

// ---- R4b: absolute code pointers in data --------------------------------------
//
// A non-PIE image stores vtable slots and function-pointer tables as
// plain absolute addresses in .data.rel.ro/.data; only a PIE needs relocations,
// so AddRelocRoots sees nothing there. Scanning the pointer-bearing data
// sections for words that land in an executable section recovers the same roots
// (3dsrecomp's Source::Pointer). .rodata is skipped on purpose: it holds offsets
// and integers, and scanning it finds far more noise than code.
bool IsPointerSection(const std::string& n) {
    static const char* kNames[] = {".data.rel.ro", ".data", ".init_array", ".fini_array",
                                   ".preinit_array", ".got", ".got.plt", ".tdata"};
    for (const char* k : kNames)
        if (n == k) return true;
    return n.rfind(".data.rel.ro.", 0) == 0;
}

void AddDataPointerRoots(const Elf& e, std::vector<uint64_t>& roots, size_t& added,
                         size_t& scanned) {
    std::unordered_set<uint64_t> seen;
    for (const auto& s : e.sections) {
        if (!s.alloc() || s.nobits() || s.size == 0) continue;
        if (s.flags & 0x4) continue;   // SHF_EXECINSTR: not pointer data
        if (!IsPointerSection(s.name)) continue;
        for (uint64_t o = 0; o + 8 <= s.size; o += 8) {
            ++scanned;
            const uint64_t v = rd<uint64_t>(e.bytes, s.off + o);
            if (v && (v & 3u) == 0 && IsExec(e, v) && seen.insert(v).second) {
                roots.push_back(v);
                ++added;
            }
        }
    }
}

// ---- R6: text coverage report -------------------------------------------------
//
// The denominator is bytes in executable sections; the numerator is bytes inside
// discovered blocks. The largest uncovered nonzero runs are the code discovery
// has not found - the same `Unknown` map 3dsrecomp shows (R6), without the per-byte provenance.
void CoverageReport(const Elf& e, const CodeImage& code, uint64_t entry,
                    const std::vector<uint64_t>& roots) {
    auto blocks = DiscoverBlocks(code.bytes.data(), code.bytes.size(), code.base, entry,
                                 roots.empty() ? nullptr : &roots);
    const size_t nb = code.bytes.size();
    std::vector<uint8_t> covered(nb, 0);
    size_t covered_bytes = 0;
    for (const auto& b : blocks) {
        const size_t off = (size_t)(b.vaddr - code.base);
        for (size_t k = 0; k < b.count && off + k * 4 < nb; ++k) {
            if (!covered[off + k * 4]) { covered[off + k * 4] = 1; covered_bytes += 4; }
        }
    }
    size_t exec_bytes = 0;
    for (const auto& s : e.sections)
        if ((s.flags & 0x4) && !s.nobits() && s.addr >= code.base && s.addr + s.size <= code.base + nb)
            exec_bytes += s.size;
    if (exec_bytes == 0) exec_bytes = nb;

    std::printf("\n--- coverage ---\n");
    std::printf("exec_bytes      %zu\n", exec_bytes);
    std::printf("blocks          %zu\n", blocks.size());
    std::printf("covered_bytes   %zu (%.2f%%)\n", covered_bytes,
                100.0 * double(covered_bytes) / double(exec_bytes ? exec_bytes : 1));
    const size_t uncovered_total = exec_bytes > covered_bytes ? exec_bytes - covered_bytes : 0;
    std::printf("uncovered_bytes %zu\n", uncovered_total);
    std::printf("\nper executable section (covered / size):\n");
    for (const auto& s : e.sections) {
        if (!(s.flags & 0x4) || s.nobits() || s.size == 0) continue;
        if (s.addr < code.base || s.addr + s.size > code.base + nb) continue;
        size_t cov = 0;
        for (uint64_t a = s.addr; a + 4 <= s.addr + s.size; a += 4)
            if (covered[(size_t)(a - code.base)]) cov += 4;
        std::printf("  %-16s %8zu / %8zu  %5.1f%%\n", s.name.c_str(), cov, s.size,
                    s.size ? 100.0 * double(cov) / double(s.size) : 0.0);
    }

    // Every uncovered run, so a zero run (padding/alignment, not code) is not
    // confused with a real undiscovered region (nonzero bytes nobody walked).
    struct Gap { uint64_t addr; size_t len; size_t nonzero; };
    std::vector<Gap> gaps;
    size_t zero_bytes = 0, nonzero_bytes = 0;
    size_t s = 0;
    while (s < nb) {
        if (covered[s]) { s += 4; continue; }
        size_t t = s, nonzero = 0;
        while (t < nb && !covered[t]) {
            if (code.bytes[t] != 0 || code.bytes[t + 1] != 0 || code.bytes[t + 2] != 0 ||
                code.bytes[t + 3] != 0)
                ++nonzero;
            t += 4;
        }
        const size_t words = (t - s) / 4;
        zero_bytes += (words - nonzero) * 4;
        nonzero_bytes += nonzero * 4;
        gaps.push_back({code.base + s, t - s, nonzero * 4});
        s = t;
    }
    std::printf("\nuncovered: %zu bytes zero (padding) + %zu bytes nonzero (not walked)\n",
                zero_bytes, nonzero_bytes);
    std::sort(gaps.begin(), gaps.end(), [](const Gap& a, const Gap& b) { return a.len > b.len; });
    std::printf("largest uncovered runs:\n");
    for (size_t k = 0; k < gaps.size() && k < 12; ++k)
        std::printf("  0x%08llx  %8zu bytes  (%zu nonzero)\n", (unsigned long long)gaps[k].addr,
                    gaps[k].len, gaps[k].nonzero);
}

// ---- recovered names (symbol files / ELF) -------------------------------------
//
// The emitted C names every block `blk_<mod>_<hex>`. When a recovered name is
// available for the block's address it becomes `blk_<mod>_<name>_<hex>` and the
// original is kept as a comment, so the recompiled code reads with the
// names of a disassembler project. Names come from the ELF's own symbol tables and from `--names`
// files (e.g. exported from a disassembler); the address suffix stays so two entries
// that share a name remain distinct.
static std::unordered_map<uint64_t, std::string> g_names;

// STT_FUNC values from .symtab/.dynsym. Exported DSO functions have real names
// with no external file, which is most of what a recompiled guest library needs.
void AddElfSymbolNames(const Elf& e, std::unordered_map<uint64_t, std::string>& names) {
    for (const auto& sym : e.sections) {
        if (sym.type != 2 && sym.type != 11) continue;  // SHT_SYMTAB, SHT_DYNSYM
        if (sym.link <= 0 || sym.link >= (uint32_t)e.sections.size()) continue;
        const Section& str = e.sections[sym.link];
        if (str.size == 0) continue;
        for (size_t o = 0; o + 24 <= sym.size; o += 24) {
            const uint32_t name_off = rd<uint32_t>(e.bytes, sym.off + o);
            const uint8_t info = e.bytes[sym.off + o + 4];
            const uint64_t value = rd<uint64_t>(e.bytes, sym.off + o + 8);
            if ((info & 0xf) != 2 || value == 0) continue;   // STT_FUNC
            if (name_off == 0 || name_off >= str.size) continue;
            const char* nm = reinterpret_cast<const char*>(e.bytes.data() + str.off + name_off);
            if (!nm[0] || !IsExec(e, value)) continue;
            names.emplace(value, std::string(nm));
        }
    }
}

// A `--names` file: `addr<TAB>name`, `start<TAB>size<TAB>name<TAB>vtable`
// (a function list) or `kind<TAB>addr<TAB>name<TAB>note`
// (a list of renames). Later files override earlier ones.
bool LoadNamesFile(const std::string& path, std::unordered_map<uint64_t, std::string>& names) {
    std::ifstream in(path);
    if (!in) return false;
    const auto hexval = [](const std::string& s, uint64_t& out) {
        if (s.empty()) return false;
        char* end = nullptr;
        const uint64_t v = std::strtoull(s.c_str(), &end, 16);
        if (end == s.c_str()) return false;
        out = v;
        return true;
    };
    std::string line;
    size_t rows = 0;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::vector<std::string> f;
        for (size_t a = 0;;) {
            const size_t t = line.find('\t', a);
            if (t == std::string::npos) { f.push_back(line.substr(a)); break; }
            f.push_back(line.substr(a, t - a));
            a = t + 1;
        }
        uint64_t addr = 0;
        std::string nm;
        if (f.size() >= 2 && hexval(f[0], addr)) {
            // `start size name ...` when column 2 is a plain size
            if (f.size() >= 3 && !f[1].empty() && std::isdigit((unsigned char)f[1][0])) nm = f[2];
            else nm = f[1];
        } else if (f.size() >= 3 && (f[0] == "func" || f[0] == "data" || f[0] == "label") &&
                   hexval(f[1], addr)) {
            nm = f[2];
        } else {
            continue;
        }
        const bool ident = !nm.empty() && nm != "-";
        if (ident) { names[addr] = nm; ++rows; }
    }
    std::fprintf(stderr, "  names: %zu from %s\n", rows, path.c_str());
    return true;
}

// Installed as the engine's g_block_name hook; the original text is returned and
// FuncNameTo sanitizes it.
static const char* BlockNameHook(const char* mod, uint64_t vaddr) {
    (void)mod;
    const auto it = g_names.find(vaddr);
    return it == g_names.end() ? nullptr : it->second.c_str();
}

// ---- R5 readiness: function grouping analysis ---------------------------------
//
// R5 (per-function emission) will emit one C function per guest function with
// the registers in locals. This pass measures what that grouping looks like using
// only the data the emitter will consume, and changes nothing: no roots, no
// output. It answers the questions that decide whether the rewrite is worth it and
// what the grouping must handle -
//
//   * how many blocks per function, and what fraction is in single-block leaves
//     (where per-function emission buys nothing);
//   * how many direct branches stay inside one function and could become a plain
//     `goto` (no chain call, no `c->pc` round-trip) - the step-0 benefit proxy;
//   * how many direct branches and calls cross a function boundary and therefore
//     stay a call or a dispatcher lookup;
//   * how many direct targets are not a discovered block start (the emitter has
//     to keep handling them).
void FunctionsReport(const CodeImage& code, uint64_t entry, const std::vector<uint64_t>& roots,
                     std::vector<uint64_t> fn_roots, const std::string& plan_path) {
    auto blocks = DiscoverBlocks(code.bytes.data(), code.bytes.size(), code.base, entry,
                                 roots.empty() ? nullptr : &roots);
    std::sort(fn_roots.begin(), fn_roots.end());
    fn_roots.erase(std::unique(fn_roots.begin(), fn_roots.end()), fn_roots.end());
    const uint32_t* p = reinterpret_cast<const uint32_t*>(code.bytes.data());

    const auto owner_of = [&](uint64_t v) -> int {
        const auto it = std::upper_bound(fn_roots.begin(), fn_roots.end(), v);
        return it == fn_roots.begin() ? -1 : int(it - fn_roots.begin()) - 1;
    };
    std::vector<int> owner(blocks.size());
    std::map<int, size_t> per_fn;
    for (size_t i = 0; i < blocks.size(); ++i) {
        owner[i] = owner_of(blocks[i].vaddr);
        ++per_fn[owner[i]];
    }

    size_t intra = 0, cross = 0, calls = 0, calls_known = 0, unknown_target = 0;
    for (size_t i = 0; i < blocks.size(); ++i) {
        const Block& b = blocks[i];
        const uint32_t first = (uint32_t)((b.vaddr - code.base) / 4);
        for (uint32_t k = 0; k < b.count; ++k) {
            const uint32_t w = p[first + k];
            const uint64_t pc = b.vaddr + (uint64_t)k * 4;
            uint64_t t = 0;
            if (!DirectBranchTarget(w, pc, t)) continue;
            const bool is_call = (w & 0xFC000000u) == 0x94000000u;  // BL
            const auto it = std::lower_bound(blocks.begin(), blocks.end(), t,
                                             [](const Block& bb, uint64_t v) { return bb.vaddr < v; });
            if (it == blocks.end() || it->vaddr != t) { ++unknown_target; continue; }
            if (is_call) {
                ++calls;
                const int ct = owner_of(t);
                if (ct >= 0 && fn_roots[ct] == t) ++calls_known;
            } else if (owner[i] == owner_of(t)) {
                ++intra;
            } else {
                ++cross;
            }
        }
    }

    size_t multi = 0, maxb = 0;
    size_t bins[4] = {0, 0, 0, 0};   // 1, 2-8, 9-32, 33+
    for (const auto& kv : per_fn) {
        const size_t n = kv.second;
        if (n > 1) multi += n;
        maxb = std::max(maxb, n);
        ++bins[n == 1 ? 0 : n <= 8 ? 1 : n <= 32 ? 2 : 3];
    }
    const size_t edges = intra + cross;

    // Optional plan file: the grouping the R5 emitter will consume, one row per
    // function, plus a soundness check (every block assigned, functions
    // non-overlapping). A block before the first function entry has no owner and
    // is reported: it would need its own function or an earlier seed.
    if (!plan_path.empty()) {
        struct Agg { uint64_t blocks = 0, instrs = 0, first = 0, last = 0; };
        std::map<int, Agg> agg;
        size_t orphan = 0;
        for (size_t i = 0; i < blocks.size(); ++i) {
            const int o = owner[i];
            if (o < 0) { ++orphan; continue; }
            Agg& a = agg[o];
            if (a.blocks == 0) { a.first = blocks[i].vaddr; a.last = blocks[i].vaddr + blocks[i].size; }
            a.blocks += 1;
            a.instrs += blocks[i].count;
            a.last = std::max<uint64_t>(a.last, blocks[i].vaddr + blocks[i].size);
        }
        bool overlap = false;
        uint64_t prev_end = 0;
        for (const auto& kv : agg) {
            if (kv.second.first < prev_end) overlap = true;
            prev_end = kv.second.last;
        }
        std::ofstream pf(plan_path);
        pf << "# function grouping plan: entry\tblocks\tinstrs\tfirst\tlast\n";
        for (const auto& kv : agg) {
            pf << "0x" << std::hex << fn_roots[kv.first] << "\t" << std::dec << kv.second.blocks
               << "\t" << kv.second.instrs << "\t0x" << std::hex << kv.second.first << "\t0x"
               << kv.second.last << "\n";
        }
        std::printf("\nplan: %zu functions, %zu blocks, %zu orphan, overlap=%s -> %s\n",
                    agg.size(), blocks.size() - orphan, orphan, overlap ? "YES" : "no",
                    plan_path.c_str());
    }

    std::printf("\n--- function grouping (R5 readiness; writes nothing) ---\n");
    std::printf("function entries        %zu\n", fn_roots.size());
    std::printf("blocks                  %zu\n", blocks.size());
    std::printf("owning functions        %zu\n", per_fn.size());
    std::printf("blocks in multi-block fns %zu (%.1f%%), max %zu\n", multi,
                blocks.empty() ? 0.0 : 100.0 * double(multi) / double(blocks.size()), maxb);
    std::printf("intra-function branches %zu (%.1f%% of %zu direct edges -> goto)\n", intra,
                edges ? 100.0 * double(intra) / double(edges) : 0.0, edges);
    std::printf("cross-function branches %zu\n", cross);
    std::printf("direct calls            %zu (%zu to a known function entry)\n", calls, calls_known);
    std::printf("direct target not a block %zu\n", unknown_target);
    std::printf("functions by block count: 1 -> %zu, 2-8 -> %zu, 9-32 -> %zu, 33+ -> %zu\n",
                bins[0], bins[1], bins[2], bins[3]);
}

// ---- reporting --------------------------------------------------------------

void ReportHistogram(const RecompileStats& st, size_t examples) {
    std::printf("text_bytes %zu\n", st.instructions * 4);
    std::printf("blocks %zu\n", st.blocks);
    std::printf("walked_instructions %zu\n", st.emitted);
    std::printf("unhandled %zu\n", st.unhandled);
    std::printf("unhandled_fraction %.8f (%.4f%%)\n", st.UnhandledFraction(),
                st.UnhandledFraction() * 100.0);
    std::printf("translated_terminators %zu\n", st.translated_terminators);
    std::printf("distinct_signatures %zu\n", st.unhandled_by_signature.size());

    std::printf("\n--- unhandled by encoding group ---\n");
    std::vector<std::pair<size_t, uint32_t>> groups;
    for (const auto& [g, c] : st.unhandled_by_group) groups.push_back({c, g});
    std::sort(groups.begin(), groups.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });
    for (const auto& [c, g] : groups)
        std::printf("%-24s %10zu  %6.2f%%\n", EncodingGroupName(g), c,
                    st.unhandled ? 100.0 * double(c) / double(st.unhandled) : 0.0);

    std::vector<std::pair<size_t, std::pair<uint32_t, UnhandledSite>>> ranked;
    for (const auto& [sig, site] : st.unhandled_by_signature) ranked.push_back({site.count, {sig, site}});
    std::sort(ranked.begin(), ranked.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });
    std::printf("\n--- unhandled by signature (top %zu of %zu) ---\n", examples, ranked.size());
    std::printf("%-12s %-24s %10s %9s  %-10s %s\n", "top10", "group", "count", "pct", "example", "pc");
    for (size_t i = 0; i < ranked.size() && i < examples; ++i) {
        const auto& [sig, site] = ranked[i].second;
        std::printf("0x%08x %-24s %10zu %8.3f%%  0x%08x 0x%llx\n", sig,
                    EncodingGroupName((sig >> 25) & 0xF), site.count,
                    st.unhandled ? 100.0 * double(site.count) / double(st.unhandled) : 0.0,
                    site.example_insn, (unsigned long long)site.example_pc);
    }
}

// Walk discovered blocks with Translate only; no files written. Mirrors what
// EmitProject counts, so the numbers are comparable to a real export.
RecompileStats WalkOnly(const uint8_t* text, size_t tn, uint64_t base, uint64_t entry,
                        const std::vector<uint64_t>& roots,
                        std::map<uint32_t, size_t>* exact = nullptr) {
    RecompileStats st;
    auto blocks = DiscoverBlocks(text, tn, base, entry, roots.empty() ? nullptr : &roots);
    const uint32_t* p = reinterpret_cast<const uint32_t*>(text);
    st.blocks = blocks.size();
    st.instructions = tn / 4;
    std::string body;
    body.reserve(4096);
    for (const auto& b : blocks) {
        const size_t first = (size_t)((b.vaddr - base) / 4);
        for (uint32_t k = 0; k < b.count; ++k) {
            const uint32_t insn = p[first + k];
            const uint64_t pc = b.vaddr + (uint64_t)k * 4;
            body.clear();
            bool unhandled = false;
            Translate(insn, pc, body, &unhandled);
            ++st.emitted;
            if (unhandled) {
                ++st.unhandled;
                ++st.unhandled_by_group[(insn >> 25) & 0xF];
                if (exact) ++(*exact)[insn];
                auto& site = st.unhandled_by_signature[insn & 0xFFC00000u];
                if (site.count == 0) { site.example_insn = insn; site.example_pc = pc; }
                ++site.count;
            }
            if (!body.empty() && body.back() == '\n') { /* terminators not tracked here */ }
        }
    }
    return st;
}
std::string Sanitize(const std::string& s) {
    std::string r;
    r.reserve(s.size());
    for (char ch : s) r += (std::isalnum((unsigned char)ch) ? ch : '_');
    return r;
}

// Emit a64port/layout.h plus one file per loadable section.
//
// The emitted project's own loader has no VA information (its comment says the
// real offsets are supposed to come from a blockmap) and only knows
// .text/.rodata/.data. A real Linux executable needs every SHF_ALLOC section
// (.eh_frame for unwinding, .data.rel.ro for vtables, .got/.got.plt,
// .init_array, .tdata) placed at its link address, and its relocations applied.
// So the driver supplies the whole picture and the shim honours it.
//
// Relocations are described, not applied here: R_AARCH64_RELATIVE is a plain
// store we can emit as data, R_AARCH64_IRELATIVE needs translated guest code to
// run (an IFUNC resolver), and symbol-based ones need a linker for the guest's
// own DSOs that we do not have yet. Describing all three makes the shim either
// apply them or name the ones it could not, instead of leaving zeros in a vtable.
void WriteLayout(const std::string& out_dir, const Elf& elf) {
    uint64_t lo = UINT64_MAX, hi = 0;
    for (const auto& l : elf.loads) {
        lo = std::min(lo, l.vaddr);
        hi = std::max(hi, l.vaddr + l.memsz);
    }
    if (lo == UINT64_MAX) { lo = elf.sections.empty() ? 0 : elf.sections.front().addr; hi = lo; }
    // Over-reserve so a guest brk/mmap has room without moving the image.
    const uint64_t kMin = UINT64_C(256) << 20;
    const uint64_t kExtend = UINT64_C(192) << 20;
    uint64_t mem_base = lo & ~UINT64_C(0xFFF);
    uint64_t mem_size = std::max(kMin, ((hi - mem_base) + kExtend + 0xFFFFF) & ~UINT64_C(0xFFFFF));

    const std::string seg_dir = out_dir + "/a64port/segments";
    std::error_code ec;
    std::filesystem::create_directories(Utf8Path(seg_dir), ec);
    std::filesystem::create_directories(Utf8Path(out_dir + "/a64port"), ec);

    struct Seg { std::string name, file; uint64_t va = 0, size = 0; };
    struct Nob { std::string name; uint64_t va = 0, size = 0; };
    struct Rel { uint64_t va = 0, value = 0; };
    struct Ire { uint64_t va = 0, resolver = 0; };
    struct Unr { uint64_t va = 0, addend = 0, sym = 0; uint32_t type = 0; std::string where; };
    std::vector<Seg> segs;
    std::vector<Nob> nobs;
    std::vector<Rel> rels;
    std::vector<Ire> ires;
    std::vector<Unr> unrs;

    int idx = 0;
    for (const auto& s : elf.sections) {
        if (!s.alloc() || s.size == 0) continue;
        if (s.nobits()) { nobs.push_back({s.name, s.addr, s.size}); continue; }
        char nm[512];
        snprintf(nm, sizeof nm, "%02d_%s.bin", idx++, Sanitize(s.name).c_str());
        WriteIfChanged(Utf8Path(seg_dir + "/" + nm),
                       elf.bytes.data() + s.off, (size_t)s.size);
        segs.push_back({s.name, std::string("segments/") + nm, s.addr, s.size});
    }

    // The ELF header and program headers are not inside any section, so they
    // would otherwise be zero-filled - and AT_PHDR must point at real bytes.
    // The first PT_LOAD maps file offset 0, so the headers live at its vaddr.
    uint64_t phdr_va = 0, phnum = 0, phent = 0, ehsize = 0;
    {
        std::memcpy(&ehsize, elf.bytes.data() + 52, 2);
        uint64_t phoff = 0;
        uint16_t pn = 0, pe = 0;
        std::memcpy(&phoff, elf.bytes.data() + 32, 8);
        std::memcpy(&pe, elf.bytes.data() + 54, 2);
        std::memcpy(&pn, elf.bytes.data() + 56, 2);
        phnum = pn;
        phent = pe;
        uint64_t hdr_len = std::max<uint64_t>(ehsize, phoff + (uint64_t)pn * pe);
        bool have = false;
        uint64_t first_load = 0;
        for (const auto& l : elf.loads)
            if (!have || l.vaddr < first_load) { first_load = l.vaddr; have = true; }
        if (have && hdr_len > 0 && hdr_len <= elf.bytes.size()) {
            WriteIfChanged(Utf8Path(seg_dir + "/elfhdr.bin"),
                           elf.bytes.data(), (size_t)hdr_len);
            segs.push_back({"elfhdr", "segments/elfhdr.bin", first_load, hdr_len});
            phdr_va = first_load + phoff;
        }
    }

    for (const auto& s : elf.sections) {
        if (!s.rela() || s.size < 24) continue;
        const uint8_t* p = elf.bytes.data() + s.off;
        for (size_t o = 0; o + 24 <= s.size; o += 24) {
            uint64_t off = 0, info = 0, add = 0;
            std::memcpy(&off, p + o, 8);
            std::memcpy(&info, p + o + 8, 8);
            std::memcpy(&add, p + o + 16, 8);
            const uint32_t type = (uint32_t)(info & 0xffffffffu);
            const uint64_t sym = info >> 32;
            if (type == 1027) {                    // R_AARCH64_RELATIVE
                rels.push_back({off, add});
            } else if (type == 1032) {             // R_AARCH64_IRELATIVE
                ires.push_back({off, add});
            } else if (type == 257 && sym == 0) {  // R_AARCH64_ABS64, no symbol
                rels.push_back({off, add});
            } else {
                unrs.push_back({off, add, sym, type, s.name});
            }
        }
    }

    // Everything the image occupies, so the shim knows where a guest heap may
    // start without colliding with a section.
    uint64_t image_end = mem_base;
    for (const auto& s : segs) image_end = std::max(image_end, s.va + s.size);
    for (const auto& s : nobs) image_end = std::max(image_end, s.va + s.size);
    image_end = (image_end + 0xFFFFF) & ~UINT64_C(0xFFFFF);

    std::ostringstream o;
    o << "/* auto-generated by tools/recomp/a64recomp.cpp - guest image layout */\n"
         "#pragma once\n#include <stdint.h>\n\n";
    o << "#define A64PORT_MEM_BASE 0x" << std::hex << mem_base << "ull\n";
    o << "#define A64PORT_MEM_SIZE 0x" << std::hex << mem_size << "ull\n";
    o << "#define A64PORT_IMAGE_END 0x" << std::hex << image_end << "ull\n";
    o << "#define A64PORT_ENTRY    0x" << std::hex << elf.entry << "ull\n";
    o << "#define A64PORT_PHDR     0x" << std::hex << phdr_va << "ull\n";
    o << "#define A64PORT_PHNUM    " << std::dec << phnum << "u\n";
    o << "#define A64PORT_PHENT    " << std::dec << phent << "u\n\n";

    o << "typedef struct { const char* name; const char* file; uint64_t va; uint64_t size; }\n"
         "    A64portSegment;\n";
    o << "static const A64portSegment A64PORT_SEGMENTS[] = {\n";
    for (const auto& s : segs)
        o << "  {\"" << s.name << "\", \"" << s.file << "\", 0x" << std::hex << s.va
          << "ull, 0x" << s.size << "ull},\n";
    o << "};\n#define A64PORT_SEGMENT_COUNT " << std::dec << segs.size() << "\n\n";

    o << "/* SHT_NOBITS: covered by the zeroed guest allocation, listed so the shim\n"
         "   can confirm the range lies inside it. */\n";
    o << "typedef struct { const char* name; uint64_t va; uint64_t size; } A64portNobits;\n";
    o << "static const A64portNobits A64PORT_NOBITS[] = {\n";
    for (const auto& s : nobs)
        o << "  {\"" << s.name << "\", 0x" << std::hex << s.va << "ull, 0x" << s.size
          << "ull},\n";
    o << "};\n#define A64PORT_NOBITS_COUNT " << std::dec << nobs.size() << "\n\n";

    o << "/* Applied as plain stores: value is already the final guest VA, because\n"
         "   the image is loaded at its link addresses (module base 0). */\n";
    o << "typedef struct { uint64_t va; uint64_t value; } A64portReloc;\n";
    o << "static const A64portReloc A64PORT_RELOCS[] = {\n";
    for (const auto& r : rels)
        o << "  {0x" << std::hex << r.va << "ull, 0x" << r.value << "ull},\n";
    o << "};\n#define A64PORT_RELOC_COUNT " << std::dec << rels.size() << "\n\n";

    o << "/* R_AARCH64_IRELATIVE: call the resolver (translated guest code) and\n"
         "   store the address it returns in x0. */\n";
    o << "typedef struct { uint64_t va; uint64_t resolver; } A64portIreloc;\n";
    o << "static const A64portIreloc A64PORT_IRELOCS[] = {\n";
    for (const auto& r : ires)
        o << "  {0x" << std::hex << r.va << "ull, 0x" << r.resolver << "ull},\n";
    o << "};\n#define A64PORT_IRELOC_COUNT " << std::dec << ires.size() << "\n\n";

    o << "/* Symbol-based relocations: no resolver for the guest's own DSOs yet.\n"
         "   The shim reports each one rather than leaving a zero where a pointer\n"
         "   belongs. */\n";
    o << "typedef struct { uint64_t va; uint32_t type; uint32_t sym; uint64_t addend;\n"
         "                   const char* section; } A64portUnresolved;\n";
    o << "static const A64portUnresolved A64PORT_UNRESOLVED[] = {\n";
    for (const auto& r : unrs)
        o << "  {0x" << std::hex << r.va << "ull, " << std::dec << r.type << "u, " << r.sym
          << "u, 0x" << std::hex << r.addend << "ull, \"" << r.where << "\"},\n";
    o << "};\n#define A64PORT_UNRESOLVED_COUNT " << std::dec << unrs.size() << "\n";

    WriteIfChanged(Utf8Path(out_dir + "/a64port/layout.h"), o.str());

    std::fprintf(stderr,
                 "  layout: base=0x%llx size=%llu MB entry=0x%llx\n"
                 "  image: %zu sections, %zu nobits; relocs %zu relative, %zu irelative, "
                 "%zu unresolved\n",
                 (unsigned long long)mem_base, (unsigned long long)(mem_size >> 20),
                 (unsigned long long)elf.entry, segs.size(), nobs.size(), rels.size(),
                 ires.size(), unrs.size());
}

// One CSV row per unhandled signature: enough to classify each as a real
// instruction gap or as data that block discovery walked.
void DumpSignatures(const char* path, const RecompileStats& st) {
    std::ofstream o(path);
    o << "signature,count,group,example_insn,example_pc\n";
    for (const auto& [sig, site] : st.unhandled_by_signature) {
        char buf[256];
        snprintf(buf, sizeof buf, "0x%08x,%zu,%s,0x%08x,0x%llx\n", sig, site.count,
                 EncodingGroupName((sig >> 25) & 0xF), site.example_insn,
                 (unsigned long long)site.example_pc);
        o << buf;
    }
}

// Every distinct unhandled encoding with its count, so a single instruction
// family can be sized exactly rather than inferred from a 10-bit signature.
void DumpExact(const char* path, const std::map<uint32_t, size_t>& exact) {
    std::vector<std::pair<size_t, uint32_t>> v;
    for (const auto& [w, c] : exact) v.push_back({c, w});
    std::sort(v.begin(), v.end(), [](const auto& a, const auto& b) { return a.first > b.first; });
    std::ofstream o(path);
    o << "count,encoding\n";
    char buf[64];
    for (const auto& [c, w] : v) { snprintf(buf, sizeof buf, "%zu,0x%08x\n", c, w); o << buf; }
}

std::string Stem(const std::string& path) {
    const size_t slash = path.find_last_of("/\\");
    std::string f = slash == std::string::npos ? path : path.substr(slash + 1);
    const size_t dot = f.find_last_of('.');
    return dot == std::string::npos ? f : f.substr(0, dot);
}

}  // namespace

// ── Hand-written leaves (R1; see tools/recomp/hand/README.md) ──────────────
//
// Leaves live in tools/recomp/hand/*.c, one function per (module, address)
// marked with A64PORT_LEAF or A64PORT_LEAF_FILTER (hand/a64port_hand.h). They are
// copied into the emitted project and compiled with it by build-guest.sh, so
// editing a leaf needs no driver rebuild, a typo is a compile error, and the
// code reads as C rather than as an escaped string constant.
//
//   A64PORT_LEAF         replaces the block body entirely.
//   A64PORT_LEAF_FILTER  runs before the translated body and returns 1 when it
//                       handled the block, 0 to run the translated body. This
//                       is how a leaf hands a slow path back (the engine hook
//                       is g_block_prefix).
//   A64PORT_LEAF_FILTER_TO(mod, addr, target)
//                       a filter that, when it returns 1, continues at the fixed
//                       guest address `target` through the emitter's own branch
//                       (a goto inside a grouped function). A plain filter that
//                       returns 1 with a new c->pc instead unwinds every caller
//                       to the dispatcher, which resumes them block by block -
//                       fine once per frame, ruinous inside a per-column loop.
//
// The table is applied unconditionally: re-emitting regenerates whole units, so
// a leaf behind a remembered flag would eventually be dropped with no error and
// no failing test. --no-native-leaf is the A/B escape hatch, and a leaf that
// matches no block fails the emit instead of silently reverting.
struct HandLeaf {
    std::string mod;
    uint64_t    addr = 0;
    std::string name;          // a64port_hand_<mod>_0x<addr>
    bool        filter = false;
    bool        has_to = false;    // A64PORT_LEAF_FILTER_TO: continue at `to` on 1
    uint64_t    to = 0;
    unsigned    hits = 0;
};
static std::vector<HandLeaf> g_hand_leaves;

static std::string HandLeafName(const std::string& mod, uint64_t addr) {
    char b[192];
    snprintf(b, sizeof b, "a64port_hand_%s_0x%llx", mod.c_str(), (unsigned long long)addr);
    return b;
}

static void Trim(std::string& s) {
    const char* ws = " \t\r\n";
    const size_t a = s.find_first_not_of(ws);
    const size_t b = s.find_last_not_of(ws);
    s = (a == std::string::npos) ? std::string() : s.substr(a, b - a + 1);
}

static bool IsIdent(const std::string& s) {
    if (s.empty()) return false;
    for (char ch : s)
        if (!std::isalnum((unsigned char)ch) && ch != '_') return false;
    return true;
}

// One .c file's A64PORT_LEAF[_FILTER](module, 0xaddr) markers. The token is not
// stripped from comments or strings: hand files do not otherwise contain it, and
// quietly honouring a marker inside a comment would be worse than missing one.
static void ParseHandSource(const std::string& text, const std::string& path) {
    static const char* kFilter = "A64PORT_LEAF_FILTER";
    static const char* kPlain  = "A64PORT_LEAF";
    static const char* kFilterTo = "A64PORT_LEAF_FILTER_TO";
    for (size_t at = text.find(kPlain); at != std::string::npos; at = text.find(kPlain, at + 1)) {
        if (at > 0 && (std::isalnum((unsigned char)text[at - 1]) || text[at - 1] == '_')) continue;
        const bool filter_to = text.compare(at, std::strlen(kFilterTo), kFilterTo) == 0;
        const bool filter = filter_to || text.compare(at, std::strlen(kFilter), kFilter) == 0;
        size_t p = at + std::strlen(filter_to ? kFilterTo : filter ? kFilter : kPlain);
        while (p < text.size() && std::isspace((unsigned char)text[p])) ++p;
        if (p >= text.size() || text[p] != '(') continue;
        const size_t close = text.find(')', p);
        if (close == std::string::npos) {
            std::fprintf(stderr, "%s: unclosed A64PORT_LEAF(\n", path.c_str());
            continue;
        }
        std::string args = text.substr(p + 1, close - p - 1);
        const size_t comma = args.find(',');
        if (comma == std::string::npos) {
            std::fprintf(stderr, "%s: A64PORT_LEAF takes (module, address)\n", path.c_str());
            continue;
        }
        std::string mod = args.substr(0, comma);
        std::string addr_s = args.substr(comma + 1);
        std::string to_s;
        if (filter_to) {
            const size_t comma2 = addr_s.find(',');
            if (comma2 == std::string::npos) {
                std::fprintf(stderr, "%s: A64PORT_LEAF_FILTER_TO takes (module, address, target)\n",
                             path.c_str());
                continue;
            }
            to_s = addr_s.substr(comma2 + 1);
            addr_s = addr_s.substr(0, comma2);
            Trim(to_s);
        }
        Trim(mod);
        Trim(addr_s);
        if (!IsIdent(mod) || addr_s.empty()) {
            std::fprintf(stderr, "%s: bad A64PORT_LEAF arguments (%s, %s)\n", path.c_str(),
                         mod.c_str(), addr_s.c_str());
            continue;
        }
        HandLeaf leaf;
        leaf.mod = mod;
        leaf.addr = std::strtoull(addr_s.c_str(), nullptr, 0);
        leaf.name = HandLeafName(mod, leaf.addr);
        leaf.filter = filter;
        if (filter_to) {
            leaf.has_to = true;
            leaf.to = std::strtoull(to_s.c_str(), nullptr, 0);
        }
        for (const auto& other : g_hand_leaves)
            if (other.mod == leaf.mod && other.addr == leaf.addr)
                std::fprintf(stderr, "%s: warning: %s+0x%llx is defined twice\n", path.c_str(),
                             leaf.mod.c_str(), (unsigned long long)leaf.addr);
        g_hand_leaves.push_back(leaf);
    }
}

// Load every .c in a hand directory, collecting the paths so the caller can
// copy them beside the emitted units.
static bool LoadHandDir(const std::string& dir, std::vector<std::string>& sources) {
    DIR* d = opendir(dir.c_str());
    if (!d) return false;
    std::vector<std::string> names;
    while (struct dirent* ent = readdir(d)) {
        const std::string n = ent->d_name;
        if (n.size() > 2 && n.compare(n.size() - 2, 2, ".c") == 0) names.push_back(n);
    }
    closedir(d);
    std::sort(names.begin(), names.end());
    for (const auto& n : names) {
        const std::string path = dir + "/" + n;
        std::ifstream in(path);
        if (!in) continue;
        const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        ParseHandSource(text, path);
        sources.push_back(path);
    }
    return true;
}

static HandLeaf* FindHandLeaf(const char* mod, uint64_t vaddr, bool filter) {
    for (auto& leaf : g_hand_leaves)
        if (leaf.filter == filter && leaf.addr == vaddr && leaf.mod == mod) return &leaf;
    return nullptr;
}

// The engine consults this once per block; a returned body replaces the
// translated instructions for that block.
static const char* OverrideBlockC(const char* mod, uint64_t vaddr, uint32_t count) {
    (void)count;
    HandLeaf* leaf = FindHandLeaf(mod, vaddr, false);
    if (!leaf) return nullptr;
    ++leaf->hits;
    static std::string body;
    body  = "{ extern void ";
    body += leaf->name;
    body += "(GuestContext*); ";
    body += leaf->name;
    body += "(c); return; }\n";
    return body.c_str();
}

// ...and this once per block too, emitted after the guard and before the body.
static const char* PrefixBlockC(const char* mod, uint64_t vaddr, uint32_t count) {
    (void)count;
    HandLeaf* leaf = FindHandLeaf(mod, vaddr, true);
    if (!leaf) return nullptr;
    ++leaf->hits;
    static std::string body;
    body  = "    { extern int ";
    body += leaf->name;
    body += "(GuestContext*); if (";
    body += leaf->name;
    body += leaf->has_to ? "(c)) " + Branch(leaf->to) + " }\n" : std::string("(c)) return; }\n");
    return body.c_str();
}

// A leaf must have matched a block while emitting its module. A miss means the
// block no longer exists (a different library build), the address is wrong, or
// the override was disabled -- either way the output would silently regress.
static bool VerifyNativeLeaves(const std::string& mod) {
    bool ok = true;
    for (const auto& leaf : g_hand_leaves) {
        if (leaf.mod != mod) continue;
        if (leaf.hits == 0) {
            std::fprintf(stderr,
                         "error: hand leaf %s+0x%llx was not emitted "
                         "(block missing from this build, or --no-native-leaf)\n",
                         leaf.mod.c_str(), (unsigned long long)leaf.addr);
            ok = false;
        }
    }
    return ok;
}

int main(int argc, char** argv) {
    // Strict static mode. The engine gates a few forms behind g_translate_all
    // precisely because a JIT fallback exists to carry them; on our targets
    // (ARMv7 and any other native host) there is no fallback, so every gated
    // form must be emitted or the guest dies on the first one it meets.
    // ELF input is validated before anything else, so this only affects the
    // encode/decode decision, never the ISA check.
    g_translate_all = true;

    if (argc < 2) {
        std::fprintf(stderr,
                     "usage: %s <aarch64-elf> [out-dir] [--mod NAME] [--entry HEX]\n"
                     "          [--roots FILE] [--no-eh-frame] [--stats-only] [--examples N]\n"
                     "          [--no-lookup-roots] [--no-reloc-roots] [--no-data-roots] [--coverage] [--dump-roots FILE]\n"
                     "          [--functions-report] [--functions-plan FILE] [--chain] [--hand DIR] [--names FILE] [--no-names] [--dump-names FILE]\n"
                     "          [--fpx] [--fastmem] [--guard-gen] [--trusted] [--vec-fast]\n"
                     "          [--vec-fast-all] [--no-native-leaf]\n"
                     "          [--callret] [--functions] [--fn-single] [--locals] [--locals-changed]\n"
                     "          [--flags-dce] [--fp-outline] [--fpx-batch] [--restrict] [--narrow-pc]\n",
                     argv[0]);
        return 2;
    }
    std::string input = argv[1];
    std::string out_dir;
    std::string mod;
    std::string roots_file;
    uint64_t entry_override = 0;
    bool have_entry = false, no_eh = false, stats_only = false;
    std::string dump_signatures, exact_map;
    size_t examples = 12;
    // ABI 6 emit features, all off by default (see the vendored engine's
    // PROVENANCE and mk8-recomp's own notes):
    //   --fpx       exact native FP fast path (needs -ffp-contract=off
    //               -fno-fast-math, which build-guest.sh now passes);
    //   --fastmem   page-table memory helpers - standalone builds have no page
    //               table, so this only changes the runtime text and is a
    //               prerequisite for --guard-gen;
    //   --guard-gen verify each block's code guard once per code change rather
    //               than on every entry (needs --fastmem, plus a host that
    //               calls recomp_image_guard_gen_v1; see the emitted
    //               recomp_export.c).
    //   --trusted   the image does not self-modify, so omit the code guard and its
    //               per-unit `_e` verification array entirely (see
    //               g_emit_trusted). Keep the guarded emit as the oracle.
    bool opt_fpx = false, opt_fastmem = false, opt_guard_gen = false;
    bool opt_trusted = false;
    bool opt_vec_fast = false;
    // Native leaves are ON by default: they are part of how this binary is
    // built, not an experiment. --no-native-leaf is the A/B escape hatch.
    bool opt_native_leaf = true;
    // Block-discovery root sources beyond entry/.dynsym/.eh_frame (R2/R4),
    // and the coverage report (R6). On by default; the
    // --no-* pair exists so the guarded emit stays the A/B oracle.
    bool opt_lookup_roots = true;
    bool opt_reloc_roots = true;
    bool opt_data_roots = true;
    bool opt_coverage = false;
    bool opt_functions_report = false;
    std::string functions_plan;
    // R5 step -1: direct branches become ChainTo (a direct C tail call) instead
    // of RCJ. Off by default.
    bool opt_chain = false;
    bool opt_callret = false;     // guest calls as host calls (implies --chain)
    bool opt_functions = false;   // R5 step 0: one C function per guest function
    bool opt_locals = false;      // R5 step 1: keep GPRs in C locals within a function
    bool opt_locals_changed = false;  // R5 step 2: sync only the changed GPRs
    std::string dump_roots;
    std::vector<std::string> hand_dirs;      // every leaf directory: --hand (repeatable), else A64PORT_HAND_DIRS
    std::vector<std::string> names_files;
    std::string dump_names;
    bool opt_names = true;
    // The general form of the vector fast path: every block, not just the
    // driver's allowlist. Kept separate so the allowlist build stays the
    // narrow, byte-exact A/B and the general one is opt-in.
    bool opt_vec_fast_all = false;

    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : std::string(); };
        if (a == "--mod") mod = next();
        else if (a == "--entry") { entry_override = std::strtoull(next().c_str(), nullptr, 16); have_entry = true; }
        else if (a == "--roots") roots_file = next();
        else if (a == "--no-eh-frame") no_eh = true;
        else if (a == "--stats-only") stats_only = true;
        else if (a == "--dump-signatures") dump_signatures = next();
        else if (a == "--dump-exact") exact_map = next();
        else if (a == "--examples") examples = std::strtoull(next().c_str(), nullptr, 10);
        else if (a == "--fpx") opt_fpx = true;
        else if (a == "--fastmem") opt_fastmem = true;
        else if (a == "--guard-gen") opt_guard_gen = true;
        else if (a == "--trusted") opt_trusted = true;
        else if (a == "--vec-fast") opt_vec_fast = true;
        else if (a == "--native-leaf") opt_native_leaf = true;
        else if (a == "--no-native-leaf") opt_native_leaf = false;
        else if (a == "--vec-fast-all") opt_vec_fast_all = true;
        else if (a == "--no-lookup-roots") opt_lookup_roots = false;
        else if (a == "--no-reloc-roots") opt_reloc_roots = false;
        else if (a == "--no-data-roots") opt_data_roots = false;
        else if (a == "--lookup-roots") opt_lookup_roots = true;
        else if (a == "--coverage") opt_coverage = true;
        else if (a == "--functions-report") opt_functions_report = true;
        else if (a == "--functions-plan") functions_plan = next();
        else if (a == "--chain") opt_chain = true;
        else if (a == "--callret") { opt_callret = true; opt_chain = true; }
        else if (a == "--fp-outline") g_emit_fp_outline = true;
        else if (a == "--flags-dce") g_emit_flags_dce = true;
        else if (a == "--fpx-batch") g_emit_fpx_batch = true;
        else if (a == "--no-interior-check") g_emit_no_interior = true;
        else if (a == "--restrict") g_emit_restrict = true;
        else if (a == "--narrow-pc") g_emit_narrow_pc = true;
        else if (a == "--fn-single") { g_emit_fn_single = true; opt_functions = true; opt_callret = true; opt_chain = true; }
        else if (a == "--functions") opt_functions = true;
        else if (a == "--locals") opt_locals = true;
        else if (a == "--locals-changed") opt_locals_changed = true;
        else if (a == "--locals-only") {
            static std::unordered_set<u64> lo;
            std::ifstream lf(next());
            for (std::string ln; std::getline(lf, ln); ) {
                if (ln.empty() || ln[0] == '#') continue;
                lo.insert(std::stoull(ln, nullptr, 16));
            }
            g_locals_only = &lo;
        }
        else if (a == "--dump-roots") dump_roots = next();
        else if (a == "--hand") hand_dirs.push_back(next());
        else if (a == "--names") names_files.push_back(next());
        else if (a == "--no-names") opt_names = false;
        else if (a == "--dump-names") dump_names = next();
        else if (!a.empty() && a[0] != '-') out_dir = a;
    }
    // A colon-separated A64PORT_NAMES is the same as repeating --names, so a
    // build script can point every module at its map without threading a flag.
    if (names_files.empty()) {
        if (const char* env = std::getenv("A64PORT_NAMES"); env && *env) {
            const std::string s = env;
            for (size_t a = 0;;) {
                const size_t t = s.find(':', a);
                names_files.push_back(s.substr(a, t == std::string::npos ? std::string::npos : t - a));
                if (t == std::string::npos) break;
                a = t + 1;
            }
        }
    }
    g_emit_chain = opt_chain;
    g_emit_callret = opt_callret;
    g_emit_fpx = opt_fpx;
    g_emit_fastmem = opt_fastmem;
    g_emit_guard_gen = opt_guard_gen && opt_fastmem;
    g_emit_trusted = opt_trusted;
    g_emit_functions = opt_functions || opt_locals || opt_locals_changed;
    g_emit_locals = opt_locals || opt_locals_changed;
    g_emit_locals_changed = opt_locals_changed;
    if (g_emit_functions && !g_emit_trusted) {
        std::fprintf(stderr, "--functions/--locals require --trusted (R5 grouping is implemented for the trusted emission shape)\n");
        return 2;
    }
    g_vec_fast_all = opt_vec_fast_all;
    // Hand leaves: load before the ELF so the override/prefix hooks are in
    // place for emit.  Leaf directories ("plug-ins": one per application, e.g.
    // apps/<app>/hand) are, in order: every --hand; else the colon-separated
    // A64PORT_HAND_DIRS; else the SDK directory next to the driver (tools/recomp/hand).
    // The SDK directory (a64port_hand.h) is always the source of the header the
    // leaves are compiled against, unless a leaf directory carries its own copy.
    std::vector<std::string> hand_sources;
    std::string sdk_dir;
    {
        std::string self = argv[0];
        const size_t slash = self.find_last_of('/');
        self = (slash == std::string::npos ? std::string(".") : self.substr(0, slash)) + "/hand";
        for (const std::string& cand : {self, std::string("tools/recomp/hand"), std::string("hand")}) {
            DIR* d = opendir(cand.c_str());
            if (d) { closedir(d); sdk_dir = cand; break; }
        }
    }
    if (hand_dirs.empty()) {
        if (const char* e = std::getenv("A64PORT_HAND_DIRS")) {
            std::string list = e;
            size_t pos = 0;
            while (pos <= list.size()) {
                size_t colon = list.find(':', pos);
                if (colon == std::string::npos) colon = list.size();
                if (colon > pos) hand_dirs.push_back(list.substr(pos, colon - pos));
                pos = colon + 1;
            }
        }
    }
    if (hand_dirs.empty() && !sdk_dir.empty()) hand_dirs.push_back(sdk_dir);
    if (opt_native_leaf) {
        if (hand_dirs.empty())
            std::fprintf(stderr, "warning: no hand-leaf directory (--hand DIR, A64PORT_HAND_DIRS): emitting without leaves\n");
        for (const std::string& dir : hand_dirs) {
            const size_t before = g_hand_leaves.size();
            if (LoadHandDir(dir, hand_sources))
                std::fprintf(stderr, "  hand leaves: %zu in %s\n", g_hand_leaves.size() - before, dir.c_str());
            else
                std::fprintf(stderr, "warning: --hand %s is not a directory\n", dir.c_str());
        }
    }
    // --vec-fast applies the NEON fast path to the blocks an application names: vec_fast_blocks.txt in a leaf
    // directory, one hex block address per line ('#' starts a comment).
    static std::unordered_set<u64> vec_fast_blocks;
    if (opt_vec_fast) {
        for (const std::string& dir : hand_dirs) {
            std::ifstream in(dir + "/vec_fast_blocks.txt");
            std::string line;
            while (std::getline(in, line)) {
                line = line.substr(0, line.find('#'));
                const size_t b0 = line.find_first_not_of(" \t\r");
                if (b0 == std::string::npos) continue;
                vec_fast_blocks.insert(std::strtoull(line.c_str() + b0, nullptr, 16));
            }
        }
        if (vec_fast_blocks.empty())
            std::fprintf(stderr, "note: --vec-fast: no vec_fast_blocks.txt in the leaf directories, so no block takes the fast path\n");
        g_vec_fast_blocks = &vec_fast_blocks;
    }
    g_block_override = opt_native_leaf ? OverrideBlockC : nullptr;
    g_block_prefix = opt_native_leaf ? PrefixBlockC : nullptr;
    if (mod.empty()) mod = Stem(input);
    if (out_dir.empty()) out_dir = "out/" + mod;
    if (stats_only) out_dir.clear();

    Elf elf;
    if (!ReadElf(input.c_str(), elf)) return 1;
    const Section* text = elf.find(".text");
    if (!text || text->size == 0) {
        std::fprintf(stderr, "no .text section\n");
        return 1;
    }
    const CodeImage code = BuildCodeImage(elf);

    std::vector<uint64_t> roots;
    std::vector<uint64_t> fn_roots;   // .eh_frame/.dynsym starts: real functions (R5 report)
    size_t fn_mark = 0;
    size_t eh_count = 0;
    if (have_entry) elf.entry = entry_override;
    else if (elf.entry == 0) std::fprintf(stderr, "warning: e_entry is 0; block discovery starts at .text\n");

    AddDynsymRoots(elf, roots);
    fn_roots.insert(fn_roots.end(), roots.begin() + fn_mark, roots.end());
    fn_mark = roots.size();
    if (!no_eh) AddEhFrameRoots(elf, roots, &eh_count);
    fn_roots.insert(fn_roots.end(), roots.begin() + fn_mark, roots.end());
    size_t reloc_roots = 0, tbl_dispatches = 0, tbl_roots = 0, data_roots = 0, data_scanned = 0;
    if (opt_reloc_roots) AddRelocRoots(elf, roots, reloc_roots);
    if (opt_data_roots) AddDataPointerRoots(elf, roots, data_roots, data_scanned);
    if (opt_lookup_roots) AddLookupTableRoots(elf, code, roots, tbl_dispatches, tbl_roots);
    if (!roots_file.empty()) {
        auto r = ReadHexLines(roots_file.c_str());
        roots.insert(roots.end(), r.begin(), r.end());
    }
    std::sort(roots.begin(), roots.end());
    roots.erase(std::unique(roots.begin(), roots.end()), roots.end());
    if (!dump_roots.empty()) {
        std::ofstream rf(dump_roots);
        for (uint64_t a : roots) rf << "0x" << std::hex << a << "\n";
    }

    // Recovered names: the ELF's own symbol tables first, then --names files,
    // which override. With no names the hook stays null and the emitted C is
    // exactly what it was before.
    if (opt_names) {
        std::unordered_map<uint64_t, std::string> elf_names;
        AddElfSymbolNames(elf, elf_names);
        for (const auto& kv : elf_names) g_names.emplace(kv.first, kv.second);
        for (const std::string& f : names_files) LoadNamesFile(f, g_names);
        if (!g_names.empty()) {
            g_block_name = BlockNameHook;
            std::fprintf(stderr, "  names: %zu (%zu from ELF symbols)\n", g_names.size(),
                         elf_names.size());
        }
        if (!dump_names.empty()) {
            std::ofstream nf(dump_names);
            for (const auto& kv : g_names)
                nf << "0x" << std::hex << kv.first << "\t" << kv.second << "\n";
        }
    }

    std::fprintf(stderr,
                 "%s: code %zu bytes (%.2fM insns) base=0x%llx entry=0x%llx\n"
                 "  roots: %zu (.eh_frame %zu%s; relocations +%zu; data pointers +%zu of %zu; lookup tables +%zu in %zu dispatches)\n"
                 "  mode: strict static (g_translate_all; no fallback engine)"
                 "%s%s%s%s%s%s%s%s%s%s\n",
                 input.c_str(), code.bytes.size(), double(code.bytes.size() / 4) / 1e6,
                 (unsigned long long)code.base, (unsigned long long)elf.entry, roots.size(),
                 eh_count, have_entry ? ", entry overridden" : "",
                 reloc_roots, data_roots, data_scanned, tbl_roots, tbl_dispatches,
                 g_emit_fastmem ? "; fastmem" : "", EmitGuardGen() ? "; guard-gen" : "",
                 g_emit_trusted ? "; trusted-image (no code guard)" : "",
                 opt_vec_fast ? "; vec-fast allowlist" : "",
                 opt_vec_fast_all ? "; vec-fast all" : "",
                 opt_native_leaf ? "; native-leaf" : "; no-native-leaf",
                 opt_chain ? "; chain" : "",
                 g_emit_fpx ? "; fpx" : "",
                 opt_functions ? "; functions" : "", opt_locals ? "; locals" : "",
                 opt_locals_changed ? "; locals-changed" : "");
    if (opt_functions_report || !functions_plan.empty())
        FunctionsReport(code, elf.entry, roots, fn_roots, functions_plan);
    if (stats_only) {
        std::map<uint32_t, size_t> exact;
        auto st = WalkOnly(code.bytes.data(), code.bytes.size(), code.base, elf.entry, roots,
                           exact_map.empty() ? nullptr : &exact);
        if (!dump_signatures.empty()) DumpSignatures(dump_signatures.c_str(), st);
        if (!exact_map.empty()) DumpExact(exact_map.c_str(), exact);
        ReportHistogram(st, examples);
        if (opt_coverage) CoverageReport(elf, code, elf.entry, roots);
        return 0;
    }
    if (opt_functions_report || !functions_plan.empty()) {   // report-only: writes nothing but the plan
        if (opt_coverage) CoverageReport(elf, code, elf.entry, roots);
        return 0;
    }

    // Immutable copies for the variadic call: code.bytes is const-qualified through
    // `code` but EmitProject takes a const u8*.
    // Publish the hand sources beside the emitted units; build-guest.sh
    // compiles out/hand/*.c with the generated code.
    if (!hand_sources.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(out_dir + "/hand", ec);
        std::set<std::string> seen_names;
        for (const auto& src : hand_sources) {
            if (!seen_names.insert(src.substr(src.find_last_of('/') + 1)).second) {
                std::fprintf(stderr, "error: two leaf directories both have %s - a leaf file name must be unique\n",
                             src.substr(src.find_last_of('/') + 1).c_str());
                return 1;
            }
            std::ifstream in(src, std::ios::binary);
            if (!in) continue;
            const std::string data((std::istreambuf_iterator<char>(in)),
                                   std::istreambuf_iterator<char>());
            WriteIfChanged(Utf8Path(out_dir + "/hand/" + src.substr(src.find_last_of('/') + 1)),
                           data);
        }
        std::ifstream hin;
        for (const std::string& dir : hand_dirs) {
            hin.open(dir + "/a64port_hand.h", std::ios::binary);
            if (hin.is_open()) break;
            hin.clear();
        }
        if (!hin.is_open() && !sdk_dir.empty()) hin.open(sdk_dir + "/a64port_hand.h", std::ios::binary);
        if (hin.is_open()) {
            const std::string data((std::istreambuf_iterator<char>(hin)),
                                   std::istreambuf_iterator<char>());
            WriteIfChanged(Utf8Path(out_dir + "/hand/a64port_hand.h"), data);
        }
    }
    // R5: sorted function entries (.eh_frame/.dynsym starts, the same set the
    // grouping report uses) so the emitter can group blocks into functions.
    std::vector<uint64_t> fn_entries_sorted;
    if (g_emit_functions) {
        fn_entries_sorted = fn_roots;
        std::sort(fn_entries_sorted.begin(), fn_entries_sorted.end());
        fn_entries_sorted.erase(std::unique(fn_entries_sorted.begin(), fn_entries_sorted.end()),
                                fn_entries_sorted.end());
        g_fn_entries = &fn_entries_sorted;
    }
    auto st = EmitProject(mod, code.bytes.data(), code.bytes.size(), code.base, out_dir,
                          /*source_only=*/false, nullptr, 0, nullptr, 0, elf.entry, mod,
                          roots.empty() ? nullptr : &roots);
    WriteLayout(out_dir, elf);
    if (opt_coverage) CoverageReport(elf, code, elf.entry, roots);
    if (!dump_signatures.empty()) DumpSignatures(dump_signatures.c_str(), st);
    if (opt_native_leaf && !VerifyNativeLeaves(mod)) return 1;
    std::printf("emitted %s (mod=%s)\n", out_dir.c_str(), mod.c_str());
    ReportHistogram(st, examples);
    return st.unhandled ? 0 : 0;
}
