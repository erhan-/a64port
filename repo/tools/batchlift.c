/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * a64port — batch Rellume lift driver.
 *
 * Lifts every function address listed in <funcs-file> from <guest-elf>:
 *   - dumps the LLVM IR of each function to <outdir>/<addr>.ll
 *   - records a census of what the lifted code needs at run time
 *     (call-hook sites, basic blocks, LLVM instructions)
 *   - with --calls, configures Rellume's call/ret-lifting hook, so BL/BLR are
 *     lifted as calls to @a64port_call and RET is lifted as a return to the
 *     dispatcher. Without it, Rellume *silently truncates* at the first call
 *     (lldecoder.cc stops decoding, the call's branch is inhibited), which
 *     makes "0 failures" meaningless.
 *
 * usage: batchlift <guest-elf> <funcs-file> <outdir> [--calls] [--limit N]
 */
#include <rellume/rellume.h>
#include <llvm-c/Core.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <string>
#include <sys/stat.h>
#include <vector>

struct Guest {
  std::vector<uint8_t> image;
  uintptr_t base = 0;
};

static size_t memcb(size_t addr, uint8_t *buf, size_t size, void *arg) {
  Guest *g = static_cast<Guest *>(arg);
  if (addr < g->base)
    return 0;
  size_t off = addr - g->base;
  if (off >= g->image.size())
    return 0;
  size_t n = std::min(size, g->image.size() - off);
  memcpy(buf, g->image.data() + off, n);
  return n;
}

static bool load_elf(const char *path, Guest &g) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return false;
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  std::vector<uint8_t> file(sz);
  if (fread(file.data(), 1, sz, f) != static_cast<size_t>(sz)) { fclose(f); return false; }
  fclose(f);
  if (file.size() < sizeof(Elf64_Ehdr))
    return false;
  auto *eh = reinterpret_cast<Elf64_Ehdr *>(file.data());
  if (memcmp(eh->e_ident, ELFMAG, 4) != 0 || eh->e_ident[EI_CLASS] != ELFCLASS64)
    return false;
  uintptr_t lo = ~uintptr_t(0), hi = 0;
  for (int i = 0; i < eh->e_phnum; i++) {
    auto *ph = reinterpret_cast<Elf64_Phdr *>(file.data() + eh->e_phoff + i * eh->e_phentsize);
    if (ph->p_type != PT_LOAD) continue;
    lo = std::min(lo, static_cast<uintptr_t>(ph->p_vaddr));
    hi = std::max(hi, static_cast<uintptr_t>(ph->p_vaddr + ph->p_memsz));
  }
  if (hi <= lo) return false;
  lo &= ~uintptr_t(0xfff);
  g.base = lo;
  g.image.assign(hi - lo, 0);
  for (int i = 0; i < eh->e_phnum; i++) {
    auto *ph = reinterpret_cast<Elf64_Phdr *>(file.data() + eh->e_phoff + i * eh->e_phentsize);
    if (ph->p_type != PT_LOAD || ph->p_filesz == 0) continue;
    memcpy(g.image.data() + (ph->p_vaddr - lo), file.data() + ph->p_offset, ph->p_filesz);
  }
  return true;
}

/* void @name(ptr) — Rellume calls hooks with only the CPU state pointer
 * (CpuStructParamIdx() is 0 for every calling convention). */
static LLVMValueRef declare_hook(LLVMModuleRef mod, LLVMContextRef ctx, const char *name) {
  LLVMTypeRef ptr = LLVMPointerTypeInContext(ctx, 0);
  LLVMTypeRef fnty = LLVMFunctionType(LLVMVoidTypeInContext(ctx), &ptr, 1, 0);
  return LLVMAddFunction(mod, name, fnty);
}

static size_t count_occurrences(const std::string &hay, const std::string &needle) {
  size_t n = 0, pos = 0;
  while ((pos = hay.find(needle, pos)) != std::string::npos) { n++; pos += needle.size(); }
  return n;
}

/* Rename the lifted function @0 to @f_<addr> so per-function objects link. */
static std::string rename_entry(std::string ir, uintptr_t addr) {
  char name[32];
  snprintf(name, sizeof name, "f_%lx", (unsigned long) addr);
  std::string out;
  out.reserve(ir.size() + 64);
  for (size_t i = 0; i < ir.size();) {
    if (ir[i] == '@' && i + 2 < ir.size() && ir[i + 1] == '0' &&
        !(isalnum((unsigned char) ir[i + 2]) || ir[i + 2] == '_')) {
      out += '@';
      out += name;
      i += 2;
    } else {
      out += ir[i++];
    }
  }
  return out;
}

int main(int argc, char **argv) {
  if (argc < 4) {
    fprintf(stderr, "usage: %s <guest-elf> <funcs-file> <outdir> [--calls] [--limit N]\n", argv[0]);
    return 1;
  }
  const char *elf = argv[1], *funcs_file = argv[2], *outdir = argv[3];
  bool use_calls = false;
  long limit = -1;
  for (int i = 4; i < argc; i++) {
    if (!strcmp(argv[i], "--calls")) use_calls = true;
    else if (!strcmp(argv[i], "--limit") && i + 1 < argc) limit = strtol(argv[++i], nullptr, 10);
  }

  Guest g;
  if (!load_elf(elf, g)) { fprintf(stderr, "cannot load %s\n", elf); return 1; }
  mkdir(outdir, 0777);

  FILE *ff = fopen(funcs_file, "r");
  if (!ff) { fprintf(stderr, "cannot open %s\n", funcs_file); return 1; }
  std::vector<uintptr_t> addrs;
  char line[64];
  while (fgets(line, sizeof line, ff)) {
    uintptr_t a = strtoull(line, nullptr, 16);
    if (a) addrs.push_back(a);
    if (limit > 0 && (long) addrs.size() >= limit) break;
  }
  fclose(ff);

  fprintf(stderr, "guest base=%#lx mapped=%zu bytes; %zu functions; calls=%d\n",
          (unsigned long) g.base, g.image.size(), addrs.size(), (int) use_calls);

  char csv[512];
  snprintf(csv, sizeof csv, "%s/census.csv", outdir);
  FILE *cf = fopen(csv, "w");
  fprintf(cf, "addr,status,ms,ir_bytes,callsites,tailcalls,blocks,llvm_instrs\n");

  double total_ms = 0;
  size_t ok = 0, fail = 0, total_ir = 0, total_calls = 0, leaves = 0;
  size_t decode_fail = 0;

  for (size_t i = 0; i < addrs.size(); i++) {
    uintptr_t addr = addrs[i];
    LLVMContextRef ctx = LLVMContextCreate();
    LLVMModuleRef mod = LLVMModuleCreateWithNameInContext("rellume", ctx);

    LLConfig *cfg = ll_config_new();
    ll_config_set_architecture(cfg, "aarch64");
    ll_config_enable_verify_ir(cfg, true);
    ll_config_set_position_independent_code(cfg, false);
    if (use_calls)
      ll_config_set_call_func(cfg, declare_hook(mod, ctx, "a64port_call"));

    LLFunc *fn = ll_func_new(mod, cfg);

    auto t0 = std::chrono::steady_clock::now();
    int decode_ok = !ll_func_decode_cfg(fn, addr, memcb, &g);
    LLVMValueRef f = decode_ok ? ll_func_lift(fn) : nullptr;
    auto t1 = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    total_ms += ms;

    if (f && decode_ok) {
      ok++;
      unsigned nbb = LLVMCountBasicBlocks(f);
      size_t nins = 0;
      for (LLVMBasicBlockRef bb = LLVMGetFirstBasicBlock(f); bb; bb = LLVMGetNextBasicBlock(bb))
        for (LLVMValueRef ins = LLVMGetFirstInstruction(bb); ins; ins = LLVMGetNextInstruction(ins))
          nins++;

      char *ir = LLVMPrintModuleToString(mod);
      std::string text = ir ? rename_entry(ir, addr) : "";
      if (ir) LLVMDisposeMessage(ir);
      total_ir += text.size();
      size_t callsites = count_occurrences(text, "call void @a64port_call");
      total_calls += callsites;
      if (callsites == 0) leaves++;

      char path[512];
      snprintf(path, sizeof path, "%s/%lx.ll", outdir, (unsigned long) addr);
      FILE *of = fopen(path, "w");
      if (of) { fwrite(text.data(), 1, text.size(), of); fclose(of); }

      fprintf(cf, "%lx,ok,%.4f,%zu,%zu,0,%u,%zu\n", (unsigned long) addr, ms,
              text.size(), callsites, nbb, nins);
    } else {
      fail++;
      if (!decode_ok) decode_fail++;
      fprintf(cf, "%lx,fail,%.4f,0,0,0,0,0\n", (unsigned long) addr, ms);
    }

    ll_func_dispose(fn);
    ll_config_free(cfg);
    LLVMDisposeModule(mod);
    LLVMContextDispose(ctx);

    if ((i + 1) % 2000 == 0)
      fprintf(stderr, "  %zu/%zu  ok=%zu fail=%zu  %.1fs\n", i + 1, addrs.size(), ok, fail,
              total_ms / 1000.0);
  }
  fclose(cf);

  fprintf(stderr,
          "LIFTED ok=%zu failed=%zu (decode failures=%zu)\n"
          "  time       %.1f ms total, %.3f ms/function\n"
          "  IR         %zu bytes total, %zu bytes avg\n"
          "  call sites %zu total (%.2f/function); leaf functions (no calls) %zu (%.1f%%)\n",
          ok, fail, decode_fail, total_ms, total_ms / (ok + fail), total_ir,
          ok ? total_ir / ok : 0, total_calls, ok ? (double) total_calls / ok : 0.0,
          leaves, ok ? 100.0 * leaves / ok : 0.0);
  return 0;
}
