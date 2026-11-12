/* SPDX-License-Identifier: GPL-2.0-or-later */
/* icount.c - qemu TCG plugin: total guest (host-to-be) instructions executed,
 * summed over every vCPU (thread).  Deterministic cost metric for ARMv7 builds
 * run under qemu-arm, where wall time means nothing:
 *   cc -shared -fPIC -O2 $(pkg-config --cflags glib-2.0) icount.c -o icount.so
 *   qemu-arm -plugin ./icount.so -d plugin <prog>     -> "icount: N"
 */
#include <inttypes.h>
#include <stdio.h>
#include <glib.h>
#include <qemu-plugin.h>
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
static struct qemu_plugin_scoreboard* sb;
static qemu_plugin_u64 cnt;
static void tb_trans(struct qemu_plugin_tb* tb, void* ud) {
    (void)ud;
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(tb, QEMU_PLUGIN_INLINE_ADD_U64, cnt,
                                                      qemu_plugin_tb_n_insns(tb));
}
static void at_exit(void* p) {
    (void)p;
    char b[64];
    snprintf(b, sizeof b, "icount: %" PRIu64 "\n", qemu_plugin_u64_sum(cnt));
    qemu_plugin_outs(b);
    qemu_plugin_scoreboard_free(sb);
}
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t* info,
                                           int argc, char** argv) {
    (void)info; (void)argc; (void)argv;
    sb = qemu_plugin_scoreboard_new(sizeof(uint64_t));
    cnt = qemu_plugin_scoreboard_u64(sb);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans, NULL);
    qemu_plugin_register_atexit_cb(id, at_exit, NULL);
    return 0;
}
