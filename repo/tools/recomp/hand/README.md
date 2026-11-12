# Hand-leaf SDK

`a64port_hand.h` is the only thing here: the macros and helpers a hand-written "leaf" (C that runs instead of the
translated code for one module + address) is compiled against.  The leaves themselves belong to the application, not
to the recompiler:

    apps/<app>/hand/*.c        leaf plug-ins, one file per module is the convention (libc.c, <exe>.c, ...)
    apps/<app>/profile.json    the app's files inside the user's rootfs (gen_mods.py)

The emitter finds leaf directories, in order: every `--hand DIR` (repeatable), else the colon-separated
`A64PORT_HAND_DIRS`, else this directory.  `scripts/a64port-env.sh` exports `A64PORT_HAND_DIRS=$A64PORT_APP_DIR/hand`
when that exists.  The emitter finds leaves by scanning for the text `A64PORT_LEAF(`, `A64PORT_LEAF_FILTER(` and
`A64PORT_LEAF_FILTER_TO(` (not through the preprocessor), copies the files into `<out>/hand/` with the header, and
fails the emit when a leaf matches no block.  Two directories must not contain the same file name.

A leaf is tied to one build of the guest binary (its addresses): ship a leaf set together with a check of the
binary it was written for (hashes), and verify every leaf with `scripts/verify-leaf(s).sh` (a differential against
the real code under qemu) before it is built in.
