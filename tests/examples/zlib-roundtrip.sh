#!/bin/sh
# zlib-roundtrip.sh RUN... - drives minigzip for tests/run-examples.sh: compress and decompress a generated input at
# several levels and print checksums.  RUN is the command prefix that runs minigzip (qemu-aarch64 BIN, or BIN).
set -e
awk 'BEGIN { for (i = 0; i < 60000; i++) printf "%d line %d %s\n", i, (i * 7919) % 10007, (i % 13 ? "abc" : "zzzzzzzzzzzzzzzzzzzz") }' > zin.txt
head -c 300000 /dev/zero | tr '\0' 'q' >> zin.txt
for lvl in 1 6 9; do
  "$@" -$lvl < zin.txt > zout.gz
  "$@" -d < zout.gz > zback.txt
  cmp -s zin.txt zback.txt && r=same || r=DIFFERENT
  echo "level $lvl: compressed $(wc -c < zout.gz) bytes, md5 $(md5sum < zout.gz | cut -c1-12), roundtrip $r"
done
"$@" -h < zin.txt | "$@" -d | md5sum | cut -c1-12
rm -f zin.txt zout.gz zback.txt
