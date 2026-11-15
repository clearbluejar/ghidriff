#!/bin/sh
# Rebuild the switch-repair fixture (macOS with Xcode). The dylibs are committed so CI needs no toolchain.
#
# loopswitch.c / loopswitch0.c are the reproducer for the upstream Ghidra report (cases 1..11 and
# 0..10). On arm64e, clang hardens the jump table (cmp x16, #N; csel x16, x16, xzr, ls), and Ghidra
# cannot recover it when the cases start at 1. "new" differs from "old" only inside one case body
# (a mask is added), which Ghidra places outside the function when the switch is not recovered.
set -e
cd "$(dirname "$0")"
mkdir -p bin tmp
build() {  # build <source> <arch>
    name=$(basename "$1" .c)
    sed 's/out\[1\] = get(r, 16) + len;/out[1] = (get(r, 16) + len) \& 0x7fff;/' "$1" > "tmp/$name.new.c"
    grep -q '0x7fff' "tmp/$name.new.c"
    xcrun clang -arch "$2" -O2 -dynamiclib -o "bin/$name.$2.old.dylib" "$1"
    xcrun clang -arch "$2" -O2 -dynamiclib -o "bin/$name.$2.new.dylib" "tmp/$name.new.c"
}
build loopswitch.c arm64e    # hardened, cases 1..11: needs switch repair
build loopswitch0.c arm64e   # control: hardened, cases 0..10: Ghidra recovers it
build loopswitch.c arm64     # control: no hardening: Ghidra recovers it
rm -r tmp
xcrun clang --version | head -1 > bin/TOOLCHAIN
