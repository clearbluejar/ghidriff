#!/bin/sh
# Rebuild the operand-only fixture (macOS with Xcode). The binaries are committed so CI needs no toolchain.
set -e
cd "$(dirname "$0")"
mkdir -p bin
CC="xcrun clang -arch arm64 -O1"
$CC -o bin/operand.base operand.c
$CC -o bin/operand.same operand.c
$CC -DBOUND=32 -o bin/operand.const operand.c
$CC -DSTACKSIZE=128 -o bin/operand.stack operand.c
$CC -DEXTRA_CHECK -o bin/operand.struct operand.c
xcrun clang --version | head -1 > bin/TOOLCHAIN
