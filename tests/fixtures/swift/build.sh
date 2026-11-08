#!/bin/sh
# Rebuild the Swift fixture dylibs (macOS with Xcode or the Command Line Tools).
# The built dylibs are committed so CI (Linux) does not need a Swift toolchain.
set -e
cd "$(dirname "$0")"
mkdir -p bin
for v in old new; do
    flag=""
    [ "$v" = new ] && flag="-DFIXTURE_NEW"
    xcrun swiftc -target arm64e-apple-macos14.0 -O -emit-library -module-name SwiftFixture \
        $flag -o "bin/libSwiftFixture.$v.dylib" SwiftFixture.swift
done
xcrun swiftc --version 2>&1 | head -1 > bin/TOOLCHAIN
shasum -a 256 bin/*.dylib
