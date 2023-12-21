---
description: Is ghidriff useful for my platform?
---

## Installation / Running

`ghidriff` will run anywhere Python will run. Follow the [Quick Start Setup](<Quick Start Environment Setup.md>) for details.

## Diffing on various platforms (or where is this useful?)

> Will `ghidriff` diff my platform?

Always.

> Will `ghidriff` do it well?? 
 
That depends.  :)


You should be able to diff any binary that Ghidra can analyze and decompile. Typically, this native code outside of frameworks.

### Windows

Binary diffing  with `ghidriff` Windows works best with native Windows binaries (unmanaged) vs(managed) .NET code. It's not impossible, but diffing managed code via Ghidra has mixed results. You are better off using something like [dnSpy](https://github.com/dnSpy/dnSpy) to decompile the application and then just text diff the result. 





## Mac / iOS

Ghidra is getting much better at analyzing and decompiling objective-c.  Mac/iOS binaries both x64 and arm64 should work. Give it a shot.

## Android

For any native arm binary Ghidra should do well. If you want to through in an APK, you will need to pull out the binaries to diff. 

## Linux / iOT

Again, if Ghidra can handle the analysis, give it a shot. 