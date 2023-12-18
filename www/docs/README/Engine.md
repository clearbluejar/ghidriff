---
sidebar_position: 2
---

<p align='center'>
<img src="https://user-images.githubusercontent.com/3752074/229976340-96394970-152f-4d88-9fe4-a46589b31c50.png" height="300">
</p>

> An "engine" is a self-contained, but externally-controllable, piece of code that encapsulates powerful logic designed to perform a specific type of work.

`ghidriff` provides a core base class [GhidraDiffEngine](https://github.com/clearbluejar/ghidriff/ghidriff/ghidra_diff_engine.py) that can be extended to create your own binary diffing [implementations](#implementations).

The base class implements the first 3 steps of the Ghidra [headless workflow](https://github.com/clearbluejar/ghidra-python-vscode-devcontainer-skeleton#steps):
>1. **Create Ghidra Project** - Directory and collection of Ghidra project files and data
>2. **Import Binary to project** - Import one or more binaries to the project for analysis
>3. **Analyze Binary** - Ghidra will perform default binary analysis on each binary

The base class provides the abstract method [find_matches](https://github.com/clearbluejar/ghidriff/ghidriff/ghidra_diff_engine.py) where the actual diffing (function matching) takes place.

