---
sidebar_position: 1
---

<p align='center'>
<img src="https://github.com/clearbluejar/ghidriff/assets/3752074/170f1a54-24d9-4c8e-ac4d-3b5bea860750" width=60% >
</p>


<p align="center">    
<img align="center" alt="GitHub Workflow Status (with event)" src="https://img.shields.io/github/actions/workflow/status/clearbluejar/ghidriff/pytest-devcontainer.yml?label=pytest&style=for-the-badge">
<img align="center" alt="PyPI - Downloads" src="https://img.shields.io/pypi/dm/ghidriff?color=yellow&label=PyPI%20downloads&style=for-the-badge">
<img align="center" src="https://img.shields.io/github/stars/clearbluejar/ghidriff?style=for-the-badge">

## Ghidriff - Ghidra Binary Diffing Engine
`ghidriff` provides a command-line binary diffing capability with a fresh take on diffing workflow and results.

It leverages the power of Ghidra's ProgramAPI and [FlatProgramAPI](https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html) to find the *added*, *deleted*, and *modified* functions of two arbitrary binaries. It is written in Python3 using `pyghidra` to orchestrate Ghidra and `jpype` as the Python to Java interface to Ghidra.

Its primary use case is patch diffing. Its ability to perform a patch diff with a single command makes it ideal for automated analysis. The diffing results are stored in JSON and rendered in markdown (optionally side-by-side HTML). The markdown output promotes "social" diffing, as results are easy to publish in a gist or include in your next writeup or blog post.