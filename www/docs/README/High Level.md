---
sidebar_position: 1
---

```mermaid
flowchart LR

a(old binary - rpcrt4.dll-v1) --> b[GhidraDiffEngine]
c(new binary - rpcrt4.dll-v2) --> b

b --> e(Ghidra Project Files)
b --> diffs_output_dir

subgraph diffs_output_dir
    direction LR
    i(rpcrt4.dll-v1-v2.diff.md)
    h(rpcrt4.dll-v1-v2.diff.json)
    j(rpcrt4.dll-v1-v2.diff.side-by-side.html)
end
```

### Sample Diffs

<div>
    <a href="https://gist.github.com/clearbluejar/b95ae854a92ee917cd0b5c7055b60282"><img width="30%" align=top alt="image" src="https://github.com/clearbluejar/ghidriff/assets/3752074/d53b681f-8cc9-479c-af4c-5ec697cf4989"></a>
    <a href="https://gist.github.com/clearbluejar/b95ae854a92ee917cd0b5c7055b60282#visual-chart-diff"><img width="30%" align=top alt="image" src="https://github.com/clearbluejar/ghidriff/assets/3752074/16d7ae4c-4df9-4bcd-b4af-0ce576d49ad1"></a>
    <a href="https://diffpreview.github.io/?f6fecbc507a9f1a92c9231e3db7ef40d"><img width="30%" align=top src="https://github.com/clearbluejar/ghidriff/assets/3752074/662ed834-738d-4be1-96c3-8500ccab9591"/></a>
<div>

### Features

- Command Line (patch diffing workflow reduced to a single step)
- Highlights important changes in the TOC
- Fast - Can diff the full Windows kernel in less than a minute (after Ghidra analysis is complete)
- Enables Social Diffing
  - Beautiful Markdown Output
  - Easily hosted in a GitHub or GitLab gist, blog, or anywhere markdown is supported
  - Visual Diff Graph Results
- Supports both unified and side by side diff results (unified is default)
- Provides unique Meta Diffs:
  - Binary Strings
  - Called
  - Calling
  - Binary Metadata
- Batteries Included
  - Docker support
  - Automated Testing
  - Ghidra (No license required)

See below for [CVE diffs and sample usage](#sample-usage)

### Design Goals

- Find all added, deleted, and modified functions
- Provide foundation for automation
- Simple, Fast, Accurate
- Resilient
- Extendable
- Easy sharing of results
- Social Diffing

### Powered by Ghidra

The heavy lifting of the binary analysis is done by Ghidra and the diffing is possible via Ghidra's Program API.  `ghidriff` provides a diffing [workflow](#engine), function matching, and resulting markdown and HTML diff output.

