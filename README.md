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

## High Level

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

## Docs

- [ghidriff official Docs](https://clearbluejar.github.io/ghidriff)
- [Blog Post](https://clearbluejar.github.io/posts/ghidriff-ghidra-binary-diffing-engine/)

## Engine

<p align='center'>
<img src="https://user-images.githubusercontent.com/3752074/229976340-96394970-152f-4d88-9fe4-a46589b31c50.png" height="300">
</p>

> An "engine" is a self-contained, but externally-controllable, piece of code that encapsulates powerful logic designed to perform a specific type of work.

`ghidriff` provides a core base class [GhidraDiffEngine](ghidriff/ghidra_diff_engine.py) that can be extended to create your own binary diffing [implementations](#implementations).

The base class implements the first 3 steps of the Ghidra [headless workflow](https://github.com/clearbluejar/ghidra-python-vscode-devcontainer-skeleton#steps):
>1. **Create Ghidra Project** - Directory and collection of Ghidra project files and data
>2. **Import Binary to project** - Import one or more binaries to the project for analysis
>3. **Analyze Binary** - Ghidra will perform default binary analysis on each binary

The base class provides the abstract method [find_matches](ghidriff/ghidra_diff_engine.py) where the actual diffing (function matching) takes place.

## Extending ghidriff 

`ghidriff` can be used as is, but it offers developers the ability to extend the tool by implementing their own differ. The basic idea is create new diffing tools by implementing the `find_matches` method from the base class. 

```python
class NewDiffTool(GhidraDiffEngine):

    def __init__(self,verbose=False) -> None:
        super().__init__(verbose)

    @abstractmethod
    def find_matches(
            self,            
            old: Union[str, pathlib.Path],
            new: Union[str, pathlib.Path]
    ) -> dict:
        """My amazing differ"""

        # find added, deleted, and modified functions
        # <code goes here>

        return [unmatched, matched]
```

### Implementations

There are currently 3 diffing implementations, which also display the evolution of diffing for the project.

1. [SimpleDiff](ghidriff/simple_diff.py) - A simple diff implementation. "Simple" as in it relies mostly on known symbol names for matching. 
2. [StructualGraphDiff](ghidriff/structural_graph_diff.py) - A slightly more advanced differ, beginning to perform some more advanced hashing (such as Halvar's Structural Graph Comparison)
3. [VersionTrackingDiff](ghidriff/version_tracking_diff.py) - The latest differ, with several [correlators](ghidriff/correlators.py) (an algorithm used to score specific associations based on code, program flow, or any observable aspect of comparison) for function matching. **This one is fast.**

Each implementation leverages the base class, and implements `find_changes`.

## Usage

```bash
usage: ghidriff [-h] [--engine {SimpleDiff,StructualGraphDiff,VersionTrackingDiff}] [-o OUTPUT_PATH] [--summary SUMMARY] [-p PROJECT_LOCATION]
                [-n PROJECT_NAME] [-s SYMBOLS_PATH] [-g GZFS_PATH] [--ba BASE_ADDRESS] [--program-options PROGRAM_OPTIONS] [--threaded | --no-threaded]
                [--force-analysis] [--force-diff] [--no-symbols] [--log-level {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}]
                [--file-log-level {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}] [--log-path LOG_PATH] [--va] [--min-func-len MIN_FUNC_LEN]
                [--use-calling-counts | --no-use-calling-counts] [--gdt GDT] [--bsim | --no-bsim] [--bsim-full | --no-bsim-full]
                [--max-ram-percent MAX_RAM_PERCENT] [--print-flags] [--jvm-args [JVM_ARGS]] [--sxs] [--max-section-funcs MAX_SECTION_FUNCS]
                [--md-title MD_TITLE]
                old new [new ...]

ghidriff - A Command Line Ghidra Binary Diffing Engine

positional arguments:
  old                   Path to old version of binary '/somewhere/bin.old'
  new                   Path to new version of binary '/somewhere/bin.new'. (For multiple new binaries add oldest to newest)

options:
  -h, --help            show this help message and exit
  --engine {SimpleDiff,StructualGraphDiff,VersionTrackingDiff}
                        The diff implementation to use. (default: VersionTrackingDiff)
  -o OUTPUT_PATH, --output-path OUTPUT_PATH
                        Output path for resulting diffs (default: ghidriffs)
  --summary SUMMARY     Add a summary diff if more than two bins are provided (default: False)
```


### Extendend Usage

There are quite a few options here, and some complexity. Generally you can succeed with the defaults, but you can override the defaults as needed. One example might be to increase the JVM RAM used to run Ghidra to enable faster analysis of large binaries (`--max-ram-percent 80`). See help for details of other options. 

<details><summary>Show Extended Usage</summary>

```bash

Ghidra Project Options:
  -p PROJECT_LOCATION, --project-location PROJECT_LOCATION
                        Ghidra Project Path (default: ghidra_projects)
  -n PROJECT_NAME, --project-name PROJECT_NAME
                        Ghidra Project Name (default: ghidriff)
  -s SYMBOLS_PATH, --symbols-path SYMBOLS_PATH
                        Ghidra local symbol store directory (default: symbols)
  -g GZFS_PATH, --gzfs-path GZFS_PATH
                        Location to store GZFs of analyzed binaries (default: gzfs)
  --ba BASE_ADDRESS, --base-address BASE_ADDRESS
                        Set base address from both programs. 0x2000 or 8192 (default: None)
  --program-options PROGRAM_OPTIONS
                        Path to json file with Program Options (custom analyzer settings) (default: None)

Engine Options:
  --threaded, --no-threaded
                        Use threading during import, analysis, and diffing. Recommended (default: True)
  --force-analysis      Force a new binary analysis each run (slow) (default: False)
  --force-diff          Force binary diff (ignore arch/symbols mismatch) (default: False)
  --no-symbols          Turn off symbols for analysis (default: False)
  --log-level {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}
                        Set console log level (default: INFO)
  --file-log-level {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}
                        Set log file level (default: INFO)
  --log-path LOG_PATH   Set ghidriff log path. (default: ghidriff.log)
  --va, --verbose-analysis
                        Verbose logging for analysis step. (default: False)
  --min-func-len MIN_FUNC_LEN
                        Minimum function length to consider for diff (default: 10)
  --use-calling-counts, --no-use-calling-counts
                        Add calling/called reference counts (default: False)
  --gdt GDT             Path to GDT file for analysis (default: [])

BSIM Options:
  --bsim, --no-bsim     Toggle using BSIM correlation (default: True)
  --bsim-full, --no-bsim-full
                        Slower but better matching. Use only when needed (default: False)

JVM Options:
  --max-ram-percent MAX_RAM_PERCENT
                        Set JVM Max Ram % of host RAM (default: 60.0)
  --print-flags         Print JVM flags at start (default: False)
  --jvm-args [JVM_ARGS]
                        JVM args to add at start (default: None)

Markdown Options:
  --sxs                 Include side by side code diff (default: False)
  --max-section-funcs MAX_SECTION_FUNCS
                        Max number of functions to display per section. (default: 200)
  --md-title MD_TITLE   Overwrite default title for markdown diff (default: None)
```

</details>

### Using Custom Analyzer Settings

If you want to configure specific analyzers for your Ghidra binary analysis, set a custom program_options.json with `--program-options`.

```bash
ghidriff --prog-options prog_options.json tapisrv.dll.x64.10.0.10240.20708 tapisrv.dll.x64.10.0.10240.20708
```

The `program_options.json` would need to look something like this:

<details>

```json
{
    "program_options": {
        "binary_name": null,
        "Analyzers": {
            "ASCII Strings": "true",
            "ASCII Strings.Create Strings Containing Existing Strings": "true",
            "ASCII Strings.Create Strings Containing References": "true",
            "ASCII Strings.Force Model Reload": "true",
            "ASCII Strings.Minimum String Length": "LEN_5",
            "ASCII Strings.Model File": "StringModel.sng",
            "ASCII Strings.Require Null Termination for String": "true",
            "ASCII Strings.Search Only in Accessible Memory Blocks": "true",
            "ASCII Strings.String Start Alignment": "ALIGN_1",
            "ASCII Strings.String end alignment": "4",
            "Aggressive Instruction Finder": "false",
            "Aggressive Instruction Finder.Create Analysis Bookmarks": "true",
            "Apply Data Archives": "true",
            "Apply Data Archives.Archive Chooser": "[Auto-Detect]",
            "Apply Data Archives.Create Analysis Bookmarks": "true",
            "Apply Data Archives.GDT User File Archive Path": null,
            "Apply Data Archives.User Project Archive Path": null,
            "Call Convention ID": "true",
        }
    }
}
```

</details>

The custom settings will then be used for your binary analysis.

### Setting a Custom Image Base Address (Bootloaders, etc.)

If you are reverse engineering firmware or other fun binary and want to change the base address for the binary, use the `--base-address` parameter to change the base address.

```bash
$ ghidriff --base-address 0x80000 STM32F103C-firmware.bin STM32F103Ca-firmware.bin
```

## Quick Start Environment Setup

1. [Download](https://github.com/NationalSecurityAgency/ghidra/releases) and [install Ghidra](https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/stable/GhidraDocs/InstallationGuide.html#Install).
2. Set Ghidra Environment Variable `GHIDRA_INSTALL_DIR` to Ghidra install location.
3. Pip install `ghidriff`

### Windows

```powershell
PS C:\Users\user> [System.Environment]::SetEnvironmentVariable('GHIDRA_INSTALL_DIR','C:\ghidra_10.2.3_PUBLIC_20230208\ghidra_10.2.3_PUBLIC')
PS C:\Users\user> pip install ghidriff
```
### Linux / Mac

```bash
export GHIDRA_INSTALL_DIR="/path/to/ghidra/"
pip install ghidriff
```

### UV

```bash
export GHIDRA_INSTALL_DIR="/path/to/ghidra/"
uvx ghidriff
```

## Ghidriff in a Box 

Don't want to install Ghidra and Java on your host? Try "Ghidriff in a box". It supports multiple-platforms (x64 and arm64).

<p align='center'>
<img src="https://github.com/clearbluejar/ghidriff/assets/3752074/688756fc-038c-471a-8e49-e56a1c06e77c" height="300">
</p>

### Docker

`docker pull ghcr.io/clearbluejar/ghidriff:latest`


This is a docker container with the latest [PyPi version of Ghidriff](https://pypi.org/project/ghidriff/) installed. You can check the latest container [here](https://github.com/clearbluejar/ghidriff/pkgs/container/ghidriff).


#### For Docker command-line diffing

You will need to map the binaries you want to compare into the container. See below for an example.
```bash
mkdir -p ghidriffs
wget https://msdl.microsoft.com/download/symbols/clfs.sys/9848245C6f000/clfs.sys -O ghidriffs/clfs.sys.x64.10.0.22621.2506
wget https://msdl.microsoft.com/download/symbols/clfs.sys/D929C6E56f000/clfs.sys -O ghidriffs/clfs.sys.x64.10.0.22621.2715
docker run -it --rm -v $(pwd)/ghidriffs:/ghidriffs ghcr.io/clearbluejar/ghidriff:latest  ghidriffs/clfs.sys.x64.10.0.22621.2506 ghidriffs/clfs.sys.x64.10.0.22621.2715
```

The result will produce the following. 

```bash
tree ghidriffs
ghidriffs
├── clfs.sys.x64.10.0.22621.2506
├── clfs.sys.x64.10.0.22621.2506-clfs.sys.x64.10.0.22621.2715.ghidriff.md
├── clfs.sys.x64.10.0.22621.2715
├── ghidra_projects
│   └── ghidriff-clfs.sys.x64.10.0.22621.2506-clfs.sys.x64.10.0.22621.2715
│       ├── ghidriff-clfs.sys.x64.10.0.22621.2506-clfs.sys.x64.10.0.22621.2715.gpr
│       ├── ghidriff-clfs.sys.x64.10.0.22621.2506-clfs.sys.x64.10.0.22621.2715.lock
│       └── ghidriff-clfs.sys.x64.10.0.22621.2506-clfs.sys.x64.10.0.22621.2715.rep
├── ghidriff.log
├── json
│   └── clfs.sys.x64.10.0.22621.2506-clfs.sys.x64.10.0.22621.2715.ghidriff.json
└── symbols
    ├── 000admin
    ├── clfs.pdb
    │   ├── 6EAE8987F981603FEFA0E55DE0CE2C521
    │   │   └── clfs.pdb
    │   └── E3D1FEA241ECEC3DC6DB2B278A22A6A31
    │       └── clfs.pdb
    └── pingme.txt

```

### Devcontainer - For Ghidriff development

Use the [.devcontainer](.devcontainer) in this repo. If you don't know how, follow the detailed instructions here: [ghidra-python-vscode-devcontainer-skeleton quick setup](https://github.com/clearbluejar/ghidra-python-vscode-devcontainer-skeleton#quick-start-setup---dev-container--best-option).


## Use Cases

### Diffing a full Windows Kernel 

#### Download two versions of the kernel (older and latest binary):

```bash
wget https://msdl.microsoft.com/download/symbols/ntoskrnl.exe/F7E31BA91047000/ntoskrnl.exe -O ntoskrnl.exe.10.0.22621.1344
wget https://msdl.microsoft.com/download/symbols/ntoskrnl.exe/17B6B7221047000/ntoskrnl.exe -O ntoskrnl.exe.10.0.22621.1413
```

<details><summary>Console Output:</summary>

```console 
vscode ➜ /workspaces/ghidriff (main) $ wget https://msdl.microsoft.com/download/symbols/ntoskrnl.exe/F7E31BA91047000/ntoskrnl.exe -O ntoskrnl.exe.10.0.22621.1344
--2023-05-17 03:18:40--  https://msdl.microsoft.com/download/symbols/ntoskrnl.exe/F7E31BA91047000/ntoskrnl.exe
Resolving msdl.microsoft.com (msdl.microsoft.com)... 204.79.197.219
Connecting to msdl.microsoft.com (msdl.microsoft.com)|204.79.197.219|:443... connected.
HTTP request sent, awaiting response... 302 Found
Could not parse String-Transport-Security header
Location: https://vsblobprodscussu5shard72.blob.core.windows.net/b-4712e0edc5a240eabf23330d7df68e77/8BFC691F50434EC2DC87BBDFC06A6A5FBACE992E60062F9C8CE829F58E3BCFB300.blob?sv=2019-07-07&sr=b&si=1&sig=Kgrvf90Kc15ac%2FtHsgPPj9ztxxTfkQ0yHGQh8dLDwQs%3D&spr=https&se=2023-05-18T03%3A32%3A47Z&rscl=x-e2eid-420cea82-598a4a00-a990abf8-919be2ff-session-5e9eb5eb-195146cb-b123c222-30eef52e [following]
--2023-05-17 03:18:40--  https://vsblobprodscussu5shard72.blob.core.windows.net/b-4712e0edc5a240eabf23330d7df68e77/8BFC691F50434EC2DC87BBDFC06A6A5FBACE992E60062F9C8CE829F58E3BCFB300.blob?sv=2019-07-07&sr=b&si=1&sig=Kgrvf90Kc15ac%2FtHsgPPj9ztxxTfkQ0yHGQh8dLDwQs%3D&spr=https&se=2023-05-18T03%3A32%3A47Z&rscl=x-e2eid-420cea82-598a4a00-a990abf8-919be2ff-session-5e9eb5eb-195146cb-b123c222-30eef52e
Resolving vsblobprodscussu5shard72.blob.core.windows.net (vsblobprodscussu5shard72.blob.core.windows.net)... 20.209.34.36
Connecting to vsblobprodscussu5shard72.blob.core.windows.net (vsblobprodscussu5shard72.blob.core.windows.net)|20.209.34.36|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 11990400 (11M) [application/octet-stream]
Saving to: ‘ntoskrnl.exe.10.0.22621.1344’

ntoskrnl.exe.10.0.22621.1344                       100%[===============================================================================================================>]  11.43M  2.47MB/s    in 5.5s    

2023-05-17 03:18:46 (2.08 MB/s) - ‘ntoskrnl.exe.10.0.22621.1344’ saved [11990400/11990400]

vscode ➜ /workspaces/ghidriff (main) $ wget https://msdl.microsoft.com/download/symbols/ntoskrnl.exe/17B6B7221047000/ntoskrnl.exe -O ntoskrnl.exe.10.0.22621.1413
--2023-05-17 03:18:58--  https://msdl.microsoft.com/download/symbols/ntoskrnl.exe/17B6B7221047000/ntoskrnl.exe
Resolving msdl.microsoft.com (msdl.microsoft.com)... 204.79.197.219
Connecting to msdl.microsoft.com (msdl.microsoft.com)|204.79.197.219|:443... connected.
HTTP request sent, awaiting response... 302 Found
Could not parse String-Transport-Security header
Location: https://vsblobprodscussu5shard75.blob.core.windows.net/b-4712e0edc5a240eabf23330d7df68e77/D946523F2726056CD289008C977D02C0C0FBBCBB89D9FA40ADBB42CDE8D5022A00.blob?sv=2019-07-07&sr=b&si=1&sig=KfYz9cB7cUPO9JVo0U8eIj0etpASEWOyvCv5NkwVkfw%3D&spr=https&se=2023-05-18T03%3A50%3A53Z&rscl=x-e2eid-4960dee3-47d94aa4-a2207913-b73825a4-session-2879fa10-75774ef4-93e39015-3be72abb [following]
--2023-05-17 03:18:59--  https://vsblobprodscussu5shard75.blob.core.windows.net/b-4712e0edc5a240eabf23330d7df68e77/D946523F2726056CD289008C977D02C0C0FBBCBB89D9FA40ADBB42CDE8D5022A00.blob?sv=2019-07-07&sr=b&si=1&sig=KfYz9cB7cUPO9JVo0U8eIj0etpASEWOyvCv5NkwVkfw%3D&spr=https&se=2023-05-18T03%3A50%3A53Z&rscl=x-e2eid-4960dee3-47d94aa4-a2207913-b73825a4-session-2879fa10-75774ef4-93e39015-3be72abb
Resolving vsblobprodscussu5shard75.blob.core.windows.net (vsblobprodscussu5shard75.blob.core.windows.net)... 20.209.34.36
Connecting to vsblobprodscussu5shard75.blob.core.windows.net (vsblobprodscussu5shard75.blob.core.windows.net)|20.209.34.36|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 11990336 (11M) [application/octet-stream]
Saving to: ‘ntoskrnl.exe.10.0.22621.1413’

ntoskrnl.exe.10.0.22621.1413                       100%[===============================================================================================================>]  11.43M  1.02MB/s    in 12s     

2023-05-17 03:19:11 (1004 KB/s) - ‘ntoskrnl.exe.10.0.22621.1413’ saved [11990336/11990336]
```

</details>

#### Run ghidriff:

```bash
ghidriff ntoskrnl.exe.10.0.22621.1344 ntoskrnl.exe.10.0.22621.1413
```

<details><summary>Console Output</summary>

```console
(.env) vscode ➜ /workspaces/ghidriff (main) $ ghidriff ntoskrnl.exe.10.0.22621.1344 ntoskrnl.exe.10.0.22621.1413
INFO | ghidriff | Init Ghidra Diff Engine...
INFO | ghidriff | Engine Console Log: INFO
INFO | ghidriff | Engine File Log:  .ghidriffs/ghidriff.log INFO
INFO | ghidriff | Starting Ghidra...
INFO  Using log config file: jar:file:/ghidra/Ghidra/Framework/Generic/lib/Generic.jar!/generic.log4j.xml (LoggingInitialization)  
INFO  Using log file: /workspaces/ghidriff/.ghidriffs/ghidriff.log (LoggingInitialization)  
INFO  Loading user preferences: /home/vscode/.ghidra/.ghidra_10.2.3_PUBLIC/preferences (Preferences)  
INFO  Class search complete (716 ms) (ClassSearcher)  
INFO  Initializing SSL Context (SSLContextInitializer)  
INFO  Initializing Random Number Generator... (SecureRandomFactory)  
INFO  Random Number Generator initialization complete: NativePRNGNonBlocking (SecureRandomFactory)  
INFO  Trust manager disabled, cacerts have not been set (ApplicationTrustManagerFactory)  
INFO | ghidriff | GHIDRA_INSTALL_DIR: /ghidra
INFO | ghidriff | GHIDRA 10.2.3  Build Date: 2023-Feb-08 1242 EST Release: PUBLIC
INFO | ghidriff | Engine Args:
INFO | ghidriff |       old:                ['ntoskrnl.exe.10.0.22621.1344']
INFO | ghidriff |       new:                [['ntoskrnl.exe.10.0.22621.1413']]
INFO | ghidriff |       engine:             VersionTrackingDiff
INFO | ghidriff |       output_path:        .ghidriffs
INFO | ghidriff |       summary:            False
INFO | ghidriff |       project_location:   .ghidra_projects
INFO | ghidriff |       project_name:       ghidriff
INFO | ghidriff |       symbols_path:       .symbols
INFO | ghidriff |       threaded:           True
INFO | ghidriff |       force_analysis:     False
INFO | ghidriff |       force_diff:         False
INFO | ghidriff |       no_symbols:         False
INFO | ghidriff |       log_level:          INFO
INFO | ghidriff |       file_log_level:     INFO
INFO | ghidriff |       log_path:           ghidriff.log
INFO | ghidriff |       va:                 False
INFO | ghidriff |       max_ram_percent:    60.0
INFO | ghidriff |       print_flags:        False
INFO | ghidriff |       jvm_args:           None
INFO | ghidriff |       side_by_side:       False
INFO | ghidriff |       max_section_funcs:  200
INFO | ghidriff |       md_title:           None
INFO | ghidriff | Setting Up Ghidra Project...
INFO  Creating project: /workspaces/ghidriff/.ghidra_projects/ghidriff-ntoskrnl.exe.10.0.22621.1344-ntoskrnl.exe.10.0.22621.1413/ghidriff-ntoskrnl.exe.10.0.22621.1344-ntoskrnl.exe.10.0.22621.1413 (DefaultProject)  
INFO | ghidriff | Created project: ghidriff-ntoskrnl.exe.10.0.22621.1344-ntoskrnl.exe.10.0.22621.1413
INFO | ghidriff | Project Location: /workspaces/ghidriff/.ghidra_projects/ghidriff-ntoskrnl.exe.10.0.22621.1344-ntoskrnl.exe.10.0.22621.1413
INFO | ghidriff | Importing ntoskrnl.exe.10.0.22621.1344
INFO  Starting cache cleanup: /tmp/vscode-Ghidra/fscache2 (FileCacheMaintenanceDaemon)  
INFO  Finished cache cleanup, estimated storage used: 0 (FileCacheMaintenanceDaemon)  
INFO  Using Loader: Portable Executable (PE) (AutoImporter)  
INFO | ghidriff | Importing ntoskrnl.exe.10.0.22621.1413
INFO  Using Loader: Portable Executable (PE) (AutoImporter)  
INFO | ghidriff | Setting up Symbol Server for symbols...
INFO | ghidriff | path: .symbols level: 1
INFO | ghidriff | Symbol Server Configured path: SymbolServerService:
        symbolStore: LocalSymbolStore: [ rootDir: /workspaces/ghidriff/.symbols, storageLevel: -1],
        symbolServers:
                HttpSymbolServer: [ url: https://msdl.microsoft.com/download/symbols/, storageLevel: -1]
                HttpSymbolServer: [ url: https://chromium-browser-symsrv.commondatastorage.googleapis.com/, storageLevel: -1]
                HttpSymbolServer: [ url: https://symbols.mozilla.org/, storageLevel: -1]
                HttpSymbolServer: [ url: https://software.intel.com/sites/downloads/symbols/, storageLevel: -1]
                HttpSymbolServer: [ url: https://driver-symbols.nvidia.com/, storageLevel: -1]
                HttpSymbolServer: [ url: https://download.amd.com/dir/bin/, storageLevel: -1]
INFO  Connecting to https://msdl.microsoft.com/download/symbols/ (ConsoleTaskMonitor)  
INFO  Success (ConsoleTaskMonitor)  
INFO  Storing ntkrnlmp.pdb in local symbol store (12.66MB) (ConsoleTaskMonitor)  
INFO | ghidriff | Pdb stored at: /workspaces/ghidriff/.symbols/ntkrnlmp.pdb/FB0913AF0585F234BD64A64A87C62DB11/ntkrnlmp.pdb
INFO  Connecting to https://msdl.microsoft.com/download/symbols/ (ConsoleTaskMonitor)  
INFO  Success (ConsoleTaskMonitor)  
INFO  Storing ntkrnlmp.pdb in local symbol store (12.66MB) (ConsoleTaskMonitor)  
INFO | ghidriff | Pdb stored at: /workspaces/ghidriff/.symbols/ntkrnlmp.pdb/797E613DB16DB6C0E57795A0CB03F4711/ntkrnlmp.pdb
INFO | ghidriff | Program: /ntoskrnl.exe.10.0.22621.1344 imported: True has_pdb: True pdb_loaded: False analyzed False
INFO | ghidriff | Program: /ntoskrnl.exe.10.0.22621.1413 imported: True has_pdb: True pdb_loaded: False analyzed False
INFO | ghidriff | Starting analysis for 2 binaries
INFO | ghidriff | Analyzing: ntoskrnl.exe.10.0.22621.1413 - .ProgramDB
INFO | ghidriff | Analyzing: ntoskrnl.exe.10.0.22621.1344 - .ProgramDB
WARNING| ghidriff | Turning off 'Shared Return Calls' for ntoskrnl.exe.10.0.22621.1344 - .ProgramDB
INFO | ghidriff | Starting Ghidra analysis of ntoskrnl.exe.10.0.22621.1344 - .ProgramDB...
INFO  PDB analyzer parsing file: /workspaces/ghidriff/.symbols/ntkrnlmp.pdb/FB0913AF0585F234BD64A64A87C62DB11/ntkrnlmp.pdb (PdbUniversalAnalyzer)  
WARNING| ghidriff | Turning off 'Shared Return Calls' for ntoskrnl.exe.10.0.22621.1413 - .ProgramDB
INFO | ghidriff | Starting Ghidra analysis of ntoskrnl.exe.10.0.22621.1413 - .ProgramDB...
INFO  PDB analyzer parsing file: /workspaces/ghidriff/.symbols/ntkrnlmp.pdb/797E613DB16DB6C0E57795A0CB03F4711/ntkrnlmp.pdb (PdbUniversalAnalyzer)  
WARN  PDB STRUCTURE reconstruction failed to align /ntkrnlmp.pdb/<unnamed-tag_00001117> (CppCompositeType)  
WARN  PDB STRUCTURE reconstruction failed to align /ntkrnlmp.pdb/<unnamed-tag_0000111B> (CppCompositeType)  
WARN  PDB STRUCTURE reconstruction failed to align /ntkrnlmp.pdb/<unnamed-tag_0000111F> (CppCompositeType)  
WARN  PDB STRUCTURE reconstruction failed to align /ntkrnlmp.pdb/_WMI_LOGGER_CONTEXT (CppCompositeType)  
WARN  PDB STRUCTURE reconstruction failed to align /ntkrnlmp.pdb/_PPM_PLATFORM_STATE (CppCompositeType)  
WARN  PDB STRUCTURE reconstruction failed to align /ntkrnlmp.pdb/_IOP_IRP_EXTENSION (CppCompositeType)  
WARN  PDB STRUCTURE reconstruction failed to align /ntkrnlmp.pdb/_EX_HEAP_POOL_NODE (CppCompositeType)  
WARN  PDB STRUCTURE reconstruction failed to align /ntkrnlmp.pdb/_BLOB (CppCompositeType)  
WARN  PDB STRUCTURE reconstruction failed to align /ntkrnlmp.pdb/_MMPAGING_FILE (CppCompositeType)  
WARN  PDB STRUCTURE reconstruction failed to align /ntkrnlmp.pdb/_MMCLONE_DESCRIPTOR (CppCompositeType)  
WARN  PDB STRUCTURE reconstruction failed to align /ntkrnlmp.pdb/_KUSER_SHARED_DATA (CppCompositeType)  
INFO  Resolve time: 1939 mS (DefaultPdbApplicator)  
INFO  resolveCount: 3644 (DefaultPdbApplicator)  
INFO  Resolve time: 1854 mS (DefaultPdbApplicator)  
INFO  resolveCount: 3644 (DefaultPdbApplicator)  
WARN  Decompiling 1402efc70, pcode error at 14000000c: Unable to resolve constructor at 14000000c (DecompileCallback)  
WARN  Decompiling 1402efc70, pcode error at 14000000c: Unable to resolve constructor at 14000000c (DecompileCallback)  
WARN  Decompiling 1402efc70, pcode error at 14000000c: Unable to resolve constructor at 14000000c (DecompileCallback)  
INFO  Packed database cache: /tmp/vscode-Ghidra/packed-db-cache (PackedDatabaseCache)  

 
INFO  -----------------------------------------------------
    ASCII Strings                              0.137 secs
    Apply Data Archives                        3.295 secs
    Call Convention ID                         2.037 secs
    Call-Fixup Installer                       0.998 secs
    Create Address Tables                      0.021 secs
    Create Address Tables - One Time           5.159 secs
    Create Function                            8.858 secs
    Data Reference                            17.246 secs
    Decompiler Switch Analysis               266.328 secs
    Demangler Microsoft                        3.514 secs
    Disassemble                                0.232 secs
    Disassemble Entry Points                  58.448 secs
    Disassemble Entry Points - One Time        1.802 secs
    Embedded Media                             0.123 secs
    External Entry References                  0.125 secs
    Function ID                              114.335 secs
    Function Start Search                      0.859 secs
    Non-Returning Functions - Discovered      25.594 secs
    Non-Returning Functions - Known            0.144 secs
    PDB Universal                            168.601 secs
    Reference                                  6.969 secs
    Scalar Operand References                 91.615 secs
    Shared Return Calls                        4.718 secs
    Stack                                    291.121 secs
    Subroutine References                     14.672 secs
    Subroutine References - One Time           0.027 secs
    Windows x86 PE Exception Handling          0.470 secs
    Windows x86 PE RTTI Analyzer               0.091 secs
    Windows x86 Thread Environment Block (TEB) Analyzer     0.115 secs
    WindowsResourceReference                   0.413 secs
    x86 Constant Reference Analyzer          261.728 secs
-----------------------------------------------------
     Total Time   1349 secs
-----------------------------------------------------
 (AutoAnalysisManager)  
INFO  -----------------------------------------------------
    ASCII Strings                              3.249 secs
    Apply Data Archives                        3.290 secs
    Call Convention ID                         1.984 secs
    Call-Fixup Installer                       0.947 secs
    Create Address Tables                      0.007 secs
    Create Address Tables - One Time           5.178 secs
    Create Function                            8.855 secs
    Data Reference                            17.320 secs
    Decompiler Switch Analysis               264.962 secs
    Demangler Microsoft                        3.649 secs
    Disassemble                                0.468 secs
    Disassemble Entry Points                  58.480 secs
    Disassemble Entry Points - One Time        1.805 secs
    Embedded Media                             0.102 secs
    External Entry References                  0.120 secs
    Function ID                              114.285 secs
    Function Start Search                      0.987 secs
    Non-Returning Functions - Discovered      25.826 secs
    Non-Returning Functions - Known            0.034 secs
    PDB Universal                            169.189 secs
    Reference                                  6.714 secs
    Scalar Operand References                 91.422 secs
    Shared Return Calls                        4.760 secs
    Stack                                    291.137 secs
    Subroutine References                     14.711 secs
    Subroutine References - One Time           0.018 secs
    Windows x86 PE Exception Handling          0.463 secs
    Windows x86 PE RTTI Analyzer               0.089 secs
    Windows x86 Thread Environment Block (TEB) Analyzer     0.119 secs
    WindowsResourceReference                   0.403 secs
    x86 Constant Reference Analyzer          262.810 secs
-----------------------------------------------------
     Total Time   1353 secs
-----------------------------------------------------
 (AutoAnalysisManager)  
INFO | ghidriff | Analysis for ghidriff-ntoskrnl.exe.10.0.22621.1344-ntoskrnl.exe.10.0.22621.1413:/ntoskrnl.exe.10.0.22621.1413 complete
INFO | ghidriff | Analysis for ghidriff-ntoskrnl.exe.10.0.22621.1344-ntoskrnl.exe.10.0.22621.1413:/ntoskrnl.exe.10.0.22621.1344 complete
INFO | ghidriff | Diffing bins: ntoskrnl.exe.10.0.22621.1344 - ntoskrnl.exe.10.0.22621.1413
INFO | ghidriff | Setup 16 decompliers
INFO | ghidriff | Loaded old program: ntoskrnl.exe.10.0.22621.1344
INFO | ghidriff | Loaded new program: ntoskrnl.exe.10.0.22621.1413
INFO | ghidriff | p1 sym count: reported: 244603 analyzed: 16772
INFO | ghidriff | p2 sym count: reported: 244606 analyzed: 16809
INFO | ghidriff | Found unmatched: 65 matched: 16758 symbols
INFO  Hashing symbols in ntoskrnl.exe.10.0.22621.1344 (ConsoleTaskMonitor)  
INFO  Hashing symbols in ntoskrnl.exe.10.0.22621.1413 (ConsoleTaskMonitor)  
INFO  Eliminate non-unique matches (ConsoleTaskMonitor)  
INFO  Finding symbol matches (ConsoleTaskMonitor)  
INFO | ghidriff | Exec time: 2.1672 secs
INFO | ghidriff | Match count 54939
INFO | ghidriff | Counter({('SymbolsHash',): 27893})
INFO | ghidriff | Running correlator: ExactBytesFunctionHasher
INFO | ghidriff | name: ExactBytesFunctionHasher hasher: ghidra.app.plugin.match.ExactBytesFunctionHasher@7167d81b one_to_one: True one_to_many: False
INFO  Hashing functions in ntoskrnl.exe.10.0.22621.1344 (ConsoleTaskMonitor)  
INFO  Hashing functions in ntoskrnl.exe.10.0.22621.1413 (ConsoleTaskMonitor)  
INFO  Finding function matches (ConsoleTaskMonitor)  
INFO | ghidriff | ExactBytesFunctionHasher Exec time: 0.8299 secs
INFO | ghidriff | Match count: 100
INFO | ghidriff | Counter({('SymbolsHash',): 27893, ('ExactBytesFunctionHasher',): 100})
INFO | ghidriff | Running correlator: ExactInstructionsFunctionHasher
INFO | ghidriff | name: ExactInstructionsFunctionHasher hasher: ghidra.app.plugin.match.ExactInstructionsFunctionHasher@3c9cfcde one_to_one: True one_to_many: False
INFO  Hashing functions in ntoskrnl.exe.10.0.22621.1344 (ConsoleTaskMonitor)  
INFO  Hashing functions in ntoskrnl.exe.10.0.22621.1413 (ConsoleTaskMonitor)  
INFO  Finding function matches (ConsoleTaskMonitor)  
INFO | ghidriff | ExactInstructionsFunctionHasher Exec time: 0.4906 secs
INFO | ghidriff | Match count: 123
INFO | ghidriff | Counter({('SymbolsHash',): 27893, ('ExactInstructionsFunctionHasher',): 123, ('ExactBytesFunctionHasher',): 100})
INFO | ghidriff | Running correlator: StructuralGraphExactHash
INFO | ghidriff | name: StructuralGraphExactHash hasher: <jpype._jproxy.proxy.StructuralGraphExactHasher object at 0xffff26c53bf0> one_to_one: True one_to_many: False
INFO  Hashing functions in ntoskrnl.exe.10.0.22621.1344 (ConsoleTaskMonitor)  
INFO  Hashing functions in ntoskrnl.exe.10.0.22621.1413 (ConsoleTaskMonitor)  
INFO  Finding function matches (ConsoleTaskMonitor)  
INFO | ghidriff | StructuralGraphExactHash Exec time: 1.3213 secs
INFO | ghidriff | Match count: 0
INFO | ghidriff | Counter({('SymbolsHash',): 27893, ('ExactInstructionsFunctionHasher',): 123, ('ExactBytesFunctionHasher',): 100})
INFO | ghidriff | Running correlator: ExactMnemonicsFunctionHasher
INFO | ghidriff | name: ExactMnemonicsFunctionHasher hasher: ghidra.app.plugin.match.ExactMnemonicsFunctionHasher@7533923b one_to_one: True one_to_many: False
INFO  Hashing functions in ntoskrnl.exe.10.0.22621.1344 (ConsoleTaskMonitor)  
INFO  Hashing functions in ntoskrnl.exe.10.0.22621.1413 (ConsoleTaskMonitor)  
INFO  Finding function matches (ConsoleTaskMonitor)  
INFO | ghidriff | ExactMnemonicsFunctionHasher Exec time: 2.5697 secs
INFO | ghidriff | Match count: 0
INFO | ghidriff | Counter({('SymbolsHash',): 27893, ('ExactInstructionsFunctionHasher',): 123, ('ExactBytesFunctionHasher',): 100})
INFO | ghidriff | Running correlator: BulkInstructionHash
INFO | ghidriff | name: BulkInstructionHash hasher: <jpype._jproxy.proxy.BulkInstructionsHasher object at 0xffff26c53b50> one_to_one: True one_to_many: False
INFO  Hashing functions in ntoskrnl.exe.10.0.22621.1344 (ConsoleTaskMonitor)  
INFO  Hashing functions in ntoskrnl.exe.10.0.22621.1413 (ConsoleTaskMonitor)  
INFO  Finding function matches (ConsoleTaskMonitor)  
INFO | ghidriff | BulkInstructionHash Exec time: 1.1462 secs
INFO | ghidriff | Match count: 2
INFO | ghidriff | Counter({('SymbolsHash',): 27893, ('ExactInstructionsFunctionHasher',): 123, ('ExactBytesFunctionHasher',): 100, ('BulkInstructionHash',): 2})
INFO | ghidriff | Running correlator: StructuralGraphHash
INFO | ghidriff | name: StructuralGraphHash hasher: <jpype._jproxy.proxy.StructuralGraphHasher object at 0xffff26c53ab0> one_to_one: True one_to_many: True
INFO  Hashing functions in ntoskrnl.exe.10.0.22621.1344 (ConsoleTaskMonitor)  
INFO  Hashing functions in ntoskrnl.exe.10.0.22621.1413 (ConsoleTaskMonitor)  
INFO  Finding function matches (ConsoleTaskMonitor)  
INFO | ghidriff | StructuralGraphHash Exec time: 0.1894 secs
INFO | ghidriff | Match count: 693
INFO | ghidriff | Counter({('SymbolsHash',): 27893, ('StructuralGraphHash',): 693, ('ExactInstructionsFunctionHasher',): 123, ('ExactBytesFunctionHasher',): 100, ('BulkInstructionHash',): 2})
INFO | ghidriff | Running correlator: BulkBasicBlockMnemonicHash
INFO | ghidriff | name: BulkBasicBlockMnemonicHash hasher: <jpype._jproxy.proxy.BulkBasicBlockMnemonicHasher object at 0xffff26c53a10> one_to_one: True one_to_many: True
INFO  Hashing functions in ntoskrnl.exe.10.0.22621.1344 (ConsoleTaskMonitor)  
INFO  Hashing functions in ntoskrnl.exe.10.0.22621.1413 (ConsoleTaskMonitor)  
INFO  Finding function matches (ConsoleTaskMonitor)  
INFO | ghidriff | BulkBasicBlockMnemonicHash Exec time: 0.1846 secs
INFO | ghidriff | Match count: 0
INFO | ghidriff | Counter({('SymbolsHash',): 27893, ('StructuralGraphHash',): 693, ('ExactInstructionsFunctionHasher',): 123, ('ExactBytesFunctionHasher',): 100, ('BulkInstructionHash',): 2})
INFO | ghidriff | Running correlator: SigCallingCalledHasher
INFO | ghidriff | name: SigCallingCalledHasher hasher: <jpype._jproxy.proxy.SigCallingCalledHasher object at 0xffff26c53970> one_to_one: True one_to_many: False
INFO  Hashing functions in ntoskrnl.exe.10.0.22621.1344 (ConsoleTaskMonitor)  
INFO  Hashing functions in ntoskrnl.exe.10.0.22621.1413 (ConsoleTaskMonitor)  
INFO  Finding function matches (ConsoleTaskMonitor)  
INFO | ghidriff | SigCallingCalledHasher Exec time: 0.1398 secs
INFO | ghidriff | Match count: 0
INFO | ghidriff | Counter({('SymbolsHash',): 27893, ('StructuralGraphHash',): 693, ('ExactInstructionsFunctionHasher',): 123, ('ExactBytesFunctionHasher',): 100, ('BulkInstructionHash',): 2})
INFO | ghidriff | p1 missing = 1
INFO | ghidriff | p2 missing = 1
INFO | ghidriff | Deduping symbols and functions...
INFO | ghidriff | Sorting symbols and strings...
INFO | ghidriff | Sorting functions...
INFO | ghidriff | Starting esym lookups for 71 symbols using 8 threads
INFO | ghidriff | Completed 4 at 5%
INFO | ghidriff | Completed 8 at 11%
INFO | ghidriff | Completed 12 at 16%
INFO | ghidriff | Completed 16 at 22%
INFO | ghidriff | Completed 20 at 28%
INFO | ghidriff | Completed 24 at 33%
INFO | ghidriff | Completed 28 at 39%
INFO | ghidriff | Completed 32 at 45%
INFO | ghidriff | Completed 36 at 50%
INFO | ghidriff | Completed 40 at 56%
INFO | ghidriff | Completed 44 at 61%
INFO | ghidriff | Completed 48 at 67%
INFO | ghidriff | Completed 52 at 73%
INFO | ghidriff | Completed 56 at 78%
INFO | ghidriff | Completed 60 at 84%
INFO | ghidriff | Completed 64 at 90%
INFO | ghidriff | Completed 68 at 95%
INFO | ghidriff | Finished diffing old program: ntoskrnl.exe.10.0.22621.1344
INFO | ghidriff | Finished diffing program: ntoskrnl.exe.10.0.22621.1413
INFO | ghidriff | {
  "added_funcs_len": 1,
  "deleted_funcs_len": 1,
  "modified_funcs_len": 11,
  "added_symbols_len": 12,
  "deleted_symbols_len": 8,
  "diff_time": 86.45361375808716,
  "deleted_strings_len": 6,
  "added_strings_len": 39,
  "match_types": {
    "SymbolsHash": 27893,
    "ExactBytesFunctionHasher": 100,
    "ExactInstructionsFunctionHasher": 123,
    "BulkInstructionHash": 2,
    "StructuralGraphHash": 693
  },
  "items_to_process": 33,
  "diff_types": {
    "code": 5,
    "length": 5,
    "refcount": 7,
    "calling": 6,
    "address": 6,
    "called": 3
  },
  "unmatched_funcs_len": 2,
  "total_funcs_len": 60664,
  "matched_funcs_len": 60662,
  "matched_funcs_with_code_changes_len": 5,
  "matched_funcs_with_non_code_changes_len": 6,
  "matched_funcs_no_changes_len": 60651,
  "match_func_similarity_percent": "99.9819%",
  "func_match_overall_percent": "99.9967%"
}
INFO | ghidriff | Writing md diff...
INFO | ghidriff | Generating markdown from {'added_funcs_len': 1, 'deleted_funcs_len': 1, 'modified_funcs_len': 11, 'added_symbols_len': 12, 'deleted_symbols_len': 8, 'diff_time': 86.45361375808716, 'deleted_strings_len': 6, 'added_strings_len': 39, 'match_types': Counter({'SymbolsHash': 27893, 'StructuralGraphHash': 693, 'ExactInstructionsFunctionHasher': 123, 'ExactBytesFunctionHasher': 100, 'BulkInstructionHash': 2}), 'items_to_process': 33, 'diff_types': Counter({'refcount': 7, 'calling': 6, 'address': 6, 'code': 5, 'length': 5, 'called': 3}), 'unmatched_funcs_len': 2, 'total_funcs_len': 60664, 'matched_funcs_len': 60662, 'matched_funcs_with_code_changes_len': 5, 'matched_funcs_with_non_code_changes_len': 6, 'matched_funcs_no_changes_len': 60651, 'match_func_similarity_percent': '99.9819%', 'func_match_overall_percent': '99.9967%'}
INFO | ghidriff | Known Command line: python ghidriff --project-location .ghidra_projects --project-name ghidriff --symbols-path .symbols --threaded --log-level INFO --file-log-level INFO --log-path ghidriff.log --max-ram-percent 60.0 --max-section-funcs 200 ntoskrnl.exe.10.0.22621.1344 ntoskrnl.exe.10.0.22621.1413
INFO | ghidriff | Extra Command line: --engine VersionTrackingDiff --output-path .ghidriffs
INFO | ghidriff | Writing pdiff json...
INFO | ghidriff | Wrote .ghidriffs/ntoskrnl.exe.10.0.22621.1344-ntoskrnl.exe.10.0.22621.1413_diff.md
INFO | ghidriff | Wrote .ghidriffs/json/ntoskrnl.exe.10.0.22621.1344-ntoskrnl.exe.10.0.22621.1413_diff.json
```
</details>

#### Analyze the Diff


Results in this beatiful markdown: [ntoskrnl.exe.10.0.22621.1344-ntoskrnl.exe.10.0.22621.1413.diff.md](https://gist.github.com/clearbluejar/b95ae854a92ee917cd0b5c7055b60282)

See if you can figure out what function was patched for [CVE-2023-2342](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23420).

- Details of [CVE-2023-2342](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23420) can be found here: [https://bugs.chromium.org/p/project-zero/issues/detail?id=2392](https://bugs.chromium.org/p/project-zero/issues/detail?id=2392)

Prefer a side by side diff? Try out `ghidriff`'s custom html viewer. https://diffpreview.github.io/?b95ae854a92ee917cd0b5c7055b60282

##### Results stored in `ghidriffs` folder

```bash
$ tree ghidriffs
ghidriffs
├── ghidra_projects
│   └── ghidriff-ntoskrnl.exe.10.0.22621.2215-ntoskrnl.exe.10.0.22621.2283
│       ├── ghidriff-ntoskrnl.exe.10.0.22621.2215-ntoskrnl.exe.10.0.22621.2283.gpr
│       └── ghidriff-ntoskrnl.exe.10.0.22621.2215-ntoskrnl.exe.10.0.22621.2283.rep
│           ├── idata
│           ├── project.prp
│           ├── user
│           └── versioned
├── ghidriff.log
├── json
│   └── ntoskrnl.exe.10.0.22621.2215-ntoskrnl.exe.10.0.22621.2283.ghidriff.json
├── ntoskrnl.exe.10.0.22621.2215-ntoskrnl.exe.10.0.22621.2283.ghidriff.md
└── symbols
    ├── ntkrnlmp.pdb
        ├── 69071F680ADFE36F178C6EC06E79E09C1
        │   └── ntkrnlmp.pdb
        └── 738ED8FF966E8502EFE17095B9F1F5481
            └── ntkrnlmp.pdb
```

### Diffing CVE-2023-21768

Details of the CVE-2023-21768 (detailed in this blog [post](https://securityintelligence.com/posts/patch-tuesday-exploit-wednesday-pwning-windows-ancillary-function-driver-winsock/)). What if you wanted to repeat this patch diff with `ghidriff`?

1. Download two versions of `AFD.sys` (vulnerable and patched):

```bash
wget https://msdl.microsoft.com/download/symbols/afd.sys/0C5C6994A8000/afd.sys -O afd.sys.x64.10.0.22621.1028
wget https://msdl.microsoft.com/download/symbols/afd.sys/50989142A9000/afd.sys -O afd.sys.x64.10.0.22621.1415
```

2.  Run `ghidriff`:

```bash
ghidriff afd.sys.x64.10.0.22621.1028 afd.sys.x64.10.0.22621.1415
```

3. Review results

The diff results are posted in this GitHub [gist](https://gist.github.com/clearbluejar/f6fecbc507a9f1a92c9231e3db7ef40d). The vulnerable function  `AfdNotifyRemoveIoCompletion` was identified here with a [single line change](https://gist.github.com/clearbluejar/f6fecbc507a9f1a92c9231e3db7ef40d#afdnotifyremoveiocompletion-diff).

Want to see the entire diff in a side by side? https://diffpreview.github.io/?f6fecbc507a9f1a92c9231e3db7ef40d or jump to the [single line change](https://diffpreview.github.io/?f6fecbc507a9f1a92c9231e3db7ef40d#d2h-703858:~:text=ProbeForWrite(*(PVOID%20*)(param_3%20%2B%200x18)%2C4%2C4)%3B)

## Notes

### Markdown Spec + MermaidJs
- Striving to be compliant with [GFM](https://github.github.com/gfm/) and [cmark](https://spec.commonmark.org/). Still working on it though. See issues.
- MermaidJs requires your markdown [renderer support](https://mermaid.js.org/ecosystem/integrations-community.html). 