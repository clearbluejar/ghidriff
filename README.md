# ghidra-simple-diff-engine

A Ghidra Headless (non-GUI) Python script to automate binary patch diffing.

## Features

- Prescribes [workflow](#workflow) to get you started (modify as needed)
- Container dependencies captured in [.devcontainer](.devcontainer/)
  - Leverages [vscode python3 devcontainer image](https://github.com/microsoft/vscode-dev-containers/tree/main/containers/python-3) with Java [feature](.devcontainer/devcontainer.json#L64-L66) added for running Ghidra
  - Provisions specified versions Ghidra based on `GHIDRA_VERSION` in [devcontainer.json](.devcontainer/devcontainer.json#L15-L16)
- Auto complete for Ghidra Python script setup and configured
  - via pyi typings from [VDOO-Connected-Trust/ghidra-pyi-generator](https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator)
- IDE debugging (available from either)
  - [justfoxing/ghidra_bridge](https://github.com/justfoxing/ghidra_bridge) over RPC
  - [pyhidra](https://github.com/dod-cyber-crime-center/pyhidra) leveraging native CPython interpreter using [jpype](https://jpype.readthedocs.io/en/latest/)
- Demonstrates running python scripts in [various ways](#different-ways-to-run-a-ghidra-headless-script).

## Design Goals

Perform binary diff
   - Find added funcitons
   - Find deleted functions
   - Find modified functions
   - Generate JSON capturing Diff Results

## Quick Start Setup

Follow directions from that repo template [Quick Start](https://github.com/clearbluejar/ghidra-python-vscode-devcontainer-skeleton#quick-start-setup---dev-container--best-option)


## Workflow

[Ghidra](https://github.com/NationalSecurityAgency/ghidra) is a binary analysis tool (and much more). In order to perform analysis via script, you first need to create a project and add binaries for analysis.  Once a project exists with at least one binary added, [headless analysis](#ghidra-headless-analyzer-running-command-line-scripts-with-ghidra) (scripting Ghidra) can begin.

### Ghidra Headless Analyzer (running command line scripts with Ghidra) 

>The Headless Analyzer is a command-line-based (non-GUI) version of Ghidra.

>The Headless Analyzer can be useful when performing repetitive tasks on a project (i.e., importing and analyzing a directory of files or running a script over all the binaries in a project).

The basic usage for the headless analyzer in Ghidra is:
``` 
analyzeHeadless <project_location> <project_name> [[-import [<directory>|<file>]+] | [-process [<project_file>]]] [-postScript <ScriptName>]
```

<details>
<summary>Show analyzeHeadless full usage</summary>

```bash
analyzeHeadless <project_location> <project_name>[/<folder_path>]
        | ghidra://<server>[:<port>]/<repository_name>[/<folder_path>]
    [[-import [<directory>|<file>]+] | [-process [<project_file>]]]
    [-preScript <ScriptName>]
    [-postScript <ScriptName>]
    [-scriptPath "<path1>[;<path2>...]"]
    [-propertiesPath "<path1>[;<path2>...]"]
    [-scriptlog <path to script log file>]
    [-log <path to log file>]
    [-overwrite]
    [-recursive]
    [-readOnly]
    [-deleteProject]
    [-noanalysis]
    [-processor <languageID>]
    [-cspec <compilerSpecID>]
    [-analysisTimeoutPerFile <timeout in seconds>]
    [-keystore <KeystorePath>]
    [-connect <userID>]
    [-p]
    [-commit ["<comment>"]]
    [-okToDelete]
    [-max-cpu <max cpu cores to use>]
    [-loader <desired loader name>]
```
</details>

### Steps

This skeleton project prescribes a workflow and demonstrates various ways to run headless Ghidra Python scripts. The steps can be modified to suit your needs.

1. **Create Ghidra Project** - Directory and collection of Ghidra project files and data
2. **Import Binary to project** - Import one or more binaries to the project for analysis
3. **Analyze Binary** - Ghidra will perform default binary analysis on each binary
4. **Run Ghidra Python [script](sample.py)**
   

Technically, all of these steps within the skeletion can be performed with a single call to `analyzeHeadless`.

`/ghidra/support/analyzeHeadless .ghidra_projects/sample_project sample_project -import /bin/ls -postscript sample.py`

For clarity they are broken down into two distinct steps:
1. [Project Creation and Importing Binaries](#project-creation-and-importing-binaries)
2. [Running Headless Scripts](#different-ways-to-run-a-ghidra-headless-script)

### Project Creation and Importing Binaries

Steps 1, 2, and 3 can be combined in a single call to `analyzeHeadless` within [import_bins.py](import_bins.py). Essentially, the script runs the following command line:

`analyzeHeadless .ghidra_projects/sample_project sample_project -import /bin/ls`

This single call will create a project (`sample_project`), import a binary (`ls`) and analyze the binary.

### Different Ways to run a Ghidra Headless script

At this point, the `sample_project` exists in [.ghidra_projects](.ghidra_projects/) and is ready to run Python Ghidra Scripts. 

Step 4 runs the script on the imported binary after analysis (*-postscript*) on a subsequent call to `analyzeHeadless` with your [sample.py](sample.py). Essentially, making this call.

`analyzeHeadless .ghidra_projects/sample_project sample_project -postscript sample.py`

There are several ways to run a Ghidra Python script.

1. Run via launch on [run_headless.py](run_headless.py).
   - The most straightforward means to run the script. It simply uses subprocess module to call `analyzeHeadless` with the correct arguments to run the [sample.py](sample.py).
   - It also creates a properties file needed to pass arguments to some Ghidra API calls.
2. Run the task `Run Current Python Script in Ghidra Jython` within [tasks.json](.vscode/tasks.json).
   - To use this task make sure you have open and focused the [sample.py](sample.py).
3. Run via launch on [sample-bridge.py](sample-bridge.py) leveraging `ghidra-bridge`.
   - Requires the ghidra-bridge to [start prior to connecting](sample-bridge.py#L43-L49) via bridge. 
   - Instead of properties file, [passes](sample-bridge.py#L37) `ls` argument to ghidra-bridge server. 
4. Run [sample-pyhidra.py](sample-pyhidra.py) leveraging `pyhidra` (best one! It really just works with the help of `jpype`)   
5. Run [sample.py](sample.py) directly in Ghidra via the GUI after copying it to the `ghidra_scripts` directory. If you are doing that, you likely don't need this repo.

### Sample Outputs

<details><summary>1. Run via launch on run_headless.py</summary>

```bash
(.env) vscode ➜ /workspaces/ghidra-python-vscode-devcontainer-skeleton (main ✗) $  ghidra-python-vscode-devcontainer-skeleton/run_headless.py 

['/ghidra/support/analyzeHeadless', '/workspaces/ghidra-python-vscode-devcontainer-skeleton/.ghidra_projects/sample_project', 'sample_project', '-postscript', 'sample.py']

program=ls

openjdk version "11.0.15" 2022-04-19 LTS
OpenJDK Runtime Environment Microsoft-32930 (build 11.0.15+10-LTS)
OpenJDK 64-Bit Server VM Microsoft-32930 (build 11.0.15+10-LTS, mixed mode)
INFO  Using log config file: jar:file:/ghidra/Ghidra/Framework/Generic/lib/Generic.jar!/generic.log4j.xml (LoggingInitialization)  
INFO  Using log file: /home/vscode/.ghidra/.ghidra_10.1.4_PUBLIC/application.log (LoggingInitialization)  
INFO  Loading user preferences: /home/vscode/.ghidra/.ghidra_10.1.4_PUBLIC/preferences (Preferences)  
INFO  Class search complete (1006 ms) (ClassSearcher)  
INFO  Initializing SSL Context (SSLContextInitializer)  
INFO  Initializing Random Number Generator... (SecureRandomFactory)  
INFO  Random Number Generator initialization complete: NativePRNGNonBlocking (SecureRandomFactory)  
INFO  Trust manager disabled, cacerts have not been set (ApplicationTrustManagerFactory)  
WARN  Neither the -import parameter nor the -process parameter was specified; therefore, the specified prescripts and/or postscripts will be executed without any type of program context. (HeadlessAnalyzer)  
INFO  HEADLESS Script Paths:
    /ghidra/Ghidra/Features/Decompiler/ghidra_scripts
    /ghidra/Ghidra/Features/Base/ghidra_scripts
    /ghidra/Ghidra/Features/BytePatterns/ghidra_scripts
    /ghidra/Ghidra/Processors/8051/ghidra_scripts
    /ghidra/Ghidra/Features/Python/ghidra_scripts
    /ghidra/Ghidra/Debug/Debugger/ghidra_scripts
    /ghidra/Ghidra/Features/FileFormats/ghidra_scripts
    /ghidra/Ghidra/Processors/PIC/ghidra_scripts
    /ghidra/Ghidra/Processors/DATA/ghidra_scripts
    /ghidra/Ghidra/Debug/Debugger-agent-dbgmodel-traceloader/ghidra_scripts
    /ghidra/Ghidra/Features/VersionTracking/ghidra_scripts
    /ghidra/Ghidra/Features/FunctionID/ghidra_scripts
    /ghidra/Ghidra/Features/GnuDemangler/ghidra_scripts
    /ghidra/Ghidra/Features/MicrosoftCodeAnalyzer/ghidra_scripts (HeadlessAnalyzer)  
INFO  HEADLESS: execution starts (HeadlessAnalyzer)  
INFO  Opening existing project: /workspaces/ghidra-python-vscode-devcontainer-skeleton/.ghidra_projects/sample_project/sample_project (HeadlessAnalyzer)  
INFO  Opening project: /workspaces/ghidra-python-vscode-devcontainer-skeleton/.ghidra_projects/sample_project/sample_project (HeadlessProject)  
INFO  SCRIPT: /workspaces/ghidra-python-vscode-devcontainer-skeleton/sample.py (HeadlessAnalyzer)  
INFO  Reading script properties file: /workspaces/ghidra-python-vscode-devcontainer-skeleton/sample.properties (GhidraScriptProperties)  
sample_project
ghidra.framework.data.ProjectFileManager@60a907d9
sample_project:/
Program Info:
Program: ls: AARCH64:LE:64:v8A_default (Wed Jul 13 12:59:48 UTC 2022)

Memory layout:
Imagebase: 0x100000L
segment_2.1 [start: 0x1048576, end: 0x1049143]
.interp [start: 0x1049144, end: 0x1049170]
.note.gnu.build-id [start: 0x1049172, end: 0x1049207]
.note.ABI-tag [start: 0x1049208, end: 0x1049239]
.gnu.hash [start: 0x1049240, end: 0x1049303]
.dynsym [start: 0x1049304, end: 0x1052423]
.dynstr [start: 0x1052424, end: 0x1053877]
.gnu.version [start: 0x1053878, end: 0x1054137]
.gnu.version_r [start: 0x1054144, end: 0x1054255]
.rela.dyn [start: 0x1054256, end: 0x1060087]
.rela.plt [start: 0x1060088, end: 0x1062703]
.init [start: 0x1062704, end: 0x1062723]
.plt [start: 0x1062736, end: 0x1064511]
.text [start: 0x1064512, end: 0x1149231]
.fini [start: 0x1149232, end: 0x1149247]
.rodata [start: 0x1149248, end: 0x1168549]
.eh_frame_hdr [start: 0x1168552, end: 0x1170795]
.eh_frame [start: 0x1170800, end: 0x1182903]
.init_array [start: 0x1250024, end: 0x1250031]
.fini_array [start: 0x1250032, end: 0x1250039]
.data.rel.ro [start: 0x1250040, end: 0x1252607]
.dynamic [start: 0x1252608, end: 0x1253119]
.got [start: 0x1253120, end: 0x1253351]
.got.plt [start: 0x1253352, end: 0x1254247]
.data [start: 0x1254248, end: 0x1254935]
.bss [start: 0x1254936, end: 0x1259735]
EXTERNAL [start: 0x1261568, end: 0x1262527]
.gnu_debugaltlink [start: 0x0, end: 0x73]
.gnu_debuglink [start: 0x0, end: 0x51]
.shstrtab [start: 0x0, end: 0x279]
_elfSectionHeaders [start: 0x0, end: 0x1855]
```
</details>

<details><summary>2. Run Current Python Script in Ghidra Jython Task Output</summary>

```bash
 *  Executing task: /ghidra/support/analyzeHeadless /workspaces/ghidra-python-vscode-devcontainer-skeleton/.ghidra_projects/sample_project sample_project -postscript /workspaces/ghidra-python-vscode-devcontainer-skeleton/sample.py 

source /workspaces/ghidra-python-vscode-devcontainer-skeleton/.env/bin/activate
openjdk version "11.0.15" 2022-04-19 LTS
OpenJDK Runtime Environment Microsoft-32930 (build 11.0.15+10-LTS)
OpenJDK 64-Bit Server VM Microsoft-32930 (build 11.0.15+10-LTS, mixed mode)
INFO  Using log config file: jar:file:/ghidra/Ghidra/Framework/Generic/lib/Generic.jar!/generic.log4j.xml (LoggingInitialization)  
INFO  Using log file: /home/vscode/.ghidra/.ghidra_10.1.4_PUBLIC/application.log (LoggingInitialization)  
INFO  Loading user preferences: /home/vscode/.ghidra/.ghidra_10.1.4_PUBLIC/preferences (Preferences)  
INFO  Class search complete (776 ms) (ClassSearcher)  
INFO  Initializing SSL Context (SSLContextInitializer)  
INFO  Initializing Random Number Generator... (SecureRandomFactory)  
INFO  Random Number Generator initialization complete: NativePRNGNonBlocking (SecureRandomFactory)  
INFO  Trust manager disabled, cacerts have not been set (ApplicationTrustManagerFactory)  
WARN  Neither the -import parameter nor the -process parameter was specified; therefore, the specified prescripts and/or postscripts will be executed without any type of program context. (HeadlessAnalyzer)  
INFO  HEADLESS Script Paths:
    /ghidra/Ghidra/Features/Decompiler/ghidra_scripts
    /ghidra/Ghidra/Features/Base/ghidra_scripts
    /ghidra/Ghidra/Features/BytePatterns/ghidra_scripts
    /ghidra/Ghidra/Processors/8051/ghidra_scripts
    /ghidra/Ghidra/Features/Python/ghidra_scripts
    /ghidra/Ghidra/Debug/Debugger/ghidra_scripts
    /ghidra/Ghidra/Features/FileFormats/ghidra_scripts
    /ghidra/Ghidra/Processors/PIC/ghidra_scripts
    /ghidra/Ghidra/Processors/DATA/ghidra_scripts
    /ghidra/Ghidra/Debug/Debugger-agent-dbgmodel-traceloader/ghidra_scripts
    /ghidra/Ghidra/Features/VersionTracking/ghidra_scripts
    /ghidra/Ghidra/Features/FunctionID/ghidra_scripts
    /ghidra/Ghidra/Features/GnuDemangler/ghidra_scripts
    /ghidra/Ghidra/Features/MicrosoftCodeAnalyzer/ghidra_scripts (HeadlessAnalyzer)  
INFO  HEADLESS: execution starts (HeadlessAnalyzer)  
INFO  Opening existing project: /workspaces/ghidra-python-vscode-devcontainer-skeleton/.ghidra_projects/sample_project/sample_project (HeadlessAnalyzer)  
INFO  Opening project: /workspaces/ghidra-python-vscode-devcontainer-skeleton/.ghidra_projects/sample_project/sample_project (HeadlessProject)  
INFO  SCRIPT: /workspaces/ghidra-python-vscode-devcontainer-skeleton/sample.py (HeadlessAnalyzer)  
INFO  Reading script properties file: /workspaces/ghidra-python-vscode-devcontainer-skeleton/sample.properties (GhidraScriptProperties)  
sample_project
ghidra.framework.data.ProjectFileManager@7a9f836e
sample_project:/
Program Info:
Program: ls: AARCH64:LE:64:v8A_default (Wed Jul 13 13:49:27 UTC 2022)

Memory layout:
Imagebase: 0x100000L
segment_2.1 [start: 0x1048576, end: 0x1049143]
.interp [start: 0x1049144, end: 0x1049170]
.note.gnu.build-id [start: 0x1049172, end: 0x1049207]
.note.ABI-tag [start: 0x1049208, end: 0x1049239]
.gnu.hash [start: 0x1049240, end: 0x1049303]
.dynsym [start: 0x1049304, end: 0x1052423]
.dynstr [start: 0x1052424, end: 0x1053877]
.gnu.version [start: 0x1053878, end: 0x1054137]
.gnu.version_r [start: 0x1054144, end: 0x1054255]
.rela.dyn [start: 0x1054256, end: 0x1060087]
.rela.plt [start: 0x1060088, end: 0x1062703]
.init [start: 0x1062704, end: 0x1062723]
.plt [start: 0x1062736, end: 0x1064511]
.text [start: 0x1064512, end: 0x1149231]
.fini [start: 0x1149232, end: 0x1149247]
.rodata [start: 0x1149248, end: 0x1168549]
.eh_frame_hdr [start: 0x1168552, end: 0x1170795]
.eh_frame [start: 0x1170800, end: 0x1182903]
.init_array [start: 0x1250024, end: 0x1250031]
.fini_array [start: 0x1250032, end: 0x1250039]
.data.rel.ro [start: 0x1250040, end: 0x1252607]
.dynamic [start: 0x1252608, end: 0x1253119]
.got [start: 0x1253120, end: 0x1253351]
.got.plt [start: 0x1253352, end: 0x1254247]
.data [start: 0x1254248, end: 0x1254935]
.bss [start: 0x1254936, end: 0x1259735]
EXTERNAL [start: 0x1261568, end: 0x1262527]
.gnu_debugaltlink [start: 0x0, end: 0x73]
.gnu_debuglink [start: 0x0, end: 0x51]
.shstrtab [start: 0x0, end: 0x279]
_elfSectionHeaders [start: 0x0, end: 0x1855]
 *  Terminal will be reused by tasks, press any key to close it. 
```
</details>

<details><summary>3. Run via launch on sample-bridge.py</summary>

```bash
(.env) vscode ➜ /workspaces/ghidra-python-vscode-devcontainer-skeleton (main ✗) $  cd /workspaces/ghidra-python-vscode-devcontainer-skeleton ; /usr/bin/env /workspaces/ghidra-python-vscode-devcontainer-skeleton/.env/bin/python /home/vscode/.vscode-server/extensions/ms-python.python-2022.10.1/pythonFiles/lib/python/debugpy/adapter/../../debugpy/launcher 38055 -- /workspaces/ghidra-python-vscode-devcontainer-skeleton/sample-bridge.py 
/ghidra/support/analyzeHeadless /workspaces/ghidra-python-vscode-devcontainer-skeleton/.ghidra_projects/sample_project sample_project -scriptPath /workspaces/ghidra-python-vscode-devcontainer-skeleton/.ghidra_bridge -postscript ghidra_bridge_server.py ls
openjdk version "11.0.15" 2022-04-19 LTS
OpenJDK Runtime Environment Microsoft-32930 (build 11.0.15+10-LTS)
OpenJDK 64-Bit Server VM Microsoft-32930 (build 11.0.15+10-LTS, mixed mode)
INFO  Using log config file: jar:file:/ghidra/Ghidra/Framework/Generic/lib/Generic.jar!/generic.log4j.xml (LoggingInitialization)  
INFO  Using log file: /home/vscode/.ghidra/.ghidra_10.1.4_PUBLIC/application.log (LoggingInitialization)  
INFO  Loading user preferences: /home/vscode/.ghidra/.ghidra_10.1.4_PUBLIC/preferences (Preferences)  
waiting for ghidra_bridge_server...
INFO  Class search complete (758 ms) (ClassSearcher)  
INFO  Initializing SSL Context (SSLContextInitializer)  
INFO  Initializing Random Number Generator... (SecureRandomFactory)  
INFO  Random Number Generator initialization complete: NativePRNGNonBlocking (SecureRandomFactory)  
INFO  Trust manager disabled, cacerts have not been set (ApplicationTrustManagerFactory)  
WARN  Neither the -import parameter nor the -process parameter was specified; therefore, the specified prescripts and/or postscripts will be executed without any type of program context. (HeadlessAnalyzer)  
INFO  HEADLESS Script Paths:
    /ghidra/Ghidra/Features/Decompiler/ghidra_scripts
    /ghidra/Ghidra/Features/Base/ghidra_scripts
    /ghidra/Ghidra/Features/BytePatterns/ghidra_scripts
    /ghidra/Ghidra/Processors/8051/ghidra_scripts
    /ghidra/Ghidra/Features/Python/ghidra_scripts
    /ghidra/Ghidra/Debug/Debugger/ghidra_scripts
    /ghidra/Ghidra/Features/FileFormats/ghidra_scripts
    /ghidra/Ghidra/Processors/PIC/ghidra_scripts
    /ghidra/Ghidra/Processors/DATA/ghidra_scripts
    /workspaces/ghidra-python-vscode-devcontainer-skeleton/.ghidra_bridge
    /ghidra/Ghidra/Debug/Debugger-agent-dbgmodel-traceloader/ghidra_scripts
    /ghidra/Ghidra/Features/VersionTracking/ghidra_scripts
    /ghidra/Ghidra/Features/FunctionID/ghidra_scripts
    /ghidra/Ghidra/Features/GnuDemangler/ghidra_scripts
    /ghidra/Ghidra/Features/MicrosoftCodeAnalyzer/ghidra_scripts (HeadlessAnalyzer)  
INFO  HEADLESS: execution starts (HeadlessAnalyzer)  
INFO  Opening existing project: /workspaces/ghidra-python-vscode-devcontainer-skeleton/.ghidra_projects/sample_project/sample_project (HeadlessAnalyzer)  
INFO  Opening project: /workspaces/ghidra-python-vscode-devcontainer-skeleton/.ghidra_projects/sample_project/sample_project (HeadlessProject)  
INFO  SCRIPT: /workspaces/ghidra-python-vscode-devcontainer-skeleton/.ghidra_bridge/ghidra_bridge_server.py (HeadlessAnalyzer)  
waiting for ghidra_bridge_server...
waiting for ghidra_bridge_server...
waiting for ghidra_bridge_server...
waiting for ghidra_bridge_server...
INFO:jfx_bridge.bridge:serving! (jfx_bridge v0.9.1, Python 2.7.2)
waiting for ghidra_bridge_server...
WARNING:jfx_bridge.bridge:Handling connection from ('127.0.0.1', 48084)
WARNING:jfx_bridge.bridge:Handling connection from ('127.0.0.1', 48086)
WARNING:jfx_bridge.bridge:Closing connection from ('127.0.0.1', 48084)
sample_project
ghidra.framework.data.ProjectFileManager@69d3307d
sample_project:/
Program Info:
Program: ls: AARCH64:LE:64:v8A_default (Thu Aug 04 01:07:04 UTC 2022)

Memory layout:
Imagebase: 0x100000
segment_2.1 [start: 0x1048576, end: 0x1049143]
.interp [start: 0x1049144, end: 0x1049170]
.note.gnu.build-id [start: 0x1049172, end: 0x1049207]
.note.ABI-tag [start: 0x1049208, end: 0x1049239]
.gnu.hash [start: 0x1049240, end: 0x1049303]
.dynsym [start: 0x1049304, end: 0x1052423]
.dynstr [start: 0x1052424, end: 0x1053877]
.gnu.version [start: 0x1053878, end: 0x1054137]
.gnu.version_r [start: 0x1054144, end: 0x1054255]
.rela.dyn [start: 0x1054256, end: 0x1060087]
.rela.plt [start: 0x1060088, end: 0x1062703]
.init [start: 0x1062704, end: 0x1062723]
.plt [start: 0x1062736, end: 0x1064511]
.text [start: 0x1064512, end: 0x1149231]
.fini [start: 0x1149232, end: 0x1149247]
.rodata [start: 0x1149248, end: 0x1168549]
.eh_frame_hdr [start: 0x1168552, end: 0x1170795]
.eh_frame [start: 0x1170800, end: 0x1182903]
.init_array [start: 0x1250024, end: 0x1250031]
.fini_array [start: 0x1250032, end: 0x1250039]
.data.rel.ro [start: 0x1250040, end: 0x1252607]
.dynamic [start: 0x1252608, end: 0x1253119]
.got [start: 0x1253120, end: 0x1253351]
.got.plt [start: 0x1253352, end: 0x1254247]
.data [start: 0x1254248, end: 0x1254935]
.bss [start: 0x1254936, end: 0x1259735]
EXTERNAL [start: 0x1261568, end: 0x1262527]
.gnu_debugaltlink [start: 0x0, end: 0x73]
.gnu_debuglink [start: 0x0, end: 0x51]
.shstrtab [start: 0x0, end: 0x279]
_elfSectionHeaders [start: 0x0, end: 0x1855]
Shutting down ghidra_bridge_server : 43841
```
</details>

<details><summary>4. Run via launch on sample-pyhidra.py</summary>

```terminal
(.env) vscode ➜ /workspaces/ghidra-python-vscode-devcontainer-skeleton (main ✗) $  cd /workspaces/ghidra-python-vscode-devcontainer-skeleton ; /usr/bin/env /workspaces/ghidra-python-vscode-devcontainer-skeleton/.env/bin/python /home/vscode/.vscode-server/extensions/ms-python.python-2022.12.0/pythonFiles/lib/python/debugpy/adapter/../../debugpy/launcher 40875 -- /workspaces/ghidra-python-vscode-devcontainer-skeleton/sample-pyhidra.py 
/ghidra/Ghidra/Framework/Utility/lib/Utility.jar
INFO  Using log config file: jar:file:/ghidra/Ghidra/Framework/Generic/lib/Generic.jar!/generic.log4j.xml (LoggingInitialization)  
INFO  Using log file: /home/vscode/.ghidra/.ghidra_10.1.4_PUBLIC/application.log (LoggingInitialization)  
INFO  Loading user preferences: /home/vscode/.ghidra/.ghidra_10.1.4_PUBLIC/preferences (Preferences)  
INFO  Class search complete (813 ms) (ClassSearcher)  
INFO  Initializing SSL Context (SSLContextInitializer)  
INFO  Initializing Random Number Generator... (SecureRandomFactory)  
INFO  Random Number Generator initialization complete: NativePRNGNonBlocking (SecureRandomFactory)  
INFO  Trust manager disabled, cacerts have not been set (ApplicationTrustManagerFactory)  
INFO  Opening project: /workspaces/ghidra-python-vscode-devcontainer-skeleton/.ghidra_projects/sample_project/sample_project/sample_project (DefaultProject)  
INFO  DWARF external debug information found: ExternalDebugInfo [filename=1a4999161b8b2da681b80d8bf351e40afc40ad.debug, crc=1816f651, hash=9c1a4999161b8b2da681b80d8bf351e40afc40ad] (ExternalDebugFilesService)  
INFO  Unable to find DWARF information, skipping DWARF analysis (DWARFAnalyzer)  
ERROR os/linux_arm_64/decompile does not exist (DecompileProcessFactory)  
INFO  Packed database cache: /tmp/vscode-Ghidra/packed-db-cache (PackedDatabaseCache)  
INFO  -----------------------------------------------------
    AARCH64 ELF PLT Thunks                     0.017 secs
    ASCII Strings                              0.249 secs
    Apply Data Archives                        0.230 secs
    Basic Constant Reference Analyzer          1.394 secs
    Call Convention ID                         0.008 secs
    Call-Fixup Installer                       0.004 secs
    Create Address Tables                      0.024 secs
    Create Function                            0.000 secs
    DWARF                                      0.017 secs
    Data Reference                             0.037 secs
    Decompiler Switch Analysis                 0.164 secs
    Demangler GNU                              0.214 secs
    Disassemble Entry Points                   0.013 secs
    Embedded Media                             0.013 secs
    External Entry References                  0.000 secs
    Function Start Search                      0.106 secs
    Function Start Search After Code           0.012 secs
    Function Start Search After Data           0.031 secs
    GCC Exception Handlers                     0.471 secs
    Non-Returning Functions - Discovered       0.026 secs
    Non-Returning Functions - Known            0.019 secs
    Reference                                  0.093 secs
    Shared Return Calls                        0.026 secs
    Stack                                      0.069 secs
    Subroutine References                      0.036 secs
-----------------------------------------------------
     Total Time   3 secs
-----------------------------------------------------
 (AutoAnalysisManager)  
Program Info:
Program: ls: AARCH64:LE:64:v8A_default (Sat Aug 06 02:18:37 UTC 2022)

Memory layout:
Imagebase: 0x100000
segment_2.1 [start: 0x1048576, end: 0x1049143]
.interp [start: 0x1049144, end: 0x1049170]
.note.gnu.build-id [start: 0x1049172, end: 0x1049207]
.note.ABI-tag [start: 0x1049208, end: 0x1049239]
.gnu.hash [start: 0x1049240, end: 0x1049303]
.dynsym [start: 0x1049304, end: 0x1052423]
.dynstr [start: 0x1052424, end: 0x1053877]
.gnu.version [start: 0x1053878, end: 0x1054137]
.gnu.version_r [start: 0x1054144, end: 0x1054255]
.rela.dyn [start: 0x1054256, end: 0x1060087]
.rela.plt [start: 0x1060088, end: 0x1062703]
.init [start: 0x1062704, end: 0x1062723]
.plt [start: 0x1062736, end: 0x1064511]
.text [start: 0x1064512, end: 0x1149231]
.fini [start: 0x1149232, end: 0x1149247]
.rodata [start: 0x1149248, end: 0x1168549]
.eh_frame_hdr [start: 0x1168552, end: 0x1170795]
.eh_frame [start: 0x1170800, end: 0x1182903]
.init_array [start: 0x1250024, end: 0x1250031]
.fini_array [start: 0x1250032, end: 0x1250039]
.data.rel.ro [start: 0x1250040, end: 0x1252607]
.dynamic [start: 0x1252608, end: 0x1253119]
.got [start: 0x1253120, end: 0x1253351]
.got.plt [start: 0x1253352, end: 0x1254247]
.data [start: 0x1254248, end: 0x1254935]
.bss [start: 0x1254936, end: 0x1259735]
EXTERNAL [start: 0x1261568, end: 0x1262527]
.gnu_debugaltlink [start: 0x0, end: 0x73]
.gnu_debuglink [start: 0x0, end: 0x51]
.shstrtab [start: 0x0, end: 0x279]
_elfSectionHeaders [start: 0x0, end: 0x1855]
```
</details>

## Ghidra Python Headless Scripting Hangups

1. Ghidra runs Jython, not actually Python. It is limited to python 2.7 features.
2. In order to pass arguments to api calls like [askProgram](https://ghidra.re/ghidra_docs/api/ghidra/app/script/GhidraScript.html#askProgram(java.lang.String)) (which sets the current program being analyzed) either:
   - a `.properties` file needs to exist with the same name and location as the script being run. In this case a [sample.properties](sample.properties) sets the arguments for [sample.py](sample.py).
   - the args have to be passed on the command line when running `analyzeHeadless`. For [sample-bridge.py](sample-bridge.py), the args are awkwardly passed when ghidra_bridge_server [starts](sample-bridge.py#L37), as that server running within the Ghidra context is the only time analyzeHeadless is called.  More details [here](https://github.com/justfoxing/ghidra_bridge#headless-analysis-context).
3. `ghidra-bridge` has to be started and running before you [connect](sample-bridge.py#L53) to it. The bridge can be started outside of sample-bridge.py, but you won't be able to pass arguments to it if neeed. Also, `ghidra-bridge` is slow for large analysis. Its best feature is the ability to step through and inspect the sample-bridge.py script within the IDE.
4. `pyhidra` - Need to be wary of conflicting module names. As python stdlib and Ghidra have some conflicting module names (such as `pdb`), there are sometimes issues getting access to the full Ghidra Script API with `pyhidra`. Python prefers local modules and stdlib over the Java imports. This is due to [this issue](https://jpype.readthedocs.io/en/latest/userguide.html#importing-java-classes) in `jpype`.