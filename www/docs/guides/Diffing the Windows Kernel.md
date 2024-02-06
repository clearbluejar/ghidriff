---
description: Diffing ntoskrnl.exe - KB5022913 - 11-22H2 - CVE-2023-2342
---

### Diffing a Windows Kernel 

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