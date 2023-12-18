---
sidebar_position: 4
---

```bash
usage: ghidriff [-h] [--engine {SimpleDiff,StructualGraphDiff,VersionTrackingDiff}] [-o OUTPUT_PATH] [--summary SUMMARY] [-p PROJECT_LOCATION] [-n PROJECT_NAME] [-s SYMBOLS_PATH] [--threaded | --no-threaded] [--force-analysis] [--force-diff] [--no-symbols] [--log-level {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}]
                [--file-log-level {CRITICAL,FATAL,ERROR,WARN,WARNING,INFO,DEBUG,NOTSET}] [--log-path LOG_PATH] [--va] [--min-func-len MIN_FUNC_LEN] [--use-calling-counts USE_CALLING_COUNTS] [--max-ram-percent MAX_RAM_PERCENT] [--print-flags] [--jvm-args [JVM_ARGS]] [--sxs] [--max-section-funcs MAX_SECTION_FUNCS]
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
  --use-calling-counts USE_CALLING_COUNTS
                        Add calling/called reference counts (default: True)

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

