# Changelog

## 1.1.0 (unreleased)

Most of this release is about arm64e (Apple) binaries: finding changes that were missed, and
making the emitted diff readable.

### Behaviour changes

These change results for existing users. Counts of modified and code-changed functions can differ
from 1.0.0 on the same inputs.

- **`m_ratio` now measures mnemonics.** The mnemonic list held the same string for every
  instruction, so `m_ratio` only compared instruction counts, and a change that kept the count and
  the sorted block mnemonics was not tagged `code`.
- **The `code` tag uses unrounded ratios.** `m_ratio` and `b_ratio` are still reported rounded to
  two places, but a few changed instructions in a large function no longer round back to 1.0 and
  lose the tag.
- **Same-named inputs are diffed correctly.** With `old/libfoo.dylib` and `new/libfoo.dylib`, the
  old side was decompiled against the new program. Decompilers and cached symbols are now keyed by
  program, not by name.
- **AArch64 switch repair is on by default** (`--no-switch-repair` to turn it off). Ghidra 12.0 and
  12.2 do not recover Apple's hardened arm64e jump tables when the cases do not start at 0. The
  function body then ends at the switch, and a change inside a case is never compared. ghidriff
  reads the table and adds the missing cases after analysis; the result is saved in the Ghidra
  project and the `.gzf`.
- **The symbol-count preflight is relative.** It stopped the diff when symbol counts differed by
  4,000 or more. It now stops only when the difference is also at least 25% of the larger program,
  and warns with both counts otherwise.
- **No heap dump by default.** `-XX:+HeapDumpOnOutOfMemoryError` wrote a dump the size of the heap
  into the working directory. Pass `--jvm-args=-XX:+HeapDumpOnOutOfMemoryError` to get one.
- **BSim is skipped when it would exhaust the heap.** BSim pairs every external function with every
  other; above `--bsim-max-external-pairs` (default 25,000,000) it is skipped with a warning.
- **SimpleDiff is deprecated** and kept as an example engine. Its `Address:Length` match compared a
  function to itself.

### Added

- `--emit-asm-diff`: an `asm_diff` per code-modified function, with build-specific addresses
  removed, in the JSON and as a collapsed section in the markdown report.
- `--pcode-gate` (experimental): also diffs matched functions of the same size whose normalized
  p-code changed, such as a changed bound or stack size. These get `pcode` in `diff_type` and a
  `pcode` entry (`hash`, `change_class`, `const_deltas`), and are in the markdown report. A changed
  constant that is compared (`cmp`, `tst`, ...) has the class `compare` and is never dropped as a
  layout shift.
- `--align-names`: renames the new side's locals, labels and matched functions to the old side's
  in the emitted C diff. Each modified function gets a `name_map` that reverses it exactly.
  `--align-unresolved` also aligns `func_0x`/`DAT_`/`PTR_` references (inferred).
- The JSON records which build made it: `ghidriff: {version, commit}`.
- `stats.ambiguous_modified_len` and `ambiguous_match: true` on modified entries that share an old
  or new function with another entry (a one-to-many match).
- Ghidra 12.2 support. CI runs on Ghidra 12.0.4, 12.1.4 and 12.2.

### Fixed

- Markdown tables and headers escape `|` and line breaks in function names.
- Matcher fixes in `correlators.py` and `structural_graph_diff.py`; a program opened twice is
  closed once.
- The test suite no longer hangs or fails under pytest 9.2.
