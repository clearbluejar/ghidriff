"""
Offline unit tests for ghidriff.markdown escaping and header cleaning.

The report generator interpolates binary-derived names (demangled C++ symbols
routinely contain '|', '<', '>') into markdown tables and mermaid node ids.
These tests pin the escaping behavior without a Ghidra runtime.

Loaded by file path to avoid importing the ghidriff package __init__ (which
pulls in the pyghidra-dependent engine). Run under pytest, or standalone:

    python3 tests/test_markdown_escaping.py
"""

import importlib.util
from pathlib import Path

import pytest

pytestmark = pytest.mark.fast

_MOD = Path(__file__).resolve().parent.parent / 'ghidriff' / 'markdown.py'
_spec = importlib.util.spec_from_file_location('ghidriff_markdown', _MOD)
md = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(md)

GhidriffMarkdown = md.GhidriffMarkdown


def test_md_cell_escapes_pipe():
    # A '|' in a demangled name must not end the table cell.
    assert GhidriffMarkdown._md_cell('a|b') == 'a\\|b'


def test_md_cell_folds_newlines():
    assert GhidriffMarkdown._md_cell('line1\nline2') == 'line1<br>line2'
    assert GhidriffMarkdown._md_cell('line1\r\nline2') == 'line1<br>line2'


def test_md_cell_escapes_backslash_before_pipe():
    # Backslash is escaped first so the pipe escape is not corrupted.
    assert GhidriffMarkdown._md_cell('a\\b') == 'a\\\\b'


def test_md_cell_none_and_nonstr():
    assert GhidriffMarkdown._md_cell(None) == ''
    assert GhidriffMarkdown._md_cell(42) == '42'


def test_md_cell_real_cpp_symbol_is_single_cell():
    # A real WIL/C++ template symbol with pipes/angle brackets must stay one cell.
    name = ("?__private_IsEnabled@?$FeatureImpl@U__WilFeatureTraits_Feature_1@@"
            "@details@wil@@QEAA_N|XZ")
    out = GhidriffMarkdown._md_cell(name)
    # no unescaped pipe remains (every '|' is preceded by a backslash)
    assert '|' in name and out.count('\\|') == name.count('|')
    assert '\n' not in out


def test_clean_md_header_strips_backslash():
    m = GhidriffMarkdown.__new__(GhidriffMarkdown)   # no __init__ / no logger needed
    # A stray backslash in a name must NOT survive into a mermaid node id.
    assert '\\' not in m._clean_md_header('foo\\bar')
    assert '\\' not in m._clean_md_header_lower('Foo\\Bar')


def test_clean_md_header_keeps_hyphen_and_underscore():
    m = GhidriffMarkdown.__new__(GhidriffMarkdown)
    assert m._clean_md_header('my func name') == 'my-func-name'
    assert m._clean_md_header('Keep_These-123') == 'Keep_These-123'


def _run_standalone():
    import traceback
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_') and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            passed += 1
            print(f'PASS {t.__name__}')
        except Exception:
            failed += 1
            print(f'FAIL {t.__name__}')
            traceback.print_exc()
    print(f'\n{passed} passed, {failed} failed')
    return failed == 0


if __name__ == '__main__':
    import sys
    sys.exit(0 if _run_standalone() else 1)
