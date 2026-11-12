import argparse
from pathlib import Path
from types import SimpleNamespace

import pytest

from ghidriff import GhidraDiffEngine, get_parser
from ghidriff.utils import get_pe_extra_data


pytestmark = pytest.mark.fast


def test_summary_is_boolean_flag():
    parser = get_parser()

    args = parser.parse_args(["old.bin", "new.bin", "--summary"])

    assert args.summary is True


def test_summary_defaults_false():
    parser = get_parser()

    args = parser.parse_args(["old.bin", "new.bin"])

    assert args.summary is False


def test_ghidra_args_parse_typed_values_and_dash_prefixed_jvm_args():
    parser = argparse.ArgumentParser()
    GhidraDiffEngine.add_ghidra_args_to_parser(parser)

    args = parser.parse_args([
        "--max-ram-percent",
        "75.5",
        "--jvm-args=-Xmx8G",
        "--jvm-args=-Dfoo=bar",
        "--decompiler-timeout",
        "120",
    ])

    assert args.max_ram_percent == 75.5
    assert args.jvm_args == ["-Xmx8G", "-Dfoo=bar"]
    assert args.decompiler_timeout == 120


def test_remove_code_sig_always_returns_list_of_strings():
    code = "int demo(void)\n{\n  return 1;\n}\n"

    stripped = GhidraDiffEngine.remove_code_sig(None, code)
    failed = GhidraDiffEngine.remove_code_sig(None, "Failed to decompile demo")
    missing = GhidraDiffEngine.remove_code_sig(None, None)

    assert stripped == ["\n", "  return 1;\n", "}\n"]
    assert failed == ["Failed to decompile demo"]
    assert missing == []


def test_pe_extra_data_rejects_non_pe_file(tmp_path: Path):
    not_a_pe = tmp_path / "not-a-pe.bin"
    not_a_pe.write_text("not a PE")

    with pytest.raises(Exception):
        get_pe_extra_data(not_a_pe)


def test_ghidra_application_info_falls_back_to_launcher_app_info():
    launcher = SimpleNamespace(
        _layout=None,
        app_info=SimpleNamespace(
            version="12.0.4",
            build_date="2026-Mar-03 1410 EST",
            release_name="PUBLIC",
        ),
    )

    app_info = GhidraDiffEngine.get_ghidra_application_info(launcher)

    assert app_info.applicationVersion == "12.0.4"
    assert app_info.applicationBuildDate == "2026-Mar-03 1410 EST"
    assert app_info.applicationReleaseName == "PUBLIC"


class _FakeBody:
    numAddresses = 8


class _FakeFunc:
    body = _FakeBody()


class _FakeFunctionManager:
    def getFunctionAt(self, address):
        return _FakeFunc()


class _FakeProgram:
    functionManager = _FakeFunctionManager()


class _FakeSymbol:
    address = "0x1000"
    program = _FakeProgram()
    referenceCount = 1


class _FastEngine(GhidraDiffEngine):
    def find_matches(self, p1, p2):
        return [[], [], []]


def test_broad_hash_matches_still_get_diffed_for_small_function_changes():
    engine = object.__new__(_FastEngine)
    engine.min_func_len = 8

    assert GhidraDiffEngine.syms_need_diff(
        engine,
        _FakeSymbol(),
        _FakeSymbol(),
        ["StructuralGraphHash"],
        [],
    ) is True


def test_exact_instruction_matches_can_skip_deeper_diff_when_metadata_matches():
    engine = object.__new__(_FastEngine)
    engine.min_func_len = 10

    assert GhidraDiffEngine.syms_need_diff(
        engine,
        _FakeSymbol(),
        _FakeSymbol(),
        ["ExactInstructionsFunctionHasher"],
        [],
    ) is False


class _FakeSymbolTable:
    def __init__(self, count):
        self.numSymbols = count


class _FakePreflightProgram:
    def __init__(self, name, language_id, symbol_count):
        self.name = name
        self.languageID = language_id
        self._symbol_table = _FakeSymbolTable(symbol_count)

    def getSymbolTable(self):
        return self._symbol_table


def test_preflight_rejects_language_mismatch_with_actionable_error():
    engine = object.__new__(_FastEngine)

    with pytest.raises(ValueError, match="Language mismatch"):
        GhidraDiffEngine.check_diff_preconditions(
            engine,
            _FakePreflightProgram("old", "x86:LE:64:default", 100),
            _FakePreflightProgram("new", "ARM:LE:32:v8", 100),
        )


def test_preflight_rejects_large_symbol_count_mismatch_with_actionable_error():
    engine = object.__new__(_FastEngine)

    with pytest.raises(ValueError, match="Symbol counts"):
        GhidraDiffEngine.check_diff_preconditions(
            engine,
            _FakePreflightProgram("old", "x86:LE:64:default", 100),
            _FakePreflightProgram("new", "x86:LE:64:default", 5000),
        )


def test_code_gate_uses_unrounded_ratios():
    # R4.9: one changed instruction in a 400-instruction function rounds back to a ratio of 1.0.
    # Distinct items: SequenceMatcher's autojunk ignores items that make up >1% of a 200+ long list.
    old = [f'op{i}' for i in range(400)]
    new = list(old)
    new[200] = 'cmp'
    changed, m_ratio, b_ratio = GhidraDiffEngine.compare_instruction_lists(old, new, sorted(old), sorted(new))
    assert m_ratio == 1.0  # the rounded value the report shows
    assert changed is True
    assert GhidraDiffEngine.compare_instruction_lists(old, list(old), sorted(old), sorted(old))[0] is False
