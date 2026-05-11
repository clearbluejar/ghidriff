import argparse
from pathlib import Path
from types import SimpleNamespace

import pytest

from ghidriff import GhidraDiffEngine, get_parser
from ghidriff.utils import get_pe_extra_data


pytestmark = pytest.mark.fast


class _PlanEngine:
    get_import_plan_options = GhidraDiffEngine.get_import_plan_options
    get_project_program_name = GhidraDiffEngine.get_project_program_name
    gen_proj_bin_name_from_path = GhidraDiffEngine.gen_proj_bin_name_from_path


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


def test_import_plan_arg_validates_json(tmp_path: Path):
    import_plan = tmp_path / "import-plan.json"
    import_plan.write_text('{"defaults": {"language": "x86:LE:64:default"}}')
    parser = argparse.ArgumentParser()
    GhidraDiffEngine.add_ghidra_args_to_parser(parser)

    args = parser.parse_args(["--import-plan", str(import_plan)])

    assert args.import_plan == str(import_plan)


def test_import_plan_rejects_unknown_keys():
    with pytest.raises(argparse.ArgumentTypeError, match="unexpected"):
        GhidraDiffEngine.validate_import_plan({"defaults": {"bad": "value"}})


def test_import_plan_merges_defaults_and_path_specific_options(tmp_path: Path):
    binary_path = tmp_path / "old.bin"
    binary_path.write_bytes(b"old")
    engine = _PlanEngine()
    engine.import_plan = GhidraDiffEngine.load_import_plan({
        "defaults": {
            "loader": "ghidra.app.util.opinion.BinaryLoader",
            "language": "x86:LE:64:default",
        },
        "imports": {
            "old.bin": {
                "compiler": "gcc",
                "program_name": "old-program",
            },
        },
    })

    options = GhidraDiffEngine.get_import_plan_options(engine, binary_path)

    assert options == {
        "loader": "ghidra.app.util.opinion.BinaryLoader",
        "language": "x86:LE:64:default",
        "compiler": "gcc",
        "program_name": "old-program",
    }
    assert GhidraDiffEngine.get_project_program_name(engine, binary_path) == "old-program"


def test_import_plan_compiler_requires_language(tmp_path: Path):
    binary_path = tmp_path / "old.bin"
    binary_path.write_bytes(b"old")
    engine = SimpleNamespace()
    engine.import_plan = GhidraDiffEngine.load_import_plan({})

    with pytest.raises(ValueError, match="compiler requires a language"):
        GhidraDiffEngine.import_program_with_plan(
            engine,
            project=None,
            program_path=binary_path,
            import_options={"compiler": "gcc"},
        )


def test_project_spec_accepts_gpr_path():
    spec = GhidraDiffEngine.normalize_project_spec(
        Path("/tmp/projects/sample.gpr"),
        "ghidriff",
    )

    assert spec.project_location == Path("/tmp/projects")
    assert spec.project_name == "sample"
    assert spec.gpr_path == Path("/tmp/projects/sample.gpr")
    assert spec.was_gpr_path is True


def test_project_spec_rejects_custom_name_with_gpr_path():
    with pytest.raises(ValueError, match="Cannot use --project-name"):
        GhidraDiffEngine.normalize_project_spec(
            Path("/tmp/projects/sample.gpr"),
            "custom",
        )


def test_project_spec_preserves_directory_project_options():
    spec = GhidraDiffEngine.normalize_project_spec(
        Path("/tmp/projects"),
        "custom",
    )

    assert spec.project_location == Path("/tmp/projects")
    assert spec.project_name == "custom"
    assert spec.gpr_path == Path("/tmp/projects/custom.gpr")
    assert spec.was_gpr_path is False


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
