"""
Operand-only changes (tests/fixtures/operand, rebuilt with build.sh): a function whose only change
is a constant keeps its size and its mnemonics, so the default triage never diffs it. --pcode-gate
finds it, and must report nothing for the unchanged control.
"""
from pathlib import Path
import json

import pytest

from ghidriff import get_parser, VersionTrackingDiff, GhidraDiffEngine

OPERAND_BINS = Path(__file__).parent / 'fixtures' / 'operand' / 'bin'


def run_diff(tmp_path: Path, variant: str, extra_args: list):
    """Diff operand.base against operand.<variant>. Returns (pdiff, markdown report text)."""
    old_bin_path = OPERAND_BINS / 'operand.base'
    new_bin_path = OPERAND_BINS / f'operand.{variant}'

    assert old_bin_path.exists()
    assert new_bin_path.exists()

    output_path = tmp_path / variant
    ghidra_project_path = output_path / 'ghidra_projects'
    ghidra_project_path.mkdir(exist_ok=True, parents=True)

    parser = get_parser()
    GhidraDiffEngine.add_ghidra_args_to_parser(parser)
    args = parser.parse_args(extra_args + [str(old_bin_path.absolute()), str(new_bin_path.absolute()),
                                           '-p', str(ghidra_project_path.absolute())])

    d: GhidraDiffEngine = VersionTrackingDiff(args=args,
                                              verbose=True,
                                              threaded=args.threaded,
                                              max_ram_percent=args.max_ram_percent,
                                              engine_log_path=output_path / parser.get_default('log_path'),
                                              engine_log_level=args.log_level,
                                              engine_file_log_level=args.file_log_level,
                                              no_symbols=True,
                                              pcode_gate=args.pcode_gate,
                                              emit_asm_diff=args.emit_asm_diff)
    d.setup_project([old_bin_path, new_bin_path], args.project_location,
                    f'{args.project_name}-{old_bin_path.name}-{new_bin_path.name}', args.symbols_path)
    d.analyze_project()

    pdiff = d.diff_bins(old_bin_path, new_bin_path)
    d.validate_diff_json(json.dumps(pdiff))

    name = f'{old_bin_path.name}-{new_bin_path.name}'
    d.dump_pdiff_to_path(name, pdiff, output_path, write_json=False, write_matches=False)
    return pdiff, (output_path / f'{name}.md').read_text(encoding='utf-8')


def find_check(pdiff):
    found = [func for func in pdiff['functions']['modified'] if func['old']['name'] == '_check']
    assert len(found) <= 1
    return found[0] if found else None


@pytest.mark.forked
def test_unchanged_control_reports_nothing(tmp_path: Path):
    """
    The same source built twice. A gate that reports changes on identical code is worse than the
    blind spot it closes.
    runs forked because each jpype jvm can only be initialized 1x
    """
    pdiff, _ = run_diff(tmp_path, 'same', ['--pcode-gate'])
    assert pdiff['functions']['modified'] == []
    assert pdiff['functions']['added'] == [] and pdiff['functions']['deleted'] == []
    assert pdiff['stats']['pcode_surfaced_len'] == 0


@pytest.mark.forked
def test_changed_bound_is_surfaced_and_reported(tmp_path: Path):
    """
    n > 64 -> n > 32 (cmp #0x40 -> #0x20). check() is inlined into main(), so two functions share
    the constant delta; a compared constant must not be dropped as a layout shift.
    runs forked because each jpype jvm can only be initialized 1x
    """
    pdiff, report = run_diff(tmp_path, 'const', ['--pcode-gate', '--emit-asm-diff'])

    check = find_check(pdiff)
    assert check is not None, pdiff['stats'].get('pcode_dropped')
    assert 'pcode' in check['diff_type']
    assert 'length' not in check['diff_type']
    assert check['pcode']['change_class'] == 'compare'
    assert ['0x40', '0x20'] in check['pcode']['const_deltas']
    assert pdiff['stats']['pcode_dropped'].get('shift', 0) == 0

    # the instruction-level diff states the change directly
    changed = [line for line in check['asm_diff'].splitlines() if line[:1] in '+-' and line[:3] not in ('+++', '---')]
    assert changed == ['-cmp x0,#0x40', '+cmp x0,#0x20']

    # and the markdown report shows the function, the p-code summary and the asm diff
    assert '## _check' in report
    assert 'compare: 0x40 → 0x20' in report
    assert '_check Assembly Diff' in report


@pytest.mark.forked
def test_changed_stack_size_is_surfaced(tmp_path: Path):
    """
    char scratch[256] -> [128]: sub sp,sp,#0x140 -> #0xc0, the MS03-026 shape.
    runs forked because each jpype jvm can only be initialized 1x
    """
    pdiff, _ = run_diff(tmp_path, 'stack', ['--pcode-gate'])

    check = find_check(pdiff)
    assert check is not None, pdiff['stats'].get('pcode_dropped')
    assert 'pcode' in check['diff_type']
    assert check['pcode']['change_class'] == 'const'
    assert ['0x140', '0xc0'] in check['pcode']['const_deltas']


@pytest.mark.forked
def test_structural_change_needs_no_gate(tmp_path: Path):
    """
    An added statement changes the size, so the default triage finds it.
    runs forked because each jpype jvm can only be initialized 1x
    """
    pdiff, report = run_diff(tmp_path, 'struct', [])

    check = find_check(pdiff)
    assert check is not None
    assert 'code' in check['diff_type'] and 'length' in check['diff_type']
    assert '## _check' in report


@pytest.mark.forked
def test_operand_only_change_is_missed_without_the_gate(tmp_path: Path):
    """
    Documents the default: a same-size, same-mnemonic change is not diffed unless --pcode-gate is
    on. If the gate becomes the default, flip this assertion.
    runs forked because each jpype jvm can only be initialized 1x
    """
    pdiff, _ = run_diff(tmp_path, 'const', [])
    assert find_check(pdiff) is None
