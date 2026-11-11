"""
--align-names on real pairs from ghidriff-test-data. Thresholds, not golden text, so a Ghidra
upgrade does not break the test. Measured on Ghidra 12.2 (changed C lines, off -> on):
  afd.sys 10.0.22621.1028 -> .1415:   917 -> 557 (-39%), 0 of 12 larger; --align-unresolved 313 (-66%)
  libcorecrypto 14.2.1 -> 14.3:       4215 -> 3985 (-5.5%), 0 of 41 larger
"""
import json
import re
from pathlib import Path

import pytest

from ghidriff import get_parser, VersionTrackingDiff, GhidraDiffEngine
from ghidriff.name_align import undo

SYMBOLS_DIR = 'symbols'
BINS_DIR = 'bins'


def changed_lines(diff: str) -> int:
    return sum(1 for line in diff.splitlines() if line[:1] in '+-' and line[:3] not in ('+++', '---'))


def base_new(func: dict, unresolved: bool) -> list:
    """The new-side text the aligned diff was built from."""
    lines = func['new']['code'].splitlines(True)
    if not unresolved:
        GhidraDiffEngine.normalize_ghidra_decomp(None, lines)
    return lines


def reverses(func: dict, unresolved: bool) -> bool:
    """Each hunk's new side, undone through name_map, equals the same slice of the original text."""
    base = base_new(func, unresolved)
    lines = func['diff'].splitlines(True)
    i = 0
    while i < len(lines):
        m = re.match(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@', lines[i])
        i += 1
        if not m:
            continue
        start, count = int(m.group(1)), int(m.group(2) or 1)
        side = []
        while i < len(lines) and not lines[i].startswith('@@'):
            if lines[i][:1] in '+ ':
                side.append(lines[i][1:])
            i += 1
        if undo(side, func.get('name_map', {})) != base[start - 1:start - 1 + count]:
            return False
    return True


def diff_modes(shared_datadir: Path, test_name: str, old_name: str, new_name: str, unresolved: bool):
    """One engine, one analysis: diff with alignment off, on, and optionally on + unresolved."""
    output_path = shared_datadir / test_name
    output_path.mkdir(exist_ok=True, parents=True)
    bins_path = shared_datadir / BINS_DIR
    old_bin_path, new_bin_path = bins_path / old_name, bins_path / new_name
    assert old_bin_path.exists() and new_bin_path.exists()

    parser = get_parser()
    GhidraDiffEngine.add_ghidra_args_to_parser(parser)
    args = parser.parse_args(['-s', str(shared_datadir / SYMBOLS_DIR), str(old_bin_path.absolute()),
                              str(new_bin_path.absolute()), '-p', str((output_path / 'ghidra_projects').absolute())])

    d: GhidraDiffEngine = VersionTrackingDiff(args=args,
                                              verbose=True,
                                              threaded=args.threaded,
                                              max_ram_percent=args.max_ram_percent,
                                              engine_log_path=output_path / parser.get_default('log_path'),
                                              engine_log_level=args.log_level,
                                              engine_file_log_level=args.file_log_level,
                                              no_symbols=True)
    d.setup_project([old_bin_path, new_bin_path], args.project_location,
                    f'{args.project_name}-{old_name}-{new_name}', args.symbols_path)
    d.analyze_project()

    results = {'off': d.diff_bins(old_bin_path, new_bin_path)}
    d.align_names = True
    results['on'] = d.diff_bins(old_bin_path, new_bin_path)
    if unresolved:
        d.align_unresolved = True
        results['unresolved'] = d.diff_bins(old_bin_path, new_bin_path)
    for pdiff in results.values():
        d.validate_diff_json(json.dumps(pdiff))
    return results


def check_alignment(off: dict, on: dict, unresolved: bool, min_drop: float):
    key = lambda f: (f['old']['address'], f['new']['address'])  # noqa: E731
    moff = {key(f): f for f in off['functions']['modified']}
    mon = {key(f): f for f in on['functions']['modified']}

    # emitted text only: the modified set, diff_type and every ratio are unchanged
    assert set(moff) == set(mon)
    for k in moff:
        for field in ('diff_type', 'ratio', 'i_ratio', 'm_ratio', 'b_ratio'):
            assert moff[k][field] == mon[k][field], (moff[k]['old']['name'], field)

    for f in mon.values():
        assert reverses(f, unresolved), f['old']['name']

    lines_off = sum(changed_lines(f['diff']) for f in moff.values())
    lines_on = sum(changed_lines(f['diff']) for f in mon.values())
    assert lines_on <= lines_off * (1 - min_drop), (lines_off, lines_on)

    larger = [f['old']['name'] for k, f in mon.items() if changed_lines(f['diff']) > changed_lines(moff[k]['diff'])]
    assert len(larger) <= 0.01 * len(mon), larger


@pytest.mark.forked
def test_align_names_afd(shared_datadir: Path):
    """
    runs forked because each jpype jvm can only be initialized 1x
    """
    r = diff_modes(shared_datadir, 'align-afd', 'afd.sys.x64.10.0.22621.1028', 'afd.sys.x64.10.0.22621.1415',
                   unresolved=True)
    check_alignment(r['off'], r['on'], unresolved=False, min_drop=0.25)
    check_alignment(r['off'], r['unresolved'], unresolved=True, min_drop=0.50)


@pytest.mark.forked
def test_align_names_libcorecrypto(shared_datadir: Path):
    """
    runs forked because each jpype jvm can only be initialized 1x
    """
    r = diff_modes(shared_datadir, 'align-corecrypto', 'libcorecrypto.dylib-14.2.1', 'libcorecrypto.dylib-14.3',
                   unresolved=False)
    check_alignment(r['off'], r['on'], unresolved=False, min_drop=0.02)
