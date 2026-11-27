"""
Gold cases: known fixes a diff must (or must not) show, checked on real binary pairs before a release or a pin.

Cases are read from tests/gold/cases.example.json (the synthetic operand fixture), tests/gold/cases.test-data.json
(real binaries from ghidriff-test-data, cloned to tests/data as in CI) and GHIDRIFF_GOLD_CASES (default
tests/gold/cases.local.json, gitignored: cases on binaries that stay on one machine). A case whose binaries or
project are not on this machine is skipped.

Each case is diffed without and then with --pcode-gate, and the fix function is looked up among the modified
functions. A report per case (in modified or not, diff_type, the gate's change class and constant deltas, pairs the
gate surfaced or dropped, seconds) is written to GHIDRIFF_GOLD_REPORT (default gold-report.json in the pytest
temporary directory) and printed.

A case:
    {"name": "CVE-... Component",
     "old": "path", "new": "path",                  relative to the cases file
     "binary": "name",                               optional: input file name (default: the old file's name)
     "project": "path",                              optional: an analyzed Ghidra project directory, cloned
     "args": ["--no-bsim-accept-seeds"],             optional: more ghidriff arguments
     "min_ghidra": "12.1",                            optional: skip on older Ghidra (its loader can't import the inputs)
     "modes": ["default"],                            optional: the diffs to run (default: both)
     "fix": "old-side function name",
     "default": {"modified": false},
     "pcode_gate": {"modified": true, "change_class": "compare", "const_deltas": [["0x40", "0x20"]]}}
An expectation key that is absent is not checked.
"""
import json
import os
import shutil
import subprocess
from pathlib import Path
from time import time

import pytest

from ghidriff import get_parser, VersionTrackingDiff, GhidraDiffEngine

GOLD = Path(__file__).parent / 'gold'
CASE_FILES = [GOLD / 'cases.example.json', GOLD / 'cases.test-data.json',
              Path(os.environ.get('GHIDRIFF_GOLD_CASES', GOLD / 'cases.local.json'))]


def load_cases():
    cases = []
    for path in CASE_FILES:
        if not path.exists():
            continue
        for case in json.loads(path.read_text()):
            for key in ('old', 'new', 'project'):
                if key in case:
                    case[key] = str((path.parent / case[key]).resolve())
            cases.append(case)
    return cases


CASES = load_cases()


def stage_input(src: Path, dst: Path):
    """Copy, keeping only the arm64e (else arm64) slice of a universal binary, as a diff pipeline would."""
    archs = []
    if shutil.which('lipo'):
        archs = subprocess.run(['lipo', '-archs', str(src)], capture_output=True, text=True).stdout.split()
    if len(archs) > 1:
        subprocess.run(['lipo', str(src), '-thin', 'arm64e' if 'arm64e' in archs else 'arm64', '-output', str(dst)],
                       check=True)
    else:
        shutil.copy2(src, dst)


def summarize(pdiff: dict, fix: str, seconds: float) -> dict:
    found = [f for f in pdiff['functions']['modified'] if f['old']['name'] == fix]
    summary = {'modified': bool(found), 'modified_len': pdiff['stats']['modified_funcs_len'], 'seconds': round(seconds, 1)}
    if 'pcode_surfaced_len' in pdiff['stats']:
        summary['surfaced'] = pdiff['stats']['pcode_surfaced_len']
        summary['dropped'] = pdiff['stats']['pcode_dropped']
    if found:
        func = found[0]
        summary.update({'new': func['new']['name'], 'diff_type': func['diff_type'], 'match_types': func['match_types'],
                        'old_length': func['old']['length'], 'new_length': func['new']['length']})
        if 'pcode' in func:
            summary['change_class'] = func['pcode'].get('change_class')
            summary['const_deltas'] = func['pcode'].get('const_deltas')
    return summary


def check(expect: dict, got: dict) -> list:
    problems = []
    for key, value in expect.items():
        if key == 'const_deltas':
            missing = [delta for delta in value if delta not in (got.get(key) or [])]
            if missing:
                problems.append(f'const_deltas {got.get(key)} lacks {missing}')
        elif key == 'diff_type':
            if not set(value) <= set(got.get(key) or []):
                problems.append(f'diff_type {got.get(key)} lacks {value}')
        elif got.get(key) != value:
            problems.append(f'{key}: expected {value}, got {got.get(key)}')
    return problems


@pytest.mark.forked
@pytest.mark.parametrize('case', CASES, ids=[case['name'] for case in CASES])
def test_gold_case(case: dict, tmp_path: Path, tmp_path_factory):
    """
    runs forked because each jpype jvm can only be initialized 1x
    """
    for key in ('old', 'new', 'project'):
        if key in case and not Path(case[key]).exists():
            pytest.skip(f'{key} not on this machine: {case[key]}')

    binary = case.get('binary', Path(case['old']).name)
    (tmp_path / 'in').mkdir()
    old, new = tmp_path / 'in' / f'{binary}.old', tmp_path / 'in' / f'{binary}.new'
    stage_input(Path(case['old']), old)
    stage_input(Path(case['new']), new)

    projects = tmp_path / 'projects'
    if 'project' in case:
        shutil.copytree(case['project'], projects)
        for lock in projects.glob('**/*.lock*'):
            lock.unlink()
        project_name = next(p.name for p in projects.iterdir() if p.is_dir())
    else:
        projects.mkdir()
        project_name = f'gold-{binary}'

    parser = get_parser()
    GhidraDiffEngine.add_ghidra_args_to_parser(parser)
    args = parser.parse_args(case.get('args', []) + [str(old), str(new), '-p', str(projects)])
    d: GhidraDiffEngine = VersionTrackingDiff(args=args,
                                              verbose=True,
                                              threaded=args.threaded,
                                              max_ram_percent=args.max_ram_percent,
                                              engine_log_path=tmp_path / 'ghidriff.log',
                                              engine_log_level=args.log_level,
                                              engine_file_log_level=args.file_log_level,
                                              no_symbols=True,
                                              bsim_accept_seeds=args.bsim_accept_seeds,
                                              pcode_gate=False)
    if 'min_ghidra' in case:
        version = tuple(int(x) for x in d.get_ghidra_version().split('.')[:3] if x.isdigit())
        if version < tuple(int(x) for x in case['min_ghidra'].split('.')):
            pytest.skip(f"Ghidra {d.get_ghidra_version()} cannot import this case's inputs (needs {case['min_ghidra']})")
    d.setup_project([old, new], projects, project_name, args.symbols_path)
    d.analyze_project()

    # default first: a gated diff leaves its surfaced pairs on the engine
    results = {}
    for mode in [m for m in ('default', 'pcode_gate') if m in case.get('modes', ('default', 'pcode_gate'))]:
        d.pcode_gate = mode == 'pcode_gate'
        start = time()
        pdiff = d.diff_bins(old, new)
        results[mode] = summarize(pdiff, case['fix'], time() - start)

    report = Path(os.environ.get('GHIDRIFF_GOLD_REPORT', tmp_path_factory.getbasetemp() / 'gold-report.json'))
    reports = json.loads(report.read_text()) if report.exists() else {}
    reports[case['name']] = results
    report.write_text(json.dumps(reports, indent=1))
    print(json.dumps({case['name']: results}, indent=1))

    problems = [f'{mode}: {problem}' for mode in results for problem in check(case.get(mode, {}), results[mode])]
    assert not problems, problems
