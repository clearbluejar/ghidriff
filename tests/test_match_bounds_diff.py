"""
BSIM bounds end to end on libcorecrypto from ghidriff-test-data (BSIM matches functions there; on the Swift
fixture it finds no seeds), and the one-to-many bucket cap on the arm64e Swift fixture (tests/fixtures/swift).
"""
from pathlib import Path
import json

import pytest

from ghidriff import get_parser, VersionTrackingDiff, GhidraDiffEngine

SWIFT_BINS = Path(__file__).parent / 'fixtures' / 'swift' / 'bin'
OLD_BIN = SWIFT_BINS / 'libSwiftFixture.old.dylib'
NEW_BIN = SWIFT_BINS / 'libSwiftFixture.new.dylib'


def make_engine(tmp_path: Path, old_bin: Path = OLD_BIN, new_bin: Path = NEW_BIN):
    output_path = tmp_path / 'out'
    ghidra_project_path = output_path / 'ghidra_projects'
    ghidra_project_path.mkdir(exist_ok=True, parents=True)

    parser = get_parser()
    GhidraDiffEngine.add_ghidra_args_to_parser(parser)
    args = parser.parse_args([str(old_bin.absolute()), str(new_bin.absolute()), '-p', str(ghidra_project_path.absolute())])

    d: GhidraDiffEngine = VersionTrackingDiff(args=args,
                                              verbose=True,
                                              threaded=args.threaded,
                                              max_ram_percent=args.max_ram_percent,
                                              engine_log_path=output_path / parser.get_default('log_path'),
                                              engine_log_level=args.log_level,
                                              engine_file_log_level=args.file_log_level,
                                              no_symbols=True,
                                              bsim_max_pairs=args.bsim_max_pairs,
                                              bsim_timeout=args.bsim_timeout,
                                              max_one_to_many_bucket=args.max_one_to_many_bucket)
    d.setup_project([old_bin, new_bin], args.project_location, f'{args.project_name}-bounds', args.symbols_path)
    d.analyze_project()
    d.bins = (old_bin, new_bin)
    return d


def diff(d):
    pdiff = d.diff_bins(*d.bins)
    d.validate_diff_json(json.dumps(pdiff))
    return pdiff


def pairs(pdiff, match_type=None):
    return {(old, new) for old, news in pdiff['matches']['address_matches'].items()
            for new, types in news if match_type is None or match_type in types}


def names(pdiff, side):
    return sorted(func['name'] for func in pdiff['functions'][side])


@pytest.mark.forked
def test_bsim_bounds(shared_datadir: Path, monkeypatch):
    """
    Under the budget BSIM runs as Ghidra's correlator; over it, functions are left out and reported; a timeout
    stops it; without Ghidra's internals it runs unbounded. Every diff completes.
    runs forked because each jpype jvm can only be initialized 1x
    """
    import jpype
    import ghidriff.bsim as bsim_module

    bins = shared_datadir / 'bins'
    d = make_engine(shared_datadir / 'bsim-bounds', bins / 'libcorecrypto.dylib-14.2.1', bins / 'libcorecrypto.dylib-14.3')

    plain = diff(d)
    report = plain['stats']['bsim']
    assert report['status'] == 'ran' and 'unbounded' not in report, report
    assert report['candidate_pairs'] > 1 and min(report['nodes']) > 0
    assert report['matches'] > 0
    assert set(report['phase_seconds']) == {'vectors', 'count', 'discover', 'seeds', 'matching'}

    # Ghidra's correlator, run whole, finds the same matches
    def no_field(obj, name):
        raise jpype.JClass('java.lang.NoSuchFieldException')(name)
    with monkeypatch.context() as m:
        m.setattr(bsim_module, 'get_field', no_field)
        stock = diff(d)
    assert stock['stats']['bsim']['unbounded'] is True and stock['stats']['bsim']['status'] == 'ran'
    assert pairs(stock, 'BSIM') == pairs(plain, 'BSIM')

    # over budget: the vectors making the most pairs are left out, the rest is matched as usual
    d.bsim_max_pairs = report['candidate_pairs'] // 2
    cut = diff(d)
    cut_report = cut['stats']['bsim']
    assert cut_report['status'] == 'cut', cut_report
    assert cut_report['candidate_pairs'] == report['candidate_pairs']
    assert cut_report['candidate_pairs_kept'] <= d.bsim_max_pairs
    assert sum(cut_report['left_out_functions']) > 0 and cut_report['left_out_vectors'] > 0
    assert cut['functions']['modified']

    # a timeout stops BSIM and the diff goes on without its matches
    class FiresAtOnce:
        def __init__(self, interval, function):
            self.function = function
            self.daemon = True

        def start(self):
            self.function()

        def cancel(self):
            pass

    d.bsim_max_pairs = 25_000_000
    with monkeypatch.context() as m:
        m.setattr(bsim_module.threading, 'Timer', FiresAtOnce)
        timed = diff(d)
    assert timed['stats']['bsim']['status'] == 'timeout'
    assert timed['stats']['bsim']['matches'] == 0 and not pairs(timed, 'BSIM')


@pytest.mark.forked
def test_one_to_many_cap(tmp_path: Path):
    """
    Buckets over the cap are matched as a group: no pairs, and no function of theirs is reported added or deleted.
    runs forked because each jpype jvm can only be initialized 1x
    """
    d = make_engine(tmp_path)

    plain = diff(d)
    assert 'one_to_many_capped' not in plain['stats']

    d.max_one_to_many_bucket = 1
    capped = diff(d)
    report = capped['stats']['one_to_many_capped']
    assert sum(entry['buckets'] for entry in report.values()) > 0, report

    for name, entry in report.items():
        assert len(pairs(capped, name)) < len(pairs(plain, name))
        assert all(max(size) > 1 for size in entry['largest'])
    assert names(capped, 'added') == names(plain, 'added')
    assert names(capped, 'deleted') == names(plain, 'deleted')
    modified = {(f['old']['address'], f['new']['address']) for f in capped['functions']['modified']}
    assert modified <= {(f['old']['address'], f['new']['address']) for f in plain['functions']['modified']}
