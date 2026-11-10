from pathlib import Path
import json
import pytest

from ghidriff import get_parser, VersionTrackingDiff, GhidraDiffEngine

SWIFT_BINS = Path(__file__).parent / 'fixtures' / 'swift' / 'bin'


def find_modified(pdiff, name):
    return [func for func in pdiff['functions']['modified']
            if name in func['old']['name'] or name in func['old']['fullname']]


@pytest.mark.forked
def test_diff_swift_dylib_arm64e_pcode_gate(tmp_path: Path):
    """
    End to end diff of an arm64e Swift dylib (tests/fixtures/swift, rebuilt with build.sh).
    Guards Swift analysis regressions and the --pcode-gate same-size path.
    runs forked because each jpype jvm can only be initialized 1x
    """

    old_bin_path = SWIFT_BINS / 'libSwiftFixture.old.dylib'
    new_bin_path = SWIFT_BINS / 'libSwiftFixture.new.dylib'

    assert old_bin_path.exists()
    assert new_bin_path.exists()

    output_path = tmp_path / 'swift-fixture'
    ghidra_project_path = output_path / 'ghidra_projects'
    ghidra_project_path.mkdir(exist_ok=True, parents=True)

    parser = get_parser()

    GhidraDiffEngine.add_ghidra_args_to_parser(parser)

    args = parser.parse_args([
        '--pcode-gate',
        str(old_bin_path.absolute()),
        str(new_bin_path.absolute()),
        '-p',
        str(ghidra_project_path.absolute())
    ])

    engine_log_path = output_path / parser.get_default('log_path')

    binary_paths = [old_bin_path, new_bin_path]
    project_name = f'{args.project_name}-{old_bin_path.name}-{new_bin_path.name}'

    d: GhidraDiffEngine = VersionTrackingDiff(args=args,
                                              verbose=True,
                                              threaded=args.threaded,
                                              max_ram_percent=args.max_ram_percent,
                                              print_jvm_flags=args.print_flags,
                                              jvm_args=args.jvm_args,
                                              force_analysis=args.force_analysis,
                                              force_diff=args.force_diff,
                                              verbose_analysis=args.va,
                                              no_symbols=True,
                                              engine_log_path=engine_log_path,
                                              engine_log_level=args.log_level,
                                              engine_file_log_level=args.file_log_level,
                                              pcode_gate=args.pcode_gate,
                                              )

    d.setup_project(binary_paths, args.project_location, project_name, args.symbols_path)

    d.analyze_project()

    pdiff = d.diff_bins(old_bin_path, new_bin_path)
    pdiff_json = json.dumps(pdiff)

    d.validate_diff_json(pdiff_json)

    d.dump_pdiff_to_path(f'{old_bin_path.name}-{new_bin_path.name}_diff',
                         pdiff,
                         output_path,
                         side_by_side=args.side_by_side,
                         max_section_funcs=args.max_section_funcs,
                         md_title=args.md_title)

    assert len(pdiff['functions']['added']) == 0
    assert len(pdiff['functions']['deleted']) == 0

    # size change: added bounds check
    read_record = find_modified(pdiff, 'readRecord')
    assert len(read_record) == 1
    assert 'code' in read_record[0]['diff_type']
    assert 'length' in read_record[0]['diff_type']

    # same size, only the compare bound changed (72 -> 36); found only by the p-code gate
    scan_name = find_modified(pdiff, 'scanName')
    assert len(scan_name) == 1
    assert 'pcode' in scan_name[0]['diff_type']
    assert 'length' not in scan_name[0]['diff_type']
    assert scan_name[0]['pcode']['change_class'] == 'const'
    assert ['0x48', '0x24'] in scan_name[0]['pcode']['const_deltas']

    # everything else only moved; layout shifts must not be surfaced
    surfaced = [func['old']['name'] for func in pdiff['functions']['modified'] if 'pcode' in func['diff_type']]
    assert len(surfaced) == 1, surfaced
    assert pdiff['stats']['pcode_surfaced_len'] == 1
