from pathlib import Path
import json
import pytest

from ghidriff import get_parser, get_engine_classes, VersionTrackingDiff, GhidraDiffEngine

SYMBOLS_DIR = 'symbols'
BINS_DIR = 'bins'


@pytest.mark.forked
def test_diff_ios_dylib_arm64(shared_datadir: Path):
    """
    Tests end to end diff of CVE
    runs forked because each jpype jvm can only be initialized 1x
    """

    test_name = 'libcrypto-dylib-CVE-2024-23218'
    output_path = shared_datadir / test_name
    output_path.mkdir(exist_ok=True, parents=True)
    symbols_path = shared_datadir / SYMBOLS_DIR
    bins_path = shared_datadir / BINS_DIR    
    ghidra_project_path = output_path / 'ghidra_projects'
    ghidra_project_path.mkdir(exist_ok=True,parents=True)

    # setup bins
    old_bin_path = bins_path / 'libcorecrypto.dylib-14.2.1'
    new_bin_path = bins_path / 'libcorecrypto.dylib-14.3'

    assert old_bin_path.exists()
    assert new_bin_path.exists()

    parser = get_parser()

    GhidraDiffEngine.add_ghidra_args_to_parser(parser)

    args = parser.parse_args([
            '-s', 
            str(symbols_path), 
            str(old_bin_path.absolute()), 
            str(new_bin_path.absolute()),
            '-p', 
            str(ghidra_project_path.absolute())
        ])        

    engine_log_path = output_path / parser.get_default('log_path')

    binary_paths = args.old + [bin for sublist in args.new for bin in sublist]

    binary_paths = [Path(path) for path in binary_paths]

    if any([not path.exists() for path in binary_paths]):
        missing_bins = [f'{path.name}' for path in binary_paths if not path.exists()]
        raise FileNotFoundError(f"Missing Bins: {' '.join(missing_bins)}")

    project_name = f'{args.project_name}-{binary_paths[0].name}-{binary_paths[-1].name}'

    DiffEngine: GhidraDiffEngine = VersionTrackingDiff

    d: GhidraDiffEngine = DiffEngine(args=args,
                                     verbose=True,
                                     threaded=args.threaded,
                                     max_ram_percent=args.max_ram_percent,
                                     print_jvm_flags=args.print_flags,
                                     jvm_args=args.jvm_args,
                                     force_analysis=args.force_analysis,
                                     force_diff=args.force_diff,
                                     verbose_analysis=args.va,
                                     no_symbols=args.no_symbols,
                                     engine_log_path=engine_log_path,
                                     engine_log_level=args.log_level,
                                     engine_file_log_level=args.file_log_level,
                                     )

    d.setup_project(binary_paths, args.project_location, project_name, args.symbols_path)

    d.analyze_project()

    pdiff = d.diff_bins(old_bin_path, new_bin_path)
    pdiff_json = json.dumps(pdiff)

    d.validate_diff_json(pdiff_json)

    diff_name = f"{old_bin_path.name}-{new_bin_path.name}_diff"

    d.dump_pdiff_to_path(diff_name,
                         pdiff,
                         output_path,
                         side_by_side=args.side_by_side,
                         max_section_funcs=args.max_section_funcs,
                         md_title=args.md_title)

    assert len(pdiff['functions']['modified']) == 39 
    assert len(pdiff['functions']['added']) == 6
    assert len(pdiff['functions']['deleted']) == 0


@pytest.mark.forked
def test_diff_macos_macho_x64(shared_datadir: Path):
    """
    Tests end to end diff of CVE
    runs forked because each jpype jvm can only be initialized 1x
    """

    test_name = 'contacts'
    output_path = shared_datadir / test_name
    output_path.mkdir(exist_ok=True, parents=True)
    symbols_path = shared_datadir / SYMBOLS_DIR
    bins_path = shared_datadir / BINS_DIR    
    ghidra_project_path = output_path / 'ghidra_projects'
    ghidra_project_path.mkdir(exist_ok=True,parents=True)

    # setup bins
    old_bin_path = bins_path / 'Contacts.mac.x86_64.2563-Mac14.0-23A344'
    new_bin_path = bins_path / 'Contacts.mac.x86_64.2565-Mac14.1-23B74'

    assert old_bin_path.exists()
    assert new_bin_path.exists()

    parser = get_parser()

    GhidraDiffEngine.add_ghidra_args_to_parser(parser)

    args = parser.parse_args([
            '-s', 
            str(symbols_path), 
            str(old_bin_path.absolute()), 
            str(new_bin_path.absolute()),
            '-p', 
            str(ghidra_project_path.absolute())
        ])        

    engine_log_path = output_path / parser.get_default('log_path')

    binary_paths = args.old + [bin for sublist in args.new for bin in sublist]

    binary_paths = [Path(path) for path in binary_paths]

    if any([not path.exists() for path in binary_paths]):
        missing_bins = [f'{path.name}' for path in binary_paths if not path.exists()]
        raise FileNotFoundError(f"Missing Bins: {' '.join(missing_bins)}")

    project_name = f'{args.project_name}-{binary_paths[0].name}-{binary_paths[-1].name}'

    DiffEngine: GhidraDiffEngine = VersionTrackingDiff

    d: GhidraDiffEngine = DiffEngine(args=args,
                                     verbose=True,
                                     threaded=args.threaded,
                                     max_ram_percent=args.max_ram_percent,
                                     print_jvm_flags=args.print_flags,
                                     jvm_args=args.jvm_args,
                                     force_analysis=args.force_analysis,
                                     force_diff=args.force_diff,
                                     verbose_analysis=args.va,
                                     no_symbols=args.no_symbols,
                                     engine_log_path=engine_log_path,
                                     engine_log_level=args.log_level,
                                     engine_file_log_level=args.file_log_level,
                                     )

    d.setup_project(binary_paths, args.project_location, project_name, args.symbols_path)

    d.analyze_project()

    pdiff = d.diff_bins(old_bin_path, new_bin_path)
    pdiff_json = json.dumps(pdiff)

    d.validate_diff_json(pdiff_json)

    diff_name = f"{old_bin_path.name}-{new_bin_path.name}_diff"

    d.dump_pdiff_to_path(diff_name,
                         pdiff,
                         output_path,
                         side_by_side=args.side_by_side,
                         max_section_funcs=args.max_section_funcs,
                         md_title=args.md_title)

    # no changes
    assert len(pdiff['functions']['modified']) == 0
    assert len(pdiff['functions']['added']) == 0
    assert len(pdiff['functions']['deleted']) == 0

    # 100 % match
    assert pdiff['stats']['func_match_overall_percent'] == '100.0000%'