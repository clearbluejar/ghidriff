from pathlib import Path
import json
import pytest

from ghidriff import get_parser, get_engine_classes, VersionTrackingDiff, GhidraDiffEngine

SYMBOLS_DIR = 'symbols'
BINS_DIR = 'bins'


@pytest.mark.forked
def test_gdt_afd(shared_datadir: Path):
    """
    Tests application of a GDT to a program
    runs forked because each jpype jvm can only be initialized 1x
    """

    test_name = 'cve-2023-21768'
    output_path = shared_datadir / test_name
    output_path.mkdir(exist_ok=True, parents=True)
    symbols_path = shared_datadir / SYMBOLS_DIR
    bins_path = shared_datadir / BINS_DIR    
    ghidra_project_path = output_path / 'ghidra_projects'
    ghidra_project_path.mkdir(exist_ok=True,parents=True)
    gdt_path = (shared_datadir / 'ntddk_64.gdt')

    # setup bins
    old_bin_path = bins_path / 'afd.sys.x64.10.0.22621.1028'
    new_bin_path = bins_path / 'afd.sys.x64.10.0.22621.1415'

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
            str(ghidra_project_path.absolute()),
            "--gdt",
            str(gdt_path.absolute())
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
                                     gdts=args.gdt
                                     )

    d.setup_project(binary_paths, args.project_location, project_name, args.symbols_path)

    d.analyze_project()

    program = None
    for df in d.project.getRootFolder().getFiles():
        program = d.project.openProgram("/", df.getName(), False)
    
    ## without GDT this func sig return UNDEFINED and not types
    known_typed_sig = "BOOLEAN IoIs32bitProcess(PIRP Irp)"
    symbol_to_test = "IoIs32bitProcess"

    for f in program.functionManager.externalFunctions:

            if f'{f.getName()}' == symbol_to_test:
                print(f)
                signature_after_gdt = f'{f.getSignature()}'

    assert signature_after_gdt is not None
    assert signature_after_gdt == known_typed_sig