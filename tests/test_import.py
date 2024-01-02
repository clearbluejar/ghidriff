from pathlib import Path
import json
import pytest
from pyhidra.version import get_ghidra_version


from ghidriff import get_parser, get_engine_classes, VersionTrackingDiff, GhidraDiffEngine

SYMBOLS_DIR = 'symbols'
BINS_DIR = 'bins'


@pytest.mark.forked
def test_gzf_import_program(shared_datadir: Path):
    """
    Tests that binaries can be successfully imported
    Tests that gzf files contain expected programs
    """

    if get_ghidra_version() < '10.4':
        # gzf files were made with 10.4
        print('Skip testing gzf on < 10.4')
        return

    test_name = 'test-imports'
    output_path = shared_datadir / test_name
    output_path.mkdir(exist_ok=True, parents=True)
    symbols_path = shared_datadir / SYMBOLS_DIR
    bins_path = shared_datadir / BINS_DIR

    # bins

    bins_to_import = [
        # bin path , expected program
        ['afd.sys.x64.10.0.22621.1028', 'afd.sys.x64.10.0.22621.1028-00a2b7'], #if a gzf file is used first, this becomes really unstable... 
        ['afd.sys.x64.10.0.22621.1415', 'afd.sys.x64.10.0.22621.1415-095200'],
        ['afd.sys.x64.10.0.22621.1028.gzf', 'afd.sys.x64.10.0.22621.1028.gzf-338a92'],        
        ['afd.sys.x64.10.0.22621.1415.gzf', 'afd.sys.x64.10.0.22621.1415.gzf-fc498a'],        
        ['ntoskrnl.exe.x64.10.0.22621.2792.10-1-5.gzf', 'ntoskrnl.exe.x64.10.0.22621.2792.10-1-5.gzf-acb020'],
        ['ntoskrnl.exe.x64.10.0.22621.2861.10-1-5.gzf', 'ntoskrnl.exe.x64.10.0.22621.2861.10-1-5.gzf-0e4e43'],
        
    ]

    parser = get_parser()

    GhidraDiffEngine.add_ghidra_args_to_parser(parser)

    engine_log_path = output_path / parser.get_default('log_path')
    
    binary_paths = [path for path in [bins_path / name[0] for name in bins_to_import ]]    
    
    args = parser.parse_args(['test', 'test2']) # these args will not be tested

    expected_names = [name for name in [name[1] for name in bins_to_import ]]
    
    binary_paths = [Path(path) for path in binary_paths]

    if any([not path.exists() for path in binary_paths]):
        missing_bins = [f'{path.name}' for path in binary_paths if not path.exists()]
        raise FileNotFoundError(f"Missing Bins: {' '.join(missing_bins)}")

    import uuid
    # ensure fresh test each time
    project_name = f'import-test-{uuid.uuid4()}'
    #project_name = f'import-test'

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

    # imports_results = d.setup_project(binary_paths, args.project_location, project_name, args.symbols_path)

    # for i,data in enumerate(imports_results):
    #     # assert import names are as expected
    #     print(i)
    #     print(data)
    #     assert expected_names[i] == data[0]

    for i,import_path in enumerate(binary_paths):
        imports_result = d.setup_project([binary_paths[i]], args.project_location, project_name, args.symbols_path)
        #d.project.wait()
        assert expected_names[i] == imports_result[0][0]

