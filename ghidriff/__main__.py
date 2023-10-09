from argparse import ArgumentParser
from pathlib import Path
import json

from ghidriff import GhidraDiffEngine
from .parser import get_parser,get_engine_classes

def main():
    """
    ghidriff - GhidraDiffEngine module main function
    """

    parser : ArgumentParser = get_parser()

    GhidraDiffEngine.add_ghidra_args_to_parser(parser)

    args = parser.parse_args()

    output_path = Path(args.output_path)
    output_path.mkdir(exist_ok=True, parents=True)

    if args.log_path == 'None':
        engine_log_path = None
    if args.log_path == parser.get_default('log_path'):
        engine_log_path = output_path / parser.get_default('log_path')
    else:
        engine_log_path = Path(args.log_path)

    binary_paths = args.old + [bin for sublist in args.new for bin in sublist]

    binary_paths = [Path(path) for path in binary_paths]

    if any([not path.exists() for path in binary_paths]):
        missing_bins = [f'{path.name}' for path in binary_paths if not path.exists()]
        raise FileNotFoundError(f"Missing Bins: {' '.join(missing_bins)}")

    project_name = f'{args.project_name}-{binary_paths[0].name}-{binary_paths[-1].name}'

    engines = get_engine_classes()
    DiffEngine: GhidraDiffEngine = engines[args.engine]

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
                                     engine_file_log_level=args.file_log_level
                                     )

    d.setup_project(binary_paths, args.project_location, project_name, args.symbols_path)

    d.analyze_project()

    diffs = []

    # pair up binaries with the n-1 version
    for i in range(len(binary_paths)-1):
        diffs.append((binary_paths[i], binary_paths[i+1]))

    # add a diff of the first and last binary for full coverage
    if not binary_paths[1] == binary_paths[-1] and args.summary:
        diffs.append((binary_paths[0], binary_paths[-1]))

    for diff in diffs:
        pdiff = d.diff_bins(diff[0], diff[1])
        pdiff_json = json.dumps(pdiff)

        d.validate_diff_json(pdiff_json)

        diff_name = f"{Path(diff[0]).name}-{Path(diff[1]).name}.ghidriff"

        d.dump_pdiff_to_path(diff_name,
                             pdiff,
                             output_path,
                             side_by_side=args.side_by_side,
                             max_section_funcs=args.max_section_funcs,
                             md_title=args.md_title)


if __name__ == "__main__":
    main()
