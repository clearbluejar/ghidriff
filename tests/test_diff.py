from pathlib import Path
import json

from ghidriff import get_parser, get_engine_classes, VersionTrackingDiff, GhidraDiffEngine

SYMBOLS_DIR = 'symbols'
BINS_DIR = 'bins'

def get_chrome_headers() -> dict:

    headers =  {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-language": "en-US,en;q=0.9",
        "cache-control": "no-cache",
        "pragma": "no-cache",
        "sec-ch-ua": '"Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1"
    }

    return headers



def test_diff_afd_cve_2023_21768(shared_datadir: Path):
    """
    Tests end to end diff of CVE
    """
    
    test_name = 'cve-2023-21768'
    output_path = shared_datadir / test_name
    output_path.mkdir(exist_ok=True, parents=True)
    symbols_path = shared_datadir / SYMBOLS_DIR
    bins_path = shared_datadir / BINS_DIR

    
    # setup bins

    old_bin_path = bins_path / 'afd.sys.x64.10.0.22621.1028'
    new_bin_path = bins_path / 'afd.sys.x64.10.0.22621.1415'

    # TODO figure out why these download are unreliable
    # for now just git clone ghidriff-test-data
    # old_bin_path = shared_datadir / 'afd.sys.x64.10.0.22621.1028'
    # old_url = 'https://msdl.microsoft.com/download/symbols/afd.sys/0C5C6994A8000/afd.sys'
    # new_bin_path = shared_datadir / 'afd.sys.x64.10.0.22621.1415'
    # new_url = 'https://msdl.microsoft.com/download/symbols/afd.sys/50989142A9000/afd.sys'

    # download binaries    
    # download is unreliage
    # headers = get_chrome_headers()
    # old_bin_path.write_bytes(requests.get(old_url,headers=headers).content)
    # new_bin_path.write_bytes(requests.get(new_url,headers=headers).content)

    assert old_bin_path.exists()
    assert new_bin_path.exists()

    parser = get_parser()

    GhidraDiffEngine.add_ghidra_args_to_parser(parser)

    args = parser.parse_args(['-s', str(symbols_path), str(old_bin_path.absolute()),str(new_bin_path.absolute())])

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

    assert len(pdiff['functions']['modified']) == 10
    assert len(pdiff['functions']['added']) == 28
    assert len(pdiff['functions']['deleted']) == 0

    func_name = "AfdNotifyRemoveIoCompletion"
    assert any([func_name in func['old']['name'] or func_name in func['new']['name'] for func in pdiff['functions']['modified'] ]) is True