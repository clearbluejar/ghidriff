import pytest
from pathlib import Path

from ghidriff import GhidraDiffEngine, VersionTrackingDiff, get_parser

SYMBOLS_DIR = 'symbols'

@pytest.mark.forked
def test_parsing_pe_garbage(shared_datadir: Path):

    parser = get_parser()

    args = parser.parse_args(['test', 'test2']) # these args will not be tested

    
    not_a_pe_path = shared_datadir / SYMBOLS_DIR / 'pingme.txt'

    DiffEngine: GhidraDiffEngine = VersionTrackingDiff
    d = DiffEngine(args=args)

    assert None == d.get_pe_download_url(not_a_pe_path,'junk')