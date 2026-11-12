"""
End-to-end regression tests on the arm64e Swift fixture (tests/fixtures/swift) for fixes that had
no automated coverage: same-named inputs, the mnemonic list, and --emit-asm-diff normalization.
"""
from pathlib import Path
import json
import re
import shutil

import pytest

from ghidriff import get_parser, VersionTrackingDiff, GhidraDiffEngine

SWIFT_BINS = Path(__file__).parent / 'fixtures' / 'swift' / 'bin'
OLD_BIN = SWIFT_BINS / 'libSwiftFixture.old.dylib'
NEW_BIN = SWIFT_BINS / 'libSwiftFixture.new.dylib'


def make_engine(tmp_path: Path, old_bin_path: Path, new_bin_path: Path, extra_args: list):
    output_path = tmp_path / 'out'
    ghidra_project_path = output_path / 'ghidra_projects'
    ghidra_project_path.mkdir(exist_ok=True, parents=True)

    parser = get_parser()
    GhidraDiffEngine.add_ghidra_args_to_parser(parser)
    args = parser.parse_args(extra_args + [str(old_bin_path.absolute()), str(new_bin_path.absolute()),
                                           '-p', str(ghidra_project_path.absolute())])

    d: GhidraDiffEngine = VersionTrackingDiff(args=args,
                                              verbose=True,
                                              threaded=args.threaded,
                                              max_ram_percent=args.max_ram_percent,
                                              engine_log_path=output_path / parser.get_default('log_path'),
                                              engine_log_level=args.log_level,
                                              engine_file_log_level=args.file_log_level,
                                              no_symbols=True,
                                              emit_asm_diff=args.emit_asm_diff)
    d.setup_project([old_bin_path, new_bin_path], args.project_location,
                    f'{args.project_name}-{old_bin_path.parent.name}-{new_bin_path.parent.name}', args.symbols_path)
    d.analyze_project()
    return d


def find_modified(pdiff, name):
    return [func for func in pdiff['functions']['modified'] if name in func['old']['name']]


@pytest.mark.forked
def test_same_named_inputs_decompile_their_own_program(tmp_path: Path):
    """
    old/libSwiftFixture.dylib vs new/libSwiftFixture.dylib: the decompiler pool and esym_memo used to
    be keyed by program name, so the old side was decompiled against the new program's bytes.
    Also checks that the mnemonic list holds mnemonics (it held one bound-method repr per instruction).
    runs forked because each jpype jvm can only be initialized 1x
    """
    for side, src in (('old', OLD_BIN), ('new', NEW_BIN)):
        (tmp_path / side).mkdir()
        shutil.copy(src, tmp_path / side / 'libSwiftFixture.dylib')
    old_bin_path, new_bin_path = tmp_path / 'old' / 'libSwiftFixture.dylib', tmp_path / 'new' / 'libSwiftFixture.dylib'

    d = make_engine(tmp_path, old_bin_path, new_bin_path, [])
    pdiff = d.diff_bins(old_bin_path, new_bin_path)
    d.validate_diff_json(json.dumps(pdiff))

    # same result as the differently named pair in tests/test_swift.py
    assert len(pdiff['functions']['added']) == 0
    assert len(pdiff['functions']['deleted']) == 0
    read_record = find_modified(pdiff, 'readRecord')
    assert len(read_record) == 1 and 'code' in read_record[0]['diff_type']

    for func in pdiff['functions']['modified']:
        for side in ('old', 'new'):
            code = func[side].get('code') or ''
            assert 'Failed to decompile' not in code, (side, func[side]['name'], code[:200])

    mnemonics = [m for func in pdiff['functions']['modified'] for side in ('old', 'new') for m in func[side]['mnemonics']]
    # the bug stored str(code.getMnemonicString) (the method, not its result) for every instruction
    assert mnemonics and not any('getMnemonicString' in m for m in mnemonics)
    assert len(set(mnemonics)) > 5


@pytest.mark.forked
def test_emit_asm_diff_is_address_normalized(tmp_path: Path):
    """
    --emit-asm-diff: present exactly on code-modified functions, no build addresses in it, and a
    function that only moved between builds normalizes to the same instruction list.
    runs forked because each jpype jvm can only be initialized 1x
    """
    d = make_engine(tmp_path, OLD_BIN, NEW_BIN, ['--emit-asm-diff'])
    pdiff = d.diff_bins(OLD_BIN, NEW_BIN)
    d.validate_diff_json(json.dumps(pdiff))

    for func in pdiff['functions']['modified']:
        assert ('asm_diff' in func) == ('code' in func['diff_type']), func['old']['name']

    read_record = find_modified(pdiff, 'readRecord')[0]
    changed = [line for line in read_record['asm_diff'].splitlines()
               if line[:1] in '+-' and line[:3] not in ('+++', '---')]
    assert changed, 'the added bounds check must show'
    assert not any(re.search(r'(?<![#\w])0x[0-9a-f]{5,}|\b(?:FUN|LAB|DAT)_[0-9a-f]{5,}', line) for line in changed)

    # every 1:1 match not reported modified must normalize identically, including the ones that moved
    modified_old = {func['old']['address'] for func in pdiff['functions']['modified']}
    pairs = [(old, news[0][0]) for old, news in pdiff['matches']['address_matches'].items()
             if len(news) == 1 and old not in modified_old and 'EXTERNAL' not in old]
    assert sum(1 for old, new in pairs if old != new) >= 20, 'the fixture must have relocated functions'

    files = {df.getName(): df for df in d.project.getRootFolder().getFiles()}
    old_p = d.project.openProgram('/', next(n for n in files if n.startswith('libSwiftFixture.old')), True)
    new_p = d.project.openProgram('/', next(n for n in files if n.startswith('libSwiftFixture.new')), True)

    def normalized(program, addr):
        func = program.getFunctionManager().getFunctionAt(program.getAddressFactory().getAddress(addr))
        units = program.getListing().getCodeUnits(func.getBody(), True)
        adrp_regs = set()
        return [d.normalize_asm_instruction(func, code, adrp_regs) for code in units], func.getName()

    differ = []
    for old_addr, new_addr in pairs:
        (old_asm, name), (new_asm, _) = normalized(old_p, old_addr), normalized(new_p, new_addr)
        if old_asm != new_asm:
            differ.append(name)
    # the only same-size change in the fixture (cmp #0x48 -> #0x24) is not reported without --pcode-gate
    assert [name for name in differ if 'scanName' not in name] == [], differ
    assert any('scanName' in name for name in differ), 'asm must still show the same-size change'
