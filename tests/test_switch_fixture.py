from pathlib import Path
import json
import pytest

from ghidriff import get_parser, VersionTrackingDiff, GhidraDiffEngine

# tests/fixtures/switch: the upstream Ghidra reproducer (loopswitch.c, loopswitch0.c), rebuilt with build.sh.
# old and new differ only inside one case body.
SWITCH_BINS = Path(__file__).parent / 'fixtures' / 'switch' / 'bin'


def run_diff(tmp_path: Path, name: str, extra_args: list) -> dict:
    old_bin_path = SWITCH_BINS / f'{name}.old.dylib'
    new_bin_path = SWITCH_BINS / f'{name}.new.dylib'

    assert old_bin_path.exists()
    assert new_bin_path.exists()

    output_path = tmp_path / name
    ghidra_project_path = output_path / 'ghidra_projects'
    ghidra_project_path.mkdir(exist_ok=True, parents=True)

    parser = get_parser()

    GhidraDiffEngine.add_ghidra_args_to_parser(parser)

    args = parser.parse_args(extra_args + [
        str(old_bin_path.absolute()),
        str(new_bin_path.absolute()),
        '-p',
        str(ghidra_project_path.absolute())
    ])

    engine_log_path = output_path / parser.get_default('log_path')

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
                                              switch_repair=args.switch_repair,
                                              )

    d.setup_project([old_bin_path, new_bin_path], args.project_location, project_name, args.symbols_path)

    d.analyze_project()

    pdiff = d.diff_bins(old_bin_path, new_bin_path)
    pdiff_json = json.dumps(pdiff)

    d.validate_diff_json(pdiff_json)

    return pdiff


def find_modified(pdiff, name='_parse_blocks'):
    return [func for func in pdiff['functions']['modified'] if func['old']['name'] == name]


def assert_case_change_found(pdiff):
    assert len(pdiff['functions']['added']) == 0
    assert len(pdiff['functions']['deleted']) == 0
    parse_blocks = find_modified(pdiff)
    assert len(parse_blocks) == 1
    assert 'code' in parse_blocks[0]['diff_type']
    assert 'length' in parse_blocks[0]['diff_type']
    assert parse_blocks[0]['old']['length'] >= 388  # the whole function, not the part before the switch
    assert '0x7fff' in parse_blocks[0]['diff']


@pytest.mark.forked
def test_switch_repair_finds_change_inside_switch_case(tmp_path: Path):
    """
    arm64e hardened jump table with cases 1..11: Ghidra recovers 1 of 11 targets and ends the
    function at the switch; switch repair recovers the rest, so the changed case is diffed.
    runs forked because each jpype jvm can only be initialized 1x
    """
    assert_case_change_found(run_diff(tmp_path, 'loopswitch.arm64e', []))


@pytest.mark.forked
def test_switch_change_is_missed_without_repair(tmp_path: Path):
    """
    Documents the Ghidra limitation the repair works around. Once a Ghidra release recovers this
    switch itself, gate this assertion on the Ghidra version rather than deleting it.
    runs forked because each jpype jvm can only be initialized 1x
    """
    pdiff = run_diff(tmp_path, 'loopswitch.arm64e', ['--no-switch-repair'])
    version = pdiff['old_meta'].get('Created With Ghidra Version')
    if find_modified(pdiff):
        # 12.1.x recovers this switch itself; 12.0.x and 12.2 do not
        pytest.skip(f'Ghidra {version} recovers this switch without repair')
    assert find_modified(pdiff) == []


@pytest.mark.forked
@pytest.mark.parametrize('name', ['loopswitch0.arm64e', 'loopswitch.arm64'])
def test_switch_controls(tmp_path: Path, name: str):
    """
    Controls: arm64e with cases 0..10 (recovered by Ghidra 12.1 and later itself), and plain arm64.
    The repair must leave them correct.
    runs forked because each jpype jvm can only be initialized 1x
    """
    assert_case_change_found(run_diff(tmp_path, name, []))


@pytest.mark.forked
def test_switch_repair_recovers_all_targets(tmp_path: Path):
    """
    The repaired br carries all 11 case targets, and repair runs once per program.
    runs forked because each jpype jvm can only be initialized 1x
    """
    import pyghidra
    pyghidra.start()

    from ghidriff.switch_repair import repair_switches

    with pyghidra.open_program(SWITCH_BINS / 'loopswitch.arm64e.old.dylib', project_location=tmp_path,
                               project_name='switch_targets', analyze=True) as flat_api:
        program = flat_api.getCurrentProgram()
        func = [f for f in program.getFunctionManager().getFunctions(True) if f.getName() == '_parse_blocks'][0]

        def computed_targets():
            brs = [i for i in program.getListing().getInstructions(func.getBody(), True)
                   if i.getFlowType().isComputed() and i.getFlowType().isJump()]
            return [len({str(r.getToAddress()) for r in i.getReferencesFrom() if r.getReferenceType().isComputed()})
                    for i in brs]

        before = computed_targets()
        assert before in ([1], [11])  # Ghidra 12.0 and 12.2 recover one of eleven, 12.1 all of them
        assert repair_switches(program) == (1 if before == [1] else 0)
        assert computed_targets() == [11]
        assert repair_switches(program) == 0  # recorded in Program Information, not repeated
