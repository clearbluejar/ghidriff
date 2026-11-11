import pytest

from ghidriff.switch_repair import _ADD_RE, _ADR_RE, _LOAD_RE, _CMP_RE, _TABLE_LOADS

pytestmark = pytest.mark.fast


def test_hardened_switch_pattern_parses():
    # CoreMedia _hevcbridgeParseVdrDmDataPayloadExMetadatatBlocks, as Ghidra renders it
    add = _ADD_RE.match('add x16,x17,x16')
    assert add and add.groups() == ('16', '17', '16', None)
    assert _ADR_RE.match('adr x17,0x18eed3310').groups() == ('17', '18eed3310')
    load = _LOAD_RE.match('ldrsw x16,[x17, x16, LSL #0x2]')
    assert load and load.groups() == ('ldrsw', '16', '17', '16')
    assert _CMP_RE.match('cmp x16,#0xa').groups() == ('16', 'a')
    assert _CMP_RE.match('cmp w16,#0xa').groups() == ('16', 'a')


def test_scaled_and_narrow_tables():
    assert _ADD_RE.match('add x16,x17,x16, LSL #0x2').group(4) == '2'
    assert _LOAD_RE.match('ldrh w16,[x17, x16, LSL #0x1]').group(1) == 'ldrh'
    assert _LOAD_RE.match('ldrb w16,[x17, x16]').group(1) == 'ldrb'
    assert _TABLE_LOADS['ldrsw'] == (4, True) and _TABLE_LOADS['ldrb'] == (1, False)


def test_non_switch_branches_rejected():
    assert _ADD_RE.match('add x17,x17,#0x874') is None  # page offset add, not the target add
    assert _LOAD_RE.match('ldr x16,[x17]') is None  # stub load, no index register
