import pytest

from ghidriff.pcode_hash import Token, classify_pair, hash_tokens, shift_deltas, _clean_name, _clean_string, _PH


pytestmark = pytest.mark.fast


def tok(template, *consts):
    return Token(template, tuple(consts))


def test_identical_pair_is_same():
    a = [tok(f'INT_LESS u0:1 = r0:8 {_PH}', (0x48, 8, 'cmp')), tok('RETURN  = ')]
    b = [tok(f'INT_LESS u0:1 = r0:8 {_PH}', (0x48, 8, 'cmp')), tok('RETURN  = ')]
    assert classify_pair(a, b) == ('same', [])
    assert hash_tokens(a) == hash_tokens(b)


def test_compare_bound_change_is_const():
    # scanName in the Swift fixture: cmp #0x48 -> cmp #0x24, same size
    a = [tok(f'INT_LESS u0:1 = r0:8 {_PH}', (0x48, 8, 'cmp'))]
    b = [tok(f'INT_LESS u0:1 = r0:8 {_PH}', (0x24, 8, 'cmp'))]
    assert classify_pair(a, b) == ('const', [(0x48, 0x24)])
    assert hash_tokens(a) != hash_tokens(b)


def test_wide_immediate_change_is_imm_id():
    a = [tok(f'COPY r0:8 = {_PH}', (0x1234, 2, 'movk'))]
    b = [tok(f'COPY r0:8 = {_PH}', (0x5678, 2, 'movk'))]
    assert classify_pair(a, b)[0] == 'imm-id'


def test_structure_change_is_code():
    a = [tok('LOAD r0:4 = c0:8 r1:8')]
    b = [tok(f'INT_ADD u0:8 = r1:8 {_PH}', (4, 8, 'add')), tok('LOAD r0:4 = c0:8 r1:8')]
    assert classify_pair(a, b) == ('code', [])


def test_shift_needs_two_functions():
    one = [('const', [(0x3dd0, 0x3dfc)])]
    assert shift_deltas(one) == set()
    two = one + [('const', [(0x4000, 0x402c)])]
    assert shift_deltas(two) == {0x2c}


def test_names_and_strings_are_build_invariant():
    assert _clean_name('FUN_100003d58') == _clean_name('FUN_100003d84')
    assert _clean_name('__foo_block_invoke.12') == _clean_name('__foo_block_invoke.3')
    assert _clean_string('/AppleInternal/Library/BuildRoots/0A1B2C3D-1111/x.c') == \
        _clean_string('/AppleInternal/Library/BuildRoots/FFEE0011-2222/x.c')
    assert _clean_string('Nov  7 2026') == '<DATE>'


def test_current_buildroots_token_is_masked():
    old = ('/AppleInternal/Library/BuildRoots/4~CWFdugDfP269IgLhhk5QxA5zD4K6Rngkv8vRhSc/Library/Caches/'
           'com.apple.xbs/TemporaryDirectory.E5D0jw/Sources/TimeMachine/TMDeviceRulesEngine.m')
    new = ('/AppleInternal/Library/BuildRoots/4~Cax5ugBBSea4NSZRTVdt94DTapNKqWnrMBpTU9M/Library/Caches/'
           'com.apple.xbs/TemporaryDirectory.Qx81aa/Sources/TimeMachine/TMDeviceRulesEngine.m')
    assert _clean_string(old) == _clean_string(new)
    assert 'TMDeviceRulesEngine.m' in _clean_string(new)


def test_outlined_function_renumbering_is_masked():
    assert _clean_name('_OUTLINED_FUNCTION_1') == _clean_name('_OUTLINED_FUNCTION_22')
    assert _clean_name('_OUTLINED_FUNCTION_5') == '_OUTLINED_FUNCTION_#'
    # other short numeric suffixes keep their meaning
    assert _clean_name('_foo_2') != _clean_name('_foo_3')
