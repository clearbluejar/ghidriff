import pytest

from ghidriff.utils import mask_zero_page_offset, normalize_asm_text, stable_symbol_name


pytestmark = pytest.mark.fast


def test_default_names_masked():
    assert normalize_asm_text('bl FUN_18a2b3c4d') == normalize_asm_text('bl FUN_1b7a70918')
    assert normalize_asm_text('b LAB_18abcdef0') == normalize_asm_text('b LAB_1b0000010')


def test_bare_absolute_address_masked_immediates_kept():
    assert normalize_asm_text('adrp x8,0x1c3000') == normalize_asm_text('adrp x8,0x1d9000')
    assert normalize_asm_text('cmp w8,#0x5') == 'cmp w8,#0x5'
    assert normalize_asm_text('ldr x0,[x8, #0x10]') == 'ldr x0,[x8, #0x10]'


def test_idempotent():
    t = normalize_asm_text('bl FUN_18a2b3c4d')
    assert normalize_asm_text(t) == t


def test_zero_page_offset_matches_nonzero_offset():
    # old: adrp x8,P ; ldr x0,[x8, #0x1a8]   new: adrp x8,P' ; ldr x0,[x8]   (the global moved to offset 0)
    assert mask_zero_page_offset('[x8]', {'x8'}) == '[x8, #<imm>]'
    # only for a register that holds an adrp page, and only the bare form
    assert mask_zero_page_offset('[x8]', {'x9'}) == '[x8]'
    assert mask_zero_page_offset('[x8, #0x10]', {'x8'}) == '[x8, #0x10]'
    assert mask_zero_page_offset('x8', {'x8'}) == 'x8'


def test_renumbered_symbol_names_are_stable():
    # names the asm diff keeps (calls to named functions) must not carry per-build numbering
    assert stable_symbol_name('___foo_block_invoke.339') == '___foo_block_invoke'
    assert stable_symbol_name('_OUTLINED_FUNCTION_22') == stable_symbol_name('_OUTLINED_FUNCTION_26')
    assert stable_symbol_name('_memmove') == '_memmove'
    assert stable_symbol_name('_foo.cold.2') == '_foo.cold.2'
