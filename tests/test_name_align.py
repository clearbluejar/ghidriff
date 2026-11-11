import difflib

import pytest

from ghidriff.name_align import (LOCAL, UNRESOLVED, align_lines, name_matches_to_functions, rename_new_side,
                                 undo)

pytestmark = pytest.mark.fast


def changed(old, new):
    return sum((a2 - a1) + (b2 - b1) for t, a1, a2, b1, b2 in
               difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes() if t != 'equal')


def check(old, new, **kw):
    renamed, maps = rename_new_side(old, new, **kw)
    assert undo(renamed, maps) == new, 'rename must be reversible'
    return renamed, maps


# ------------------------------------------------------------------ names

@pytest.mark.parametrize('name', ['uVar1', 'pcVar2', 'ppuVar3', 'auVar4', 'pFVar4', 'p_Var4', 'AVar3', '_Var8',
                                  'Var32', 'local_28', 'uStack_c', 'auStack_28', 'extraout_x8', 'in_NZCV',
                                  'unaff_x19', 'LAB_1000040', 'switchD_10004a2c', 'caseD_3'])
def test_every_default_local_form(name):
    # seen in iOS/macOS 27 output: AnyView, FILE *, __CFString *, _StringGuts, unkbyte10
    assert LOCAL.findall(f'x = {name} + 1;') == [name]


@pytest.mark.parametrize('name', ['_memmove', 'FUN_100004a2c', 'kGlobalVar2x', 'SwiftUI::AnyView::_init'])
def test_symbols_are_not_locals(name):
    assert LOCAL.findall(f'{name}(a);') == []


@pytest.mark.parametrize('name', ['func_0x0001980f1dd0', 'DAT_1000a0', '_DAT_1e11daa38',
                                  'PTR__OBJC_CLASS___TMLogging_1e11daa38'])
def test_unresolved_forms(name):
    assert UNRESOLVED.findall(f'x = {name};') == [name]


# ----------------------------------------------------------------- rename

def test_added_variable_does_not_renumber_the_rest():
    old = ['uint uVar1;', 'long lVar2;', 'uVar1 = f(lVar2);', 'return uVar1;']
    new = ['int *piVar1;', 'uint uVar2;', 'long lVar3;', 'piVar1 = g();', 'uVar2 = f(lVar3);', 'return uVar2;']
    renamed, _ = check(old, new)
    assert changed(old, renamed) == 2  # only the new declaration and its use


def test_retype_across_bases():
    # libz inflate_fast: a uint becomes a pointer between builds
    old = ['uint uVar1;', 'ulong uVar2;', 'uVar1 = a;', 'uVar2 = b;', 'return uVar2;']
    new = ['long *plVar1;', 'ulong uVar1;', 'plVar1 = a;', 'uVar1 = b;', 'return uVar1;']
    renamed, _ = check(old, new)
    assert renamed[1:] == ['ulong uVar2;', 'uVar1 = a;', 'uVar2 = b;', 'return uVar2;']


def test_swapped_variables():
    old = ['x = uVar1 + uVar2;', 'y = uVar1;']
    new = ['x = uVar2 + uVar1;', 'y = uVar2;']
    renamed, _ = check(old, new)
    assert renamed == old


def test_real_change_of_variable_still_shows():
    # the fix reads a different variable: must not be renamed away
    old = ['uVar1 = a;', 'uVar2 = b;', 'len = uVar1;', 'use(uVar1, uVar2);']
    new = ['uVar1 = a;', 'uVar2 = b;', 'len = uVar2;', 'use(uVar1, uVar2);']
    renamed, _ = check(old, new)
    assert renamed != old
    assert 'len = uVar2;' in renamed


def test_never_merges_two_names():
    old = ['a = uVar1;', 'b = uVar2;']
    new = ['a = uVar1;', 'b = uVar1;', 'c = uVar2;']
    renamed, maps = check(old, new)
    assert len(set(maps['locals'].values())) == len(maps['locals'])
    assert len({t for line in renamed for t in LOCAL.findall(line)}) == 2


def test_labels():
    old = ['if (x) goto LAB_100040;', 'f();', 'LAB_100040:', 'return;']
    new = ['if (x) goto LAB_200080;', 'f();', 'LAB_200080:', 'return;']
    renamed, _ = check(old, new)
    assert renamed == old


def test_two_labels_on_one_line():
    old = ['if (DAT_1000a0 == 0) goto LAB_100040;', 'LAB_100040:']
    new = ['if (DAT_2000a0 == 0) goto LAB_200040;', 'LAB_200040:']
    renamed, _ = check(old, new)
    assert renamed[1] == 'LAB_100040:'
    assert 'DAT_2000a0' in renamed[0], 'unresolved data is left alone by default'
    renamed, _ = check(old, new, infer_unresolved=True)
    assert renamed == old


def test_functions_via_match_table():
    old = ['FUN_100(a);', '_OUTLINED_FUNCTION_5();']
    new = ['FUN_200(a);', '_OUTLINED_FUNCTION_7();']
    renamed, _ = check(old, new, functions={'FUN_200': 'FUN_100', '_OUTLINED_FUNCTION_7': '_OUTLINED_FUNCTION_5'})
    assert renamed == old


def test_changed_callee_still_shows():
    # new calls a different function than its old counterpart's match
    renamed, _ = check(['FUN_100(a);'], ['FUN_300(a);'], functions={'FUN_200': 'FUN_100'})
    assert renamed == ['FUN_300(a);']


def test_function_rename_never_collides():
    # the new build reuses an old name for a different function
    old = ['FUN_100(a);', 'b();']
    new = ['FUN_200(a);', 'FUN_100(b);']
    renamed, _ = check(old, new, functions={'FUN_200': 'FUN_100'})
    assert renamed[0] == 'FUN_100(a);'
    assert renamed[1] != 'FUN_100(b);'


# ------------------------------------------------- ghidriff line-level API

OLD_C = '''
void FUN_100004000(long param_1)

{
  uint uVar1;
  long lVar2;

  /* WARNING: comment */
  uVar1 = FUN_100004a2c(param_1);
  if (uVar1 < 0x48) goto LAB_100004040;
  lVar2 = (long)uVar1;
LAB_100004040:
  return;
}
'''.splitlines(True)

NEW_C = '''
void FUN_100008000(long param_1)

{
  int *piVar1;
  uint uVar2;
  long lVar3;

  /* WARNING: comment */
  piVar1 = (int *)0x0;
  uVar2 = FUN_100008a2c(param_1);
  if (uVar2 < 0x24) goto LAB_100008040;
  lVar3 = (long)uVar2;
LAB_100008040:
  return;
}
'''.splitlines(True)


def test_align_lines_keeps_indentation_and_reverses():
    functions = {'FUN_100008000': 'FUN_100004000', 'FUN_100008a2c': 'FUN_100004a2c'}
    renamed, maps = align_lines(OLD_C, NEW_C, functions=functions)
    assert undo(renamed, maps) == NEW_C
    assert all(m for m in maps.values()), 'only non-identity renames are kept'
    assert '  uVar1 = FUN_100004a2c(param_1);\n' in renamed
    assert 'LAB_100004040:\n' in renamed
    # the real change survives: the bound and the added variable
    assert '  if (uVar1 < 0x24) goto LAB_100004040;\n' in renamed
    assert any('piVar' in line for line in renamed)
    plain = changed(OLD_C, NEW_C)
    aligned = changed(OLD_C, renamed)
    assert aligned < plain


def test_name_matches_to_functions_is_one_to_one():
    name_matches = {'FUN_1': [['FUN_2', ['SymbolsHash']]],
                    'FUN_3': [['FUN_4', ['StructuralGraphHash']], ['FUN_5', ['StructuralGraphHash']]]}
    assert name_matches_to_functions(name_matches) == {'FUN_2': 'FUN_1'}
