"""
Bounds that keep large binaries diffable: BSIM's candidate-pair budget, the one-to-many bucket cap, and the
linear decomp correlator. No JVM needed.
"""
import logging
import random

import pytest

from ghidriff.bsim import drop_vectors_over_budget
from ghidriff.decomp_correlate import decomp_correlate
from ghidriff.ghidra_diff_engine import GhidraDiffEngine
from ghidriff.version_tracking_diff import match_functions

pytestmark = pytest.mark.fast


# ------------------------------------------------------------ BSIM budget

def test_under_budget_keeps_everything():
    pairs = {(1, 1): 100, (2, 2): 50, (1, 2): 10}
    assert drop_vectors_over_budget(pairs, 160) == (set(), 160)
    assert drop_vectors_over_budget(pairs, 0) == (set(), 160)  # 0 = no limit


def test_drops_the_vector_shared_by_thousands():
    # Mail.framework: one vector shared by 9,149 old and 9,111 new stubs makes 83M of 105M pairs
    pairs = {(7, 7): 9149 * 9111, (8, 8): 4125 * 4147, (1, 1): 1, (2, 3): 1, (4, 4): 64}
    dropped, kept = drop_vectors_over_budget(pairs, 20_000_000)
    assert dropped == {7}
    assert kept == 4125 * 4147 + 66


def test_counts_pairs_between_different_vectors():
    # Music.app: a 3,946-function vector also pairs with two similar ones
    pairs = {(5, 5): 3946 * 3874, (5, 6): 3946 * 2500, (5, 9): 3946 * 2399, (6, 6): 10, (9, 9): 10}
    dropped, kept = drop_vectors_over_budget(pairs, 1000)
    assert dropped == {5}
    assert kept == 20


def test_drops_until_it_fits_and_never_more():
    pairs = {(v, v): n for v, n in enumerate([1000, 900, 800, 700, 10, 10])}
    dropped, kept = drop_vectors_over_budget(pairs, 1600)
    assert dropped == {0, 1}
    assert kept == 1520


def test_contribution_falls_as_partners_are_dropped():
    # 1 pairs heavily with 0; once 0 is gone, 1 makes 5 pairs and 2 is the one to drop
    pairs = {(0, 0): 1000, (0, 1): 900, (1, 1): 5, (2, 2): 600}
    dropped, kept = drop_vectors_over_budget(pairs, 604)
    assert dropped == {0, 2}
    assert kept == 5


def test_deterministic_on_ties():
    pairs = {(3, 3): 100, (2, 2): 100, (1, 1): 100}
    assert drop_vectors_over_budget(pairs, 250) == ({1}, 200)
    assert drop_vectors_over_budget(dict(reversed(list(pairs.items()))), 250) == ({1}, 200)


# ------------------------------------------------------- one-to-many buckets

class Func:
    def __init__(self, addr, key, size=20, thunk=False):
        self.addr, self.key, self.size, self.thunk = addr, key, size, thunk

    def isThunk(self):
        return self.thunk

    def getBody(self):
        size = self.size
        return type('Body', (), {'getNumAddresses': lambda _: size})()

    def getEntryPoint(self):
        return self.addr


class Program:
    def __init__(self, funcs):
        self.funcs = funcs

    def getFunctionManager(self):
        funcs = self.funcs
        return type('FM', (), {'getFunctions': lambda _, addr_set, forward: iter(funcs)})()


class Hasher:
    def hash(self, func, monitor):
        return func.key


def bucket(p1_funcs, p2_funcs, **kw):
    args = dict(min_func_len=10, one_to_one=True, one_to_many=True, hasher=Hasher(), max_bucket=3, monitor=object())
    args.update(kw)
    return match_functions(Program(p1_funcs), None, Program(p2_funcs), None, **args)


def test_one_to_one_and_small_buckets_are_paired_as_before():
    p1 = [Func('a1', 1), Func('a2', 2), Func('a3', 2)]
    p2 = [Func('b1', 1), Func('b2', 2), Func('b3', 2), Func('b4', 9)]
    pairs, absorbed = bucket(p1, p2)
    assert sorted(pairs) == [('a1', 'b1'), ('a2', 'b2'), ('a2', 'b3'), ('a3', 'b2'), ('a3', 'b3')]
    assert absorbed == []


def test_large_bucket_is_absorbed_not_paired():
    p1 = [Func(f'a{i}', 7) for i in range(5)] + [Func('x', 1)]
    p2 = [Func(f'b{i}', 7) for i in range(4)] + [Func('y', 1)]
    pairs, absorbed = bucket(p1, p2)
    assert pairs == [('x', 'y')]
    assert absorbed == [([f'a{i}' for i in range(5)], [f'b{i}' for i in range(4)])]


def test_one_sided_and_filtered_functions_are_left_alone():
    p1 = [Func('a1', 4), Func('thunk', 5, thunk=True), Func('tiny', 5, size=4)]
    p2 = [Func('b1', 6), Func('thunk2', 5, thunk=True), Func('tiny2', 5, size=4)]
    assert bucket(p1, p2) == ([], [])


def test_flags_and_no_limit():
    p1 = [Func(f'a{i}', 7) for i in range(5)] + [Func('x', 1)]
    p2 = [Func(f'b{i}', 7) for i in range(4)] + [Func('y', 1)]
    pairs, absorbed = bucket(p1, p2, max_bucket=0)
    assert len(pairs) == 1 + 5 * 4 and absorbed == []
    assert bucket(p1, p2, one_to_many=False) == ([('x', 'y')], [])
    assert bucket(p1, p2, one_to_one=False, max_bucket=0)[0] == [(f'a{i}', f'b{j}') for i in range(5) for j in range(4)]


# ------------------------------------------------------------ decomp correlate

class Sym:
    def __init__(self, func):
        self.func = func


class DFunc:
    def __init__(self, addr, code):
        self.addr, self.code = addr, code

    def getEntryPoint(self):
        return self.addr

    def getSymbol(self):
        return Sym(self)


class AddrSet:
    def __init__(self, addrs=()):
        self.addrs = set(addrs)

    def contains(self, addr):
        return addr in self.addrs

    def add(self, addr):
        self.addrs.add(addr)


class Engine:
    max_workers = 4
    logger = logging.getLogger('test')
    remove_code_sig = GhidraDiffEngine.remove_code_sig

    def enhance_sym(self, sym, thread_id=0, timeout=15, get_decomp_info=False, use_calling_counts=False):
        return {'code': sym.func.code}


def decomp_correlate_quadratic(self, matches, p1_missing, p2_missing, p1_matches, p2_matches):
    """ghidriff 1.1.0's decomp_correlate, the reference"""
    if len(p1_missing) > 0 and len(p2_missing) > 0:
        for p1_func in p1_missing:
            if p1_matches.contains(p1_func.getEntryPoint()):
                continue
            decomp1 = self.enhance_sym(p1_func.getSymbol(), get_decomp_info=True)['code']
            for p2_func in p2_missing:
                if p2_matches.contains(p2_func.getEntryPoint()):
                    continue
                decomp2 = self.enhance_sym(p2_func.getSymbol(), get_decomp_info=True)['code']
                if self.remove_code_sig(decomp1) == self.remove_code_sig(decomp2):
                    name = 'Decomp Match'
                    p1_addr = p1_func.getEntryPoint()
                    p2_addr = p2_func.getEntryPoint()
                    matches.setdefault((p1_addr, p2_addr), {}).setdefault(name, 0)
                    matches[(p1_addr, p2_addr)][name] += 1
                    p1_matches.add(p1_addr)
                    p2_matches.add(p2_addr)
                    break


@pytest.mark.parametrize('seed', range(20))
def test_decomp_correlate_matches_the_quadratic_version(seed):
    rng = random.Random(seed)
    bodies = [f'{{\n  return {i};\n}}\n' for i in range(6)] + ['Failed to decompile']

    def funcs(prefix, n):
        return [DFunc(f'{prefix}{i}', f'void {prefix}{i}(void)\n' + rng.choice(bodies)) for i in range(n)]

    p1, p2 = funcs('a', rng.randrange(0, 30)), funcs('b', rng.randrange(0, 30))
    pre1 = {f.getEntryPoint() for f in p1 if rng.random() < 0.1}
    pre2 = {f.getEntryPoint() for f in p2 if rng.random() < 0.1}

    results = []
    for impl in (decomp_correlate_quadratic, decomp_correlate):
        matches, m1, m2 = {}, AddrSet(pre1), AddrSet(pre2)
        impl(Engine(), matches, p1, p2, m1, m2)
        results.append((list(matches.items()), m1.addrs, m2.addrs))
    assert results[0] == results[1]
