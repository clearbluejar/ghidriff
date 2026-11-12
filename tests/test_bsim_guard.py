import logging

import pytest

from ghidriff.bsim import correlate_bsim

pytestmark = pytest.mark.fast


class _Iter:
    def __init__(self, n):
        self.n = n

    def hasNext(self):
        return self.n > 0

    def next(self):
        self.n -= 1
        return object()


class _Program:
    """Just enough of a Ghidra Program for the external-function count."""

    def __init__(self, externals):
        self.externals = externals

    def getFunctionManager(self):
        return self

    def getExternalFunctions(self):
        return _Iter(self.externals)


def run(p1_externals, p2_externals, limit, caplog):
    with caplog.at_level(logging.WARNING):
        correlate_bsim({}, _Program(p1_externals), _Program(p2_externals), None, None, None,
                       logging.getLogger('test'), max_external_pairs=limit)


def test_bsim_skipped_when_external_pairs_exceed_limit(caplog):
    # RealityKit: 22,097 externals per side would be ~488M candidate pairs
    run(22097, 22097, 25_000_000, caplog)
    assert 'Skipping BSIM correlator' in caplog.text
    assert '22097 x 22097' in caplog.text


def test_bsim_runs_under_limit_and_without_limit(caplog):
    # past the guard BSim needs Ghidra; reaching that import (no JVM here) proves it was not skipped
    for p1, p2, limit in ((100, 100, 25_000_000), (22097, 22097, 0)):
        with pytest.raises(ImportError):
            run(p1, p2, limit, caplog)
        assert 'Skipping BSIM correlator' not in caplog.text
