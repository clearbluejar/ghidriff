from pathlib import Path

import pytest_forked


def _patch_pytest_forked_nodeid():
    """
    pytest >= 9.2 keeps a report's node id as a NodeId object (`_id`). pytest-forked
    (<= 1.7.5) marshals report.__dict__ from the forked child back to the parent, and
    marshal cannot encode NodeId, so every forked (Ghidra) test fails with
    "running the test EXITED with status 3". Send the plain `nodeid` string instead;
    the parent rebuilds the report with TestReport(**d), which accepts it.
    """

    serialize_report = pytest_forked.serialize_report

    if getattr(serialize_report, '_nodeid_patched', False):
        return

    def _serialize_report(rep):
        d = serialize_report(rep)
        node_id = d.pop('_id', None)
        if node_id is not None:
            d['nodeid'] = str(node_id)
        return d

    _serialize_report._nodeid_patched = True
    pytest_forked.serialize_report = _serialize_report


_patch_pytest_forked_nodeid()


def pytest_collection_modifyitems(config, items):
    for item in items:
        relpath = Path(item.path).relative_to(config.rootpath)
        if relpath.parts[:1] == ("tests",) and item.get_closest_marker("fast") is None:
            item.add_marker("integration")
