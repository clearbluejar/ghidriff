__version__ = '0.3.0'
__author__ = 'clearbluejar'

# Expose API
from .ghidra_diff_engine import GhidraDiffEngine
from .version_tracking_diff import VersionTrackingDiff
from .simple_diff import SimpleDiff
from .structural_graph_diff import StructualGraphDiff
from .auto_version_tracking_diff import AutoVersionTrackingDiff

__all__ = [
    "GhidraDiffEngine", "SimpleDiff", "StructualGraphDiff", "VersionTrackingDiff", "AutoVersionTrackingDiff"
]
