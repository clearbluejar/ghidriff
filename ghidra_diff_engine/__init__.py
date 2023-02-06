__version__ = '0.2.0'
__author__ = 'clearbluejar'

# Expose API
from .ghidra_diff_engine import GhidraDiffEngine
from .simple_diff import GhidraSimpleDiff
from .structural_diff import GhidraStructualDiff
from .version_tracking_diff import VersionTrackingDiff

__all__ = [
    "GhidraDiffEngine", "GhidraSimpleDiff", "GhidraStructualDiff", "VersionTrackingDiff"
]
