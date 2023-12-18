---
sidebar_position: 3
---

## Extending ghidriff 

`ghidriff` can be used as is, but it offers developers the ability to extend the tool by implementing their own differ. The basic idea is create new diffing tools by implementing the `find_matches` method from the base class. 

```python
class NewDiffTool(GhidraDiffEngine):

    def __init__(self,verbose=False) -> None:
        super().__init__(verbose)

    @abstractmethod
    def find_matches(
            self,            
            old: Union[str, pathlib.Path],
            new: Union[str, pathlib.Path]
    ) -> dict:
        """My amazing differ"""

        # find added, deleted, and modified functions
        # <code goes here>

        return [unmatched, matched]
```

### Implementations

There are currently 3 diffing implementations, which also display the evolution of diffing for the project.

1. [SimpleDiff](https://github.com/clearbluejar/ghidriff/ghidriff/simple_diff.py) - A simple diff implementation. "Simple" as in it relies mostly on known symbol names for matching. 
2. [StructualGraphDiff](https://github.com/clearbluejar/ghidriff/ghidriff/structural_graph_diff.py) - A slightly more advanced differ, beginning to perform some more advanced hashing (such as Halvar's Structural Graph Comparison)
3. [VersionTrackingDiff](https://github.com/clearbluejar/ghidriff/ghidriff/version_tracking_diff.py) - The latest differ, with several [correlators](https://github.com/clearbluejar/ghidriff/ghidriff/correlators.py) (an algorithm used to score specific associations based on code, program flow, or any observable aspect of comparison) for function matching. **This one is fast.**

Each implementation leverages the base class, and implements `find_changes`.

