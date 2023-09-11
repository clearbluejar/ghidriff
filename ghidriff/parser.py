import inspect
import argparse
import ghidriff


def get_engine_classes() -> dict:
    engines = {}

    for name, klass in inspect.getmembers(ghidriff, inspect.isclass):
        if name.endswith('Diff'):
            engines[name] = klass

    return engines

def get_parser() -> argparse.ArgumentParser:
    """
    Build main ghidriff parser
    """

    parser = argparse.ArgumentParser(description='ghidriff - A Command Line Ghidra Binary Diffing Engine',
                                formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('old', nargs=1, help="Path to old version of binary '/somewhere/bin.old'")
    parser.add_argument('new', action='append', nargs='+',
                        help="Path to new version of binary '/somewhere/bin.new'. (For multiple new binaries add oldest to newest)")

    # setup Engine class options
    engines = get_engine_classes()
    parser.add_argument('--engine', help='The diff implementation to use.',
                        default='VersionTrackingDiff', choices=engines.keys())

    parser.add_argument('-o', '--output-path', help='Output path for resulting diffs', default='ghidriffs')
    parser.add_argument('--summary', help='Add a summary diff if more than two bins are provided', default=False)

    return parser