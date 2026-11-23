import concurrent.futures
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


def decomp_correlate(self, matches, p1_missing, p2_missing, p1_matches, p2_matches):
    """
    from all of the unmatched functions remaining, see if any should be matched by decomp
    Each old function is matched to the first unmatched new function whose code (after the signature) is the same.
    """

    p1_missing = [func for func in p1_missing if not p1_matches.contains(func.getEntryPoint())]
    p2_missing = [func for func in p2_missing if not p2_matches.contains(func.getEntryPoint())]

    # only attempt if there is something to match
    if len(p1_missing) > 0 and len(p2_missing) > 0:

        self.logger.info(f'Attempting to Decomp Correlate unmatched functions p1:{len(p1_missing)} p2:{len(p2_missing)}')

        # decompile each function once, in parallel (esyms are memoized)
        def body(func):
            return tuple(self.remove_code_sig(self.enhance_sym(func.getSymbol(), get_decomp_info=True)['code']))

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            bodies = list(executor.map(body, p1_missing + p2_missing))

        p2_by_body = {}
        for p2_func, code in zip(p2_missing, bodies[len(p1_missing):]):
            p2_by_body.setdefault(code, []).append(p2_func)

        for p1_func, code in zip(p1_missing, bodies[:len(p1_missing)]):

            candidates = p2_by_body.get(code)
            if not candidates:
                continue
            p2_func = candidates.pop(0)

            # Correlate function Same Decomp
            name = 'Decomp Match'
            p1_addr = p1_func.getEntryPoint()
            p2_addr = p2_func.getEntryPoint()
            matches.setdefault((p1_addr, p2_addr), {}).setdefault(name, 0)
            matches[(p1_addr, p2_addr)][name] += 1
            p1_matches.add(p1_addr)
            p2_matches.add(p2_addr)
