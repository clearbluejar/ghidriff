from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


def decomp_correlate(self, matches, p1_missing, p2_missing, p1_matches, p2_matches):
    """
    from all of the unmatched functions remaining, see if any should be matched by decomp
    This is slow, but sometimes necessary
    """

    # only attempt if there is something to match
    if len(p1_missing) > 0 and len(p2_missing) > 0:

        self.logger.info(f'Attempting to Decomp Correlate unmatched functions p1:{len(p1_missing)} p2:{len(p1_missing)}')

        for p1_func in p1_missing:

            # skip already matched functions
            if p1_matches.contains(p1_func.getEntryPoint()):
                continue

            decomp1 = self.enhance_sym(p1_func.getSymbol(), get_decomp_info=True)['code']

            for p2_func in p2_missing:

                # skip already matched functions
                if p2_matches.contains(p2_func.getEntryPoint()):
                    continue

                decomp2 = self.enhance_sym(p2_func.getSymbol(), get_decomp_info=True)['code']

                if self.remove_code_sig(decomp1) == self.remove_code_sig(decomp2):

                    # Correlate function Same Decomp
                    name = 'Decomp Match'
                    p1_addr = p1_func.getEntryPoint()
                    p2_addr = p2_func.getEntryPoint()
                    matches.setdefault((p1_addr, p2_addr), {}).setdefault(name, 0)
                    matches[(p1_addr, p2_addr)][name] += 1
                    p1_matches.add(p1_addr)
                    p2_matches.add(p2_addr)

                    # break to find the next match
                    break
