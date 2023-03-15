import hashlib

from typing import List, Tuple, TYPE_CHECKING

from .ghidra_diff_engine import GhidraDiffEngine

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


class StructualGraphDiff(GhidraDiffEngine):
    """
    An Ghidra Diff implementation using simple comparison mechanisms
    """

    def find_matches(
        self,
        p1: "ghidra.program.model.listing.Program",
        p2: "ghidra.program.model.listing.Program",
        ignore_FUN: bool = False,
    ) -> dict:
        """
        Find matching and unmatched functions between p1 and p2
        """

        from ghidra.program.util import DiffUtility

        compare_key_memo = {}

        def _get_compare_key(sym: 'ghidra.program.model.symbol.Symbol', func: 'ghidra.program.model.listing.Function') -> tuple:
            """
            Builds tuple from symbol (parent, name, refcount, length, paramcount)
            """
            key = f'{sym.getID()}-{sym.getProgram().getName()}'

            if compare_key_memo.get(key) is None:

                fhash = ''
                cu_count = 0
                if (not func.isThunk() and func.getBody().getNumAddresses() >= 10):
                    # reset iterator
                    code_units = func.getProgram().getListing().getCodeUnits(func.getBody(), True)

                    mnemonics = []

                    # Mnemonic Bulker
                    for code in code_units:
                        mnemonics.append(code.getMnemonicString())
                        cu_count += 1

                    fhash = hashlib.sha256(''.join(mnemonics).encode('UTF-8')).hexdigest()

                compare_key_memo[key] = (cu_count, sym.getReferenceCount(),
                                         func.body.numAddresses, func.parameterCount, fhash)

            return compare_key_memo[key]

        def _get_compare_key2(sym: 'ghidra.program.model.symbol.Symbol', func: 'ghidra.program.model.listing.Function') -> tuple:
            """
            Builds structural graph hash. Thank you Halvar Flake!)
            """

            from ghidra.program.model.block import BasicBlockModel
            from ghidra.util.task import ConsoleTaskMonitor

            # graph structure vars
            num_basic_blocks = 0
            num_edges_of_blocks = 0
            num_call_subfunctions = 0

            if (not func.isThunk() and func.getBody().getNumAddresses() >= 10):

                monitor = ConsoleTaskMonitor()

                basic_model = BasicBlockModel(func.getProgram(), True)
                basic_blocks = basic_model.getCodeBlocksContaining(func.getBody(), monitor)

                for block in basic_blocks:
                    num_edges_of_blocks += block.getNumDestinations(monitor)
                    num_basic_blocks += 1

                    code_units = func.getProgram().getListing().getCodeUnits(block, True)
                    for code in code_units:
                        if code.getMnemonicString() == 'CALL':
                            num_call_subfunctions += 1

            # ignore Ghidra generated function names
            gen_sym_prefix = ['FUN_', 'lambda', 'destructor', '~', 'dynamic_initializer', 'dtor', '::']
            fname = sym.getName(True)

            if any([generated in fname for generated in gen_sym_prefix]):
                fname = ''
            # ignore sections of names with relative addresses or offsets
            # Catch_All@64616295 _GrowCompBitsBuffer@4
            elif '@' in fname:
                fname = fname.split('@')[0]
            elif '$' in fname:
                fname = fname.split('$')[0]

            return (fname, num_basic_blocks, num_edges_of_blocks, num_call_subfunctions, func.body.numAddresses, func.parameterCount)

        def _syms_match(esym, esym2) -> Tuple[bool, str]:
            found = False
            match_type = None
            min_func_length = 15

            if esym2['name'] == esym['name'] and esym2['paramcount'] == esym['paramcount']:
                self.logger.info("Name + Paramcount {} {}".format(sym.getName(True), sym2.getName(True)))
                found = True
                match_type = 'Name:Param'
            if esym2['name'] == esym['name'] and esym2['length'] == esym['length']:
                self.logger.info("Name + length {} {}".format(sym.getName(True), sym2.getName(True)))
                found = True
                match_type = 'Name:Length'
            elif esym2['fullname'] == esym['fullname']:
                self.logger.info("Name Exact {} {}".format(sym.getName(True), sym2.getName(True)))
                found = True
                match_type = 'Fullname'

            return found, match_type

        from ghidra.program.model.symbol import SymbolType

        self.logger.info(f'Calculating initial structural signature for all ')
        p1_funcs = {}
        p2_funcs = {}

        from time import time
        start_p1 = time()
        for sym in p1.getSymbolTable().getDefinedSymbols():
            if sym.getSymbolType() == SymbolType.FUNCTION:
                func = p1.functionManager.getFunctionAt(sym.getAddress())
                p1_funcs[func] = _get_compare_key2(sym, func)
        end_p1 = time()

        for sym in p2.getSymbolTable().getDefinedSymbols():
            if sym.getSymbolType() == SymbolType.FUNCTION:
                func = p2.functionManager.getFunctionAt(sym.getAddress())
                p2_funcs[func] = _get_compare_key2(sym, func)
        end_p2 = time()

        self.logger.info(f'p1 structural signature time: {end_p1 - start_p1}')
        self.logger.info(f'p2 structural signature time: {end_p2 - end_p1}')

        from collections import Counter

        p1_funcs_vals = Counter(p1_funcs.values())
        p2_funcs_vals = Counter(p1_funcs.values())

        count_non_unique = 0
        for key, val in p1_funcs_vals.items():
            if val > 1:
                count_non_unique += 1
                self.logger.debug(f'{key, val}')
        self.logger.info(f'non-unique p1: {count_non_unique}')
        count_non_unique = 0
        for key, val in p2_funcs_vals.items():
            if val > 1:
                count_non_unique += 1
                self.logger.debug(f'{key, val}')
        self.logger.info(f'non-unique p2: {count_non_unique}')

        old_func_set = set(p1_funcs.values())
        new_func_set = set(p2_funcs.values())

        modified_old = sorted(old_func_set.difference(new_func_set))
        modified_new = sorted(new_func_set.difference(old_func_set))

        matching_compare_keys = sorted(old_func_set.intersection(new_func_set))
        self.logger.info(f'modified_old: {len(modified_old)}')
        self.logger.info(f'modified_new: {len(modified_new)}')
        self.logger.info(f'matching_compare_keys: {len(matching_compare_keys)}')

        p1_modified = []
        p2_modified = []

        p1_name_to_func = {}
        p2_name_to_func = {}

        for func, compare_key in p1_funcs.items():
            if compare_key in modified_old:
                p1_modified.append(func.getSymbol())
                key = (func.getName(True), func.parameterCount)
                p1_name_to_func.setdefault(key, []).append(func)

        for func, compare_key in p2_funcs.items():
            if compare_key in modified_new:
                p2_modified.append(func.getSymbol())
                key = (func.getName(True), func.parameterCount)
                p2_name_to_func.setdefault(key, []).append(func)

        self.logger.info("\nmodified_old_modified")
        for sym in p1_modified:
            self.logger.info(sym)

        self.logger.info("\nmodified_new_modified")
        for sym in p2_modified:
            self.logger.info(sym)

        # Find modified functions based on compare_key
        for sym in p1.getSymbolTable().getDefinedSymbols():

            if "function".lower() in sym.getSymbolType().toString().lower():
                func = p1.functionManager.getFunctionAt(sym.getAddress())
                if (_get_compare_key2(sym, func)) in modified_old:
                    p1_modified.append(sym)

        for sym in p2.getSymbolTable().getDefinedSymbols():

            if "function".lower() in sym.getSymbolType().toString().lower():
                func = p2.functionManager.getFunctionAt(sym.getAddress())
                if (_get_compare_key2(sym, func)) in modified_new:
                    p2_modified.append(sym)

        matched = []
        unmatched = []
        matches = []

        self.logger.info("\nMatching functions...")

        # match by name and paramcount
        for sym in p1_modified:

            if sym in matched:
                continue

            func = sym.getProgram().functionManager.getFunctionAt(sym.getAddress())

            key = (func.getName(True), func.parameterCount)

            if p2_name_to_func.get(key):

                func2 = p2_name_to_func[key][0]

                if len(p2_name_to_func[key]) > 1:

                    for func in p1_name_to_func[key]:

                        if func.getSymbol() in matched:
                            continue

                        for func2 in p2_name_to_func[key]:

                            if func2.getSymbol() in matched:
                                continue
                            # fname, num_basic_blocks, num_edges_of_blocks, num_call_subfunctions, func.body.numAddresses, func.parameterCount

                            _, _, _, func2_num_calls, _, _ = p2_funcs[func2]
                            _, _, _, func_num_calls, _, _ = p1_funcs[func]

                            if func2_num_calls == func_num_calls:
                                sym = func.getSymbol()
                                sym2 = func2.getSymbol()
                                self.logger.info(
                                    f"FullName + Paramcount + NumCalls {sym.getName(True)} {sym2.getName(True)}")
                                match_type = 'FullName:Param:NumCalls'
                                matched.append(sym)
                                matched.append(sym2)
                                matches.append([sym, sym2, match_type])

                else:
                    sym2 = func2.getSymbol()
                    self.logger.info(f"FullName + Paramcount {sym.getName(True)} {sym2.getName(True)}")
                    match_type = 'FullName:Param'
                    matched.append(sym)
                    matched.append(sym2)
                    matches.append([sym, sym2, match_type])

        for sym in p1_modified:
            found = False

            if sym in matched:
                continue

            sym2 = DiffUtility.getSymbol(sym, p2)

            if sym2 and sym.getName(True) == sym2.getName(True):
                found = True
                match_type = 'Direct'
                self.logger.info(f"direct getsymbol match {sym.getName(True)} {sym2.getName(True)}")
            else:
                for sym2 in p2_modified:
                    if sym2 in matched:
                        continue

                    func = sym.getProgram().functionManager.getFunctionAt(sym.getAddress())
                    ck1 = _get_compare_key(sym, func)

                    func2 = sym2.getProgram().functionManager.getFunctionAt(sym2.getAddress())
                    ck2 = _get_compare_key(sym2, func2)

                    if ck1[4] == ck2[4]:
                        found = True
                        match_type = 'MnemonicOrdered:Hash'
                        self.logger.info(f"{match_type} match {sym.getName(True)} {sym2.getName(True)}")

                    if found:
                        break

            if found:
                matched.append(sym)
                matched.append(sym2)
                matches.append([sym, sym2, match_type])
            else:
                self.logger.info(f"Deleted func found: {sym}")
                self.logger.info(
                    f"Deleted func found: {_get_compare_key(sym,sym.getProgram().functionManager.getFunctionAt(sym.getAddress()))}")
                unmatched.append(sym)
                # matched.append(sym)  # TODO check this

        for sym in p2_modified:
            found = False
            match_type = None

            if sym in matched:
                continue

            sym2 = DiffUtility.getSymbol(sym, p1)

            if sym2 and sym.getName(True) == sym2.getName(True):
                found = True
                match_type = 'Direct'
                self.logger.info(f"direct getsymbol match {sym.getName(True)} {sym2.getName(True)}")
            else:
                for sym2 in p1_modified:
                    if sym2 in matched:
                        continue

                    esym = self.enhance_sym(sym)
                    esym2 = self.enhance_sym(sym2)
                    found, match_type = _syms_match(esym, esym2)

                    if found:
                        break

            if found:
                matched.append(sym)
                matched.append(sym2)
                matches.append([sym, sym2, match_type])
            else:
                self.logger.info(f"Added func found: {sym}")
                unmatched.append(sym)

        self.logger.info(len(p1_modified))
        self.logger.info(len(p2_modified))

        matches = sorted(matches, key=lambda x: str(x[0]))

        # no need to skip types because we just ignore the matches for structual sig
        skip_types = []

        return [unmatched, matches, skip_types]
