from collections import Counter
from time import time


from typing import List, Tuple, TYPE_CHECKING

from .ghidra_diff_engine import GhidraDiffEngine
from .implied_matches import correlate_implied_matches
from .decomp_correlate import decomp_correlate
from .bsim import correlate_bsim

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


class VersionTrackingDiff(GhidraDiffEngine):
    """
    An Ghidra Diff implementation using several exact and some fuzzy correlators
    This differ is inspired by Ghidra's Version Tracking (albeit much faster)
    ghidra/tree/master/Ghidra/Features/VersionTracking
    """

    def find_matches(
        self,
        p1: "ghidra.program.model.listing.Program",
        p2: "ghidra.program.model.listing.Program",
    ) -> list:
        """
        Find matching and unmatched functions between p1 and p2
        """

        from ghidra.program.model.symbol import SymbolType
        from ghidra.program.model.address import AddressSet
        from ghidra.util.task import ConsoleTaskMonitor

        # Match functions
        from ghidra.app.plugin.match import MatchFunctions, MatchSymbol

        # Correlators
        from ghidra.app.plugin.match import ExactMnemonicsFunctionHasher, ExactBytesFunctionHasher, ExactInstructionsFunctionHasher
        from .correlators import StructuralGraphExactHasher, StructuralGraphHasher, BulkInstructionsHasher, BulkMnemonicHasher, BulkBasicBlockMnemonicHasher, NamespaceNameParamHasher, NameParamHasher, NameParamRefHasher, SigCallingCalledHasher, StringsRefsHasher, SwitchSigHasher, StrUniqueFuncRefsHasher

        monitor = ConsoleTaskMonitor()

        # loadedAndInitializedAddressSet
        #   /**
        #  * Returns the set of addresses which correspond to all the "loaded" memory blocks that have
        #  * initialized data.  This does not include initialized memory blocks that contain data from
        #  * the program's file header such as debug sections.
        #  */
        p1_unmatched = AddressSet(p1.memory.loadedAndInitializedAddressSet)
        p2_unmatched = AddressSet(p2.memory.loadedAndInitializedAddressSet)

        # keep track of all function mathces
        p1_matches = AddressSet()
        p2_matches = AddressSet()

        # tuples of correlators instances
        # ( name, hasher, one_to_one, one_to_many)
        # DO NOT CHANGE ORDER UNLESS INTENDED, ORDER HAS MAJOR IMPACT ON ACCURACY AND EFFICIENCY
        func_correlators = [
            ('ExactBytesFunctionHasher', ExactBytesFunctionHasher.INSTANCE, True, False),
            ('ExactInstructionsFunctionHasher', ExactInstructionsFunctionHasher.INSTANCE, True, False),
            (StructuralGraphExactHasher.MATCH_TYPE, StructuralGraphExactHasher(), True, False),
            ('ExactMnemonicsFunctionHasher', ExactMnemonicsFunctionHasher.INSTANCE, True, False),
            ('BSIM', None, True, False), # not a true function hasher
            (BulkInstructionsHasher.MATCH_TYPE, BulkInstructionsHasher(), True, False),
            (SigCallingCalledHasher.MATCH_TYPE, SigCallingCalledHasher(), True, False),
            (StringsRefsHasher.MATCH_TYPE, StringsRefsHasher(), True, False),
            (StrUniqueFuncRefsHasher.MATCH_TYPE, StrUniqueFuncRefsHasher(), True, False),
            (SwitchSigHasher.MATCH_TYPE, SwitchSigHasher(), True, False),
            # WARN: one_to_many=True flag allows for false negatives is structal graph matching. Mitgated by added references, func name in hash
            (StructuralGraphHasher.MATCH_TYPE, StructuralGraphHasher(), True, True),
            # WARN: one_to_many=True flag allows for false negatives
            (BulkBasicBlockMnemonicHasher.MATCH_TYPE, BulkBasicBlockMnemonicHasher(), True, True),
            (SigCallingCalledHasher.MATCH_TYPE, SigCallingCalledHasher(), True, False),
            (StringsRefsHasher.MATCH_TYPE, StringsRefsHasher(), True, False),
            (StrUniqueFuncRefsHasher.MATCH_TYPE, StrUniqueFuncRefsHasher(), True, False),
            (SwitchSigHasher.MATCH_TYPE, SwitchSigHasher(), True, False),
        ]

        unmatched = []
        matches = {}

        # Run Symbol Hash Correlator

        one_to_one = True
        include_externals = True
        min_sym_name_len = 3
        matchedSymbols = MatchSymbol.matchSymbol(
            p1, p1.getMemory(), p2, p2.getMemory(), min_sym_name_len, one_to_one, include_externals, monitor)

        start = time()
        name = 'SymbolsHash'
        skipped = 0
        for match in matchedSymbols:
            if match.matchType == SymbolType.FUNCTION:
                # sanity check symbolmatch
                func = p1.functionManager.getFunctionAt(match.aSymbolAddress)
                func2 = p2.functionManager.getFunctionAt(match.bSymbolAddress)
                if func.getName(True) != func2.getName(True):
                    skipped += 1
                    continue
                p1_matches.add(match.aSymbolAddress)
                p2_matches.add(match.bSymbolAddress)
                matches.setdefault((match.aSymbolAddress, match.bSymbolAddress), {}).setdefault(name, 0)
                matches[(match.aSymbolAddress, match.bSymbolAddress)][name] += 1
        end = time()

        p1_unmatched = p1_unmatched.subtract(p1_matches)
        p2_unmatched = p2_unmatched.subtract(p2_matches)

        self.logger.info(f'Exec time: {end-start:.4f} secs')
        self.logger.info(f'Match count {matchedSymbols.size() - skipped}')
        self.logger.info(Counter([tuple(x) for x in matches.values()]))


        # Run Function Hash Correlators
        # Each round of matching will "accept" the matches and subtract them from the unmatched functions
        # This is why the order of correlators matter
        for cor in func_correlators:            

            start = time()

            name, hasher, one_to_one, one_to_many = cor

            self.logger.info(f'Running correlator: {name}')
            self.logger.debug(f'hasher: {hasher}')
            self.logger.info(f'name: {name} one_to_one: {one_to_one} one_to_many: {one_to_many}')

            if name == 'BSIM':             
                if self.bsim_full:
                    # slower, but uses full adddress space for matching
                    correlate_bsim(matches, p1,p2, p1_matches, p2_matches, monitor, self.logger,enabled=self.bsim)
                else:
                    # only matches on functions that have no match
                    correlate_bsim(matches, p1,p2, p1_matches, p2_matches, monitor, self.logger, p1_addr_set=p1_unmatched, p2_addr_set=p2_unmatched, enabled=self.bsim)
            else:
                func_matches = MatchFunctions.matchFunctions(
                    p1, p1_unmatched, p2, p2_unmatched, self.min_func_len, one_to_one, one_to_many, hasher, monitor)

                for match in func_matches:
                    p1_matches.add(match.aFunctionAddress)
                    p2_matches.add(match.bFunctionAddress)
                    matches.setdefault((match.aFunctionAddress, match.bFunctionAddress), {}).setdefault(name, 0)
                    matches[(match.aFunctionAddress, match.bFunctionAddress)][name] += 1
                
                self.logger.info(f'Match count: {func_matches.size()}')

            end = time()

            # subtract unmatched functions
            p1_unmatched = p1_unmatched.subtract(p1_matches)
            p2_unmatched = p2_unmatched.subtract(p2_matches)

            self.logger.info(f'{name} Exec time: {end-start:.4f} secs')
            

            # kill noisy monitor after first run
            monitor = ConsoleTaskMonitor().DUMMY_MONITOR

        # Log current counts
        self.logger.info(Counter([tuple(x) for x in matches.values()]))

        monitor = ConsoleTaskMonitor()

        # Find unmatched functions

        p1_missing = self.get_funcs_from_addr_set(p1, p1_unmatched)
        p2_missing = self.get_funcs_from_addr_set(p2, p2_unmatched)

        # Find implied matches
        correlate_implied_matches(matches,
                                  p1_missing,
                                  p2_missing,
                                  p1_matches,
                                  p2_matches,
                                  p1,
                                  p2,
                                  self.max_workers,
                                  monitor,
                                  self.logger)

        p1_unmatched = p1_unmatched.subtract(p1_matches)
        p2_unmatched = p2_unmatched.subtract(p2_matches)

        p1_missing = self.get_funcs_from_addr_set(p1, p1_unmatched)
        p2_missing = self.get_funcs_from_addr_set(p2, p2_unmatched)

        # attempt to correlate amongst unmatched functions
        decomp_correlate(self, matches, p1_missing, p2_missing, p1_matches, p2_matches)

        p1_unmatched = p1_unmatched.subtract(p1_matches)
        p2_unmatched = p2_unmatched.subtract(p2_matches)

        p1_missing = self.get_funcs_from_addr_set(p1, p1_unmatched)
        p2_missing = self.get_funcs_from_addr_set(p2, p2_unmatched)

        unmatched.extend([func.getSymbol() for func in p1_missing])
        unmatched.extend([func.getSymbol() for func in p2_missing])

        self.logger.info(f'p1 missing = {len(p1_missing)}')
        self.logger.info(f'p2 missing = {len(p2_missing)}')

        # Debug umatched
        if self.logger.level == 10:  # debug level
            self.debug_function_hasher(unmatched, func_correlators, p1, p2)

        # Find external function unmatched and matched
        p1_externals = {}
        # get external funcs (these are still interesting)
        for func in p1.functionManager.getExternalFunctions():
            key = func.getName(True)
            # Apple Machos Specific (externals provide no relevant info)
            if "<EXTERNAL>::EXT_FUN_" in key:
                continue
            p1_externals[key] = func

        p2_externals = {}
        # get external funcs (these are still interesting)
        for func in p2.functionManager.getExternalFunctions():
            key = func.getName(True)
            # Apple Machos Specific (externals provide no relevant info)
            if "<EXTERNAL>::EXT_FUN_" in key:
                continue
            p2_externals[key] = func

        deleted_externs = list(set(p1_externals.keys()).difference(p2_externals.keys()))
        added_externs = list(set(p2_externals.keys()).difference(p1_externals.keys()))
        matched_externs = list(set(p2_externals.keys()).intersection(p1_externals.keys()))

        self.logger.info(f'Externs - deleted: {len(deleted_externs)} added: {len(added_externs)} matched:{len(matched_externs)}')

        unmatched.extend([p1_externals[key].getSymbol() for key in deleted_externs])
        unmatched.extend([p2_externals[key].getSymbol() for key in added_externs])

        for key in matched_externs:
            name = 'ExternalsName'
            func = p1_externals[key]
            func2 = p2_externals[key]
            matches.setdefault((func.entryPoint, func2.entryPoint), {}).setdefault(name, 0)
            matches[(func.entryPoint, func2.entryPoint)][name] += 1

        # translate matches to expected format [ sym, sym2, match_type ]
        matched = []
        for match_addrs, match_types in matches.items():

            func = p1.functionManager.getFunctionContaining(match_addrs[0])
            assert func.entryPoint == match_addrs[0]
            func2 = p2.functionManager.getFunctionContaining(match_addrs[1])
            assert func2.entryPoint == match_addrs[1]

            matched.append([func.getSymbol(), func2.getSymbol(), list(match_types.keys())])

        # skip types will undergo less processing
        skip_types = ['BulkBasicBlockMnemonicHash' 'Decomp Match']

        return [unmatched, matched, skip_types]

    def debug_function_hasher(self,
                              functions: list,
                              func_correlators: list,
                              p1: "ghidra.program.model.listing.Program",
                              p2: "ghidra.program.model.listing.Program"):
        """
        Debug unmatched functions throuh each function hasher
        """
        from ghidra.util.task import ConsoleTaskMonitor

        for cor in func_correlators:

            name, hasher, one_to_one, one_to_many = cor

            self.logger.debug(f'Debug umatched correlator: {name}')

            if hasattr(hasher, 'DEBUG'):
                hasher.DEBUG = True

            dummy = ConsoleTaskMonitor().DUMMY_MONITOR
            dummy.cancel()

            p1_hashes_seen = {}
            p2_hashes_seen = {}

            for sym in sorted(functions, key=lambda x: x.getProgram().getFunctionManager().getFunctionAt(x.address).body.numAddresses, reverse=True):
                func = sym.getProgram().getFunctionManager().getFunctionAt(sym.address)
                in_p1 = (func.getProgram().name == p1.name)

                if hasher is None:
                    continue

                func_hash = hasher.hash(func, dummy)
                func_len = func.getBody().getNumAddresses()

                if in_p1:
                    if func_hash in p1_hashes_seen.keys():
                        print(f'hash matches another func in p1? {func_hash} {name} {func_len}')
                    p1_hashes_seen.setdefault(func_hash, []).append(func)

                    if func_hash in p2_hashes_seen.keys():
                        print(f'why though? {func_hash} {name} {func_len}')
                        func_json = self.enhance_sym(func.getSymbol(), get_decomp_info=True)
                        p2_func_json = self.enhance_sym(p2_hashes_seen[func_hash][0].getSymbol(), get_decomp_info=True)
                        for key in func_json.keys():
                            print(func_json[key])
                            print(p2_func_json[key])
                else:
                    if func_hash in p2_hashes_seen:
                        print(f'hash matches another func in p2 {func_hash} {name} {func_len}')
                    p2_hashes_seen.setdefault(func_hash, []).append(func)

                    if func_hash in p1_hashes_seen:
                        print(f'why though? {func_hash} {name} {func_len}')

                self.logger.debug(f'{func.getProgram().getName()}:{func}:{func_hash}')
