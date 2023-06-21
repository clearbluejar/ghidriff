from collections import Counter
from time import time
import concurrent.futures


from typing import List, Tuple, TYPE_CHECKING

from .ghidra_diff_engine import GhidraDiffEngine
from .implied_matches import get_actual_reference, find_implied_match, find_implied_matches, find_matching_ref

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


class VersionTrackingDiff(GhidraDiffEngine):
    """
    An Ghidra Diff implementation using several exact and some fuzzy correlators
    This differ is inspired by Ghidra's Version Tracking (albeit much faster)
    ghidra/tree/master/Ghidra/Features/VersionTracking
    """

    MIN_FUNC_LEN = 10

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
        from .correlators import StructuralGraphExactHasher, StructuralGraphHasher, BulkInstructionsHasher, BulkMnemonicHasher, BulkBasicBlockMnemonicHasher, NamespaceNameParamHasher, NameParamHasher, NameParamRefHasher, SigCallingCalledHasher, StringsRefsHasher, SwitchSigHasher, StrUniqueFuncRefsHasher, MyManualMatchProgramCorrelator

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

        for cor in func_correlators:

            start = time()

            name, hasher, one_to_one, one_to_many = cor

            self.logger.info(f'Running correlator: {name}')
            self.logger.debug(f'hasher: {hasher}')
            self.logger.info(f'name: {name} one_to_one: {one_to_one} one_to_many: {one_to_many}')

            func_matches = MatchFunctions.matchFunctions(
                p1, p1_unmatched, p2, p2_unmatched, self.MIN_FUNC_LEN, one_to_one, one_to_many, hasher, monitor)

            end = time()

            for match in func_matches:
                p1_matches.add(match.aFunctionAddress)
                p2_matches.add(match.bFunctionAddress)
                matches.setdefault((match.aFunctionAddress, match.bFunctionAddress), {}).setdefault(name, 0)
                matches[(match.aFunctionAddress, match.bFunctionAddress)][name] += 1

            p1_unmatched = p1_unmatched.subtract(p1_matches)
            p2_unmatched = p2_unmatched.subtract(p2_matches)

            self.logger.info(f'{name} Exec time: {end-start:.4f} secs')
            self.logger.info(f'Match count: {func_matches.size()}')

            # kill noisy monitor after first run
            monitor = ConsoleTaskMonitor().DUMMY_MONITOR

        # Log current counts
        self.logger.info(Counter([tuple(x) for x in matches.values()]))

        monitor = ConsoleTaskMonitor()

        # Find unmatched functions

        p1_missing = self.get_funcs_from_addr_set(p1, p1_unmatched)
        p2_missing = self.get_funcs_from_addr_set(p2, p2_unmatched)

        # build list of function entry points that have already been matched
        matched_src_addrs = {}
        matched_dst_addrs = {}
        for i, match in enumerate(matches):
            matched_src_addrs[match[0]] = i
            matched_dst_addrs[match[1]] = i

        # from all of the unmatched functions, get every function that has already been acceped that calls an unmatched function
        # if the calling function has been accepted, then accept the unmatched called function
        potential_calling_funcs = []
        src_missing_addrs = []
        dst_missing_addrs = []

        for src_func in p1_missing:
            src_func: "ghidra.program.model.listing.Function" = src_func
            src_missing_addrs.append(src_func.getEntryPoint())
            potential_p1_calling_funcs = [func for func in list(src_func.getCallingFunctions(
                monitor)) if func.getEntryPoint() in matched_src_addrs.keys()]
            self.logger.debug(
                f'Found {len(potential_p1_calling_funcs)} p1 calling functions for potential implied match for {src_func}')
            potential_calling_funcs.extend(potential_p1_calling_funcs)

        for dst_func in p2_missing:
            dst_func: "ghidra.program.model.listing.Function" = dst_func
            dst_missing_addrs.append(dst_func.getEntryPoint())
            potential_p2_calling_funcs = [func for func in list(
                dst_func.getCallingFunctions(monitor)) if func.getEntryPoint() in matched_dst_addrs.keys()]
            self.logger.debug(
                f'Found {len(potential_p2_calling_funcs)} p2 calling functions for potential implied match for {dst_func}')
            potential_calling_funcs.extend(potential_p2_calling_funcs)

        potential_calling_funcs = list(set(potential_calling_funcs))

        # find all matches that might provide an implied match for unmatched functions
        potential_accepted_matches = []
        for func in potential_calling_funcs:
            match_index = None
            if matched_src_addrs.get(func.getEntryPoint()) is not None:
                match_index = matched_src_addrs.get(func.getEntryPoint())
            elif matched_dst_addrs.get(func.getEntryPoint()) is not None:
                match_index = matched_dst_addrs.get(func.getEntryPoint())

            if match_index is not None:
                match = list(matches.keys())[match_index]
                f1 = p1.functionManager.getFunctionAt(match[0])
                f2 = p2.functionManager.getFunctionAt(match[1])
                potential_accepted_matches.append((f1, f2))

        recovered = 0
        completed = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = (executor.submit(find_implied_matches, f1, f2)
                       for f1, f2 in potential_accepted_matches)

            for future in concurrent.futures.as_completed(futures):
                implied_matches = future.result()

                completed += 1
                if completed % 50 == 0:
                    percent = int((float(completed)/len(potential_accepted_matches)) * 100)
                    print(f'Completed {percent} %  recovered" {recovered}')

                if implied_matches is not None:
                    for implied_match in implied_matches:
                        # only apply function matches
                        if implied_match[2] == 'FUNCTION':
                            if implied_match[0] in src_missing_addrs or implied_match[1] in dst_missing_addrs:
                                if matches.get((implied_match[0], implied_match[1])) is None:
                                    recovered += 1

                                # Correlate function as Implied Match
                                name = 'Implied Match'
                                matches.setdefault((implied_match[0], implied_match[1]), {}).setdefault(name, 0)
                                matches[(implied_match[0], implied_match[1])][name] += 1
                                p1_matches.add(implied_match[0])
                                p2_matches.add(implied_match[1])

        p1_unmatched = p1_unmatched.subtract(p1_matches)
        p2_unmatched = p2_unmatched.subtract(p2_matches)

        p1_missing = self.get_funcs_from_addr_set(p1, p1_unmatched)
        p2_missing = self.get_funcs_from_addr_set(p2, p2_unmatched)

        self.logger.info(f'p1 missing = {len(p1_missing)}')
        self.logger.info(f'p2 missing = {len(p2_missing)}')

        unmatched.extend([func.getSymbol() for func in p1_missing])
        unmatched.extend([func.getSymbol() for func in p2_missing])

        # for sym in sorted(unmatched, key=lambda x: x.getProgram().getFunctionManager().getFunctionAt(x.address).body.numAddresses, reverse=True):
        #     func = sym.getProgram().getFunctionManager().getFunctionAt(sym.address)
        #     self.logger.debug(f'\n\n{func.getProgram()}')
        #     self.logger.debug(func)

        #     for cor in func_correlators:

        #         name, hasher, one_to_one, one_to_many = cor

        #         self.logger.debug(f'Debug umatched correlator: {name}')

        #         if hasattr(hasher, 'DEBUG'):
        #             hasher.DEBUG = True

        #         dummy = ConsoleTaskMonitor().DUMMY_MONITOR
        #         dummy.cancel()
        #         self.logger.debug(hasher.hash(func, dummy))

        # self.logger.debug(self.enhance_sym(sym, get_decomp_info=False))

        # Find external function unmatched and matched

        p1_externals = {}
        # get external funcs (these are still interesting)
        for func in p1.functionManager.getExternalFunctions():
            key = func.getName(True)
            p1_externals[key] = func

        p2_externals = {}
        # get external funcs (these are still interesting)
        for func in p2.functionManager.getExternalFunctions():
            key = func.getName(True)
            p2_externals[key] = func

        deleted_externs = list(set(p1_externals.keys()).difference(p2_externals.keys()))
        added_externs = list(set(p2_externals.keys()).difference(p1_externals.keys()))
        matched_externs = list(set(p2_externals.keys()).intersection(p1_externals.keys()))

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
        skip_types = ['BulkBasicBlockMnemonicHash', 'ExternalsName']

        return [unmatched, matched, skip_types]
