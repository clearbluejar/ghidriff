from collections import Counter
from time import time


from typing import List, Tuple, TYPE_CHECKING

from .ghidra_diff_engine import GhidraDiffEngine

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
        ignore_FUN: bool = False,
    ) -> dict:
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
        from .correlators import StructuralGraphExactHasher, StructuralGraphHasher, BulkInstructionsHasher, BulkMnemonicHasher, BulkBasicBlockMnemonicHasher, NamespaceNameParamHasher, NameParamHasher, NameParamRefHasher

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
        # DO NOT CHANGE ORDER UNLESS INTENDED, ORDER HAS MAJOR IMPACT ON EFFICIENCY
        func_correlators = [
            ('ExactBytesFunctionHasher', ExactBytesFunctionHasher.INSTANCE, True, False),
            ('ExactInstructionsFunctionHasher', ExactInstructionsFunctionHasher.INSTANCE, True, False),
            (StructuralGraphExactHasher.MATCH_TYPE, StructuralGraphExactHasher(), True, False),
            ('ExactMnemonicsFunctionHasher', ExactMnemonicsFunctionHasher.INSTANCE, True, False),
            # WARN: one_to_many=True flag allows for false negatives is structal graph matching. Mitgated by added references, func name in hash
            (StructuralGraphHasher.MATCH_TYPE, StructuralGraphHasher(), True, True),
            (NamespaceNameParamHasher.MATCH_TYPE, NamespaceNameParamHasher(), True, False),
            # WARN: one_to_many=True flag allows for false negatives is structal graph matching. Mitgated by added references, func name in hash
            (BulkBasicBlockMnemonicHasher.MATCH_TYPE, BulkBasicBlockMnemonicHasher(), True, True),
            # (NameParamHasher.MATCH_TYPE, NameParamHasher(), True, True)
        ]

        unmatched = []
        matches = {}

        # Run Symbol Correlator

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

        # Run Function Correlators

        for cor in func_correlators:

            start = time()

            name, hasher, one_to_one, one_to_many = cor

            self.logger.info(f'Running correlator: {name}')
            self.logger.debug(f'name: {name} hasher: {hasher} one_to_one: {one_to_one} one_to_many: {one_to_many}')

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

        self.logger.info(f'Exec time: {end-start:.4f} secs')
        self.logger.info(f'Match count {matchedSymbols.size() - skipped}')
        self.logger.info(Counter([tuple(x) for x in matches.values()]))

        # Find unmatched functions

        p1_missing = []
        p2_missing = []
        for func in p1.functionManager.getFunctions(p1_unmatched, True):
            if (not func.isThunk() and func.getBody().getNumAddresses() >= self.MIN_FUNC_LEN):
                p1_missing.append(func)

        for func in p2.functionManager.getFunctions(p2_unmatched, True):
            if (not func.isThunk() and func.getBody().getNumAddresses() >= self.MIN_FUNC_LEN):
                p2_missing.append(func)

        self.logger.info(f'p1 missing = {len(p1_missing)}')
        self.logger.info(f'p2 missing = {len(p2_missing)}')

        unmatched.extend([func.getSymbol() for func in p1_missing])
        unmatched.extend([func.getSymbol() for func in p2_missing])

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
        skip_types = ['ExternalsName', 'ExactInstructionsFunctionHasher',
                      'ExactBytesFunctionHasher', 'ExactMnemonicsFunctionHasher']

        return [unmatched, matched, skip_types]
