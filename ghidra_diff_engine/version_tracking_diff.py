import argparse
from collections import Counter
import json
import pathlib
import hashlib
from time import time

from typing import List, Tuple, TYPE_CHECKING

from .ghidra_diff_engine import GhidraDiffEngine


if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


class VersionTrackingDiff(GhidraDiffEngine):
    """
    An Ghidra Diff implementation using several exact and fuzzy correlators
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

        from .correlators import StructuralGraphExactHasher, StructuralGraphHasher, BulkInstructionsHasher, BulkMnemonicHasher, BulkBasicBlockMnemonicHasher, NamespaceNameParamHasher, NameParamHasher, NameParamRefHasher
        from ghidra.program.model.symbol import SourceType

        from ghidra.app.plugin.match import FunctionHasher
        from ghidra.app.plugin.match import MatchFunctions
        from ghidra.app.plugin.match import ExactMnemonicsFunctionHasher, ExactBytesFunctionHasher, ExactInstructionsFunctionHasher
        from ghidra.app.plugin.match import MatchSymbol
        from ghidra.program.model.listing import Function
        from ghidra.program.model.symbol import SymbolType
        from ghidra.program.model.address import AddressSet
        from ghidra.util.task import ConsoleTaskMonitor


# # first pass detect added and deleted symbols
        # common_sym_prefix = ['switch', 'FUN_', 'caseD', 'local_']

        # for sym in p1.getSymbolTable().getDefinedSymbols():
        #     name = sym.getName()
        #     if not any([common in name for common in common_sym_prefix]):
        #         old_symbols.append(name)

        # for sym in p2.getSymbolTable().getDefinedSymbols():
        #     name = sym.getName()
        #     if not any([common in name for common in common_sym_prefix]):
        #         new_symbols.append(name)

        # olds = set(old_symbols)
        # news = set(new_symbols)

        # # translate matches to expected format [ sym, sym2, match_type ]
        # for func in unmatched_p1:
        #     unmatched.append(func.getSymbol())

        # for func in unmatched_p2:
        #     unmatched.append(func.getSymbol())

        # expected_matches = []
        # for match_addrs, match_types in matches.items():
        #     address = match_addrs[0]
        #     address2 = match_addrs[1]
        #     sym = all_p1_funcs[address].getSymbol()
        #     sym2 = all_p2_funcs[address2].getSymbol()
        #     expected_matches.append([sym, sym2, match_types])

        # skip_types = ['ExternalsName', 'StructuralGraphHash']

        # return [deleted_symbols, added_symbols, unmatched, expected_matches, skip_types]

        # ==============================
        # one_to_one = True
        # one_to_many = False
        # hasher = ExactBytesFunctionHasher.INSTANCE

        # with _catchtime() as t:
        #     exact_bytes_funcs = MatchFunctions.matchFunctions(
        #         p1, p1_unmatched, p2, p2_unmatched, 10, one_to_one, one_to_many, hasher, monitor)

        # print(f'Exec time ExactBytesFunctionHasher: {t():.4f} secs')
        # print(exact_bytes_funcs.size())

        # # p1.functionManager.getFunctionContaining(match.aFunctionAddress).getBody() TODO
        # for match in exact_bytes_funcs:
        #     p1_matches.add(match.aFunctionAddress)
        #     p2_matches.add(match.bFunctionAddress)

        # p1_unmatched = p1_unmatched.subtract(p1_matches)
        # p2_unmatched = p2_unmatched.subtract(p2_matches)

        # one_to_one = True
        # one_to_many = False
        # hasher = ExactInstructionsFunctionHasher.INSTANCE

        # with _catchtime() as t:
        #     exact_instr_funcs = MatchFunctions.matchFunctions(
        #         p1, p1_unmatched, p2, p2_unmatched, 10, one_to_one, one_to_many, hasher, monitor)

        # print(f'Exec time ExactInstructionsFunctionHasher: {t():.4f} secs')
        # print(exact_instr_funcs.size())

        # for match in exact_instr_funcs:
        #     p1_matches.add(match.aFunctionAddress)
        #     p2_matches.add(match.bFunctionAddress)

        # p1_unmatched = p1_unmatched.subtract(p1_matches)
        # p2_unmatched = p2_unmatched.subtract(p2_matches)

        # hasher = StructuralGraphExactHasher()
        # one_to_one = True

        # one_to_many = False

        # # graph_funcs = MatchFunctions.matchFunctions(
        # #     p1, p1_addrs, p2, p2_addrs, self.MIN_FUNC_LEN, one_to_one, one_to_many, hasher, monitor)

        # with _catchtime() as t:
        #     exact_struct_funcs = MatchFunctions.matchFunctions(
        #         p1, p1_unmatched, p2, p2_unmatched, self.MIN_FUNC_LEN, one_to_one, one_to_many, StructuralGraphExactHasher(), monitor)

        # print(f'Exec time StructuralGraphExactHasher: {t():.4f} secs')
        # print(exact_struct_funcs.size())

        # for match in exact_struct_funcs:
        #     p1_matches.add(match.aFunctionAddress)
        #     p2_matches.add(match.bFunctionAddress)

        # p1_unmatched = p1_unmatched.subtract(p1_matches)
        # p2_unmatched = p2_unmatched.subtract(p2_matches)

        # one_to_one = True
        # one_to_many = False
        # hasher = ExactMnemonicsFunctionHasher.INSTANCE

        # with _catchtime() as t:
        #     # exact_mnemonics_funcs = MatchFunctions.matchFunctions(
        #     #     p1, p1_addrs, p2, p2_addrs, 10, one_to_one, one_to_many, hasher, monitor)
        #     exact_mnemonics_funcs = MatchFunctions.matchFunctions(
        #         p1, p1_unmatched, p2, p2_unmatched, 10, one_to_one, one_to_many, hasher, monitor)

        # print(f'Exec time ExactMnemonicsFunctionHasher: {t():.4f} secs')
        # print(exact_mnemonics_funcs.size())

        # for match in exact_mnemonics_funcs:
        #     p1_matches.add(match.aFunctionAddress)
        #     p2_matches.add(match.bFunctionAddress)

        # p1_unmatched = p1_unmatched.subtract(p1_matches)
        # p2_unmatched = p2_unmatched.subtract(p2_matches)

        # hasher = StructuralGraphHasher()
        # one_to_one = True

        # # TODO: Yes flag allows for false positives is structal graph matching.
        # # At the same time, if a function had a matching sig (matching logic in p2) how important can it be?
        # one_to_many = True

        # # graph_funcs = MatchFunctions.matchFunctions(
        # #     p1, p1_addrs, p2, p2_addrs, self.MIN_FUNC_LEN, one_to_one, one_to_many, hasher, monitor)

        # with _catchtime() as t:
        #     struct_funcs = MatchFunctions.matchFunctions(
        #         p1, p1_unmatched, p2, p2_unmatched, self.MIN_FUNC_LEN, one_to_one, one_to_many, hasher, monitor)

        # print(f'Exec time StructuralGraphHasher: {t():.4f} secs')
        # print(struct_funcs.size())

        # for match in struct_funcs:
        #     p1_matches.add(match.aFunctionAddress)
        #     p2_matches.add(match.bFunctionAddress)

        # p1_unmatched = p1_unmatched.subtract(p1_matches)
        # p2_unmatched = p2_unmatched.subtract(p2_matches)

        # one_to_one = True
        # one_to_many = False
        # hasher = NameParamHasher()

        # with _catchtime() as t:
        #     # exact_mnemonics_funcs = MatchFunctions.matchFunctions(
        #     #     p1, p1_addrs, p2, p2_addrs, 10, one_to_one, one_to_many, hasher, monitor)
        #     name_param_funcs = MatchFunctions.matchFunctions(
        #         p1, p1_unmatched, p2, p2_unmatched, 10, one_to_one, one_to_many, hasher, monitor)

        # print(f'Exec time NameParam: {t():.4f} secs')
        # print(name_param_funcs.size())

        # for match in name_param_funcs:
        #     p1_matches.add(match.aFunctionAddress)
        #     p2_matches.add(match.bFunctionAddress)

        # p1_unmatched = p1_unmatched.subtract(p1_matches)
        # p2_unmatched = p2_unmatched.subtract(p2_matches)

        # one_to_one = True
        # one_to_many = False
        # hasher = BulkBasicBlockMnemonicHasher()
        # with _catchtime() as t:
        #     bulk_block_mnemonic_matches = MatchFunctions.matchFunctions(
        #         p1, p1_unmatched, p2, p2_unmatched, 10, one_to_one, one_to_many, hasher, monitor)

        # print(f'Exec time BulkBasicBlockMnemonicHasher: {t():.4f} secs')

        # for match in bulk_block_mnemonic_matches:
        #     p1_matches.add(match.aFunctionAddress)
        #     p2_matches.add(match.bFunctionAddress)

        # p1_unmatched = p1_unmatched.subtract(p1_matches)
        # p2_unmatched = p2_unmatched.subtract(p2_matches)

        # print(f'Exec time NameParam: {t():.4f} secs')
        # print(bulk_block_mnemonic_matches.size())

        # ==================

        all_p1_funcs = {}
        all_p2_funcs = {}

        monitor = ConsoleTaskMonitor()

        p1_addrs = p1.getMemory().loadedAndInitializedAddressSet
        p2_addrs = p1.getMemory().loadedAndInitializedAddressSet

        p1_unmatched = AddressSet(p1.getMemory().loadedAndInitializedAddressSet)
        p2_unmatched = AddressSet(p2.getMemory().loadedAndInitializedAddressSet)
        p1_matches = AddressSet()
        p2_matches = AddressSet()

        # tuples of correlators instances
        # ( name, hasher, one_to_one, one_to_many)
        # DO NOT CHANGE ORDER UNLESS INTENDED
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

        for cor in func_correlators:
            print(cor)
            start = time()

            name, hasher, one_to_one, one_to_many = cor

            func_matches = MatchFunctions.matchFunctions(
                p1, p1_unmatched, p2, p2_unmatched, self.MIN_FUNC_LEN, one_to_one, one_to_many, hasher, monitor)

            end = time()

            # p1.functionManager.getFunctionContaining(match.aFunctionAddress).getBody() TODO
            for match in func_matches:
                p1_matches.add(match.aFunctionAddress)
                p2_matches.add(match.bFunctionAddress)
                matches.setdefault((match.aFunctionAddress, match.bFunctionAddress), {}).setdefault(name, 0)
                matches[(match.aFunctionAddress, match.bFunctionAddress)][name] += 1

            p1_unmatched = p1_unmatched.subtract(p1_matches)
            p2_unmatched = p2_unmatched.subtract(p2_matches)

            print(f'Exec time {name}: {end-start:.4f} secs')
            print(func_matches.size())
            print(Counter([tuple(x) for x in matches.values()]))

        one_to_one = True
        include_externals = True
        min_sym_name_len = 3
        matchedSymbols = MatchSymbol.matchSymbol(p1, p1.getMemory(), p2, p2.getMemory(),
                                                 min_sym_name_len, one_to_one, include_externals, monitor)

        start = time()
        for match in matchedSymbols:
            if match.matchType == SymbolType.FUNCTION:
                func = p1.functionManager.getFunctionContaining(match.aSymbolAddress)
                assert func.entryPoint == match.aSymbolAddress
                func2 = p2.functionManager.getFunctionContaining(match.bSymbolAddress)
                assert func2.entryPoint == match.bSymbolAddress

                p1_matches.add(match.aSymbolAddress)
                p2_matches.add(match.bSymbolAddress)
                matches.setdefault((match.aSymbolAddress, match.bSymbolAddress), {}).setdefault(name, 0)
                matches[(match.aSymbolAddress, match.bSymbolAddress)][name] += 1
        end = time()

        p1_unmatched = p1_unmatched.subtract(p1_matches)
        p2_unmatched = p2_unmatched.subtract(p2_matches)

        print(f'Exec time MatchSymbol: {end-start:.4f} secs')
        print(matchedSymbols.size())
        print(Counter([tuple(x) for x in matches.values()]))

        p1_missing = []
        p2_missing = []
        for func in p1.functionManager.getFunctions(p1_unmatched, True):
            if (not func.isThunk() and func.getBody().getNumAddresses() >= self.MIN_FUNC_LEN):
                p1_missing.append(func)

        for func in p2.functionManager.getFunctions(p2_unmatched, True):
            if (not func.isThunk() and func.getBody().getNumAddresses() >= self.MIN_FUNC_LEN):
                p2_missing.append(func)

        print(f'p1 missing = {len(p1_missing)}')
        print(f'p2 missing = {len(p2_missing)}')

        unmatched.extend([func.getSymbol() for func in p1_missing])
        unmatched.extend([func.getSymbol() for func in p2_missing])

        # Find added and deleted externs
        p1_externals = {}
        # get external funcs (these are still interesting)
        for func in p1.functionManager.getExternalFunctions():
            key = func.getName(True)
            if p1_externals.get(key):
                print(f'Warning: key already found in p1 externals {key}')
            p1_externals[key] = func

        p2_externals = {}
        # get external funcs (these are still interesting)
        for func in p2.functionManager.getExternalFunctions():
            key = func.getName(True)
            if p2_externals.get(key):
                print(f'Warning: key already found in p2 externals {key}')
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

        # find matching functions with different references counts
        # NameParamRefHasher

        # translate matches to expected format [ sym, sym2, match_type ]
        matched = []
        for match_addrs, match_types in matches.items():

            func = p1.functionManager.getFunctionContaining(match_addrs[0])
            assert func.entryPoint == match_addrs[0]
            func2 = p2.functionManager.getFunctionContaining(match_addrs[1])
            assert func2.entryPoint == match_addrs[1]

            matched.append([func.getSymbol(), func2.getSymbol(), list(match_types.keys())])

        # skip types will undergo less processing
        skip_types = ['ExternalsName', 'StructuralGraphHash',
                      'ExactInstructionsFunctionHasher', 'ExactBytesFunctionHasher']

        return [unmatched, matched, skip_types]

        all_p1_funcs = {}
        all_p2_funcs = {}

        monitor = ConsoleTaskMonitor()

        p1_addrs = p1.getMemory().loadedAndInitializedAddressSet
        p2_addrs = p1.getMemory().loadedAndInitializedAddressSet

        # get external funcs (these are still interesting)
        for func in p1.functionManager.getExternalFunctions():
            key = func.getEntryPoint()
            assert all_p1_funcs.get(key) is None
            all_p1_funcs[key] = func

        # get all real funcs
        # for func in p1.functionManager.getFunctions(p1.getMemory().getLoadedAndInitializedAddressSet(), True):
        for func in p1.functionManager.getFunctions(p1.getMemory(), True):
            if (not func.isThunk() and func.getBody().getNumAddresses() >= self.MIN_FUNC_LEN):
                key = func.getEntryPoint()
                assert all_p1_funcs.get(key) is None
                all_p1_funcs[key] = func

        print(f'p1 func count: reported: {p1.functionManager.functionCount} analyzed: {len(all_p1_funcs)}')

        # get external funcs (these are still interesting)
        for func in p2.functionManager.getExternalFunctions():
            key = func.getEntryPoint()
            assert all_p2_funcs.get(key) is None
            all_p2_funcs[key] = func

        # get all real funcs
        # for func in p2.functionManager.getFunctions(p2.getMemory().getLoadedAndInitializedAddressSet(), True):
        for func in p2.functionManager.getFunctions(p2.getMemory(), True):
            if (not func.isThunk() and func.getBody().getNumAddresses() >= self.MIN_FUNC_LEN):
                key = func.getEntryPoint()
                assert all_p2_funcs.get(key) is None
                all_p2_funcs[key] = func

        print(f'p2 func count: reported: {p2.functionManager.functionCount} analyzed: {len(all_p2_funcs)}')

        all_p1_syms = {}
        all_p2_syms = {}

        # build symbols dict
        # don't include DEFAULT (FUN_ LAB_) but do include strings s_something

        # follow pattern for Ghidra/Features/Base/src/main/java/ghidra/app/plugin/match/MatchSymbol.java
        for sym in p1.getSymbolTable().getAllSymbols(True):
            # skip default names
            if sym.getSource() != SourceType.DEFAULT or _is_sym_string(sym):
                # skip local symbols
                if not isinstance(sym.getParentNamespace(), Function):
                    all_p1_syms[sym.getAddress()] = sym

        print(f'p1 sym count: reported: {p1.symbolTable.numSymbols} analyzed: {len(all_p1_syms)}')

        for sym in p2.getSymbolTable().getAllSymbols(True):
            # skip default names
            if sym.getSource() != SourceType.DEFAULT or _is_sym_string(sym):
                # skip local symbols
                if not isinstance(sym.getParentNamespace(), Function):
                    all_p2_syms[sym.getAddress()] = sym

        print(f'p2 sym count: reported: {p2.symbolTable.numSymbols} analyzed: {len(all_p2_syms)}')

        # this sets Addresses over which functions are hashed (does not include externals)
        #   /**
        #  * Returns the set of addresses which correspond to all the "loaded" memory blocks that have
        #  * initialized data.  This does not include initialized memory blocks that contain data from
        #  * the program's file header such as debug sections.
        #  */
        p1_addrs = p1.getMemory().loadedAndInitializedAddressSet
        p2_addrs = p1.getMemory().loadedAndInitializedAddressSet
        from ghidra.program.model.address import AddressSet

        remaining = AddressSet()
        p1_leftovers = AddressSet()
        p2_leftovers = AddressSet()

        matched_p1 = set()
        matched_p2 = set()
        unmatched = []
        matches = {}

        # match exeternals O(N x M) :(
        for ext in p1.functionManager.getExternalFunctions():
            for ext2 in p2.functionManager.getExternalFunctions():
                if ext.getName() == ext2.getName():
                    matched_p1.add(ext)
                    matched_p2.add(ext2)
                    matches.setdefault((ext.getEntryPoint(), ext2.getEntryPoint()), set()).add('ExternalsName')

        unmatched_p1 = set(all_p1_funcs.values()).difference(matched_p1)
        unmatched_p2 = set(all_p2_funcs.values()).difference(matched_p2)

        print(len(unmatched_p1))
        print(len(unmatched_p2))
        print(Counter([tuple(x) for x in matches.values()]))

        one_to_one = True
        one_to_many = False
        hasher = ExactMnemonicsFunctionHasher.INSTANCE
        exact_mnemonics_funcs = MatchFunctions.matchFunctions(
            p1, p1_addrs, p2, p2_addrs, 10, one_to_one, one_to_many, hasher, monitor)

        for match in exact_mnemonics_funcs:
            func = all_p1_funcs[match.aFunctionAddress]
            func2 = all_p2_funcs[match.bFunctionAddress]
            matched_p1.add(func)
            matched_p2.add(func2)
            matches.setdefault((match.aFunctionAddress, match.bFunctionAddress),
                               set()).add('ExactMnemonicsFunctionHasher')

        unmatched_p1 = set(all_p1_funcs.values()).difference(matched_p1)
        unmatched_p2 = set(all_p2_funcs.values()).difference(matched_p2)
        print(len(unmatched_p1))
        print(len(unmatched_p2))
        print(Counter([tuple(x) for x in matches.values()]))

        one_to_one = True
        one_to_many = False
        hasher = BulkBasicBlockMnemonicHasher()
        bulk_block_mnemonic_matches = MatchFunctions.matchFunctions(
            p1, p1_addrs, p2, p2_addrs, 10, one_to_one, one_to_many, hasher, monitor)

        for match in bulk_block_mnemonic_matches:
            func = all_p1_funcs[match.aFunctionAddress]
            func2 = all_p2_funcs[match.bFunctionAddress]
            matched_p1.add(func)
            matched_p2.add(func2)
            matches.setdefault((match.aFunctionAddress, match.bFunctionAddress),
                               set()).add(BulkBasicBlockMnemonicHasher.MATCH_TYPE)

        unmatched_p1 = set(all_p1_funcs.values()).difference(matched_p1)
        unmatched_p2 = set(all_p2_funcs.values()).difference(matched_p2)
        print(len(unmatched_p1))
        print(len(unmatched_p2))
        print(Counter([tuple(x) for x in matches.values()]))

        one_to_one = True
        one_to_many = False
        hasher = BulkMnemonicHasher()
        bulk_mnemonic_matches = MatchFunctions.matchFunctions(
            p1, p1_addrs, p2, p2_addrs, 10, one_to_one, one_to_many, hasher, monitor)

        for match in bulk_mnemonic_matches:
            func = all_p1_funcs[match.aFunctionAddress]
            func2 = all_p2_funcs[match.bFunctionAddress]
            matched_p1.add(func)
            matched_p2.add(func2)
            matches.setdefault((match.aFunctionAddress, match.bFunctionAddress),
                               set()).add(BulkMnemonicHasher.MATCH_TYPE)

        unmatched_p1 = set(all_p1_funcs.values()).difference(matched_p1)
        unmatched_p2 = set(all_p2_funcs.values()).difference(matched_p2)
        print(len(unmatched_p1))
        print(len(unmatched_p2))
        print(Counter([tuple(x) for x in matches.values()]))

        one_to_one = True
        one_to_many = False
        hasher = BulkInstructionsHasher()
        bulk_instr_matches = MatchFunctions.matchFunctions(
            p1, p1_addrs, p2, p2_addrs, 10, one_to_one, one_to_many, hasher, monitor)

        for match in bulk_instr_matches:
            func = all_p1_funcs[match.aFunctionAddress]
            func2 = all_p2_funcs[match.bFunctionAddress]
            matched_p1.add(func)
            matched_p2.add(func2)
            matches.setdefault((match.aFunctionAddress, match.bFunctionAddress),
                               set()).add(BulkInstructionsHasher.MATCH_TYPE)

        unmatched_p1 = set(all_p1_funcs.values()).difference(matched_p1)
        unmatched_p2 = set(all_p2_funcs.values()).difference(matched_p2)
        print(len(unmatched_p1))
        print(len(unmatched_p2))
        print(Counter([tuple(x) for x in matches.values()]))

        hasher = StructuralGraphHasher()
        one_to_one = True

        # TODO: Yes flag allows for false positives is structal graph matching.
        # At the same time, if a function had a matching sig (matching logic in p2) how important can it be?
        one_to_many = True

        graph_funcs = MatchFunctions.matchFunctions(
            p1, p1_addrs, p2, p2_addrs, self.MIN_FUNC_LEN, one_to_one, one_to_many, hasher, monitor)

        # graph_funcs2 = MatchFunctions.matchFunctions(
        #     p1, p1_addrs, p2, p2_addrs, self.MIN_FUNC_LEN, one_to_one, False, StructuralGraphExactHasher(), monitor)

#        print(graph_funcs2.size())
        print(graph_funcs.size())

        for match in graph_funcs:
            func = all_p1_funcs[match.aFunctionAddress]
            func2 = all_p2_funcs[match.bFunctionAddress]
            matched_p1.add(func)
            matched_p2.add(func2)
            matches.setdefault((match.aFunctionAddress, match.bFunctionAddress),
                               set()).add(StructuralGraphHasher.MATCH_TYPE)

        unmatched_p1 = set(all_p1_funcs.values()).difference(matched_p1)
        unmatched_p2 = set(all_p2_funcs.values()).difference(matched_p2)
        print(len(unmatched_p1))
        print(len(unmatched_p2))
        print(Counter([tuple(x) for x in matches.values()]))

        if len(unmatched_p1) < 1000 and len(unmatched_p2) < 1000:
            one_to_one = True
        else:
            # put all hope in last correlator lol
            one_to_one = False
        include_externals = True
        min_sym_name_len = 5
        matchedSymbols = MatchSymbol.matchSymbol(p1, p1.getMemory(), p2, p2.getMemory(),
                                                 min_sym_name_len, one_to_one, include_externals, monitor)

        # use symbols
        matched_p1_syms = set()
        matched_p2_syms = set()

        for match in matchedSymbols:

            if all_p1_syms.get(match.aSymbolAddress) and all_p2_syms.get(match.bSymbolAddress):
                matched_p1_syms.add(all_p1_syms[match.aSymbolAddress])
                matched_p2_syms.add(all_p2_syms[match.bSymbolAddress])
            else:
                print(f'missing {all_p1_syms.get(match.aSymbolAddress)} and {all_p2_syms.get(match.bSymbolAddress)}')

            if match.matchType == SymbolType.FUNCTION:
                if all_p1_funcs.get(match.aSymbolAddress) and all_p2_funcs.get(match.bSymbolAddress):
                    func = all_p1_funcs[match.aSymbolAddress]
                    func2 = all_p2_funcs[match.bSymbolAddress]
                    matched_p1.add(func)
                    matched_p2.add(func2)
                    matches.setdefault((match.aSymbolAddress, match.bSymbolAddress),
                                       set()).add('SymbolMatcher')
                else:
                    print(f'missing {all_p1_funcs.get(match.aSymbolAddress)} and {all_p2_funcs.get(match.bSymbolAddress)}')
                    print(all_p1_syms.get(match.aSymbolAddress))
                    print(all_p2_syms.get(match.bSymbolAddress))

                # print(p1.functionManager.getFunctionAt(match.aSymbolAddress))
                # print(p2.functionManager.getFunctionAt(match.bSymbolAddress))

        unmatched_p1 = set(all_p1_funcs.values()).difference(matched_p1)
        unmatched_p2 = set(all_p2_funcs.values()).difference(matched_p2)
        print(len(unmatched_p1))
        print(len(unmatched_p2))
        print(Counter([tuple(x) for x in matches.values()]))

        deleted_symbols = list(set(all_p1_syms.values()).difference(set(matched_p1_syms)))
        added_symbols = list(set(all_p2_syms.values()).difference(set(matched_p2_syms)))

        # match symbols by name

        for sym in deleted_symbols:
            for sym2 in added_symbols:
                if sym.getName() == sym2.getName():
                    matched_p1_syms.add(sym)
                    matched_p2_syms.add(sym2)

        deleted_symbols = list(set(deleted_symbols).difference(matched_p1_syms))
        added_symbols = list(set(added_symbols).difference(matched_p2_syms))

        unmatched_p1 = set(all_p1_funcs.values()).difference(matched_p1)
        unmatched_p2 = set(all_p2_funcs.values()).difference(matched_p2)

        # match umatched funcs by name and param
        for func in unmatched_p1:
            for func2 in unmatched_p2:
                if func.getName(True) == func2.getName(True) and func.parameterCount == func2.parameterCount:
                    matched_p1.add(func)
                    matched_p2.add(func2)
                    matches.setdefault((func.getEntryPoint(), func2.getEntryPoint()),
                                       set()).add('NameParam')

        unmatched_p1 = set(all_p1_funcs.values()).difference(matched_p1)
        unmatched_p2 = set(all_p2_funcs.values()).difference(matched_p2)

        monitor.setMessage(f'Missing {len(unmatched_p1)} funcs in p1{sorted(unmatched_p1, key=lambda x: x.name)}')
        monitor.setMessage(f'Missing {len(unmatched_p2)} funcs in p1{sorted(unmatched_p2, key=lambda x: x.name)}')

        for func in unmatched_p1:
            unmatched.append(func.getSymbol())

        for func in unmatched_p2:
            unmatched.append(func.getSymbol())

        # translate matches to expected format [ sym, sym2, match_type ]
        expected_matches = []
        for match_addrs, match_types in matches.items():
            address = match_addrs[0]
            address2 = match_addrs[1]
            sym = all_p1_funcs[address].getSymbol()
            sym2 = all_p2_funcs[address2].getSymbol()
            expected_matches.append([sym, sym2, match_types])

        skip_types = ['ExternalsName', 'StructuralGraphHash']

        return [deleted_symbols, added_symbols, unmatched, expected_matches, skip_types]


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='A simple Ghidra binary diffing tool')

    parser.add_argument('old', nargs=1, help='Path to older version of binary "/somewhere/bin.old"')
    parser.add_argument('new', action='append', nargs='+',
                        help="Path to new version of binary '/somewhere/bin.new'. For multiple binaries add oldest to newest")
    parser.add_argument('-o', '--output-path', help='Output path for resulting diff', default='.output_diffs')

    GhidraDiffEngine.add_ghidra_args_to_parser(parser)

    args = parser.parse_args()

    print(args)

    output_path = pathlib.Path(args.output_path)
    output_path.mkdir(exist_ok=True)

    binary_paths = args.old + [bin for sublist in args.new for bin in sublist]

    binary_paths = [pathlib.Path(path) for path in binary_paths]

    project_name = f'{args.project_name}-{binary_paths[0].name}-{binary_paths[1].name}'

    d = VersionTrackingDiff(True, MAX_MEM=True, threaded=True)

    d.setup_project(binary_paths, args.project_location, project_name, args.symbols_path)

    d.analyze_project()

    diffs = []

    # pair up binaries with the n-1 version
    for i in range(len(binary_paths)-1):
        diffs.append((binary_paths[i], binary_paths[i+1]))

    # add a diff of the first and last binary for full coverage
    if not binary_paths[1] == binary_paths[-1]:
        diffs.append((binary_paths[0], binary_paths[-1]))

    for diff in diffs:
        pdiff = d.diff_bins(diff[0], diff[1])
        pdiff_json = json.dumps(pdiff)

        print(pdiff['stats'])
        assert d.validate_diff_json(pdiff_json) is True

        diff_name = f"{pathlib.Path(diff[0]).name}_to_{pathlib.Path(diff[1]).name}_diff"
        d.dump_pdiff_to_dir(diff_name, pdiff, args.output_path)
