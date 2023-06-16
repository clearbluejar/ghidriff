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
        # DO NOT CHANGE ORDER UNLESS INTENDED, ORDER HAS MAJOR IMPACT ON EFFICIENCY
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
            self.logger.info(f'name: {name} hasher: {hasher} one_to_one: {one_to_one} one_to_many: {one_to_many}')

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

        # Create Implied Matches
        from ghidra.feature.vt.api.db import VTSessionDB
        from ghidra.feature.vt.api.main import VTSession
        from ghidra.feature.vt.api.main import VTMatchInfo, VTAssociationType
        from java.lang import Object

        def _create_match_info(src_addr, dst_addr, src_len, dst_len, vt_score) -> VTMatchInfo:
            info: VTMatchInfo = VTMatchInfo(None)
            info.setSourceAddress(src_addr)
            info.setDestinationAddress(dst_addr)
            info.setDestinationLength(dst_len)
            info.setSourceLength(src_len)
            info.setSimilarityScore(vt_score)
            info.setConfidenceScore(vt_score)
            info.setAssociationType(VTAssociationType.FUNCTION)

            return info

        session: VTSession = VTSessionDB.createVTSession(name, p1, p2, Object())
        my_cor = MyManualMatchProgramCorrelator(p1, p2)
        transact = session.startTransaction('test')
        match_set = session.createMatchSet(my_cor)
        for match, m_types in matches.items():
            if "SymbolsHash" in m_types:
                vt_match = _create_match_info(match[0], match[1], 10, 23, MyManualMatchProgramCorrelator.MANUAL_SCORE)
                match_set.addMatch(vt_match)
        for match in match_set.getMatches():
            print(match)
            match.association.setAccepted()
        session.endTransaction(int(transact), True)

        from ghidra.feature.vt.api.correlator.program import ImpliedMatchProgramCorrelator

        transact = session.startTransaction('implied')
        implied_match_set = session.createMatchSet(ImpliedMatchProgramCorrelator(p1, p2))

        for match in implied_match_set.getMatches():
            print(match)
            match.association.setAccepted()
        session.endTransaction(int(transact), True)

        # Print all match sets from session
        match_sets = session.getMatchSets()
        for match_set in match_sets:
            print(match_set)

        def get_actual_reference(program:  "ghidra.program.model.listing.Program", ref_to_addr):

            ref_func = program.getFunctionManager().getFunctionAt(ref_to_addr)
            if ref_func is not None and ref_func.isThunk():
                print('Resolving thunked func addr')
                ref_to_addr = ref_func.getThunkedFunction(True).getEntryPoint()

            return ref_to_addr

        def find_matching_ref(ref_type, refs_from):

            if refs_from is None:
                return None

            for ref in refs_from:
                if ref.getReferenceType() == ref_type:
                    return ref

            return None

        def find_implied_match(src_func: "ghidra.program.model.listing.Function", dst_func: "ghidra.program.model.listing.Function", ref: "ghidra.program.model.symbol.Reference"):

            # // Get the reference type of the passed in reference and make sure it is either a call or
            # // data reference
            ref_type = ref.getReferenceType()
            if not (ref_type.isCall() or ref_type.isData()):
                print(f'skipped: reftype is {ref_type}')
                return None

            # // Get the source reference's "to" address (the address the reference is pointing to)
            # // and make sure it is in the current program memory space

            src_ref_to_addr = ref.getToAddress()
            if not src_ref_to_addr.isMemoryAddress():
                print(f'skipped: src_ref_to_addr {src_ref_to_addr} is not Memory address!')
                return None

            src_ref_to_addr = get_actual_reference(src_func.getProgram(), src_ref_to_addr)

            src_ref_from_addr = ref.getFromAddress()

            from ghidra.feature.vt.api.correlator.address import VTHashedFunctionAddressCorrelation
            from ghidra.util.task import ConsoleTaskMonitor
            from ghidra.program.model.symbol import RefType

            monitor = ConsoleTaskMonitor()

            cor = VTHashedFunctionAddressCorrelation(src_func, dst_func)

            addr_range = cor.getCorrelatedDestinationRange(src_ref_from_addr, monitor)
            if addr_range is None:
                return None

            dest_addr = addr_range.getMinAddress()
            dest_ref_man = dst_func.getProgram().getReferenceManager()
            refs_from = dest_ref_man.getReferencesFrom(dest_addr)
            dest_ref = find_matching_ref(ref_type, refs_from)

            if dest_ref is None:
                return None

            dest_ref_to_addr = dest_ref.getToAddress()
            dest_ref_to_addr = get_actual_reference(dst_func.getProgram(), dest_ref_to_addr)

            actual_type = None
            if ref_type.isData():
                actual_type = 'DATA'
                if src_func.getProgram().getListing().getInstructionAt(src_ref_to_addr) is not None:
                    if ref_type != RefType.DATA:
                        return None
                    actual_type = 'FUNCTION'
            else:
                actual_type = 'FUNCTION'

            if actual_type == 'FUNCTION':
                if src_func.getProgram().getFunctionManager().getFunctionAt(src_ref_to_addr) is None:
                    return None

            return (src_ref_to_addr, dest_ref_to_addr, actual_type)

        def find_implied_matches(src_func: "ghidra.program.model.listing.Function", dst_func: "ghidra.program.model.listing.Function"):
            """
            Find implied matches for already accepted functions
            # Ghidra/Features/VersionTracking/src/main/java/ghidra/feature/vt/gui/util/ImpliedMatchUtils.java
            """
            implied_matches = {}
            ref_man = src_func.getProgram().getReferenceManager()
            body = src_func.getBody()
            for addr in ref_man.getReferenceSourceIterator(body, True):
                refs_from = ref_man.getReferencesFrom(addr)
                for ref in refs_from:
                    implied_match = find_implied_match(src_func, dst_func, ref)
                    if implied_match is not None:
                        print(implied_match)

        # find implied matches
        implied_matches = {}
        for match, m_types in matches.items():
            if "SymbolsHash" in m_types:
                func = p1.functionManager.getFunctionAt(match[0])
                func2 = p2.functionManager.getFunctionAt(match[1])
                implied_match = find_implied_matches(func, func2)
                if implied_match is not None:
                    print(implied_match)
                # vt_match = _create_match_info(match[0], match[1], 10, 23, MyManualMatchProgramCorrelator.MANUAL_SCORE)

        # Find unmatched functions

        # https://github.com/NationalSecurityAgency/ghidra/blob/2a97771c0fd2f0d41f836e4d1ce8092cec3c7b63/Ghidra/Features/VersionTracking/src/main/java/ghidra/feature/vt/gui/util/ImpliedMatchUtils.java#L39

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

        # Find Implied Matches
        # TODO

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
