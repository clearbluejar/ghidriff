import concurrent.futures
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *

# Python port of Ghidra/Features/VersionTracking/src/main/java/ghidra/feature/vt/gui/util/ImpliedMatchUtils.java


def get_actual_reference(program: "ghidra.program.model.listing.Program", ref_to_addr):

    ref_func = program.getFunctionManager().getFunctionAt(ref_to_addr)
    if ref_func is not None and ref_func.isThunk():
        # print('Resolving thunked func addr')
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

    # original
    # if not (ref_type.isCall() or ref_type.isData()):
    if not (ref_type.isCall()):  # ignore data
        # print(f'skipped: reftype is {ref_type}')
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
    implied_matches = []

    ref_man = src_func.getProgram().getReferenceManager()
    body = src_func.getBody()
    for addr in ref_man.getReferenceSourceIterator(body, True):
        refs_from = ref_man.getReferencesFrom(addr)
        for ref in refs_from:
            implied_match = find_implied_match(src_func, dst_func, ref)
            if implied_match is not None:
                # print(implied_match)
                implied_matches.append(implied_match)

    return list(set(implied_matches))


def correlate_implied_matches(matches, p1_missing, p2_missing, p1_matches, p2_matches, p1, p2, max_workers, monitor, logger=None):
    """
    from all of the unmatched functions, get every function that has already been acceped that calls an unmatched function
    if the calling function has been accepted, then accept the unmatched called function
    """

    # build list of function entry points that have already been matched
    matched_src_addrs = {}
    matched_dst_addrs = {}
    for i, match in enumerate(matches):
        matched_src_addrs[match[0]] = i
        matched_dst_addrs[match[1]] = i

    potential_calling_funcs = []
    src_missing_addrs = []
    dst_missing_addrs = []

    for src_func in p1_missing:
        src_func: "ghidra.program.model.listing.Function" = src_func
        src_missing_addrs.append(src_func.getEntryPoint())
        potential_p1_calling_funcs = [func for func in list(src_func.getCallingFunctions(
            monitor)) if func.getEntryPoint() in matched_src_addrs.keys()]
        if logger is not None:
            logger.debug(
                f'Found {len(potential_p1_calling_funcs)} p1 calling functions for potential implied match for {src_func}')
        potential_calling_funcs.extend(potential_p1_calling_funcs)

    for dst_func in p2_missing:
        dst_func: "ghidra.program.model.listing.Function" = dst_func
        dst_missing_addrs.append(dst_func.getEntryPoint())
        potential_p2_calling_funcs = [func for func in list(
            dst_func.getCallingFunctions(monitor)) if func.getEntryPoint() in matched_dst_addrs.keys()]
        if logger is not None:
            logger.debug(
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

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = (executor.submit(find_implied_matches, f1, f2)
                   for f1, f2 in potential_accepted_matches)

        for future in concurrent.futures.as_completed(futures):
            implied_matches = future.result()

            completed += 1
            if completed % 50 == 0:
                percent = int((float(completed)/len(potential_accepted_matches)) * 100)
                if logger is not None:
                    logger.debug(f'Completed {percent} %  recovered" {recovered}')

            if implied_matches is not None:
                for implied_match in implied_matches:
                    # only apply function matches
                    if implied_match[2] == 'FUNCTION':
                        # ensure implied match is correlating an unmatched function
                        if implied_match[0] in src_missing_addrs or implied_match[1] in dst_missing_addrs:
                            if matches.get((implied_match[0], implied_match[1])) is None:
                                recovered += 1

                            # Correlate function as Implied Match
                            name = 'Implied Match'
                            matches.setdefault((implied_match[0], implied_match[1]), {}).setdefault(name, 0)
                            matches[(implied_match[0], implied_match[1])][name] += 1
                            p1_matches.add(implied_match[0])
                            p2_matches.add(implied_match[1])
