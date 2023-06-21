from typing import List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *

# Python version of Ghidra/Features/VersionTracking/src/main/java/ghidra/feature/vt/gui/util/ImpliedMatchUtils.java


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
