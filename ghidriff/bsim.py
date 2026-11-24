# Ghidra/Features/VersionTrackingBSim/src/main/java/ghidra/feature/vt/api/BSimProgramCorrelator.java

# BSIM runs after the exact correlators, on the functions they left unmatched (all functions with --bsim-full).
# It decompiles them into feature vectors, pairs every two functions whose vectors are similar (the
# potential-match graph), picks seeds from that graph and grows matches outward through the call graph.
#
# The graph is what exhausts time and heap on large binaries. Thousands of small functions (tail-call stubs,
# outlined helpers) decompile to the same vector, so BSIM pairs each with every other: 105 million candidate
# pairs for Mail.framework, 603 million for Maps.app. External functions all share one vector too. The bounded
# path below drives Ghidra's own stages and counts the graph first, from one function per distinct vector. Under
# max_pairs BSIM runs exactly as Ghidra's correlator would; over it, the vectors that make the most pairs are
# left out until the rest fits.

import heapq
import threading
from collections import Counter, defaultdict
from time import time

from .utils import get_private_class, set_field, get_field, get_method


def count_external_functions(program) -> int:
    count = 0
    iterator = program.getFunctionManager().getExternalFunctions()
    while iterator.hasNext():
        iterator.next()
        count += 1
    return count


def drop_vectors_over_budget(pair_counts: dict, max_pairs: int) -> tuple:
    """
    pair_counts: {(old vector, new vector): candidate pairs BSIM builds between the functions with them}
    Leave out the vectors that account for the most candidate pairs until the rest fit in max_pairs. A vector
    left out is left out of both programs.
    Returns (vectors left out, candidate pairs kept)
    """

    total = sum(pair_counts.values())
    if not max_pairs or total <= max_pairs:
        return set(), total

    contribution = Counter()
    by_vector = defaultdict(list)
    for key, count in pair_counts.items():
        for vector in set(key):
            contribution[vector] += count
            by_vector[vector].append(key)

    # contributions only fall as vectors are left out, so a stale heap entry is pushed back with its current value
    heap = [(-count, vector) for vector, count in contribution.items()]
    heapq.heapify(heap)
    dropped = set()
    removed = set()
    while total > max_pairs and heap:
        count, vector = heapq.heappop(heap)
        if -count != contribution[vector]:
            heapq.heappush(heap, (-contribution[vector], vector))
            continue
        dropped.add(vector)
        for key in by_vector[vector]:
            if key in removed:
                continue
            removed.add(key)
            total -= pair_counts[key]
            for other in set(key) - {vector}:
                contribution[other] -= pair_counts[key]

    return dropped, total


def _is_cancelled(exc) -> bool:
    from ghidra.util.exception import CancelledException
    from java.lang import InterruptedException

    while exc is not None:
        if isinstance(exc, (CancelledException, InterruptedException)):
            return True
        exc = exc.getCause() if hasattr(exc, 'getCause') else None
    return False


def _vector_id(node):
    vector = node.getVector()
    return None if vector is None else int(vector.calcUniqueHash())


def _correlate_bounded(p1, p1_addr_set, p2, p2_addr_set, monitor, logger, max_pairs, report, seeds=None):
    """
    BSimProgramCorrelator.doCorrelate, stage by stage, with the candidate pairs counted and bounded before
    BSIM builds them. Returns [(source address, destination address)], or None when this Ghidra's correlator
    does not have the internals used here.
    seeds: [(source address, destination address)] of accepted matches, used as BSIM seeds where both functions
    are BSIM nodes (Ghidra's findAcceptedSeeds); BSIM then chooses more. None: BSIM chooses them all.
    """

    import jpype
    from ghidra.feature.vt.api import (BSimProgramCorrelator, BSimProgramCorrelatorFactory,
                                       BSimProgramCorrelatorMatching, FunctionNode, FunctionNodeContainer)
    from ghidra.features.bsim.query import GenSignatures
    from ghidra.util.xml import SpecXmlUtils
    from ghidra.xml import NonThreadedXmlPullParserImpl
    from java.util import ArrayList

    factory = BSimProgramCorrelatorFactory()
    options = factory.createDefaultOptions()
    correlator = factory.createCorrelator(p1, p1_addr_set, p2, p2_addr_set, options)
    try:
        vector_factory = get_field(correlator, 'vectorFactory')
        generate_nodes = get_method(correlator, 'generateNodes')
        matching_class = BSimProgramCorrelatorMatching.class_
        matching_class.getDeclaredField('seeds')
        next(m for m in matching_class.getDeclaredMethods() if m.getName() == 'chooseSeeds')
    except (jpype.JException, StopIteration) as err:
        logger.warning(f'BSIM bounds unavailable in this Ghidra ({err}); running BSIM unbounded')
        return None

    weights = GenSignatures.getWeightsFile(p1.getLanguageID(), p2.getLanguageID())
    if weights is None:
        logger.warning(f'Skipping BSIM correlator. No BSim weights to compare {p1.getLanguageID()} with {p2.getLanguageID()}')
        report['status'] = 'skipped'
        report['reason'] = 'architectures'
        return []
    # constant pool languages (Dalvik, JVM) have reliable namespaces and no absolute calls
    cpool = 'cpool' in weights.getName()
    stream = weights.getInputStream()
    try:
        vector_factory.readWeights(NonThreadedXmlPullParserImpl(
            stream, 'Vector weights parser', SpecXmlUtils.getXmlHandler(), False))
    finally:
        stream.close()

    model = options.getEnum(BSimProgramCorrelatorFactory.MEMORY_MODEL, BSimProgramCorrelatorFactory.MEMORY_MODEL_DEFAULT)
    conf = options.getDouble(BSimProgramCorrelatorFactory.SEED_CONF_THRESHOLD,
                             BSimProgramCorrelatorFactory.SEED_CONF_THRESHOLD_DEFAULT)
    imp = options.getDouble(BSimProgramCorrelatorFactory.IMPLICATION_THRESHOLD,
                            BSimProgramCorrelatorFactory.IMPLICATION_THRESHOLD_DEFAULT)

    def matching(src_container, dst_container):
        return BSimProgramCorrelatorMatching(src_container, dst_container, vector_factory, conf, imp,
                                             BSimProgramCorrelator.SIMILARITY_THRESHOLD, cpool, model)

    phase = time()
    nodes = [list(generate_nodes.invoke(correlator, program, addr_set, jpype.JBoolean(cpool), monitor))
             for program, addr_set in ((p1, p1_addr_set), (p2, p2_addr_set))]
    report['nodes'] = [len(nodes[0]), len(nodes[1])]
    report['phase_seconds'] = {'vectors': round(time() - phase, 1)}
    logger.info(f'BSIM: {len(nodes[0])} + {len(nodes[1])} functions decompiled to feature vectors in {time() - phase:.0f}s')

    # count the potential-match graph from one node per distinct vector: identical vectors are candidates
    # for the same nodes, so their pairs multiply
    phase = time()
    groups = (defaultdict(list), defaultdict(list))
    for side in (0, 1):
        for node in nodes[side]:
            vector = _vector_id(node)
            if vector is not None:
                groups[side][vector].append(node)

    def copy(program, node):
        # discovery consumes a node's call list, so the count runs on copies
        func = program.getFunctionManager().getFunctionAt(node.getAddress())
        return FunctionNode(func, node.getVector(), ArrayList())

    reps = ([copy(p1, group[0]) for group in groups[0].values()],
            [copy(p2, group[0]) for group in groups[1].values()])
    probe = matching(FunctionNodeContainer(p1, ArrayList(reps[0])), FunctionNodeContainer(p2, ArrayList(reps[1])))
    probe.discoverPotentialMatches(monitor)
    pair_counts = Counter()
    for rep in reps[0]:
        src_vector = _vector_id(rep)
        associates = rep.getAssociateIterator()
        while associates.hasNext():
            dst_vector = _vector_id(associates.next().getKey())
            pair_counts[(src_vector, dst_vector)] += len(groups[0][src_vector]) * len(groups[1][dst_vector])
    del probe, reps

    dropped, kept = drop_vectors_over_budget(pair_counts, max_pairs)
    total = sum(pair_counts.values())
    report['candidate_pairs'] = total
    report['phase_seconds']['count'] = round(time() - phase, 1)
    if dropped:
        left_out = [sum(len(groups[side].get(vector, [])) for vector in dropped) for side in (0, 1)]
        largest = sorted(([len(groups[0].get(v, [])), len(groups[1].get(v, []))] for v in dropped), key=sum, reverse=True)
        nodes = [[node for node in nodes[side] if _vector_id(node) not in dropped] for side in (0, 1)]
        report['status'] = 'cut'
        report['candidate_pairs_kept'] = kept
        report['left_out_functions'] = left_out
        report['left_out_vectors'] = len(dropped)
        report['largest_left_out'] = largest[:5]
        logger.warning(f'BSIM: {total:,} candidate pairs exceed --bsim-max-pairs {max_pairs:,}. Leaving out {left_out[0]} + '
                       f'{left_out[1]} functions that share {len(dropped)} feature vectors (largest {largest[0][0]} x '
                       f'{largest[0][1]} functions); {kept:,} pairs remain')
    else:
        logger.info(f'BSIM: {total:,} candidate pairs')

    src_container = FunctionNodeContainer(p1, ArrayList(nodes[0]))
    dst_container = FunctionNodeContainer(p2, ArrayList(nodes[1]))
    omni = matching(src_container, dst_container)
    phase = time()
    omni.discoverPotentialMatches(monitor)
    report['phase_seconds']['discover'] = round(time() - phase, 1)

    phase = time()
    if seeds is None:
        if not omni.generateSeeds(None, False, monitor):
            logger.info('BSIM: no seeds')
    else:
        # generateSeeds(matchSet, true) without a Version Tracking session: the accepted matches whose functions
        # are both BSIM nodes and BSIM candidates, then BSIM's own choice
        accepted = jpype.JClass('java.util.HashSet')()
        for src, dst in seeds:
            src_node, dst_node = src_container.get(src), dst_container.get(dst)
            if src_node is not None and dst_node is not None:
                edge = src_node.findEdge(dst_node)
                if edge is not None:
                    accepted.add(edge)
        field = omni.getClass().getDeclaredField('seeds')
        field.setAccessible(True)
        field.set(omni, accepted)
        report['accepted_seeds'] = int(accepted.size())
        get_method(omni, 'chooseSeeds').invoke(omni, monitor)
        report['seeds'] = int(get_field(omni, 'seeds').size())
        logger.info(f"BSIM: {report['accepted_seeds']} accepted seeds, {report['seeds']} seeds in all")
    report['phase_seconds']['seeds'] = round(time() - phase, 1)

    phase = time()
    try:
        result = omni.doMatching(monitor)
    except jpype.JException as err:
        if not _is_cancelled(err):
            raise
        # matches are accepted best first and never withdrawn: those accepted so far stand
        result = get_field(omni, 'matches')
        report['status'] = 'timeout'
        report['partial'] = True
    report['phase_seconds']['matching'] = round(time() - phase, 1)

    return [(pair.getSourceNode().getAddress(), pair.getDestNode().getAddress()) for pair in result]


def _correlate_stock(p1, p1_addr_set, p2, p2_addr_set, monitor, logger, max_external_pairs, report, seeds=None):
    """
    Ghidra's BSimProgramCorrelator as is, seeded with seeds [(source address, destination address)] accepted in
    its Version Tracking session. Returns [(source address, destination address)]
    """

    # BSimProgramCorrelator adds every external function as a node (ignoring the address sets) with one shared
    # feature vector, so each source external pairs with each destination external. Binaries with tens of
    # thousands of imports (dylibs extracted from a dyld shared cache) exhaust any heap (ghidriff #155).
    if max_external_pairs:
        p1_externals = count_external_functions(p1)
        p2_externals = count_external_functions(p2)
        if p1_externals * p2_externals > max_external_pairs:
            logger.warning(f"Skipping BSIM correlator. {p1_externals} x {p2_externals} external functions would create "
                           f"{p1_externals * p2_externals} candidate pairs (limit {max_external_pairs}, see --bsim-max-external-pairs)")
            report['status'] = 'skipped'
            report['reason'] = 'externals'
            return []

    import jpype
    from ghidra.feature.vt.api import BSimProgramCorrelatorFactory
    from ghidra.feature.vt.api.db import VTSessionDB
    from ghidra.util import SystemUtilities
    from java.lang import Object

    bsim_factory = BSimProgramCorrelatorFactory()
    options = bsim_factory.createDefaultOptions()
    session_ref = Object()

    # Start fix Ghidra 11.1 for ghidriff #95
    reset_mode = False

    if not SystemUtilities.isInTestingMode():
        su = get_private_class('ghidra.util.SystemUtilities')
        set_field(su, "isInTestingMode", True)
        reset_mode = True

    session = VTSessionDB.createVTSession(bsim_factory.name, p1, p2, session_ref)

    if reset_mode:
        set_field(su, "isInTestingMode", False)
        assert SystemUtilities.isInTestingMode() == False
    # end fix for #95

    try:
        if seeds:
            from ghidra.feature.vt.api.main import VTAssociationType, VTMatchInfo, VTScore

            # see Ghidra/Features/VersionTracking/src/main/java/ghidra/feature/vt/gui/task/CreateManualMatchTask.java
            transaction = session.startTransaction('seed')
            match_set = session.getManualMatchSet()
            for src, dst in seeds:
                func1 = p1.getFunctionManager().getFunctionAt(src)
                func2 = p2.getFunctionManager().getFunctionAt(dst)
                info = VTMatchInfo(match_set)
                info.setSourceAddress(func1.getEntryPoint())
                info.setDestinationAddress(func2.getEntryPoint())
                info.setSourceLength(int(func1.getBody().getNumAddresses()))
                info.setDestinationLength(int(func2.getBody().getNumAddresses()))
                info.setSimilarityScore(VTScore(1.0))
                info.setConfidenceScore(VTScore(1.0))
                info.setAssociationType(VTAssociationType.FUNCTION)
                match_set.addMatch(info)
            # BSIM seeds itself with the accepted function matches (BSimProgramCorrelatorMatching.findAcceptedSeeds)
            accepted = 0
            for match in match_set.getMatches():
                try:
                    match.getAssociation().setAccepted()
                    accepted += 1
                except jpype.JException:
                    pass  # conflicts with an association already accepted
            session.endTransaction(int(transaction), True)
            report['accepted_seeds'] = accepted

        transaction = session.startTransaction(bsim_factory.name)
        bsim_correlator = bsim_factory.createCorrelator(p1, p1_addr_set, p2, p2_addr_set, options)
        bsim_correlator.correlate(session, monitor)
        session.endTransaction(int(transaction), True)

        found = []
        for match_set in session.getMatchSets():
            if match_set.getProgramCorrelatorName() == bsim_factory.name:
                logger.info(f'{match_set}')
                for bsim_match in match_set.getMatches():
                    found.append((bsim_match.sourceAddress, bsim_match.destinationAddress))
        return found
    finally:
        session.release(session_ref)


# matches BSIM accepts as seeds
SEED_MATCH_TYPES = ('SymbolsHash', 'ExactBytesFunctionHasher', 'ExactInstructionsFunctionHasher',
                    'StructuralGraphExactHash', 'ExactMnemonicsFunctionHasher')


def correlate_bsim(matches, p1, p2, p1_matches, p2_matches, monitor, logger=None, p1_addr_set=None, p2_addr_set=None,
                   enabled=True, max_external_pairs=0, max_pairs=0, timeout=0, accept_seeds=True) -> dict:
    """
    Match functions with BSim and add them to matches as 'BSIM'.
    max_external_pairs: only when max_pairs is unavailable (Ghidra internals changed), skip BSIM when
        externals(p1) x externals(p2) exceeds this (0 = no limit)
    max_pairs: bound on BSIM's candidate pairs (its potential-match graph, ~140 bytes of heap each). The functions
        whose feature vectors make the most pairs (externals share one) are left out of BSIM until the rest fit.
        0 = no limit
    timeout: seconds before BSIM is cancelled; the matches it has accepted by then are kept. 0 = no limit
    accept_seeds: seed BSIM with the SEED_MATCH_TYPES matches (only the externals among them are BSIM nodes,
        unless --bsim-full). ghidriff 0.6 to 1.0 never accepted them: the accept loop ran over the wrong match set.
    Returns a report of what BSIM did, kept in the diff's stats.
    """

    report = {'status': 'ran'}

    if not enabled:
        logger.info(f"Skipping BSIM correlator. BSIM disabled with arg --no-bsim")
        report['status'] = 'disabled'
        return report

    from ghidra.feature.vt import api as vtapi

    if not hasattr(vtapi, 'BSimProgramCorrelatorFactory'):
        logger.info(f"Skipping BSIM correlator. BSIM not present in this version of Ghidra")
        report['status'] = 'unavailable'
        return report

    import jpype
    from ghidra.util.task import TaskMonitorAdapter

    logger.info("Starting BSIM correlator")

    # if not AddrSetView is defined, use the entire loaded mem
    if p1_addr_set is None:
        p1_addr_set = p1.memory.loadedAndInitializedAddressSet
    if p2_addr_set is None:
        p2_addr_set = p2.memory.loadedAndInitializedAddressSet

    # quiet and cancellable: BSIM checks it often, so cancelling it from a timer bounds BSIM's time
    bsim_monitor = TaskMonitorAdapter(True)
    timer = None
    if timeout:
        timer = threading.Timer(timeout, bsim_monitor.cancel)
        timer.daemon = True
        timer.start()

    start = time()
    found = []
    seeds = [match for match, types in matches.items() if any(t in SEED_MATCH_TYPES for t in types)] \
        if accept_seeds else None
    try:
        found = _correlate_bounded(p1, p1_addr_set, p2, p2_addr_set, bsim_monitor, logger, max_pairs, report, seeds)
        if found is None:
            report['unbounded'] = True
            found = _correlate_stock(p1, p1_addr_set, p2, p2_addr_set, bsim_monitor, logger, max_external_pairs, report,
                                     seeds)
    except jpype.JException as err:
        if not _is_cancelled(err):
            raise
        found = []
        report['status'] = 'timeout'
    finally:
        if timer is not None:
            timer.cancel()

    # BSIM returns its accepted seeds among its matches; they are matched already
    if seeds:
        seed_pairs = set(seeds)
        found = [pair for pair in found if pair not in seed_pairs]

    if report['status'] == 'timeout':
        logger.warning(f'BSIM correlator stopped at --bsim-timeout {timeout}s with {len(found)} matches')

    for src, dst in found:
        name = 'BSIM'
        matches.setdefault((src, dst), {}).setdefault(name, 0)
        matches[(src, dst)][name] += 1
        p1_matches.add(src)
        p2_matches.add(dst)

    report['matches'] = len(found)
    report['seconds'] = round(time() - start, 1)
    logger.info(f'BSIM: {len(found)} matches')
    return report
