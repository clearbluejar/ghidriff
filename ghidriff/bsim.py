# Ghidra/Features/VersionTrackingBSim/src/main/java/ghidra/feature/vt/api/BSimProgramCorrelator.java

# this should be called after several reliable correlators have taken place
# we need reliable matches to seed BSIM
# auto tracking lets you run autoversiontracking first (which runs all 8 correlators)
# then it runs BSIM

def correlate_bsim(matches, p1, p2, p1_matches, p2_matches, monitor, logger=None, seed_match_types=['SymbolsHash', ]):
    """
    matches: previously matched functions
    p1:  
    """

    from ghidra.feature.vt.api.main import VTMatchInfo, VTAssociationType, VTSession, VTScore
    from ghidra.feature.vt.api import BSimProgramCorrelatorFactory, BSimProgramCorrelator
    from ghidra.feature.vt.api.correlator.program import SymbolNameProgramCorrelatorFactory
    from ghidra.feature.vt.api.db import VTSessionDB

    # see Ghidra/Features/VersionTracking/src/main/java/ghidra/feature/vt/gui/task/CreateManualMatchTask.java#L62 
    def _create_match_info(match, match_set, p1, p2) -> VTMatchInfo:
        info: VTMatchInfo = VTMatchInfo(match_set)

        func1 = p1.getFunctionManager().getFunctionAt(match[0])
        func2 = p2.getFunctionManager().getFunctionAt(match[1])

        info.setSourceAddress(func1.getEntryPoint())
        info.setDestinationAddress(func2.getEntryPoint())
        info.setSourceLength(int(func1.getBody().getNumAddresses()))
        info.setDestinationLength(int(func2.getBody().getNumAddresses()))
        info.setSimilarityScore(VTScore(1.0))
        info.setConfidenceScore(VTScore(1.0))
        info.setAssociationType(VTAssociationType.FUNCTION)

        return info
        

    logger.info("Starting BSIM correlator")

    # create a VT session and match set for bsim "accepted matches" seed

    from java.lang import Object
    
    bsim_factory = BSimProgramCorrelatorFactory()
    options = bsim_factory.createDefaultOptions()
    session: VTSession = VTSessionDB.createVTSession(bsim_factory.name, p1, p2, Object())

    # symbol_factory = SymbolNameProgramCorrelatorFactory()
    # options = symbol_factory.createDefaultOptions()
    # symbol_correlator = symbol_factory.createCorrelator(p1,p1_addr_set,p2,p2_addr_set, options)
    
    # create match set of already accepted matches using fake correlator
    transaction = session.startTransaction('seed')
    #match_set = session.createMatchSet(symbol_correlator)
    match_set = session.getManualMatchSet()

    for match, m_types in matches.items():
        # if the match type is in the allowed seed_types create a seed match
        if any(m_type in seed_match_types for m_type in m_types):
            vt_match_info = _create_match_info(match,match_set, p1, p2)
            match_set.addMatch(vt_match_info)
    

    ## BSIM will seed using accepted matches Ghidra/Features/VersionTrackingBSim/src/main/java/ghidra/feature/vt/api/BSimProgramCorrelatorMatching.java#L558-L595
    for match in match_set.getMatches():        
        match.association.setAccepted()
    
    session.endTransaction(int(transaction), True)

    # instantiate bsim and find matches

    transaction = session.startTransaction(bsim_factory.name);

    p1_addr_set = p1.memory.loadedAndInitializedAddressSet
    p2_addr_set = p2.memory.loadedAndInitializedAddressSet

    bsim_correlator: BSimProgramCorrelator = bsim_factory.createCorrelator(p1,p1_addr_set,p2,p2_addr_set, options)
    bsim_correlator.correlate(session,monitor)
    session.endTransaction(int(transaction), True)

    # Print all match sets from session
    match_sets = session.getMatchSets()
    for match_set in match_sets:
        logger.info(f'{match_set}')


        # updated ghidriff matches with BSIM findings
        if match_set.getProgramCorrelatorName() == bsim_factory.name:

            for bsim_match in match_set.getMatches():
                # Correlate function as Implied Match
                name = 'BSIM'
                matches.setdefault((bsim_match.sourceAddress, bsim_match.destinationAddress), {}).setdefault(name, 0)
                matches[(bsim_match.sourceAddress, bsim_match.destinationAddress)][name] += 1
                p1_matches.add(bsim_match.sourceAddress)
                p2_matches.add(bsim_match.destinationAddress)    