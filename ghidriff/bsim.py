# https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/VersionTrackingBSim/src/main/java/ghidra/feature/vt/api/BSimProgramCorrelator.java


# this should be called after several reliable correlators have taken place
# auto tracking lets you run autoversiontracking first (which runs all 8 correlators)
# then it runs BSIM

def correlate_bsim(matches, p1, p2, monitor, logger=None):

    logger.info("Starting BSIM correlator")

    # create fake session and match set for bsim "accepted matches" seed

    # https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/VersionTracking/src/test/java/ghidra/feature/vt/api/AbstractCorrelatorTest.java#L79

    # instantiate bsim and find matches

        # factory https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/VersionTrackingBSim/src/main/java/ghidra/feature/vt/api/BSimProgramCorrelatorFactory.java#L62

    # updated matches with BSIM findings

    pass