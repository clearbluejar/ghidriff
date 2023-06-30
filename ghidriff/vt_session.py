# Create Implied Matches
# from ghidra.feature.vt.api.db import VTSessionDB
# from ghidra.feature.vt.api.main import VTSession
# from ghidra.feature.vt.api.main import VTMatchInfo, VTAssociationType
# from java.lang import Object

# def _create_match_info(src_addr, dst_addr, src_len, dst_len, vt_score) -> VTMatchInfo:
#     info: VTMatchInfo = VTMatchInfo(None)
#     info.setSourceAddress(src_addr)
#     info.setDestinationAddress(dst_addr)
#     info.setDestinationLength(dst_len)
#     info.setSourceLength(src_len)
#     info.setSimilarityScore(vt_score)
#     info.setConfidenceScore(vt_score)
#     info.setAssociationType(VTAssociationType.FUNCTION)

#     return info

# session: VTSession = VTSessionDB.createVTSession(name, p1, p2, Object())
# my_cor = MyManualMatchProgramCorrelator(p1, p2)
# transact = session.startTransaction('test')
# match_set = session.createMatchSet(my_cor)
# for match, m_types in matches.items():
#     if "SymbolsHash" in m_types:
#         vt_match = _create_match_info(match[0], match[1], 10, 23, MyManualMatchProgramCorrelator.MANUAL_SCORE)
#         match_set.addMatch(vt_match)
# for match in match_set.getMatches():
#     print(match)
#     match.association.setAccepted()
# session.endTransaction(int(transact), True)

# from ghidra.feature.vt.api.correlator.program import ImpliedMatchProgramCorrelator

# transact = session.startTransaction('implied')
# implied_match_set = session.createMatchSet(ImpliedMatchProgramCorrelator(p1, p2))

# for match in implied_match_set.getMatches():
#     print(match)
#     match.association.setAccepted()
# session.endTransaction(int(transact), True)

# # Print all match sets from session
# match_sets = session.getMatchSets()
# for match_set in match_sets:
#     print(match_set)

# find implied matches
# implied_matches = {}
# for match, m_types in matches.items():
#     func = p1.functionManager.getFunctionAt(match[0])
#     func2 = p2.functionManager.getFunctionAt(match[1])
#     implied_match = find_implied_matches(func, func2)
#     if implied_match is not None:
#         print(implied_match)
# vt_match = _create_match_info(match[0], match[1], 10, 23, MyManualMatchProgramCorrelator.MANUAL_SCORE)

# src_matched_addrs = []
# for func in potential_calling_funcs:
