
from collections import Counter
from time import time
from typing import List, Tuple, TYPE_CHECKING


from jpype import JImplements, JOverride, JClass

from .ghidra_diff_engine import GhidraDiffEngine

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


class AutoVersionTrackingDiff(GhidraDiffEngine):
    """
    An Ghidra Diff implementation that uses the AutoVersiontRacking task to find matches.using several exact and some fuzzy correlators
    See ghidra/tree/master/Ghidra/Features/VersionTracking

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

        from ghidra.feature.vt.api.db import VTSessionDB
        from ghidra.feature.vt.api.main import VTSession
        from ghidra.feature.vt.gui.actions import AutoVersionTrackingTask
        from ghidra.feature.vt.gui.plugin import VTPlugin, VTControllerImpl
        from ghidra.framework.model import DomainFolder
        from ghidra.framework.plugintool import Plugin
        from ghidra.framework.plugintool import PluginTool
        from ghidra.program.model.listing import Program
        from ghidra.util.task import TaskLauncher
        from java.lang import Object
        # from ghidra.test import TestEnv
        from ghidra.framework.project.tool import GhidraTool
        from java.lang import String
        from javax.swing import SwingUtilities

        from .swing_classes import Launch

        SwingUtilities.invokeAndWait(Launch(self.project, 'toolguy', p1, p2))

        from ghidra.util.task import ConsoleTaskMonitor

        def _get_private_class(path: str) -> JClass:
            from java.lang import ClassLoader
            gcl = ClassLoader.getSystemClassLoader()
            return JClass(path, loader=gcl)

        # monitor = ConsoleTaskMonitor()

        # name = 'vt-sess1'

        # session: VTSession = VTSessionDB.createVTSession(name, p1, p2, Object())

        # root = self.project.getRootFolder()

        # root.createFile(name, session, monitor)

        # VTPlugin()

        # env = TestEnv(100, 'test')

        # vtPlugin = env.getPlugin(VTPlugin.getClass())

        # vtPlugin = _get_private_class('ghidra.feature.vt.gui.plugin.VTPlugin')

        # controller = VTControllerImpl(vtPlugin)

        # controller.openVersionTrackingSession(session)

        # tool = state.getTool();
        # vtPlugin = getPlugin(tool, VTPlugin.class);
        # if (vtPlugin == None) {
        # 	tool.addPlugin(VTPlugin.class.getName());
        # 	vtPlugin = getPlugin(tool, VTPlugin.class);
        # }

        # translate matches to expected format [ sym, sym2, match_type ]
        matched = []
        unmatched = []
        # for match_addrs, match_types in matches.items():

        #     func = p1.functionManager.getFunctionContaining(match_addrs[0])
        #     assert func.entryPoint == match_addrs[0]
        #     func2 = p2.functionManager.getFunctionContaining(match_addrs[1])
        #     assert func2.entryPoint == match_addrs[1]

        #     matched.append([func.getSymbol(), func2.getSymbol(), list(match_types.keys())])

        # skip types will undergo less processing
        skip_types = ['BulkBasicBlockMnemonicHash', 'ExternalsName']

        return [unmatched, matched, skip_types]

    # def find_matches(
    #     self,
    #     p1: "ghidra.program.model.listing.Program",
    #     p2: "ghidra.program.model.listing.Program",
    # ) -> list:
    #     """
    #     Find matching and unmatched functions between p1 and p2
    #     """

    #     from ghidra.feature.vt.api.main import VTSession
    #     from ghidra.feature.vt.api.db import VTSessionDB
    #     from ghidra.feature.vt.api.main import VTSession
    #     from ghidra.feature.vt.gui.actions import AutoVersionTrackingTask
    #     from ghidra.feature.vt.gui.plugin import VTPlugin, VTControllerImpl
    #     from ghidra.framework.model import DomainFolder
    #     from ghidra.framework.plugintool import Plugin
    #     from ghidra.framework.plugintool import PluginTool
    #     from ghidra.program.model.listing import Program
    #     from ghidra.util.task import TaskLauncher
    #     from java.lang import Object
    #     # from ghidra.test import TestEnv
    #     from ghidra.framework.project.tool import GhidraTool
    #     from java.lang import String
    #     from javax.swing import SwingUtilities

    #     # tool = GhidraTool(self.project.project, String('toolguy'))
    #     # toolList = tool.getManagedPlugins()

    #     # for t in toolList:
    #     #     print(t)

    #     from ghidra.util.task import ConsoleTaskMonitor

    #     # def _get_private_class(path: str) -> JClass:
    #     #     from java.lang import ClassLoader
    #     #     gcl = ClassLoader.getSystemClassLoader()
    #     #     return JClass(path, loader=gcl)

    #     monitor = ConsoleTaskMonitor()

    #     for domainFile in self.project.getRootFolder().getFiles():
    #         if domainFile.getContentType() == 'VersionTracking':
    #             session_df = domainFile

    #     df: "ghidra.framework.model.DomainFile" = session_df

    #     vtSession: VTSessionDB = df.getDomainObject(Object(), True, True, monitor)

    #     matches = vtSession.getMatchSets()

    #     for match in matches:
    #         print(match)

    #     # translate matches to expected format [ sym, sym2, match_type ]
    #     matched = []
    #     unmatched = []
    #     # for match_addrs, match_types in matches.items():

    #     #     func = p1.functionManager.getFunctionContaining(match_addrs[0])
    #     #     assert func.entryPoint == match_addrs[0]
    #     #     func2 = p2.functionManager.getFunctionContaining(match_addrs[1])
    #     #     assert func2.entryPoint == match_addrs[1]

    #     #     matched.append([func.getSymbol(), func2.getSymbol(), list(match_types.keys())])

    #     # skip types will undergo less processing
    #     skip_types = ['BulkBasicBlockMnemonicHash', 'ExternalsName']

    #     return [unmatched, matched, skip_types]
