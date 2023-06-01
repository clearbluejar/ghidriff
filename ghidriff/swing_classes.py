from typing import List, Tuple, TYPE_CHECKING
import time
if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *

from javax.swing import *
import javax
import java

from jpype import JImplements, JOverride, JClass

# @JImplements(Runnable, deferred=True)
# class MyGhidraTool:

#     def __init__(self, project, name) -> None:
#         self.project = project
#         self.name = name

#     @JOverride
#     def run(self):
#         # perform any required shutdown activities


import jpype
import jpype.imports


import string
import random


def createAndShowGUI():
    print('hello')
    # tool = GhidraTool(self.project.project, String(self.name))
    # toolList = tool.getManagedPlugins()

    # for t in toolList:
    #     print(t)

# Start an event loop thread to handling gui events


@jpype.JImplements(java.lang.Runnable, deferred=True)
class Launch:

    def __init__(self, project, tool_name, p1, p2) -> None:
        self.project = project
        self.p1 = p1
        self.p2 = p2
        self.tool_name = tool_name

    @jpype.JOverride
    def run(self):

        # DO NOT CALL TO ANOTHER PYTHON METHOD

        from java.lang import Object
        from ghidra.util.task import ConsoleTaskMonitor
        from ghidra.feature.vt.api.db import VTSessionDB
        from ghidra.feature.vt.api.main import VTSession
        from ghidra.framework.project.tool import GhidraTool
        from java.lang import String
        from ghidra.feature.vt.gui.plugin import VTPlugin, VTControllerImpl
        from ghidra.util.task import ConsoleTaskMonitor
        from ghidra.feature.vt.gui.actions import AutoVersionTrackingTask
        from ghidra.util.task import TaskLauncher

        monitor = ConsoleTaskMonitor()

        # create session
        name = 'vt-sess1' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
        session: VTSession = VTSessionDB.createVTSession(name, self.p1, self.p2, Object())
        root = self.project.getRootFolder()
        root.createFile(name, session, monitor)

        print(self.project.project)
        tool = GhidraTool(self.project.project, String(self.tool_name))
        print(tool)
        print('hi')
        print(VTPlugin)
        print('hi2')
        vtplug = VTPlugin(tool)
        print(vtplug.getClass())
        print('hi3')
        tool.addPlugin(vtplug)
        print('hi4')
        toolList = tool.getManagedPlugins()

        for t in toolList:
            print(t)

        print('hi5')
        controller = VTControllerImpl(vtplug)
        print('hi6')
        controller.openVersionTrackingSession(session)
        autoVtTask = AutoVersionTrackingTask(controller, session, 1.0, 10.0)
        print('hi7')
        TaskLauncher.launch(autoVtTask)

        for match_set in session.getMatchSets():
            print(match_set)

        # TODO CreateImpliedMatchAction
