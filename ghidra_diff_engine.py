import json
import pathlib
from typing import List, Union, TYPE_CHECKING

import pyhidra

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *

class GhidraDiffEngine:
    """
    Base Ghidra Diff Engine
    """

    def __init__(self,verbose=False) -> None:
        pyhidra.start(verbose)

    def setup_project(
            self,
            binary_paths: List[Union[str, pathlib.Path]],
            project_location: Union[str, pathlib.Path],
            project_name: str
    ) -> "ghidra.base.project.GhidraProject":
        """
        Setup and verify Ghidra Project
        """
        from ghidra.base.project import GhidraProject
        from java.io import IOException
        
        project_location = pathlib.Path(project_location) / project_name
        project_location.mkdir(exist_ok=True, parents=True)

        # Open/Create project
        project = None
        try:
            project = GhidraProject.openProject(project_location, project_name, True)        
        except IOException:
            project = GhidraProject.createProject(project_location, project_name, False)

        # Import binaries
        for program_path in binary_paths:
            program_path = pathlib.Path(program_path)
            # Import binary if necessary they don't already exist
            if not project.getRootFolder().getFile(program_path.name):
                print(program_path)
                program = project.importProgram(program_path)                        
                project.saveAs(program, "/", program.getName(), True)
                project.close(program)
        return project


    def setup_symbols(self, symbols_path: Union[str, pathlib.Path]) -> None:
        """setup symbols to allow Ghidra to download as needed"""

        symbols_path = pathlib.Path(symbols_path).absolute()

        from pdb_ import PdbPlugin    
        from pdb_.symbolserver import LocalSymbolStore
        from pdb_.symbolserver import HttpSymbolServer
        from pdb_.symbolserver import SymbolServerService

        from java.util import List
        from java.io import File
        from java.net import URI

        # todo support more than just Windows
        symbolsDir = File(symbols_path)
        localSymbolStore = LocalSymbolStore(symbols_path)

        # Creates a MS-compatible symbol server directory location. pdb/symbolserver/LocalSymbolStore.java#L67
        localSymbolStore.create(symbolsDir,1)
        msSymbolServer = HttpSymbolServer(URI.create("https://msdl.microsoft.com/download/symbols/"))
        symbolServerService = SymbolServerService(localSymbolStore, List.of(msSymbolServer))

        PdbPlugin.saveSymbolServerServiceConfig(symbolServerService)

    def analyze_project(self, project: "ghidra.base.project.GhidraProject") -> None:
        """
        Analyzes all files found within the project
        """
        from ghidra.program.flatapi import FlatProgramAPI

        for domainFile in project.getRootFolder().getFiles():
            print(domainFile)    

            program = project.openProgram("/", domainFile.getName(), False)        



            from ghidra.app.plugin.core.analysis import PdbAnalyzer
            from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
            PdbUniversalAnalyzer.setAllowRemoteOption(program, True)
            PdbAnalyzer.setAllowRemoteOption(program, True)

            try:
                flat_api = FlatProgramAPI(program)

                from ghidra.program.util import GhidraProgramUtilities
                from ghidra.app.script import GhidraScriptUtil
                if GhidraProgramUtilities.shouldAskToAnalyze(program):
                    GhidraScriptUtil.acquireBundleHostReference()
                    try:
                        print(GhidraProgramUtilities.shouldAskToAnalyze(program))
                        flat_api.analyzeAll(program)
                        print(GhidraProgramUtilities.shouldAskToAnalyze(program))
                        GhidraProgramUtilities.setAnalyzedFlag(program, True)
                        print(GhidraProgramUtilities.shouldAskToAnalyze(program))
                    finally:
                        GhidraScriptUtil.releaseBundleHostReference()
                        project.save(program)
                else:
                    print("analysis already complete.. skipping!")
            finally:          
                project.close(program)

            print(f"Analysis for {domainFile} complete")

    def metadata_diff(
            self,
            p1: "ghidra.program.model.listing.Program",
            p2: "ghidra.program.model.listing.Program",
        ) -> str:
        """Generate binary metadata diff"""

        import difflib

        meta = p1.getDomainFile().getMetadata()
        meta2 = p2.getDomainFile().getMetadata()    

        dmeta = {}
        dmeta2 = {}

        p1_text = ''    
        for i in meta:
            print(f"{i}: {meta[i]}")
            p1_text += f"{i}: {meta[i]}\n"
            dmeta[f"{i}"] = f"{meta[i]}"
            
        p2_text = ''    
        for i in meta2:
            print(f"{i}: {meta2[i]}")
            p2_text += f"{i}: {meta2[i]}\n"
            dmeta2[f"{i}"] = f"{meta2[i]}"

        dmeta = sorted(dmeta)

        dmeta2 = sorted(dmeta2)


        diff = ''.join(list(difflib.unified_diff(p1_text.splitlines(True),p2_text.splitlines(True),lineterm='\n',fromfile=p1.getName(),tofile=p2.getName(),n=10)))
        diff_text = "```## Metadata Diff\n"
        diff_text += diff
        diff_text += "```\n"
        diff_text += "\n"

        return diff_text

    def diff_bins(
        self,
        project: "ghidra.base.project.GhidraProject",
        old: Union[str, pathlib.Path],
        new: Union[str, pathlib.Path]
    ) -> json:
        raise NotImplementedError

    def validate_diff_json(
        self,
        results: json
    ) -> bool:
        try:
            json.loads(results)
        except ValueError as err:
            print(err)
            return False
        return True
