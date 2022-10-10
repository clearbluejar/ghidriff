import json
import pathlib
import difflib
from typing import List, Tuple,Union, TYPE_CHECKING

import pyhidra

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *

class GhidraDiffEngine:
    """
    Base Ghidra Diff Engine
    """

    def __init__(self,verbose: bool=False,output_dir: str='.diffs') -> None:

        # Init Pyhidra
        pyhidra.start(verbose)        

        # Setup decompiler interface
        from ghidra.app.decompiler import DecompInterface        
        self.ifc = DecompInterface()

        self.output_dir: pathlib.Path = pathlib.Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        self.project: "ghidra.base.project.GhidraProject" = None

        # Global instance var to store symbol lookup results
        self.esym_memo = {}

        # self.deleted_funcs = []
        # self.added_funcs = []
        # self.modified_funcs = []
        # self.modified_funcs_short = []
        # self.funcs = {}        
        # self.symbols = {}
        self.pdiff = {}
    
    def enhance_sym( self, sym: 'ghidra.program.model.symbol.Symbol') -> dict:
        """
        Standardize enhanced symbol. Use esym_memo to speed things up. 
        Based on data from Ghidra/Features/VersionTracking/src/main/java/ghidra/feature/vt/api/main/VTMatchInfo.java
        """

        key = str(sym.getID()) + sym.getProgram().getName()

        if key not in self.esym_memo:

            from ghidra.util.task import ConsoleTaskMonitor

            prog = sym.getProgram()
            
            listing = prog.getListing().getFunctionAt(sym.getAddress())
            func = prog.functionManager.getFunctionAt(sym.getAddress())
            if not sym.getSymbolType().toString().lower() == "function" and not listing and not func:
                print("not a func. {} type {}".format(sym.getName(True),sym.getSymbolType().toString()))
                return None

            instructions = []
            mnemonics = []
            blocks = []

            code_units = func.getProgram().getListing().getCodeUnits(func.getBody(), True)
            #print("\nInstruction Bulker")
            for code in code_units:
                #print(code)
                instructions.append(str(code))

            # reset iterator
            code_units = func.getProgram().getListing().getCodeUnits(func.getBody(), True)

            #print("\nMnemonic Bulker")
            for code in code_units:
                mnemonic = code.getMnemonicString()
                mnemonics.append(str(mnemonic))
                #print(mnemonic)
            
            from ghidra.program.model.block import BasicBlockModel

            #print("\nBasic Block Bulker")
            basic_model = BasicBlockModel(func.getProgram(),True)
            basic_blocks = basic_model.getCodeBlocksContaining(func.getBody(),ConsoleTaskMonitor())

            for block in basic_blocks:

                code_units = func.getProgram().getListing().getCodeUnits(block, True)            
                for code in code_units:
                    mnemonic = code.getMnemonicString()
                    blocks.append(str(mnemonic))
                    #print(mnemonic)

            # sort - This case handles the case for compiler optimizations
            blocks = sorted(blocks)

            self.ifc.openProgram(prog)
            func = prog.functionManager.getFunctionAt(sym.getAddress())

            called_funcs = []
            for f in func.getCalledFunctions(ConsoleTaskMonitor()):
                called_funcs.append(f.toString())

            calling_funcs = []
            for f in func.getCallingFunctions(ConsoleTaskMonitor()):
                calling_funcs.append(f.toString())


            results = self.ifc.decompileFunction(func,1,ConsoleTaskMonitor()).getDecompiledFunction()
            code = results.getC() if results else ""
            
            parent_namespace = sym.getParentNamespace().toString().split('@')[0]

            self.esym_memo[key] = {'name': sym.getName(), 'fullname': sym.getName(True),  'parent':  parent_namespace, 'refcount': sym.getReferenceCount(), 'length': func.body.numAddresses, 'called': called_funcs,
                                   'calling': calling_funcs, 'paramcount': func.parameterCount, 'address': str(sym.getAddress()), 'sig': str(func.getSignature(False)), 'code': code,
                                   'instructions': instructions, 'mnemonics': mnemonics, 'blocks': blocks}

        return self.esym_memo[key]

    def setup_project(
            self,
            binary_paths: List[Union[str, pathlib.Path]],
            project_location: Union[str, pathlib.Path],
            project_name: str
    ):
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
        
        self.project = project

        return        
        
    def get_pdb(self, prog: "ghidra.program.model.listing.Program") -> "java.io.File":
        """
        Searches the currently configured symbol server paths for a Pdb symbol file.
        """
        
        from pdb_.symbolserver import FindOption
        from ghidra.util.task import TaskMonitor
        from pdb_ import PdbPlugin
        
        find_opts = FindOption.of(FindOption.ALLOW_REMOTE)
        #find_opts = FindOption.NO_OPTIONS
        
        # Ghidra/Features/PDB/src/main/java/pdb/PdbPlugin.java#L191
        pdb =  PdbPlugin.findPdb(prog, find_opts, TaskMonitor.DUMMY)

        return pdb

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

    def analyze_project(self, require_symbols=True) -> None:
        """
        Analyzes all files found within the project
        """
        from ghidra.program.flatapi import FlatProgramAPI

        for domainFile in self.project.getRootFolder().getFiles():
            print(domainFile)    

            program = self.project.openProgram("/", domainFile.getName(), False)

            from ghidra.app.plugin.core.analysis import PdbAnalyzer
            from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
            
            PdbUniversalAnalyzer.setAllowRemoteOption(program, True)
            PdbAnalyzer.setAllowRemoteOption(program, True)

            if require_symbols:
                pdb = self.get_pdb(program)
                assert pdb is not None

            # TODO can analysis be threaded??
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
                        self.project.save(program)
                else:
                    print("analysis already complete.. skipping!")
            finally:          
                self.project.close(program)

            print(f"Analysis for {domainFile} complete")


    def get_metadata(
        self,
        prog: "ghidra.program.model.listing.Program"
    ) -> dict:
        """
        Generate dict from program metadata
        """

        meta = prog.getMetadata()

        dmeta = dict(meta)

        return dmeta

    def gen_metadata_diff(
            self,
            pdiff: Union[str,dict]
        ) -> str:
        """Generate binary metadata diff"""

        if isinstance(pdiff,str):
            pdiff = json.loads(pdiff)

        old_meta = pdiff['old_meta']
        new_meta = pdiff['new_meta']
        
        old_text = ''
        old_name = old_meta['Program Name']
        
        new_text = ''
        new_name = new_meta['Program Name']
        

        for i in old_meta:
            # print(f"{i}: {old_meta[i]}")
            old_text += f"{i}: {old_meta[i]}\n"
        
        for i in new_meta:
            # print(f"{i}: {new_meta[i]}")
            new_text += f"{i}: {new_meta[i]}\n"            

        diff = ''.join(list(difflib.unified_diff(old_text.splitlines(True),new_text.splitlines(True),lineterm='\n',fromfile=old_name,tofile=new_name,n=10)))

        return diff

    def diff_bins(
        self,        
        old: Union[str, pathlib.Path],
        new: Union[str, pathlib.Path]
    ) -> dict:
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

    def _gen_heading_diff_section_md(self,heading: str, level: int, diff: str = None, prefix: str = None,) -> str:

        text = ''        
        if heading:
            text += f"{'#'*level} {heading}\n"
        if prefix:
            text += prefix
            text += "\n"
        if diff:
            text += "```diff\n"
            text += diff
            text += "```\n"
            text += "\n"

        return text

    def gen_diff_md(
        self,
        pdiff: Union[str,dict],
        ) -> str:
        """
        Generate Markdown Diff from pdiff match results
        """

        diff_text = ''
        deleted_text = ''
        added_text = ''
        modified_text = ''
        
        if isinstance(pdiff,str):
            pdiff = json.loads(pdiff)
        

            
        funcs = pdiff['functions']

        old_name = pdiff['old_meta']['Program Name']
        new_name = pdiff['new_meta']['Program Name']

        # Create Metadata section
        meta_text = self._gen_heading_diff_section_md(None,0,self.gen_metadata_diff(pdiff))

        # Create Deleted section
        for esym in funcs['deleted']:
            old_code = esym['code'].splitlines(True)
            new_code = ''.splitlines(True)

            diff = ''.join(list(difflib.unified_diff(old_code,new_code,lineterm='\n',fromfile=old_name,tofile=new_name)))
            deleted_text += self._gen_heading_diff_section_md(esym['name'],2,diff)

        # Create Added section
        for esym in funcs['added']:            
            old_code = ''.splitlines(True)		
            new_code = esym['code'].splitlines(True)		

            diff = ''.join(list(difflib.unified_diff(old_code,new_code,lineterm='\n',fromfile=old_name,tofile=new_name)))
            added_text += self._gen_heading_diff_section_md(esym['name'],2,diff)

        # Create Modified section        
        for modified in funcs['modified']:
            diff = None
            pretext = str(modified['diff_type'])
            pretext += str(modified['m_ratio'])
            if 'code' in modified['diff_type']:
                diff =  modified['diff']
            modified_text += self._gen_heading_diff_section_md(modified['old']['sig'],2,diff,pretext)
            # print(f"{modified['diff_type']} {modified['old']['sig']} {modified['new']['sig']}")


        # Add short?
        # modified_funcs_short.append({'name': [ematch_1['name'], ematch_2['name']], 'length': [ematch_1['length'], ematch_2['length']], 'ratio': ratio, 'diff_type': diff_type })

        diff_text += "# Metadata\n"
        diff_text += meta_text
        diff_text += "# Deleted\n"
        diff_text += deleted_text
        diff_text += "# Added\n"
        diff_text += added_text
        diff_text += "# Modified\n"
        diff_text += modified_text

        return diff_text

    def dump_pdiff_to_dir(
        self,
        name: str,
        pdiff: Union[str,dict],
        dir: Union[str,pathlib.Path]
    ) -> None:
        """
        Dump pdiff result to directory
        """

        if isinstance(pdiff,str):
            pdiff = json.loads(pdiff)

        dir = pathlib.Path(dir)
        
        md_path = dir / pathlib.Path(name + '.md')
        json_path = dir / pathlib.Path(name + '.json')

        diff_text = self.gen_diff_md(pdiff)

        with md_path.open('w') as f:
            f.write(diff_text)

        with json_path.open('w') as f:
            json.dump(pdiff,f,indent=4)

    # def add_arg_group_to_parser(parser: argparse.ArgumentParser):
    #     pass