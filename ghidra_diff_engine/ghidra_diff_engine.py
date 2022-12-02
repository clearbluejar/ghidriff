import json
import pathlib
import difflib
import argparse
from typing import List, Tuple,Union, TYPE_CHECKING

import pyhidra
from mdutils.tools.Table import Table
from mdutils.mdutils import MdUtils
import asyncio
import multiprocessing

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *

class GhidraDiffEngine:
    """
    Base Ghidra Diff Engine
    """

    def __init__(self,verbose: bool=False,output_dir: str='.diffs', MAX_MEM=None, threaded=False, max_workers=multiprocessing.cpu_count()) -> None:

        # Init Pyhidra
        if not MAX_MEM:
            pyhidra.start(verbose)     
        else:
            # Set Ghidra Max Memory
            launcher = pyhidra.HeadlessPyhidraLauncher(verbose)
            MAX_MEM = "10G"
            launcher.add_vmargs(f"-Xmx{MAX_MEM}")
            launcher.start()

        self.threaded: bool = threaded
        self.max_workers = max_workers

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
    
    @staticmethod
    def add_ghidra_args_to_parser(parser: argparse.ArgumentParser) -> None:
        """
        Add required Ghidra args to a parser
        """

        group = parser.add_argument_group('Ghidra options')
        group.add_argument('-p', '--project-location', dest="project_location",
                        help='Ghidra Project Path', default='.ghidra_projects')
        group.add_argument('-n', '--project-name', dest="project_name",
                        help='Ghidra Project Name', default='diff_project')
        group.add_argument('-s', '--symbols-path', dest="symbols_path",
                        help='Ghidra local symbol store directory', default='.symbols')
        group.add_argument('-o', '--output-path', dest="output_path",
                        help='Directory to output results', default='.diffs')                

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
                print(f'\nImporting {program_path}')
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

    def analyze_program(self, domainFile, require_symbols):
        
        from ghidra.program.flatapi import FlatProgramAPI

        print(f"\n Analyzing: {domainFile}")

        program = self.project.openProgram("/", domainFile.getName(), False)

        from ghidra.app.plugin.core.analysis import PdbAnalyzer
        from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
        
        PdbUniversalAnalyzer.setAllowRemoteOption(program, True)
        PdbAnalyzer.setAllowRemoteOption(program, True)

        # handle large binaries more efficiently see ghidra/issues/4573 (turn off feature Shared Return Calls )
        if program and program.getFunctionManager().functionCount > 1000:
            self.set_analysis_option_bool(program,'Shared Return Calls.Assume Contiguous Functions Only', False)

        # Print analysis options
        options = self.get_analysis_options(program)
        print("\nAnalysis Options:")
        for option in options:
            print(f"\t{option} : {options[option]}")

        if require_symbols:
            pdb = self.get_pdb(program)
            assert pdb is not None

        try:
            flat_api = FlatProgramAPI(program)

            from ghidra.program.util import GhidraProgramUtilities
            from ghidra.app.script import GhidraScriptUtil
            if GhidraProgramUtilities.shouldAskToAnalyze(program):
                GhidraScriptUtil.acquireBundleHostReference()                
                try:                        
                    flat_api.analyzeAll(program)                        
                    GhidraProgramUtilities.setAnalyzedFlag(program, True)                                           
                finally:
                    GhidraScriptUtil.releaseBundleHostReference()
                    self.project.save(program)
            else:
                print("analysis already complete.. skipping!")
        finally:
            self.project.close(program)

        print(f"Analysis for {domainFile} complete")

    async def run_threaded_analysis(self, require_symbols):

        from concurrent.futures.thread import ThreadPoolExecutor
        import multiprocessing

        
        loop = asyncio.get_running_loop()
        executor = ThreadPoolExecutor(max_workers=self.max_workers)
        futures = [loop.run_in_executor(executor,self.analyze_program,*[domainFile,require_symbols]) for domainFile in self.project.getRootFolder().getFiles()]

        completed, pending = await asyncio.wait(futures,return_when=asyncio.ALL_COMPLETED)

    def analyze_project(self, require_symbols=True) -> None:
        """
        Analyzes all files found within the project
        """
        
        if self.threaded:
            event_loop = asyncio.get_event_loop()
            try:
                event_loop.run_until_complete(
                    self.run_threaded_analysis(require_symbols)
                )
            finally:
                event_loop.close()
        else:
            for domainFile in self.project.getRootFolder().getFiles():
                self.analyze_program(domainFile,require_symbols)
            
    def get_metadata(
        self,
        prog: "ghidra.program.model.listing.Program"
    ) -> dict:
        """
        Generate dict from program metadata
        """

        meta = prog.getMetadata()       

        return dict(meta)

    def get_analysis_options(
        self,
        prog: "ghidra.program.model.listing.Program"
    ) -> dict:
        """
        Generate dict from program analysis options
        Inspired by: Ghidra/Features/Base/src/main/java/ghidra/app/script/GhidraScript.java#L1272
        """

        from ghidra.program.model.listing import Program        
        
        prog_options = prog.getOptions(Program.ANALYSIS_PROPERTIES)
        options = {}
        
        for propName in prog_options.getOptionNames():            
            options[propName] = prog_options.getValueAsString(propName)
            
        return options

    def set_analysis_option_bool(
        self,
        prog: "ghidra.program.model.listing.Program",
        option_name: str,
        value: bool
    ) -> None:
        """
        Set boolean program analysis options
        Inspired by: Ghidra/Features/Base/src/main/java/ghidra/app/script/GhidraScript.java#L1272
        """

        from ghidra.program.model.listing import Program        
        
        prog_options = prog.getOptions(Program.ANALYSIS_PROPERTIES)
        
        prog_options.setBoolean(option_name,value)           
        

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

    def _wrap_with_diff(self,diff: str) -> str:

        text = ''
        text += "```diff\n"
        text += diff
        text += "```\n"
        text += "\n"

        return text

    def gen_esym_table_diff(self, old,new,modified) -> str:
        diff_table = ''

        table_list = []
        table_list.extend(['Key', old, new])
        # table_list.extend(['Key', 'Diff'])
        column_len = len(table_list)

        skip_keys = ['code', 'instructions', 'mnemonics', 'blocks', 'parent']
        count = 1
        for key in modified['old']:
            if key in skip_keys:
                continue
            if key in modified['diff_type']:
                diff_key = f"`{key}`"
                table_list.extend([diff_key, modified['old'][key], modified['new'][key]])
            else:
                table_list.extend([key, modified['old'][key], modified['new'][key]])
            
            # diff_text = '```diff'
            # diff_text += ''.join(list(difflib.unified_diff(str(modified['old'][key]).splitlines(True),str(modified['new'][key]).splitlines(True),lineterm='\n',fromfile=old,tofile=new)))
            # diff_text += '```'
            # table_list.extend([key, diff_text])
            count += 1

        diff_table = Table().create_table(columns=column_len, rows=count, text=table_list, text_align='center')

        return diff_table

    def gen_diff_md(
        self,
        pdiff: Union[str,dict],
        ) -> str:
        """
        Generate Markdown Diff from pdiff match results
        """
        
        if isinstance(pdiff,str):
            pdiff = json.loads(pdiff)
        
        funcs = pdiff['functions']

        old_name = pdiff['old_meta']['Program Name']
        new_name = pdiff['new_meta']['Program Name']

        md = MdUtils('example', f"{old_name}-{new_name} Diff")

        # Create Metadata section
        md.new_header(1,'Metadata')
        md.new_paragraph(self._wrap_with_diff(self.gen_metadata_diff(pdiff)))

        # Create Deleted section
        md.new_header(1,'Deleted')

        for esym in funcs['deleted']:
            old_code = esym['code'].splitlines(True)
            new_code = ''.splitlines(True)
            diff = ''.join(list(difflib.unified_diff(old_code, new_code, lineterm='\n', fromfile=old_name, tofile=new_name)))
            md.new_header(2, esym['name'])
            md.new_paragraph(self._wrap_with_diff(diff))
            
        
        # Create Added section
        md.new_header(1,'Added')
        for esym in funcs['added']:            
            old_code = ''.splitlines(True)		
            new_code = esym['code'].splitlines(True)
            diff = ''.join(list(difflib.unified_diff(old_code,new_code,lineterm='\n',fromfile=old_name,tofile=new_name)))
            md.new_header(2, esym['name'])
            md.new_paragraph(self._wrap_with_diff(diff))

        # Create Modified section    
        md.new_header(1,'Modified')    
        for modified in funcs['modified']:
            diff = None
            if 'code' in modified['diff_type']:
                md.new_header(2, modified['old']['name'])
                diff =  modified['diff']
            else:
                md.new_header(2, modified['old']['name'],add_table_of_contents='n')
            
            md.new_paragraph(self.gen_esym_table_diff(old_name,new_name,modified))
            if diff:
                md.new_paragraph(self._wrap_with_diff(modified['diff']))            
           
        md.new_table_of_contents('TOC',3)
        
        return md.get_md_text()

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