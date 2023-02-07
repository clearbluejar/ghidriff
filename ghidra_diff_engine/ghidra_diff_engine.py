import json
import pathlib
import difflib
import argparse
import re
from time import time
from collections import Counter
import difflib
import concurrent
from textwrap import dedent
from typing import List, Tuple, Union, TYPE_CHECKING

import pyhidra
from mdutils.tools.Table import Table
from mdutils.mdutils import MdUtils
import asyncio
import multiprocessing

from ghidra_diff_engine import __version__

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


class GhidraDiffEngine:
    """
    Base Ghidra Diff Engine
    """

    def __init__(self, verbose: bool = False, MAX_MEM=None, threaded=False, max_workers=multiprocessing.cpu_count(), max_ram_percent: float = 75.0, debug_jvm: bool = False) -> None:

        # Init Pyhidra
        if not MAX_MEM:
            pyhidra.start(verbose)
        else:

            launcher = pyhidra.HeadlessPyhidraLauncher(verbose)

            # Set Ghidra Heap Max
            # Ghidra/RuntimeScripts/Linux/support/analyzeHeadless#L7
            # MAX_MEM = "16G"
            # launcher.add_vmargs(f"-Xmx{MAX_MEM}")

            # max % if RAM
            launcher.add_vmargs(f'-XX:MaxRAMPercentage={max_ram_percent}')
            # want JVM to crash if we run out of memory (otherwise no error it propagated)
            launcher.add_vmargs('-XX:+CrashOnOutOfMemoryError')

            # Match ghidra launch support script

            if debug_jvm:
                launcher.add_vmargs('-XX:+HeapDumpOnOutOfMemoryError')
                launcher.add_vmargs('-XX:+PrintFlagsFinal')

            launcher.start()

        self.threaded: bool = threaded
        self.max_workers = max_workers

        # Setup decompiler interface
        from ghidra.app.decompiler import DecompInterface
        self.ifc = DecompInterface()

        self.project: "ghidra.base.project.GhidraProject" = None

        self.version = __version__

        # Global instance var to store symbol lookup results
        self.esym_memo = {}

    @staticmethod
    def add_ghidra_args_to_parser(parser: argparse.ArgumentParser) -> None:
        """
        Add required Ghidra args to a parser
        """

        group = parser.add_argument_group('Ghidra options')
        group.add_argument('-p', '--project-location', help='Ghidra Project Path', default='.ghidra_projects')
        group.add_argument('-n', '--project-name', help='Ghidra Project Name', default='diff_project')
        group.add_argument('-s', '--symbols-path', help='Ghidra local symbol store directory', default='.symbols')

    def enhance_sym(self, sym: 'ghidra.program.model.symbol.Symbol') -> dict:
        """
        Standardize enhanced symbol. Use esym_memo to speed things up.
        Inspired by Ghidra/Features/VersionTracking/src/main/java/ghidra/feature/vt/api/main/VTMatchInfo.java
        """

        from ghidra.program.model.symbol import SymbolType

        key = str(sym.getID()) + sym.getProgram().getName()

        if key not in self.esym_memo:

            from ghidra.util.task import ConsoleTaskMonitor

            prog = sym.program
            listing = prog.getListing().getFunctionAt(sym.getAddress())
            func: 'ghidra.program.model.listing.Function' = prog.functionManager.getFunctionAt(sym.getAddress())

            if not sym.symbolType == SymbolType.FUNCTION and not listing and not func:

                # process symbol

                calling = set()
                ref_types = set()
                for ref in sym.references:
                    ref_types.add(ref.referenceType.toString())
                    f = prog.getFunctionManager().getFunctionContaining(ref.fromAddress)
                    if f:
                        calling.add(f.getName())

                calling = list(calling)
                ref_types = list(ref_types)

                if sym.parentSymbol is not None:
                    parent = str(sym.parentSymbol)
                else:
                    parent = None

                self.esym_memo[key] = {'name': sym.getName(), 'fullname': sym.getName(True), 'parent':  parent, 'refcount': sym.getReferenceCount(), 'reftypes': ref_types,  'calling': calling,
                                       'address': str(sym.getAddress()), 'sym_type': str(sym.getSymbolType()), 'external': sym.external}

            else:
                # proces function

                instructions = []
                mnemonics = []
                blocks = []

                code_units = func.getProgram().getListing().getCodeUnits(func.getBody(), True)

                # instruction and mnemonic bulker
                for code in code_units:
                    # print(code)
                    instructions.append(str(code))
                    mnemonics.append(str(code.mnemonicString))

                from ghidra.program.model.block import BasicBlockModel

                # Basic Block Bulker
                basic_model = BasicBlockModel(func.getProgram(), True)
                basic_blocks = basic_model.getCodeBlocksContaining(func.getBody(), ConsoleTaskMonitor())

                for block in basic_blocks:
                    code_units = func.getProgram().getListing().getCodeUnits(block, True)
                    for code in code_units:
                        blocks.append(str(code.mnemonicString))

                # sort - This case handles the case for compiler optimizations
                blocks = sorted(blocks)

                self.ifc.openProgram(prog)

                called_funcs = []
                for f in func.getCalledFunctions(ConsoleTaskMonitor()):
                    called_funcs.append(f.toString())

                calling_funcs = []
                for f in func.getCallingFunctions(ConsoleTaskMonitor()):
                    calling_funcs.append(f.toString())

                results = self.ifc.decompileFunction(func, 1, ConsoleTaskMonitor()).getDecompiledFunction()
                code = results.getC() if results else ""

                parent_namespace = sym.getParentNamespace().toString().split('@')[0]

                called_funcs = sorted(called_funcs)
                calling_funcs = sorted(calling_funcs)

                self.esym_memo[key] = {'name': sym.getName(), 'fullname': sym.getName(True),  'parent':  parent_namespace, 'refcount': sym.getReferenceCount(), 'length': func.body.numAddresses, 'called': called_funcs,
                                       'calling': calling_funcs, 'paramcount': func.parameterCount, 'address': str(sym.getAddress()), 'sig': str(func.getSignature(False)), 'code': code,
                                       'instructions': instructions, 'mnemonics': mnemonics, 'blocks': blocks, 'sym_type': str(sym.getSymbolType()), 'external': sym.external}

        return self.esym_memo[key]

    def setup_project(
            self,
            binary_paths: List[Union[str, pathlib.Path]],
            project_location: Union[str, pathlib.Path],
            project_name: str,
            symbols_path: Union[str, pathlib.Path]
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

        self.project = project

        # Setup Symbols
        self.setup_symbols(symbols_path)

        bin_results = []

        # Import binaries
        for program_path in binary_paths:

            program_path = pathlib.Path(program_path)

            # Import binary if they don't already exist
            if not project.getRootFolder().getFile(program_path.name):
                print(f'\nImporting {program_path}')
                program = project.importProgram(program_path)
                project.saveAs(program, "/", program.getName(), True)
            else:
                program = self.project.openProgram("/", program_path.name, True)

            pdb = self.get_pdb(program)
            project.close(program)

            if pdb is None:
                print(f"PDB not found for {program.getName()}!")

            imported = program is not None
            has_pdb = pdb is not None

            bin_results.append([program_path, imported, has_pdb])

        return bin_results

    def get_pdb(self, prog: "ghidra.program.model.listing.Program") -> "java.io.File":
        """
        Searches the currently configured symbol server paths for a Pdb symbol file.
        """

        from pdb_.symbolserver import FindOption
        from ghidra.util.task import TaskMonitor
        from pdb_ import PdbPlugin

        find_opts = FindOption.of(FindOption.ALLOW_REMOTE)
        # find_opts = FindOption.NO_OPTIONS

        # Ghidra/Features/PDB/src/main/java/pdb/PdbPlugin.java#L191
        pdb = PdbPlugin.findPdb(prog, find_opts, TaskMonitor.DUMMY)

        return pdb

    def download_project_program_pdbs(self) -> List[List]:
        """
        Downloads PDBs for all programs within project
        """

        pdb_list = []

        if self.project is None:
            raise Exception('ProjectNotSet')

        for domainFile in self.project.getRootFolder().getFiles():
            prog_name = domainFile.getName()

            # open readonly prog
            prog = self.project.openProgram("/", prog_name, True)
            pdb = self.get_pdb(prog)

            if pdb is not None:
                pdb = pathlib.Path(pdb.absoluteFile.toString())
                print(f"PDB {pdb} found for {prog_name}")

            pdb_list.append([prog_name, pdb])

        return pdb_list

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

        # TODO support more than just Windows
        symbolsDir = File(symbols_path)
        localSymbolStore = LocalSymbolStore(symbols_path)

        # Creates a MS-compatible symbol server directory location. pdb/symbolserver/LocalSymbolStore.java#L67
        localSymbolStore.create(symbolsDir, 1)
        msSymbolServer = HttpSymbolServer(URI.create("https://msdl.microsoft.com/download/symbols/"))
        symbolServerService = SymbolServerService(localSymbolStore, List.of(msSymbolServer))

        PdbPlugin.saveSymbolServerServiceConfig(symbolServerService)

    def analyze_program(self, df_or_prog: Union["ghidra.framework.model.DomainFile", "ghidra.program.model.listing.Program"], require_symbols: bool, force_analysis: bool = False):

        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.framework.model import DomainFile
        from ghidra.program.model.listing import Program

        if isinstance(df_or_prog, DomainFile):
            program = self.project.openProgram("/", df_or_prog.getName(), False)
        elif isinstance(df_or_prog, Program):
            program = df_or_prog

        print(f"\n Analyzing: {program}")

        try:
            flat_api = FlatProgramAPI(program)

            from ghidra.program.util import GhidraProgramUtilities
            from ghidra.app.script import GhidraScriptUtil

            if GhidraProgramUtilities.shouldAskToAnalyze(program) or force_analysis:
                GhidraScriptUtil.acquireBundleHostReference()

                from ghidra.app.plugin.core.analysis import PdbAnalyzer
                from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer

                PdbUniversalAnalyzer.setAllowRemoteOption(program, True)
                PdbAnalyzer.setAllowRemoteOption(program, True)

                # handle large binaries more efficiently
                # see ghidra/issues/4573 (turn off feature Shared Return Calls )
                if program and program.getFunctionManager().functionCount > 1000:
                    self.set_analysis_option_bool(
                        program, 'Shared Return Calls.Assume Contiguous Functions Only', False)

                try:
                    flat_api.analyzeAll(program)
                    GhidraProgramUtilities.setAnalyzedFlag(program, True)
                finally:
                    GhidraScriptUtil.releaseBundleHostReference()
                    self.project.save(program)
            else:
                print(f"analysis already complete.. skipping {program}!")
        finally:
            self.project.close(program)

        print(f"Analysis for {df_or_prog} complete")

        return df_or_prog

    async def run_threaded_analysis(self, require_symbols):

        from concurrent.futures.thread import ThreadPoolExecutor

        loop = asyncio.get_running_loop()
        executor = ThreadPoolExecutor(max_workers=self.max_workers)
        futures = [loop.run_in_executor(executor, self.analyze_program, *[domainFile, require_symbols])
                   for domainFile in self.project.getRootFolder().getFiles()]

        completed, pending = await asyncio.wait(futures, return_when=asyncio.ALL_COMPLETED)

    def analyze_project(self, require_symbols=True) -> None:
        """
        Analyzes all files found within the project
        """

        if self.threaded:

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = (executor.submit(self.analyze_program, *[domainFile, require_symbols])
                           for domainFile in self.project.getRootFolder().getFiles())
                for future in concurrent.futures.as_completed(futures):

                    prog = future.result()
                    print(prog)

        else:
            for domainFile in self.project.getRootFolder().getFiles():
                self.analyze_program(domainFile, require_symbols)

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

        prog_options.setBoolean(option_name, value)

    def set_proginfo_option_bool(
        self,
        prog: "ghidra.program.model.listing.Program",
        option_name: str,
        value: bool
    ) -> None:
        """
        Set boolean program info options
        Inspired by: Ghidra/Features/Base/src/main/java/ghidra/app/script/GhidraScript.java#L1272
        """

        from ghidra.program.model.listing import Program

        prog_options = prog.getOptions(Program.PROGRAM_INFO)

        prog_options.setBoolean(option_name, value)

    def gen_metadata_diff(
        self,
        pdiff: Union[str, dict]
    ) -> str:
        """Generate binary metadata diff"""

        if isinstance(pdiff, str):
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

        diff = ''.join(list(difflib.unified_diff(old_text.splitlines(True), new_text.splitlines(
            True), lineterm='\n', fromfile=old_name, tofile=new_name, n=10)))

        return diff

    def find_matches(
        self,
        p1: "ghidra.program.model.listing.Program",
        p2: "ghidra.program.model.listing.Program"
    ) -> list:
        """
        Find matching and unmatched functions between p1 and p2
        """
        raise NotImplementedError

    def diff_symbols(
        self,
        p1: "ghidra.program.model.listing.Program",
        p2: "ghidra.program.model.listing.Program"
    ) -> list:
        """
        Find matching and unmatched symbols between p1 and p2
        """

        # from Features/Base/src/main/java/ghidra/app/plugin/match/MatchSymbol.java
        def _is_sym_string(sym: 'ghidra.program.model.symbol.Symbol') -> bool:

            sym_addr = sym.getAddress()
            if sym_addr is not None:
                data = sym.getProgram().getListing().getDataAt(sym_addr)
                if data is not None and data.hasStringValue():
                    return True

            return False

        # find added and deleted symbols
        from ghidra.program.model.symbol import SymbolUtilities
        from ghidra.program.model.symbol import SourceType
        from ghidra.program.model.listing import Function

        all_p1_syms = {}
        all_p2_syms = {}

        # build symbols dict

        # follow pattern for Ghidra/Features/Base/src/main/java/ghidra/app/plugin/match/MatchSymbol.java
        for sym in p1.getSymbolTable().getAllSymbols(True):
            # don't include DEFAULT (FUN_ LAB_) but do include strings s_something
            if sym.getSource() != SourceType.DEFAULT or _is_sym_string(sym):
                # skip local symbols
                if not isinstance(sym.getParentNamespace(), Function):
                    # get name lacking '_' or '@'
                    clean_name = SymbolUtilities.getCleanSymbolName(sym.getName(), sym.address)
                    all_p1_syms[clean_name] = sym

        print(f'p1 sym count: reported: {p1.symbolTable.numSymbols} analyzed: {len(all_p1_syms)}')

        for sym in p2.getSymbolTable().getAllSymbols(True):
            # don't include DEFAULT (FUN_ LAB_) but do include strings s_something
            if sym.getSource() != SourceType.DEFAULT or _is_sym_string(sym):
                # skip local symbols
                if not isinstance(sym.getParentNamespace(), Function):
                    # get name lacking '_' or '@'
                    clean_name = SymbolUtilities.getCleanSymbolName(sym.getName(), sym.address)
                    all_p2_syms[clean_name] = sym

        print(f'p2 sym count: reported: {p2.symbolTable.numSymbols} analyzed: {len(all_p2_syms)}')

        deleted_sym_keys = list(set(all_p1_syms.keys()).difference(all_p2_syms.keys()))
        added_syms_keys = list(set(all_p2_syms.keys()).difference(all_p1_syms.keys()))
        matching_sym_keys = list(set(all_p1_syms.keys()).intersection(all_p2_syms.keys()))

        unmatched = []
        matched = []

        # translate keys to symbols
        unmatched.extend([all_p1_syms[key] for key in deleted_sym_keys])
        unmatched.extend([all_p2_syms[key] for key in added_syms_keys])
        matched = [all_p1_syms[key] for key in matching_sym_keys]

        print(f'Found unmatched: {len(unmatched)} matched: {len(matched)}')

        return [unmatched, matched]

    def diff_bins(
            self,
            old: Union[str, pathlib.Path],
            new: Union[str, pathlib.Path],
            ignore_FUN: bool = False,
    ) -> dict:
        """
        Diff the old and new binary from the GhidraProject.
        ignore_FUN : skip nameless functions matching names containing "FUN_". Useful for increasing speed of diff.
        last_attempt : flag to prevent infinte loop on recursive instances
        """

        start = time()

        print(len(self.esym_memo))

        # reset pdiff
        pdiff = {}

        old = pathlib.Path(old)
        new = pathlib.Path(new)

        # open both programs read-only
        p1 = self.project.openProgram("/", old.name, True)
        p2 = self.project.openProgram("/", new.name, True)

        print("Loaded old program: {}".format(p1.getName()))
        print("Loaded new program: {}".format(p2.getName()))

        sym_count_diff = abs(p1.getSymbolTable().numSymbols - p2.getSymbolTable().numSymbols)

        # sanity check - ensure comparing apples to apples
        assert sym_count_diff < 4000, f'Symbols counts between programs ({p1.name} and {p2.name}) are too high {sym_count_diff}! Likely bad analyiss or only one binary has symbols! Check Ghidra analysis or pdb!'

        unmatched_syms, matched_syms = self.diff_symbols(p1, p2)

        deleted_symbols = []
        added_symbols = []

        for sym in unmatched_syms:
            if sym.program == p1:
                deleted_symbols.append(sym)
            else:
                added_symbols.append(sym)

        unmatched, matches, skip_types = self.find_matches(p1, p2)

        symbols = {}
        funcs = {}
        symbols['added'] = []
        symbols['deleted'] = []

        deleted_funcs = []
        added_funcs = []
        modified_funcs = []
        all_match_types = []

        # thread the symbol lookups
        #   esyms are memoized and can be later just read from memory
        if self.threaded:

            esym_lookups = []
            esym_lookups.extend(deleted_symbols)
            esym_lookups.extend(added_symbols)

            for sym, sym2, match_types in matches:

                # skip enhancing matches with these types
                if any([match_type in skip_types for match_type in match_types]):
                    # want to keep ref differences
                    if sym.referenceCount == sym2.referenceCount:
                        continue

                esym_lookups.append(sym)
                esym_lookups.append(sym2)

            print(f'Starting esym lookups for {len(esym_lookups)} symbols using {self.max_workers} threads')

            # TODO add monitor and progress updates
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = (executor.submit(self.enhance_sym, sym)
                           for sym in esym_lookups)
                for future in concurrent.futures.as_completed(futures):
                    # TODO increment progress
                    result = future.result()

        for sym in deleted_symbols:
            symbols['deleted'].append(self.enhance_sym(sym))

        for sym in added_symbols:
            symbols['added'].append(self.enhance_sym(sym))

        for lost in unmatched:
            elost = self.enhance_sym(lost)

            # deleted func
            if lost.getProgram().getName() == p1.getName():
                deleted_funcs.append(elost)
            else:
                added_funcs.append(elost)

        for sym, sym2, match_types in matches:

            skip_match = False

            # skip enhancing matches with these types
            if any([match_type in skip_types for match_type in match_types]):
                # want to keep ref differences
                if sym.referenceCount == sym2.referenceCount:
                    skip_match = True

            # account for match types
            # (only take fist match as this will count towards total)

            first_match = match_types[0]
            all_match_types.append(first_match)

            if skip_match:
                continue

            diff_type = []
            diff = ''
            only_code_diff = ''

            ematch_1 = self.enhance_sym(sym)
            ematch_2 = self.enhance_sym(sym2)

            old_code = ematch_1['code'].splitlines(True)
            new_code = ematch_2['code'].splitlines(True)

            old_code_no_sig = ematch_1['code'].split('{', 1)[1].splitlines(True) if ematch_1['code'] else ''
            new_code_no_sig = ematch_2['code'].split('{', 1)[1].splitlines(True) if ematch_2['code'] else ''

            old_instructions = ematch_1['instructions']
            new_instructions = ematch_2['instructions']

            instructions_ratio = difflib.SequenceMatcher(None, old_instructions, new_instructions).ratio()

            old_mnemonics = ematch_1['mnemonics']
            new_mnemonics = ematch_2['mnemonics']

            mnemonics_ratio = difflib.SequenceMatcher(None, old_mnemonics, new_mnemonics).ratio()

            old_blocks = ematch_1['blocks']
            new_blocks = ematch_2['blocks']

            blocks_ratio = difflib.SequenceMatcher(None, old_blocks, new_blocks).ratio()

            # ignore signature for ratio
            ratio = difflib.SequenceMatcher(None, old_code_no_sig, new_code_no_sig).ratio()

            print(ematch_1['sig'])
            print(ematch_2['sig'])

            diff = ''.join(list(difflib.unified_diff(old_code, new_code, lineterm='\n',
                           fromfile=sym.getProgram().getName(), tofile=sym2.getProgram().getName())))
            only_code_diff = ''.join(list(difflib.unified_diff(old_code_no_sig, new_code_no_sig, lineterm='\n', fromfile=sym.getProgram(
            ).getName(), tofile=sym2.getProgram().getName())))  # ignores name changes

            if len(only_code_diff) > 0 and (mnemonics_ratio < 1.0 or blocks_ratio < 1.0):

                # TODO remove this hack to find false positives
                # potential decompile jumptable issue ghidra/issues/2452
                if not "Could not recover jumptable" in diff:
                    diff_type.append('code')

            if ematch_1['name'] != ematch_2['name']:
                diff_type.append('name')

            if ematch_1['fullname'] != ematch_2['fullname']:
                diff_type.append('fullname')

            if ematch_1['refcount'] != ematch_2['refcount']:
                diff_type.append('refcount')

            if ematch_1['length'] != ematch_2['length']:
                diff_type.append('length')

            if ematch_1['sig'] != ematch_2['sig']:
                diff_type.append('sig')

            if ematch_1['address'] != ematch_2['address']:
                diff_type.append('address')

            if len(set(ematch_1['calling']).difference(set(ematch_2['calling']))) > 0:
                diff_type.append('calling')

            if len(set(ematch_1['called']).difference(set(ematch_2['called']))) > 0:
                diff_type.append('called')

            if ematch_1['parent'] != ematch_2['parent']:
                diff_type.append('parent')

            # if no differences were found, there should not be a match (see modified func ident)
            # assert len(diff_type) > 0
            if len(diff_type) == 0:
                print(f'no diff: {sym} {sym2} {match_types}')
                continue

            modified_funcs.append({'old': ematch_1, 'new': ematch_2, 'diff': diff, 'diff_type': diff_type, 'ratio': ratio,
                                  'i_ratio': instructions_ratio, 'm_ratio': mnemonics_ratio, 'b_ratio': blocks_ratio, 'match_types': match_types})

        # Set funcs
        funcs['added'] = added_funcs
        funcs['deleted'] = deleted_funcs
        funcs['modified'] = modified_funcs

        # TODO Build Call Graphs

        # Set pdiff
        elapsed = time() - start
        pdiff['stats'] = {'added_funcs_len': len(added_funcs), 'deleted_funcs_len': len(deleted_funcs), 'modified_funcs_len': len(modified_funcs), 'added_symbols_len': len(
            symbols['added']), 'deleted_symbols_len': len(symbols['deleted']), 'diff_time': elapsed, 'match_types': Counter(all_match_types)}
        pdiff['symbols'] = symbols
        pdiff['functions'] = funcs

        pdiff['old_meta'] = self.get_metadata(p1)
        pdiff['new_meta'] = self.get_metadata(p2)

        # analysis options used (just check p1, same used for both)
        pdiff['analysis_options'] = self.get_analysis_options(p1)

        self.project.close(p1)
        self.project.close(p2)

        return pdiff

    def get_command_line(self, pdiff) -> str:

        # create command line to generate current diff

        # assert len(pdiff) > 1, 'Pdiff needs to exist to create command line!'

        # cmd = f"{file} "
        pass

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

    def _wrap_with_diff(self, diff: str) -> str:

        text = ''
        text += "```diff\n"
        text += diff
        text += "```\n"
        text += "\n"

        return text

    def _wrap_with_details(self, diff: str, summary: str = None) -> str:

        text = ''
        text += "<details>\n"
        if summary:
            text += f"<summary>{summary}</summary>"
        text += diff
        text += "\n</details>\n"

        return text

    def gen_esym_table(self, old_name, esym) -> str:

        table_list = []
        table_list.extend(['Key', old_name])
        column_len = len(table_list)

        skip_keys = ['code', 'instructions', 'mnemonics', 'blocks', 'parent']
        count = 1
        for key in esym:
            if key in skip_keys:
                continue
            table_list.extend([key, esym[key]])
            count += 1

        diff_table = Table().create_table(columns=column_len, rows=count, text=table_list, text_align='center')

        return diff_table

    def gen_esym_table_diff(self, old_name, new_name, modified) -> str:
        diff_table = ''

        table_list = []
        table_list.extend(['Key', old_name, new_name])
        column_len = len(table_list)

        skip_keys = ['code', 'instructions', 'mnemonics', 'blocks', 'parent']
        count = 1
        for key in modified['old']:
            if key in skip_keys:
                continue
            if key in modified['diff_type']:
                diff_key = f"`{key}`"
            else:
                diff_key = f"{key}"

            table_list.extend([diff_key, modified['old'][key], modified['new'][key]])
            count += 1

        diff_table = Table().create_table(columns=column_len, rows=count,
                                          text=table_list, text_align='center')

        return diff_table

    def gen_esym_table_diff_meta(self, old_name, new_name, modified) -> str:
        diff_table = ''

        table_list = []
        table_list.extend(['Key', f"{old_name} - {new_name}"])
        column_len = len(table_list)

        keys = ['diff_type', 'ratio', 'i_ratio', 'm_ratio', 'b_ratio', 'match_types']
        count = 1
        for key in keys:
            table_list.extend([key, modified[key]])
            count += 1

        diff_table = Table().create_table(columns=column_len, rows=count, text=table_list, text_align='center')

        return diff_table

    def gen_code_table_diff_html(self, old_code, new_code, old_name, new_name) -> str:
        """
        Generates side by side diff in HTML
        """

        if isinstance(old_code, str):
            old_code = old_code.splitlines(True)
        if isinstance(new_code, str):
            new_code = new_code.splitlines(True)

        diff_html = ''.join(list(difflib.HtmlDiff(tabsize=4).make_table(
            old_code, new_code, fromdesc=old_name, todesc=new_name)))
        diff_html = dedent(diff_html) + '\n'

        return diff_html

    def gen_table_from_dict(self, headers: list, items: dict):

        table = ''

        table_list = []
        table_list.extend(headers)
        column_len = len(table_list)

        count = 1
        for key, values in items.items():
            table_list.extend([key, values])
            count += 1

        table = Table().create_table(columns=column_len, rows=count, text=table_list, text_align='center')

        return table

    def gen_mermaid_diff_flowchart(self, pdiff: dict) -> str:

        diff_flow = '''
```mermaid

flowchart LR

{modified_links}

subgraph {new_bin}
    {new_modified}
    {added_sub}
end

subgraph {old_bin}
    {old_modified}
    {deleted_sub}
end

```'''

        added = []
        deleted = []
        modified_links = []
        old_modified = []
        new_modified = []

        old_bin = pdiff['old_meta']['Program Name']
        new_bin = pdiff['new_meta']['Program Name']

        for func in pdiff['functions']['added']:
            if func['external']:
                name = func['fullname']
            else:
                name = func['name']
            added.append(self._clean_md_header(name))

        for func in pdiff['functions']['deleted']:
            if func['external']:
                name = func['fullname']
            else:
                name = func['name']
            deleted.append(self._clean_md_header(name))

        for modified in pdiff['functions']['modified']:

            if 'code' in modified['diff_type']:
                old_modified.append(self._clean_md_header(
                    f"{modified['old']['name']}-{modified['old']['paramcount']}-old"))
                new_modified.append(self._clean_md_header(
                    f"{modified['new']['name']}-{modified['old']['paramcount']}-new"))
                modified_links.append(
                    f"{self._clean_md_header(modified['old']['name'])}-{modified['old']['paramcount']}-old<--Match {int(modified['b_ratio']*100)}%-->{self._clean_md_header(modified['new']['name'])}-{modified['old']['paramcount']}-new")

        deleted_sub = ''
        added_sub = ''
        if len(deleted) > 0:
            deleted_sub = '''subgraph Deleted\ndirection LR\n{}\nend'''.format('\n    '.join(deleted))
        if len(added) > 0:
            added_sub = '''subgraph Added\ndirection LR\n{}\nend'''.format('\n    '.join(added))

        return diff_flow.format(old_bin=old_bin, new_bin=new_bin, added_sub=added_sub, deleted_sub=deleted_sub, modified_links='\n'.join(modified_links), old_modified='\n'.join(old_modified), new_modified='\n'.join(new_modified))

    def gen_mermaid_pie_from_dict(self, data: dict, title: str, skip_keys: list = None, include_keys: list = None) -> str:
        """
        Generate basic mermaidjs Pie chart from dict
        skip_keys: [ 'skipkey1', 'skipkey45'] List of keys to skip from Dict
        includes_keys: ['random_key1', 'otherkey2'] - Only include these keys
        Default: include all keys and values from dict.
        """

        pie_template = '''
```mermaid
pie showData
    title {title}
{rows}
```
'''
        rows = []

        for key, value in data.items():

            row = None

            if skip_keys and key in skip_keys:
                continue

            if include_keys:
                if key in include_keys:
                    row = f'"{self._clean_md_header(key)}" : {value}'
            else:
                row = f'"{self._clean_md_header(key)}" : {value}'

            if row:
                rows.append(row)

        return pie_template.format(title=title, rows='\n'.join(rows))

    def _clean_md_header_lower(self, text):
        return re.sub('[^a-z0-9_\-]', '', text.lower().replace(' ', '-'))

    def _clean_md_header(self, text):
        return re.sub('[^A-Za-z0-9_\-]', '', text.replace(' ', '-'))

    def gen_diff_md(
        self,
        pdiff: Union[str, dict],
        side_by_side: bool = False,
    ) -> str:
        """
        Generate Markdown Diff from pdiff match results
        """

        if isinstance(pdiff, str):
            pdiff = json.loads(pdiff)

        funcs = pdiff['functions']

        old_name = pdiff['old_meta']['Program Name']
        new_name = pdiff['new_meta']['Program Name']

        md = MdUtils('example', f"{old_name}-{new_name} Diff")

        md.new_header(1, 'Visual Chart Diff')
        md.new_paragraph(self.gen_mermaid_diff_flowchart(pdiff))

        # Create Metadata section
        md.new_header(1, 'Metadata')

        md.new_header(2, 'Ghidra Diff Engine')

        md.new_header(3, 'Command Line')
        # md.new_paragraph(self.get_command_line(pdiff))

        md.new_header(3, 'Ghidra Analysis Options', add_table_of_contents='n')
        md.new_paragraph(self._wrap_with_details(self.gen_table_from_dict(
            ['Analysis Option', 'Value'], pdiff['analysis_options'])))

        md.new_header(2, 'Binary Metadata Diff')
        md.new_paragraph(self._wrap_with_diff(self.gen_metadata_diff(pdiff)))

        md.new_header(2, 'Diff Stats')
        md.new_paragraph(self.gen_table_from_dict(['Stat', 'Value'], pdiff['stats']))
        md.new_paragraph(self.gen_mermaid_pie_from_dict(pdiff['stats']['match_types'], 'Match Types'))
        md.new_paragraph(self.gen_mermaid_pie_from_dict(pdiff['stats'], 'Diff Stats', skip_keys=[
                         'match_types', 'diff_time', 'added_symbols_len', 'deleted_symbols_len']))
        md.new_paragraph(self.gen_mermaid_pie_from_dict(
            pdiff['stats'], 'Symbols', include_keys=['added_symbols_len', 'deleted_symbols_len']))

        # Create Deleted section
        md.new_header(1, 'Deleted')

        for esym in funcs['deleted']:
            old_code = esym['code'].splitlines(True)
            new_code = ''.splitlines(True)
            diff = ''.join(list(difflib.unified_diff(old_code, new_code,
                                                     lineterm='\n', fromfile=old_name, tofile=new_name)))
            if esym['external']:
                md.new_header(2, esym['fullname'])
            else:
                md.new_header(2, esym['name'])
            md.new_header(3, "Function Meta", add_table_of_contents='n')
            md.new_paragraph(self.gen_esym_table(old_name, esym))
            md.new_paragraph(self._wrap_with_diff(diff))

        # Create Added section
        md.new_header(1, 'Added')

        for esym in funcs['added']:
            old_code = ''.splitlines(True)
            new_code = esym['code'].splitlines(True)
            diff = ''.join(list(difflib.unified_diff(old_code, new_code,
                                                     lineterm='\n', fromfile=old_name, tofile=new_name)))
            if esym['external']:
                md.new_header(2, esym['fullname'])
            else:
                md.new_header(2, esym['name'])
            md.new_header(3, "Function Meta", add_table_of_contents='n')
            md.new_paragraph(self.gen_esym_table(old_name, esym))
            md.new_paragraph(self._wrap_with_diff(diff))

        # Create Modified section
        md.new_header(1, 'Modified')
        md.new_paragraph(f"*Modified functions contain code changes*")
        for modified in funcs['modified']:

            diff = None

            # selectively include matches
            if 'code' in modified['diff_type']:

                md.new_header(2, modified['old']['name'])

                md.new_header(3, "Match Info", add_table_of_contents='n')
                md.new_paragraph(self.gen_esym_table_diff_meta(old_name, new_name, modified))

                md.new_header(3, "Function Meta Diff", add_table_of_contents='n')
                md.new_paragraph(self.gen_esym_table_diff(old_name, new_name, modified))

                md.new_header(3, f"{modified['old']['name']} Diff", add_table_of_contents='n')
                md.new_paragraph(self._wrap_with_diff(modified['diff']))

                # only include side by side diff if requested (this adds html to markdown and considerable size)
                if side_by_side:
                    md.new_header(3, f"{modified['old']['name']} Side By Side Diff", add_table_of_contents='n')
                    html_diff = self.gen_code_table_diff_html(
                        modified['old']['code'], modified['new']['code'], old_name, new_name)
                    md.new_paragraph(self._wrap_with_details(html_diff))

        # Create Slightly Modified secion
        # slightly as in no code changes but other relevant changes.
        slight_mods = ['refcount', 'length', 'called', 'calling', 'name', 'fullname']

        md.new_header(1, 'Modified (No Code Changes)')
        md.new_paragraph(f"*Slightly modified functions have no code changes, rather differnces in:*")
        md.new_list(slight_mods)

        for modified in funcs['modified']:

            mods = set(slight_mods).intersection(set(modified['diff_type']))

            if 'code' not in modified['diff_type'] and len(mods) > 0:

                if modified['old']['name'].startswith('FUN_') or modified['new']['name'].startswith('FUN_'):

                    ignore_called = False
                    ignore_calling = False

                    if len(modified['old']['called']) > 0 and len(modified['new']['called']) > 0:
                        called_set = set(modified['old']['called']).difference(modified['new']['called'])
                        ignore_called = all('FUN_' in name for name in list(called_set))

                    if len(modified['old']['calling']) > 0 and len(modified['new']['calling']) > 0:
                        calling_set = set(modified['old']['calling']).difference(modified['new']['calling'])
                        ignore_calling = all('FUN_' in name for name in list(calling_set))

                    # skip name and fullname changes
                    if len(mods.difference(['name', 'fullname'])) == 0:
                        continue
                    # if all called are FUN_ skip
                    elif 'called' in modified['diff_type'] and 'calling' in modified['diff_type'] and ignore_called and ignore_calling:
                        continue
                    elif 'calling' in modified['diff_type'] and ignore_calling:
                        continue
                    elif 'called' in modified['diff_type'] and called_set:
                        continue

                # only include in TOC if code change
                md.new_header(2, modified['old']['name'])

                md.new_header(3, "Match Info", add_table_of_contents='n')
                md.new_paragraph(self.gen_esym_table_diff_meta(old_name, new_name, modified))

                md.new_header(3, "Function Meta Diff", add_table_of_contents='n')
                md.new_paragraph(self.gen_esym_table_diff(old_name, new_name, modified))

        md.new_table_of_contents('TOC', 3)

        return md.get_md_text()

    def dump_pdiff_to_dir(
        self,
        name: str,
        pdiff: Union[str, dict],
        dir: Union[str, pathlib.Path],
        side_by_side: bool = False,
    ) -> None:
        """
        Dump pdiff result to directory
        """

        if isinstance(pdiff, str):
            pdiff = json.loads(pdiff)

        dir = pathlib.Path(dir)

        md_path = dir / pathlib.Path(name + '.md')
        json_path = dir / pathlib.Path(name + '.json')

        diff_text = self.gen_diff_md(pdiff, side_by_side=side_by_side)

        with md_path.open('w') as f:
            f.write(diff_text)

        with json_path.open('w') as f:
            json.dump(pdiff, f, indent=4)
