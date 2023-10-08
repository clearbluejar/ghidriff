from abc import ABCMeta, abstractmethod
from pathlib import Path
import json
import difflib
import argparse
import re
from time import time
from datetime import datetime
from collections import Counter
import concurrent.futures
from typing import List, Tuple, Union, TYPE_CHECKING
from argparse import Namespace
import logging

from pyhidra.launcher import PyhidraLauncher, GHIDRA_INSTALL_DIR
from .utils import sha1_file, get_microsoft_download_url, get_pe_extra_data
from .markdown import GhidriffMarkdown

import multiprocessing

from ghidriff import __version__

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


class HeadlessLoggingPyhidraLauncher(PyhidraLauncher):
    """
    Headless pyhidra launcher
    Slightly Modified from Pyhidra to allow the Ghidra log path to be set
    """

    def __init__(self, verbose=False, log_path=None):
        super().__init__(verbose)
        self.log_path = log_path

    def _launch(self):
        from pyhidra.launcher import _silence_java_output
        from ghidra.framework import Application, HeadlessGhidraApplicationConfiguration
        from java.io import File
        with _silence_java_output(not self.verbose, not self.verbose):
            config = HeadlessGhidraApplicationConfiguration()
            if self.log_path:
                log = File(self.log_path)
                config.setApplicationLogFile(log)

            Application.initializeApplication(self.layout, config)


class GhidraDiffEngine(GhidriffMarkdown, metaclass=ABCMeta):
    """
    Base Ghidra Diff Engine
    """

    def __init__(
            self,
            args: Namespace = None,
            verbose: bool = True,
            threaded: bool = False,
            max_workers=multiprocessing.cpu_count(),
            max_ram_percent: float = 60.0,
            print_jvm_flags: bool = False,
            jvm_args: List[str] = [],
            force_analysis: bool = False,
            force_diff: bool = False,
            verbose_analysis: bool = False,
            no_symbols: bool = False,
            engine_log_path: Path = None,
            engine_log_level: int = logging.INFO,
            engine_file_log_level: int = logging.INFO,
            max_section_funcs: int = 200,
            min_func_len: int = 10) -> None:

        # setup engine logging
        self.logger = self.setup_logger(engine_log_level)

        self.logger.info('Init Ghidra Diff Engine...')
        self.logger.info(f'Engine Console Log: {engine_log_level}')

        if engine_log_path:
            # send application log to output path
            self.add_log_to_path(engine_log_path, engine_log_level)
            self.logger.info(f'Engine File Log:  {engine_log_path} {engine_file_log_level}')
        else:
            self.logger.warn('Engine File Log: {engine_log_path}')

        # Init Pyhidra
        launcher = HeadlessLoggingPyhidraLauncher(verbose=verbose, log_path=engine_log_path)

        # JVM Settings

        # max % of host RAM
        launcher.add_vmargs(f'-XX:MaxRAMPercentage={max_ram_percent}')

        # want JVM to crash if we run out of memory (otherwise no error it propagated)
        launcher.add_vmargs('-XX:+CrashOnOutOfMemoryError')
        launcher.add_vmargs('-XX:+HeapDumpOnOutOfMemoryError')

        # Set Ghidra Heap Max
        # Ghidra/RuntimeScripts/Linux/support/analyzeHeadless#L7
        # MAX_MEM = "16G"
        # launcher.add_vmargs(f"-Xmx{MAX_MEM}")

        if print_jvm_flags:
            launcher.add_vmargs('-XX:+PrintFlagsFinal')

        if jvm_args:
            for jvm_arg in jvm_args:
                self.logger.info('Adding JVM arg {jvm_arg}')
                launcher.add_vmargs(jvm_arg)

        self.logger.info(f'Starting Ghidra...')
        self.logger.debug(f'Starting JVM with args: {launcher.vm_args}')

        launcher.start()

        self.logger.info(f'GHIDRA_INSTALL_DIR: {GHIDRA_INSTALL_DIR}')
        app_prop = launcher.layout.getApplicationProperties()
        self.logger.info(
            f'GHIDRA {app_prop.applicationVersion}  Build Date: {app_prop.applicationBuildDate} Release: {app_prop.applicationReleaseName}')
        self.logger.info(f"Engine Args:")
        for arg in vars(args):
            self.logger.info('\t%-20s%s', f'{arg}:', vars(args)[arg])

        self.launcher = launcher
        self.threaded = threaded
        self.max_workers = max_workers
        self.max_section_funcs = max_section_funcs
        self.min_func_len = min_func_len

        # store args used from init
        self.args = args

        # Setup decompiler interface
        self.decompilers = {}

        self.project: "ghidra.base.project.GhidraProject" = None

        self.version = __version__

        # Global instance var to store symbol lookup results
        self.esym_memo = {}

        # set instance preferences
        self.force_analysis = force_analysis
        self.force_diff = force_diff
        self.verbose_analysis = verbose_analysis
        self.no_symbols = no_symbols

        # if looking up more than calling_count_funcs_limit symbols, skip function counts
        self.calling_count_funcs_limit = 500

        self.logger.debug(f'{vars(self)}')

    @ staticmethod
    def add_ghidra_args_to_parser(parser: argparse.ArgumentParser) -> None:
        """
        Add required Ghidra args to a parser
        """

        group = parser.add_argument_group('Ghidra Project Options')
        group.add_argument('-p', '--project-location', help='Ghidra Project Path', default='.ghidra_projects')
        group.add_argument('-n', '--project-name', help='Ghidra Project Name', default='ghidriff')
        group.add_argument('-s', '--symbols-path', help='Ghidra local symbol store directory', default='.symbols')

        group = parser.add_argument_group('Engine Options')
        group.add_argument('--threaded', help='Use threading during import, analysis, and diffing. Recommended',
                           default=True,  action=argparse.BooleanOptionalAction)
        group.add_argument('--force-analysis', help='Force a new binary analysis each run (slow)',
                           action='store_true')
        group.add_argument('--force-diff', help='Force binary diff (ignore arch/symbols mismatch)',
                           action='store_true')
        group.add_argument('--no-symbols', help='Turn off symbols for analysis', action='store_true')
        group.add_argument('--log-level', help='Set console log level',
                           default='INFO', choices=logging._nameToLevel.keys())
        group.add_argument('--file-log-level', help='Set log file level',
                           default='INFO', choices=logging._nameToLevel.keys())
        group.add_argument('--log-path', help='Set ghidriff log path.', default='ghidriff.log')
        group.add_argument('--va', '--verbose-analysis',
                           help='Verbose logging for analysis step.', action='store_true')

        # TODO add following option
        # group.add_argument('--exact-matches', help='Only consider exact matches', action='store_true')

        group = parser.add_argument_group('JVM Options')
        group.add_argument('--max-ram-percent', help='Set JVM Max Ram %% of host RAM', default=60.0)
        group.add_argument('--print-flags', help='Print JVM flags at start', action='store_true')
        group.add_argument('--jvm-args', nargs='?', help='JVM args to add at start', default=None)

        group = parser.add_argument_group('Markdown Options')
        group.add_argument('--sxs', dest='side_by_side', action='store_true',
                           help='Include side by side code diff')
        group.add_argument('--max-section-funcs',
                           help='Max number of functions to display per section.', type=int, default=200)
        group.add_argument('--md-title', help='Overwrite default title for markdown diff', type=str, default=None)

    def get_default_args(self) -> list:
        """
        Return list of default args for engine
        """

        parser = argparse.ArgumentParser()

        self.add_ghidra_args_to_parser(parser)

        defaults = vars(parser.parse_args([]))

        return defaults

    def setup_logger(self, level: int = logging.INFO) -> logging.Logger:
        """
        Setup Class Instance Logger
        """
        logging.basicConfig(
            format='%(levelname)-5s| %(name)s | %(message)s',
            datefmt='%H:%M:%S'
        )

        logger = logging.getLogger(__package__)
        logger.setLevel(level)

        return logger

    def add_log_to_path(self, log_path: Path, level: int = logging.INFO):
        """
        Directory to write log to
        """
        file_handler = logging.FileHandler(log_path)
        formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)-8s %(message)s')

        file_handler.setFormatter(formatter)
        file_handler.setLevel(level)
        self.logger.addHandler(file_handler)

    def gen_credits(self, html: bool = False) -> str:
        """
        Generate script credits
        """
        now = datetime.now().replace(microsecond=0).isoformat()
        if html:
            text = f"\n<sub>Generated with <code>{__package__}</code> version: {self.version} on {now}</sub>"
        else:
            text = f"\n<sub>Generated with `{__package__}` version: {self.version} on {now}</sub>"

        return text

    def enhance_sym(self, sym: 'ghidra.program.model.symbol.Symbol', thread_id: int = 0, timeout: int = 15, get_decomp_info: bool = False, use_calling_counts: bool = False) -> dict:
        """
        Standardize enhanced symbol. Use esym_memo to speed things up.
        Inspired by Ghidra/Features/VersionTracking/src/main/java/ghidra/feature/vt/api/main/VTMatchInfo.java
        timeout is for decompiler. -1 is infinite, and too long
        """

        from ghidra.program.model.symbol import SymbolType

        # key = f'{sym.iD}-{sym.program.name}-{get_decomp_info}-{use_calling_counts}'
        key = f'{sym.iD}-{sym.program.name}'

        # if sym.getName() == 'SepAppendAceToTokenObjectAcl':
        #     print('hi')

        if key not in self.esym_memo:

            from ghidra.util.task import ConsoleTaskMonitor

            monitor = ConsoleTaskMonitor()
            prog = sym.program
            func: 'ghidra.program.model.listing.Function' = prog.functionManager.getFunctionAt(sym.address)

            if not sym.symbolType == SymbolType.FUNCTION:

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
                                       'address': str(sym.getAddress()), 'sym_type': str(sym.getSymbolType()), 'sym_source': str(sym.source), 'external': sym.external}

            else:
                # proces function

                instructions = []
                mnemonics = []
                blocks = []
                called_funcs = []
                calling_funcs = []
                code = ''

                if get_decomp_info:

                    code_units = func.getProgram().getListing().getCodeUnits(func.getBody(), True)

                    # instruction and mnemonic bulker
                    for code in code_units:
                        instructions.append(str(code))
                        mnemonics.append(str(code.mnemonicString))

                    from ghidra.program.model.block import BasicBlockModel

                    # Basic Block Bulker
                    basic_model = BasicBlockModel(func.getProgram(), True)
                    basic_blocks = basic_model.getCodeBlocksContaining(func.getBody(), monitor)

                    for block in basic_blocks:
                        code_units = func.getProgram().getListing().getCodeUnits(block, True)
                        for code in code_units:
                            blocks.append(str(code.mnemonicString))

                    # sort - This case handles the case for compiler optimizations
                    blocks = sorted(blocks)

                    if not func.external:
                        error, code = self.decompile_func(func.program, func, timeout,)

                        if error:
                            err = f'Failed to decompile {func.program} {func} : {error}'
                            self.logger.warn(err)
                            code = err

                # if use_calling_counts:
                if False:
                    for f in func.getCalledFunctions(monitor):
                        count = 0
                        print(len(f.symbol.references))
                        for ref in f.symbol.references:
                            if func.getBody().contains(ref.fromAddress, ref.fromAddress):
                                count += 1
                        called_funcs.append(f'{f}-{count}')

                    for f in func.getCallingFunctions(monitor):
                        count = 0
                        print(len(func.symbol.references))
                        for ref in func.symbol.references:
                            if f.getBody().contains(ref.fromAddress, ref.fromAddress):
                                count += 1
                        called_funcs.append(f'{f}-{count}')
                else:
                    for f in func.getCalledFunctions(monitor):
                        called_funcs.append(f'{f}')
                    for f in func.getCallingFunctions(monitor):
                        calling_funcs.append(f'{f}')

                called_funcs = sorted(called_funcs)
                calling_funcs = sorted(calling_funcs)
                parent_namespace = sym.getParentNamespace().toString().split('@')[0]

                self.esym_memo[key] = {'name': sym.getName(), 'fullname': sym.getName(True),  'parent':  parent_namespace, 'refcount': sym.getReferenceCount(), 'length': func.body.numAddresses, 'called': called_funcs,
                                       'calling': calling_funcs, 'paramcount': func.parameterCount, 'address': str(sym.getAddress()), 'sig': str(func.getSignature(False)), 'code': code,
                                       'instructions': instructions, 'mnemonics': mnemonics, 'blocks': blocks, 'sym_type': str(sym.getSymbolType()), 'sym_source': str(sym.source), 'external': sym.external}

        return self.esym_memo[key]

    def setup_project(
            self,
            binary_paths: List[Union[str, Path]],
            project_location: Union[str, Path],
            project_name: str,
            symbols_path: Union[str, Path],
            symbol_urls: list = None,
    ) -> list:
        """
        Setup and verify Ghidra Project
        1. Creat / Open Project
        2. Import / Open Binaries
        3. Configure and verify symbols
        """
        from ghidra.base.project import GhidraProject
        from java.io import IOException
        from ghidra.app.plugin.core.analysis import PdbAnalyzer
        from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer

        project_location = Path(project_location) / project_name
        project_location.mkdir(exist_ok=True, parents=True)
        pdb = None

        self.logger.info(f'Setting Up Ghidra Project...')

        # Open/Create project
        project = None

        # remove duplicate paths, maintain order
        binary_paths = list(dict.fromkeys(binary_paths))

        # remove duplicate files (different path, but same content)
        bin_hashes = []
        for i, bin_hash in enumerate([sha1_file(path) for path in binary_paths]):

            if bin_hash in bin_hashes:
                self.logger.warn(f'Duplicate file detected {binary_paths[i]} with sha1: {bin_hash}')
                binary_paths.pop(i)
            else:
                bin_hashes.append(bin_hash)

        try:
            project = GhidraProject.openProject(project_location, project_name, True)
            self.logger.info(f'Opened project: {project.project.name}')
        except IOException:
            project = GhidraProject.createProject(project_location, project_name, False)
            self.logger.info(f'Created project: {project.project.name}')

        self.project = project

        self.logger.info(f'Project Location: {project.project.projectLocator.location}')

        bin_results = []
        proj_programs = []

        # Import binaries and configure symbols
        for program_path in binary_paths:

            # add sha1 to prevent files with same name collision
            program_name = self.gen_proj_bin_name_from_path(program_path)

            # Import binaries and configure symbols
            if not project.getRootFolder().getFile(program_name):
                self.logger.info(f'Importing {program_path} as {program_name}')
                program = project.importProgram(program_path)
                project.saveAs(program, "/", program_name, True)
            else:
                self.logger.info(f'Opening {program_path}')
                program = self.project.openProgram("/", program_name, False)

            proj_programs.append(program)

        # Setup Symbols Server
        if not self.no_symbols:
            if any(self.prog_is_windows(prog) for prog in proj_programs):
                # Windows level 1 symbol server location
                level = 1
            else:
                # Symbols stored in specified symbols path
                level = 0
            self.setup_symbol_server(symbols_path, level, server_urls=symbol_urls)

        for program in proj_programs:

            if not self.no_symbols:
                # Enable Remote Symbol Servers
                PdbUniversalAnalyzer.setAllowRemoteOption(program, True)
                PdbAnalyzer.setAllowRemoteOption(program, True)

                pdb = self.get_pdb(program)
            else:
                # Run get_pdb to make sure the symbols dont exist locally
                pdb = self.get_pdb(program, allow_remote=False)

                if pdb:
                    err = f'Symbols are disabled, but the symbol is already downloaded {pdb}. Delete symbol or remove --no-symbol flag'
                    self.logger.error(err)
                    raise FileExistsError(err)

            if pdb is None and not self.no_symbols:
                self.logger.warn(f"PDB not found for {program.getName()}!")

            from ghidra.app.util.pdb import PdbProgramAttributes

            pdb_attr = PdbProgramAttributes(program)

            imported = program is not None
            has_pdb = pdb is not None
            pdb_loaded = pdb_attr.pdbLoaded
            prog_analyzed = pdb_attr.programAnalyzed

            # TODO only save if changes are made
            # project.save(program)
            project.close(program)

            bin_results.append([program.getExecutablePath(), imported, has_pdb, pdb_loaded, prog_analyzed])

        for result in bin_results:
            self.logger.info('Program: %s imported: %s has_pdb: %s pdb_loaded: %s analyzed %s', *result)

        return bin_results

    def setup_decompliers(
        self,
        p1: "ghidra.program.model.listing.Program",
        p2: "ghidra.program.model.listing.Program"
    ) -> bool:
        """
        Setup decompliers to use during diff bins. Each one must be initialized with a program.
        """

        from ghidra.app.decompiler import DecompInterface
        from ghidra.app.decompiler import DecompileOptions

        p1_options = DecompileOptions()
        p2_options = DecompileOptions()

        # grab default options from program
        p1_options.grabFromProgram(p1)
        p2_options.grabFromProgram(p2)

        # increase maxpayload size to 100MB (default 50MB)
        p1_options.setMaxPayloadMBytes(100)
        p2_options.setMaxPayloadMBytes(100)

        if self.threaded:
            decompiler_count = 2 * self.max_workers
            for i in range(self.max_workers):
                self.decompilers.setdefault(p1.name, {}).setdefault(i, DecompInterface())
                self.decompilers.setdefault(p2.name, {}).setdefault(i, DecompInterface())
                self.decompilers[p1.name][i].setOptions(p1_options)
                self.decompilers[p2.name][i].setOptions(p2_options)
                self.decompilers[p1.name][i].openProgram(p1)
                self.decompilers[p2.name][i].openProgram(p2)
                self.decompilers[p1.name].setdefault('available', []).append(i)
                self.decompilers[p2.name].setdefault('available', []).append(i)
        else:
            decompiler_count = 2
            self.decompilers.setdefault(p1.name, {}).setdefault(0, DecompInterface())
            self.decompilers.setdefault(p2.name, {}).setdefault(0, DecompInterface())
            self.decompilers[p1.name][0].setOptions(p1_options)
            self.decompilers[p2.name][0].setOptions(p2_options)
            self.decompilers[p1.name][0].openProgram(p1)
            self.decompilers[p2.name][0].openProgram(p2)
            self.decompilers[p1.name].setdefault('available', []).append(0)
            self.decompilers[p2.name].setdefault('available', []).append(0)

        self.logger.info(f'Setup {decompiler_count} decompliers')

        return True

    def shutdown_decompilers(
        self,
        p1: "ghidra.program.model.listing.Program",
        p2: "ghidra.program.model.listing.Program"
    ) -> bool:
        """
        Shutdown decompliers
        """

        if self.threaded:
            for i in range(self.max_workers):
                self.decompilers[p1.name][i].closeProgram()
                self.decompilers[p2.name][i].closeProgram()
        else:
            self.decompilers[p1.name][0].closeProgram(p1)
            self.decompilers[p2.name][0].closeProgram(p2)

        self.decompilers = {}

    def decompile_func(
        self,
        prog: "ghidra.program.model.listing.Program",
        func: 'ghidra.program.model.listing.Function',
        timeout: int = 15
    ) -> List[str]:

        from ghidra.util.task import ConsoleTaskMonitor

        code = ''
        error = ''
        decomp_id = None
        monitor = ConsoleTaskMonitor()

        # list operations are atomic. right?
        while decomp_id == None:
            try:
                decomp_id = self.decompilers[prog.name]['available'].pop()
            except IndexError:
                pass

        results: 'ghidra.app.decompiler.DecompileResults' = self.decompilers[prog.name][decomp_id].decompileFunction(
            func, timeout, monitor)

        error = results.getErrorMessage()
        if error == '':
            code = results.getDecompiledFunction().getC()
        else:
            error = f'Error: Decompile error: {error}'

        # set decomp as available
        self.decompilers[prog.name]['available'].append(decomp_id)

        return error, code

    def get_pdb(self, prog: "ghidra.program.model.listing.Program", allow_remote=True) -> "java.io.File":
        """
        Searches the currently configured symbol server paths for a Pdb symbol file.
        If remote is enabled, downloads pdb to saved SymbolService path
        """

        from pdb_.symbolserver import FindOption
        from ghidra.util.task import ConsoleTaskMonitor
        from pdb_ import PdbPlugin

        if allow_remote:
            find_opts = FindOption.of(FindOption.ALLOW_REMOTE)
        else:
            find_opts = FindOption.NO_OPTIONS

        # Ghidra/Features/PDB/src/main/java/pdb/PdbPlugin.java#L191
        pdb = PdbPlugin.findPdb(prog, find_opts, ConsoleTaskMonitor())

        if pdb is not None:
            self.logger.info(f'Pdb stored at: {pdb}')

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
                pdb = Path(pdb.absoluteFile.toString())
                self.logger.info(f"PDB {pdb} found for {prog_name}")

            pdb_list.append([prog_name, pdb])

        return pdb_list

    # program: "ghidra.program.model.listing.Program",
    def setup_symbol_server(self,  symbols_path: Union[str, Path], level=0, server_urls=None) -> None:
        """setup symbols to allow Ghidra to download as needed
        1. Configures symbol_path as local symbol store path
        2. Sets Index level for local symbol path
        - Level 0 indexLevel is a special Ghidra construct that is just a user-friendlier plain directory with a collection of Pdb files
        [symbol-store-folder-tree](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbol-store-folder-tree) (applies to 1 and 2)
        - Level 1, with pdb files stored directly underthe root directory
        - Level 2, using the first 2 characters of the pdb filename as a bucket to place each pdb file-directory in
        """

        self.logger.info("Setting up Symbol Server for symbols...")
        self.logger.info(f"path: {symbols_path} level: {level}")

        symbols_path = Path(symbols_path).absolute()

        from pdb_ import PdbPlugin
        from pdb_.symbolserver import LocalSymbolStore
        from pdb_.symbolserver import HttpSymbolServer
        from pdb_.symbolserver import SymbolServerService
        from ghidra.framework import Application

        from java.io import File
        from java.net import URI
        from java.util import ArrayList

        # Configure local symbols directory
        symbolsDir = File(symbols_path)
        localSymbolStore = LocalSymbolStore(symbols_path)

        # Create loacl symbold soCreates a MS-compatible symbol server directory location. pdb/symbolserver/LocalSymbolStore.java#L67
        localSymbolStore.create(symbolsDir, level)

        # Configure symbol urls
        if server_urls is None:
            # load wellknown servers
            # Ghidra/Features/PDB/src/main/java/pdb/symbolserver/ui/WellKnownSymbolServerLocation.java#L89
            known_urls = []
            pdbUrlFiles = Application.findFilesByExtensionInApplication(".pdburl")
            for pdbFile in pdbUrlFiles:
                data = Path(pdbFile.absolutePath).read_text()
                self.logger.debug(f"Loaded well known {pdbFile.absolutePath}' length: {len(data)}'")
                for line in data.splitlines(True):
                    cat, location, warning = line.split('|')
                    known_urls.append(location)
            server_urls = known_urls
        else:
            if not isinstance(server_urls, list):
                raise TypeError('server_urls must be a list of urls')

        sym_servers = ArrayList()

        for url in server_urls:
            sym_servers.add(HttpSymbolServer(URI.create(url)))

        symbolServerService = SymbolServerService(localSymbolStore, sym_servers)

        PdbPlugin.saveSymbolServerServiceConfig(symbolServerService)

        self.logger.info(f'Symbol Server Configured path: {symbolServerService.toString().strip()}')

    def analyze_program(self, df_or_prog: Union["ghidra.framework.model.DomainFile", "ghidra.program.model.listing.Program"], require_symbols: bool, force_analysis: bool = False, verbose_analysis: bool = False):

        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.framework.model import DomainFile
        from ghidra.program.model.listing import Program
        from ghidra.util.task import ConsoleTaskMonitor
        from ghidra.program.util import GhidraProgramUtilities
        from ghidra.app.script import GhidraScriptUtil
        from ghidra.app.util.pdb import PdbProgramAttributes

        if isinstance(df_or_prog, DomainFile):
            program = self.project.openProgram("/", df_or_prog.getName(), False)
        elif isinstance(df_or_prog, Program):
            program = df_or_prog

        self.logger.info(f"Analyzing: {program}")

        try:
            if verbose_analysis or self.verbose_analysis:
                monitor = ConsoleTaskMonitor()
                flat_api = FlatProgramAPI(program, monitor)
            else:
                flat_api = FlatProgramAPI(program)

            pdb_attr = PdbProgramAttributes(program)
            # force_reload_for_symbols = not pdb_attr.isPdbLoaded(
            # ) and not self.no_symbols and pdb_attr.isProgramAnalyzed()
            force_reload_for_symbols = False

            if force_reload_for_symbols:
                self.set_analysis_option_bool(program, 'PDB Universal', True)
                self.logger.info('Symbols missing. Re-analysis is required. Setting PDB Universal: True')
                self.logger.debug(f'pdb loaded: {pdb_attr.isPdbLoaded()} prog analyzed: {pdb_attr.isProgramAnalyzed()}')

            if GhidraProgramUtilities.shouldAskToAnalyze(program) or force_analysis or self.force_analysis or force_reload_for_symbols:
                GhidraScriptUtil.acquireBundleHostReference()

                # handle large binaries more efficiently
                # see ghidra/issues/4573 (turn off feature Shared Return Calls )
                if program and program.getFunctionManager().getFunctionCount() > 1000:
                    self.logger.warn(f"Turning off 'Shared Return Calls' for {program}")
                    self.set_analysis_option_bool(
                        program, 'Shared Return Calls.Assume Contiguous Functions Only', False)

                if self.no_symbols:
                    self.logger.warn(f'Disabling symbols for analysis! --no-symbols flag: {self.no_symbols}')
                    self.set_analysis_option_bool(program, 'PDB Universal', False)

                self.logger.info(f'Starting Ghidra analysis of {program}...')
                try:
                    flat_api.analyzeAll(program)
                    if hasattr(GhidraProgramUtilities, 'setAnalyzedFlag'):
                        GhidraProgramUtilities.setAnalyzedFlag(program, True)
                    elif hasattr(GhidraProgramUtilities, 'markProgramAnalyzed'):
                        GhidraProgramUtilities.markProgramAnalyzed(program)
                    else:
                        raise Exception('Missing set analyzed flag method!')
                finally:
                    GhidraScriptUtil.releaseBundleHostReference()
                    self.project.save(program)
            else:
                self.logger.info(f"Analysis already complete.. skipping {program}!")
        finally:
            self.project.close(program)

        self.logger.info(f"Analysis for {df_or_prog} complete")

        return df_or_prog

    def analyze_project(self, require_symbols: bool = True, force_analysis: bool = False, verbose_analysis: bool = False) -> None:
        """
        Analyzes all files found within the project
        """
        self.logger.info(f'Starting analysis for {len(self.project.getRootFolder().getFiles())} binaries')

        if self.threaded:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = (executor.submit(self.analyze_program, *[domainFile, require_symbols, force_analysis, verbose_analysis])
                           for domainFile in self.project.getRootFolder().getFiles() if domainFile.getContentType() == 'Program')
                for future in concurrent.futures.as_completed(futures):
                    prog = future.result()
        else:
            for domainFile in self.project.getRootFolder().getFiles():
                self.analyze_program(domainFile, require_symbols, force_analysis)

    def get_metadata(
        self,
        prog: "ghidra.program.model.listing.Program"
    ) -> dict:
        """
        Generate dict from program metadata
        """

        meta = prog.getMetadata()

        return dict(meta)

    def get_pe_download_url(
        self,
        path: Path,
        filename: str
    ) -> str:
        """
        Generate Microsoft PE download URL 
        """

        path = Path(path)
        pe_info = get_pe_extra_data(path)
        url = get_microsoft_download_url(filename, pe_info['timestamp'], pe_info['image_size'])

        # from ghidra.app.util.bin.format.pe import PortableExecutable
        # from ghidra.app.util.bin import FileByteProvider

        # from java.nio.file import AccessMode
        # from java.io import File

        # file_path = File(path)

        # bp = FileByteProvider(file_path, None, AccessMode.READ)

        # pe = PortableExecutable(bp, PortableExecutable.SectionLayout.FILE)
        # ntHeader = pe.getNTHeader()
        # if ntHeader is not None and ntHeader.getOptionalHeader() is not None:
        #     timestamp = abs(ntHeader.getFileHeader().getTimeDateStamp())
        #     virtual_size = ntHeader.getOptionalHeader().getSizeOfImage()

        # if timestamp is not None and virtual_size is not None and filename is not None:
        #     timestamp = format(timestamp, '08X')
        #     virtual_size = format(virtual_size, 'X')

        #     url = f'https://msdl.microsoft.com/download/symbols/{filename}/{timestamp}{virtual_size}/{filename}'

        return url

    def get_all_program_options(self,
                                prog: "ghidra.program.model.listing.Program"
                                ) -> dict:
        """
        Retrieve all program options
        Inspired by: Ghidra/Features/Base/src/main/java/ghidra/app/script/GhidraScript.java#L1272
        """

        all_options = {}

        for opt_name in prog.getOptionsNames():
            all_options[opt_name] = self.get_program_options(prog, opt_name)

        return all_options

    def get_program_options(
        self,
        prog: "ghidra.program.model.listing.Program",
        name: str
    ) -> dict:
        """
        Generate dict program options
        Inspired by: Ghidra/Features/Base/src/main/java/ghidra/app/script/GhidraScript.java#L1272
        """

        from ghidra.program.model.listing import Program

        possible_props = prog.getOptionsNames()

        if name not in possible_props:
            err = f'Program property name not found: {name} in {possible_props}'
            self.logger.error(err)
            raise err

        prog_options = prog.getOptions(name)
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
        See: Ghidra/Features/Base/src/main/java/ghidra/app/script/GhidraScript.java#L1272
        """

        from ghidra.program.model.listing import Program

        prog_options = prog.getOptions(Program.PROGRAM_INFO)

        prog_options.setBoolean(option_name, value)

    def prog_is_windows(
        self,
        prog: "ghidra.program.model.listing.Program"
    ) -> bool:
        """
        Determines if program is Windows
        "Compiler ID" == "windows"
        """

        meta = self.get_metadata(prog)

        return meta['Compiler ID'] == 'windows'

    def get_funcs_from_addr_set(
            self,
            prog: 'ghidra.program.database.ProgramDB',
            addr_set: 'ghidra.program.model.address.AddressSet',
            min_fun_len=None):
        """
        Build a list of functions that match a provided address set
        Ignores Thunks and functions smaller than `min_fun_len`
        """

        funcs = []

        if min_fun_len is None:
            min_fun_len = self.min_func_len

        for func in prog.functionManager.getFunctions(addr_set, True):
            if (not func.isThunk() and func.getBody().getNumAddresses() >= min_fun_len):
                funcs.append(func)

        return funcs

    @ abstractmethod
    def find_matches(
            self,
            p1: "ghidra.program.model.listing.Program",
            p2: "ghidra.program.model.listing.Program"
    ) -> list:
        """
        Find matching and unmatched functions between `p1` and `p2`
        return `[unmatched, matched, skip_types]`
        `unmatched` : list of symbols that have not been matched
        `matched` : list of symbols that have been matched
        `skip_types`: list of match combinations that should not be considered for diffing. skip types will undergo less processing
        """
        raise NotImplementedError

    # based on Features/Base/src/main/java/ghidra/app/plugin/match/MatchSymbol.java
    def is_sym_string(self, sym: 'ghidra.program.model.symbol.Symbol') -> bool:

        sym_addr = sym.getAddress()
        if sym_addr is not None:
            data = sym.getProgram().getListing().getDataAt(sym_addr)
            if data is not None and data.hasStringValue():
                return True

        return False

    def diff_nf_symbols(
        self,
        p1: "ghidra.program.model.listing.Program",
        p2: "ghidra.program.model.listing.Program"
    ) -> list:
        """
        Find matching and unmatched (non-function) symbols between p1 and p2
        """

        # find added and deleted symbols
        from ghidra.program.model.symbol import SymbolUtilities
        from ghidra.program.model.symbol import SourceType
        from ghidra.program.model.symbol import SymbolType
        from ghidra.program.model.listing import Function

        all_p1_syms = {}
        all_p2_syms = {}

        # build symbols dict

        # follow pattern for Ghidra/Features/Base/src/main/java/ghidra/app/plugin/match/MatchSymbol.java
        for sym in p1.getSymbolTable().getAllSymbols(True):
            if not sym.referenceCount == 0:
                # skip functions
                if not sym.symbolType == SymbolType.FUNCTION:
                    # don't include DEFAULT (FUN_ LAB_) but do include strings s_something
                    if sym.getSource() != SourceType.DEFAULT or self.is_sym_string(sym):
                        # skip local symbols
                        if not isinstance(sym.getParentNamespace(), Function):
                            # get name lacking '_' or '@'
                            clean_name = SymbolUtilities.getCleanSymbolName(sym.getName(), sym.address)
                            all_p1_syms[clean_name] = sym

        self.logger.info(f'p1 sym count: reported: {p1.symbolTable.numSymbols} analyzed: {len(all_p1_syms)}')

        for sym in p2.getSymbolTable().getAllSymbols(True):
            if not sym.referenceCount == 0:
                # skip functions
                if not sym.symbolType == SymbolType.FUNCTION:
                    # don't include DEFAULT (FUN_ LAB_) but do include strings s_something
                    if sym.getSource() != SourceType.DEFAULT or self.is_sym_string(sym):
                        # skip local symbols
                        if not isinstance(sym.getParentNamespace(), Function):
                            # get name lacking '_' or '@'
                            clean_name = SymbolUtilities.getCleanSymbolName(sym.getName(), sym.address)
                            all_p2_syms[clean_name] = sym

        self.logger.info(f'p2 sym count: reported: {p2.symbolTable.numSymbols} analyzed: {len(all_p2_syms)}')

        deleted_sym_keys = list(set(all_p1_syms.keys()).difference(all_p2_syms.keys()))
        added_syms_keys = list(set(all_p2_syms.keys()).difference(all_p1_syms.keys()))
        matching_sym_keys = list(set(all_p1_syms.keys()).intersection(all_p2_syms.keys()))

        unmatched = []
        matched = []

        # translate keys to symbols
        unmatched.extend([all_p1_syms[key] for key in deleted_sym_keys])
        unmatched.extend([all_p2_syms[key] for key in added_syms_keys])
        matched = [all_p1_syms[key] for key in matching_sym_keys]

        self.logger.info(f'Found unmatched: {len(unmatched)} matched: {len(matched)} symbols')

        return [unmatched, matched]

    def syms_need_diff(
        self,
        sym: 'ghidra.program.model.symbol.Symbol',
        sym2: 'ghidra.program.model.symbol.Symbol',
        match_types: list,
        skip_types: list = []
    ) -> bool:
        """
        Determine quickly if a function match requires a deeper diff
        If the the match type == any of the skip types. Return false.
        """

        from ghidra.program.model.symbol import SourceType

        func: 'ghidra.program.model.listing.Function' = sym.program.functionManager.getFunctionAt(sym.address)
        func2: 'ghidra.program.model.listing.Function' = sym2.program.functionManager.getFunctionAt(sym2.address)

        assert func is not None and func2 is not None

        need_diff = False

        if not any(skip_type in match_types for skip_type in skip_types):
            if func.body.numAddresses != func2.body.numAddresses:
                need_diff = True
            elif sym.referenceCount != sym2.referenceCount:
                need_diff = True

        return need_diff

    def gen_proj_bin_name_from_path(self, path: Path):
        """
        Generate unique project name from binary for Ghidra Project
        """

        return '-'.join((path.name, sha1_file(path.absolute())[:6]))

    def normalize_ghidra_decomp(self, code: list):
        """
        Normalize some of the dynamic labels to simplify the diff
        ie. Translate LAB_0003234 to LAB_0,LAB_1, etc.
        Renames based on first appearance in decompilation

        """

        default_labels = ['LAB', 'DAT', 'SUB', 'UNK', 'EXT', 'FUN_', 'OFF_']

        matches = {}
        for i, line in enumerate(code):

            for label in default_labels:

                match = re.search(fr'{label}_[0-9a-f]+', line)
                if match is not None:
                    if matches.get(match.group(0)) is None:
                        prefix = match.group(0).split('_')[0]
                        matches[match.group(0)] = f'{prefix}_{len(matches)}'
                    code[i] = line.replace(match.group(0), matches[match.group(0)])
                    # TODO fix this line to work when a line has multiple default label

    def diff_bins(
            self,
            old: Union[str, Path],
            new: Union[str, Path],
            ignore_FUN: bool = False,
            force_diff=False
    ) -> dict:
        """
        Diff the old and new binary from the GhidraProject.
        ignore_FUN : skip nameless functions matching names containing "FUN_". Useful for increasing speed of diff.
        last_attempt : flag to prevent infinte loop on recursive instances
        """

        self.logger.info(f'Diffing bins: {old} - {new}')

        start = time()

        # reset pdiff
        pdiff = {}

        old = Path(old)
        new = Path(new)

        p1_name = self.gen_proj_bin_name_from_path(old)
        p2_name = self.gen_proj_bin_name_from_path(new)

        # analysis options used
        pdiff['program_options'] = {}

        # need RW program to get full options
        p1 = self.project.openProgram("/", p1_name, False)

        if p1_name == p2_name:
            self.logger.warn(f'Diffed files have the same content. Are you sure you want to do this??')
            p2 = p1
        else:
            p2 = self.project.openProgram("/", p2_name, False)

        pdiff['program_options'][p1.name] = self.get_all_program_options(p1)
        pdiff['program_options'][p2.name] = self.get_all_program_options(p2)

        self.project.close(p1)
        self.project.close(p2)

        # now open both programs read-only
        p1 = self.project.openProgram("/", p1_name, True)
        if p1_name == p2_name:
            p2 = p1
        else:
            p2 = self.project.openProgram("/", p2_name, True)

        # setup decompilers
        self.setup_decompliers(p1, p2)

        self.logger.info(f"Loaded old program: {p1.name}")
        self.logger.info(f"Loaded new program: {p2.name}")

        if not force_diff and not self.force_diff:
            # ensure architectures match
            assert p1.languageID == p2.languageID, 'p1: {} != p2: {}. The arch or processor does not match. Add --force-diff to ignore this assert'

            # sanity check - ensure both programs have symbols, or both don't
            sym_count_diff = abs(p1.getSymbolTable().numSymbols - p2.getSymbolTable().numSymbols)
            assert sym_count_diff < 4000, f'Symbols counts between programs ({p1.name} and {p2.name}) are too high {sym_count_diff}! Likely bad analyiss or only one binary has symbols! Check Ghidra analysis or pdb! Add --force-diff to ignore this assert'

        # Find (non function) symbols
        unmatched_nf_syms, _ = self.diff_nf_symbols(p1, p2)

        # Find functions matches
        unmatched, matched, skip_types = self.find_matches(p1, p2)

        # dedupe unmatched funcs with syms by names (rare but somtimes Ghidra symbol types get crossed, or pdb parsing issues)
        self.logger.info('Deduping symbols and functions...')

        dupes = []
        for func in unmatched:
            for sym in unmatched_nf_syms:
                # ensure they are from different progs
                if func.getName(True) == sym.getName(True) and func.getProgram() != sym.getProgram():
                    dupes.append(func)
                    dupes.append(sym)

        for dupe in dupes:
            if dupe in unmatched:
                self.logger.warn(f'Removing function dupe: {dupe}')
                unmatched.remove(dupe)
            if dupe in unmatched_nf_syms:
                self.logger.warn(f'Removing symbol dupe: {dupe}')
                unmatched_nf_syms.remove(dupe)

        deleted_symbols = []
        added_symbols = []
        deleted_strings = []
        added_strings = []

        self.logger.info('Sorting symbols and strings...')

        for sym in unmatched_nf_syms:
            if sym.program == p1:
                if self.is_sym_string(sym):
                    self.logger.debug(f'Found deleted string: {sym}')
                    deleted_strings.append(sym)
                else:
                    deleted_symbols.append(sym)
            else:
                if self.is_sym_string(sym):
                    self.logger.debug(f'Found added string: {sym}')
                    added_strings.append(sym)
                else:
                    added_symbols.append(sym)

        symbols = {}
        funcs = {}
        strings = {}
        symbols['added'] = []
        symbols['deleted'] = []
        strings['added'] = []
        strings['deleted'] = []

        deleted_funcs = []
        added_funcs = []
        modified_funcs = []
        all_match_types = []
        all_diff_types = []
        funcs_need_decomp = []

        self.logger.info('Sorting functions...')

        # thread the symbol lookups
        #   esyms are memoized and can be later just read from memory
        if self.threaded:

            esym_lookups = []

            esym_lookups.extend(deleted_strings)
            esym_lookups.extend(added_strings)
            esym_lookups.extend(unmatched)

            # TODO consider removing this complexity
            funcs_need_decomp.extend(unmatched)

            for sym, sym2, match_types in matched:

                if not self.syms_need_diff(sym, sym2, match_types, skip_types):
                    continue

                funcs_need_decomp.append(sym)
                funcs_need_decomp.append(sym2)

            esym_lookups.extend(funcs_need_decomp)

            use_calling_counts = len(funcs_need_decomp) < self.calling_count_funcs_limit

            # TODO add code to symbols!

            # there can be duplicate multiple function matches, just do this once
            # esym_lookups = list(set(esym_lookups))

            self.logger.info(f'Starting esym lookups for {len(esym_lookups)} symbols using {self.max_workers} threads')

            completed = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # futures = (executor.submit(self.enhance_sym, sym, thread_id % self.max_workers, 15, (sym in funcs_need_decomp), (use_calling_counts and sym in funcs_need_decomp))
                futures = (executor.submit(self.enhance_sym, sym, thread_id % self.max_workers, 60, (sym in funcs_need_decomp), (use_calling_counts and sym in funcs_need_decomp))
                           for thread_id, sym in enumerate(esym_lookups))

                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    completed += 1
                    if (completed % int((len(esym_lookups) * .05) + 1) == 0):
                        self.logger.info(f'Completed {completed} at {int(completed/len(esym_lookups)*100)}%')

        for sym in deleted_symbols:
            symbols['deleted'].append(sym.name)

        for sym in added_symbols:
            symbols['added'].append(sym.name)

        for sym in deleted_strings:
            strings['deleted'].append(self.enhance_sym(sym))

        for sym in added_strings:
            strings['added'].append(self.enhance_sym(sym))

        for lost in unmatched:
            elost = self.enhance_sym(lost)

            # deleted func
            if lost.getProgram().getName() == p1.getName():
                deleted_funcs.append(elost)
            else:
                added_funcs.append(elost)

        for sym, sym2, match_types in matched:

            first_match = match_types[0]
            all_match_types.append(first_match)

            if not self.syms_need_diff(sym, sym2, match_types, skip_types):
                continue

            diff_type = []
            diff = ''
            only_code_diff = ''

            ematch_1 = self.enhance_sym(sym)
            ematch_2 = self.enhance_sym(sym2)

            old_code = ematch_1['code'].splitlines(True)
            new_code = ematch_2['code'].splitlines(True)

            old_code_no_sig = ematch_1['code'].split('{', 1)[1].splitlines(
                True) if ematch_1['code'] is not None and "Failed to decompile" not in ematch_1['code'] and '{' in ematch_1['code'] else ematch_1['code']

            new_code_no_sig = ematch_2['code'].split('{', 1)[1].splitlines(
                True) if ematch_2['code'] is not None and "Failed to decompile" not in ematch_2['code'] and '{' in ematch_2['code'] else ematch_2['code']

            old_instructions = ematch_1['instructions']
            new_instructions = ematch_2['instructions']

            instructions_ratio = round(difflib.SequenceMatcher(None, old_instructions, new_instructions).ratio(),2)

            old_mnemonics = ematch_1['mnemonics']
            new_mnemonics = ematch_2['mnemonics']

            mnemonics_ratio = round(difflib.SequenceMatcher(None, old_mnemonics, new_mnemonics).ratio(),2)

            old_blocks = ematch_1['blocks']
            new_blocks = ematch_2['blocks']

            blocks_ratio = round(difflib.SequenceMatcher(None, old_blocks, new_blocks).ratio(),2)

            # ignore signature for ratio
            ratio = round(difflib.SequenceMatcher(None, old_code_no_sig, new_code_no_sig).ratio(),2)

            self.normalize_ghidra_decomp(old_code)
            self.normalize_ghidra_decomp(new_code)

            from_file_name = ematch_1['fullname']
            to_file_name = ematch_2['fullname']

            diff = ''.join(list(difflib.unified_diff(old_code, new_code, lineterm='\n',
                           fromfile=from_file_name, tofile=to_file_name, n=1000)))
            only_code_diff = ''.join(list(difflib.unified_diff(old_code_no_sig, new_code_no_sig, lineterm='\n',
                                     fromfile=from_file_name, tofile=to_file_name)))  # ignores name changes

            if len(only_code_diff) > 0 and (mnemonics_ratio < 1.0 or blocks_ratio < 1.0):

                # TODO remove this hack to find false positives
                # potential decompile jumptable issue ghidra/issues/2452
                if not "Could not recover jumptable" in diff:
                    diff_type.append('code')
                else:
                    self.logger.warn(
                        f"Code diff type not appended for {ematch_1['name']} due to jumptable decomp issue")

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

            if not (len(ematch_1['calling']) == len(ematch_2['calling']) and len(set(ematch_2['calling']).union(set(ematch_1['calling']))) == len(ematch_1['calling'])):
                diff_type.append('calling')

            if not (len(ematch_1['called']) == len(ematch_2['called']) and len(set(ematch_2['called']).union(set(ematch_1['called']))) == len(ematch_1['called'])):
                diff_type.append('called')

            if ematch_1['parent'] != ematch_2['parent']:
                diff_type.append('parent')

            # if no differences were found, there should not be a match (see modified func ident)
            if len(diff_type) == 0:
                self.logger.warn(f'no diff: {sym} {sym2} {match_types}')
                continue

            all_diff_types.extend(diff_type)

            modified_funcs.append({'old': ematch_1, 'new': ematch_2, 'diff': diff, 'diff_type': diff_type, 'ratio': ratio,
                                  'i_ratio': instructions_ratio, 'm_ratio': mnemonics_ratio, 'b_ratio': blocks_ratio, 'match_types': match_types})

        # Set funcs
        funcs['added'] = added_funcs
        funcs['deleted'] = deleted_funcs
        funcs['modified'] = modified_funcs

        # TODO Build Call Graphs

        # Set pdiff
        elapsed = time() - start
        items_to_process = len(added_funcs) + len(deleted_funcs) + len(modified_funcs) + \
            len(symbols['added']) + len(symbols['deleted'])
        unmatched_funcs_len = len(added_funcs) + len(deleted_funcs)
        total_funcs_len = p1.functionManager.functionCount + p2.functionManager.functionCount
        matched_funcs_len = total_funcs_len - unmatched_funcs_len
        matched_funcs_with_code_changes_len = len(
            [mod_func for mod_func in modified_funcs if 'code' in mod_func['diff_type']])
        matched_funcs_with_non_code_changes_len = len(
            [mod_func for mod_func in modified_funcs if 'code' not in mod_func['diff_type']])
        matched_funcs_no_changes_len = matched_funcs_len - \
            matched_funcs_with_code_changes_len - matched_funcs_with_non_code_changes_len
        match_func_similarity_percent = f'{((matched_funcs_no_changes_len / matched_funcs_len)*100):.4f}%'
        func_match_overall_percent = f'{((matched_funcs_len / total_funcs_len)*100):.4f}%'

        pdiff['stats'] = {'added_funcs_len': len(added_funcs), 'deleted_funcs_len': len(deleted_funcs), 'modified_funcs_len': len(modified_funcs), 'added_symbols_len': len(
            symbols['added']), 'deleted_symbols_len': len(symbols['deleted']), 'diff_time': elapsed, 'deleted_strings_len': len(deleted_strings), 'added_strings_len': len(added_strings),
            'match_types': Counter(all_match_types), 'items_to_process': items_to_process, 'diff_types': Counter(all_diff_types), 'unmatched_funcs_len': unmatched_funcs_len,
            'total_funcs_len': total_funcs_len, 'matched_funcs_len': matched_funcs_len, 'matched_funcs_with_code_changes_len': matched_funcs_with_code_changes_len,
            'matched_funcs_with_non_code_changes_len': matched_funcs_with_non_code_changes_len, 'matched_funcs_no_changes_len': matched_funcs_no_changes_len,
            'match_func_similarity_percent': match_func_similarity_percent, 'func_match_overall_percent': func_match_overall_percent}

        pdiff['symbols'] = symbols
        pdiff['strings'] = strings
        pdiff['functions'] = funcs

        pdiff['old_meta'] = self.get_metadata(p1)
        pdiff['new_meta'] = self.get_metadata(p2)

        # add pe url
        if 'visualstudio' in p1.compiler:
            pdiff['old_pe_url'] = self.get_pe_download_url(old, pdiff['old_meta']['PE Property[OriginalFilename]'])
        if 'visualstudio' in p1.compiler:
            pdiff['new_pe_url'] = self.get_pe_download_url(new, pdiff['new_meta']['PE Property[OriginalFilename]'])

        pdiff['md_credits'] = self.gen_credits()
        pdiff['html_credits'] = self.gen_credits(html=True)

        self.shutdown_decompilers(p1, p2)

        # reset global esym OTHERWISE this gets big
        self.esym_memo = {}

        self.project.close(p1)
        self.project.close(p2)

        self.logger.info("Finished diffing old program: {}".format(p1.getName()))
        self.logger.info("Finished diffing program: {}".format(p2.getName()))

        self.logger.debug(json.dumps(pdiff['stats'], indent=2))

        return pdiff

    def gen_diff_cmd_line(self, old_name: str, new_name: str) -> list:
        """
        Return command line used to start engine implementation
        """

        known_cmd_line = []
        extra_cmd_line = []
        full_cmd_line = []

        known_skip_args = ['old', 'new']

        if not self.args:
            err = 'Could not generate command line. No args passed to init of GhidraDiffEngine.'
            known_cmd_line.append(err)
            extra_cmd_line.append(err)
            full_cmd_line.append(err)
            self.logger.error(err)
        else:
            args = self.args
            defaults = self.get_default_args()

            self.logger.debug(f'Engine Args {args}')
            self.logger.debug(f'Engine Arg Defaults {defaults}')

            known_cmd_line.append(__package__)

            for arg in vars(args):

                opt = arg.replace("_", "-")
                val = getattr(args, arg)

                full_cmd_line.append(f'--{opt}')
                full_cmd_line.append(f'{val}')

                if arg in known_skip_args:
                    self.logger.debug(f'Skipping known_skip_arg: {arg}')
                    continue

                if val is None:
                    continue

                # which cmd_line
                if arg not in defaults:
                    cmd_line = extra_cmd_line
                else:
                    cmd_line = known_cmd_line

                # handle bool options
                if isinstance(val, bool):
                    if val:
                        cmd_line.append(f'--{opt}')
                else:
                    cmd_line.append(f'--{opt}')
                    cmd_line.append(f'{val}')

            # add binary names
            known_cmd_line.append(old_name)
            known_cmd_line.append(new_name)

        known_cmd_line = ' '.join(known_cmd_line)
        extra_cmd_line = ' '.join(extra_cmd_line)
        full_cmd_line = ' '.join(full_cmd_line)

        self.logger.info('Known Command line: %s', known_cmd_line)
        self.logger.info('Extra Command line: %s', extra_cmd_line)
        self.logger.debug('Extra Command line: %s', extra_cmd_line)

        return [known_cmd_line, extra_cmd_line, full_cmd_line]

    def validate_diff_json(
        self,
        results: json
    ) -> bool:

        is_valid = False
        try:
            json.loads(results)
            is_valid = True
        except ValueError as err:
            self.logger.error(err)
            raise err

        return is_valid

    def minimise_pdiff(self, pdiff: dict):
        """
        Function to allow subclasses to modify pdiff before writing to disk.
        Simply override this method. It will be called in `dump_pdiff_to_dir`
        """

        # reduce size of esym with hashes
        for func_type in ['added', 'deleted', 'modified']:

            for func in pdiff['functions'][func_type]:

                for field in ['instructions', 'mnemonics', 'blocks']:

                    if func_type == 'modified':

                        for func_mod_type in ['old', 'new']:

                            if not func[func_mod_type].get(field) is None:
                                if isinstance(func[func_mod_type][field], list) and len(func[func_mod_type][field]) > 0:
                                    func[func_mod_type][field] = hash(tuple(func[func_mod_type][field]))

                    else:

                        if func.get(field) is None:
                            continue

                        if isinstance(func[field], list) and len(func[field]) > 0:
                            func[field] = hash(tuple(func[field]))

        return pdiff

    def dump_pdiff_to_path(
        self,
        name: str,
        pdiff: Union[str, dict],
        output_path: Union[str, Path],
        side_by_side: bool = False,
        max_section_funcs: int = None,
        md_title: str = None,
        write_diff: bool = True,
        write_json: bool = True

    ) -> None:
        """
        Dump pdiff result to directory
        """

        def _clean_func(func, max=30) -> str:
            func = re.sub('`', '', func)
            func = func.replace('`', '')
            if len(func) > max:
                func = func[:max] + '...'
            return func.strip()

        if not write_diff and not write_json and not side_by_side:
            self.logger.warn('Not writing json or diff.md.')
            return

        if isinstance(pdiff, str):
            pdiff = json.loads(pdiff)

        pdiff = self.minimise_pdiff(pdiff)

        output_path = Path(output_path)
        output_path.mkdir(exist_ok=True)

        if write_diff:
            md_path = output_path / Path(name + '.md')
            self.logger.info(f'Writing md diff...')

            diff_text = self.gen_diff_md(
                pdiff,
                side_by_side=side_by_side,
                max_section_funcs=max_section_funcs,
                title=md_title)

            with md_path.open('w') as f:
                f.write(diff_text)

        if write_json:
            json_base_path = output_path / 'json'
            json_base_path.mkdir(exist_ok=True)
            json_path = json_base_path / Path(name + '.json')
            self.logger.info(f'Writing pdiff json...')

            with json_path.open('w') as f:
                json.dump(pdiff, f, indent=4)

        sxs_count = 0
        if side_by_side:
            sxs_output_path = output_path / Path('sxs_html')
            sxs_output_path.mkdir(exist_ok=True)

            sxs_diff_htmls = GhidriffMarkdown.gen_sxs_html_from_pdiff(pdiff)

            for func_name, sxs_diff_html in sxs_diff_htmls:

                # give line ending md despite html so it will render in gists and vscode
                sxs_diff_path = sxs_output_path / Path('.'.join([name, _clean_func(func_name), 'md']))
                sxs_diff_path.write_text(sxs_diff_html)

            combined_sxs_diff_html = GhidriffMarkdown.gen_combined_sxs_html_from_pdiff(pdiff)
            combined_sxs_diff_path = sxs_output_path / Path('.'.join([name, 'combined', 'html']))
            combined_sxs_diff_path.write_text(combined_sxs_diff_html)

        if write_diff:
            self.logger.info(f'Wrote {md_path}')
        if write_json:
            self.logger.info(f'Wrote {json_path}')
        if side_by_side:
            self.logger.info(f'Wrote {len(sxs_diff_htmls)} sxs hmtl diffs to {sxs_output_path}')
