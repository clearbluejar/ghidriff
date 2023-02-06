import argparse
import json
import pathlib
import hashlib

from typing import List, Tuple, TYPE_CHECKING

from .ghidra_diff_engine import GhidraDiffEngine

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


class GhidraStructualDiff(GhidraDiffEngine):
    """
    An Ghidra Diff implementation using simple comparison mechanisms
    """

    # def __init__(self, verbose: bool = False, output_dir: str = '.diffs', MAX_MEM=None, threaded=False, max_workers=...) -> None:
    #     super().__init__(verbose, output_dir, MAX_MEM, threaded, max_workers)
    #     self.name = 'GhidraSimpleDiff'
    #     self.file = __file__

    def find_matches(
        self,
        p1: "ghidra.program.model.listing.Program",
        p2: "ghidra.program.model.listing.Program",
        ignore_FUN: bool = False,
    ) -> dict:
        """
        Find matching and unmatched functions between p1 and p2
        """

        from ghidra.program.util import DiffUtility

        compare_key_memo = {}

        def _get_compare_key(sym: 'ghidra.program.model.symbol.Symbol', func: 'ghidra.program.model.listing.Function') -> tuple:
            """
            Builds tuple from symbol (parent, name, refcount, length, paramcount)
            """
            # from ghidra.app.plugin.match import ExactBytesFunctionHasher
            # from ghidra.app.plugin.match import FunctionHasher
            # from ghidra.util.task import ConsoleTaskMonitor

            # hasher = FunctionHasher

            # fhash = hasher.hash(func2,ConsoleTaskMonitor())
            key = f'{sym.getID()}-{sym.getProgram().getName()}'

            if compare_key_memo.get(key) is None:

                fhash = ''
                cu_count = 0
                if (not func.isThunk() and func.getBody().getNumAddresses() >= 10):
                    # reset iterator
                    code_units = func.getProgram().getListing().getCodeUnits(func.getBody(), True)

                    mnemonics = []

                    # print("\nMnemonic Bulker")
                    for code in code_units:
                        mnemonics.append(code.getMnemonicString())
                        cu_count += 1

                    fhash = hashlib.sha256(''.join(mnemonics).encode('UTF-8')).hexdigest()

                compare_key_memo[key] = (cu_count, sym.getReferenceCount(),
                                         func.body.numAddresses, func.parameterCount, fhash)

            # return (sym.getParentNamespace().toString().split('@')[0], sym.getName(), sym.getReferenceCount(), func.body.numAddresses, func.parameterCount, fhash)
            return compare_key_memo[key]

        def _get_compare_key2(sym: 'ghidra.program.model.symbol.Symbol', func: 'ghidra.program.model.listing.Function') -> tuple:
            """
            Builds tuple from symbol (parent, name, refcount, length, paramcount)
            """

            from ghidra.program.model.block import BasicBlockModel
            from ghidra.util.task import ConsoleTaskMonitor

            # graph structure vars
            num_basic_blocks = 0
            num_edges_of_blocks = 0
            num_call_subfunctions = 0

            if (not func.isThunk() and func.getBody().getNumAddresses() >= 10):

                monitor = ConsoleTaskMonitor()

                basic_model = BasicBlockModel(func.getProgram(), True)
                basic_blocks = basic_model.getCodeBlocksContaining(func.getBody(), monitor)
                blocks = []

                for block in basic_blocks:
                    num_edges_of_blocks += block.getNumDestinations(monitor)
                    num_basic_blocks += 1

                    code_units = func.getProgram().getListing().getCodeUnits(block, True)
                    for code in code_units:
                        # print(code.getMnemonicString())
                        if code.getMnemonicString() == 'CALL':
                            num_call_subfunctions += 1

            # ignore Ghidra generated function names
            gen_sym_prefix = ['FUN_', 'lambda', 'destructor', '~', 'dynamic_initializer', 'dtor', '::']
            fname = sym.getName(True)

            if any([generated in fname for generated in gen_sym_prefix]):
                fname = ''
            # ignore sections of names with relative addresses or offsets
            # Catch_All@64616295 _GrowCompBitsBuffer@4
            elif '@' in fname:
                fname = fname.split('@')[0]
            elif '$' in fname:
                fname = fname.split('$')[0]

            # return (sym.getParentNamespace().toString().split('@')[0], fname, num_basic_blocks, num_edges_of_blocks, num_call_subfunctions, sym.getReferenceCount(), func.body.numAddresses, func.parameterCount)
            return (fname, num_basic_blocks, num_edges_of_blocks, num_call_subfunctions, func.body.numAddresses, func.parameterCount)
            # return (num_basic_blocks, num_edges_of_blocks, num_call_subfunctions)

        def _syms_match(esym, esym2) -> Tuple[bool, str]:
            found = False
            match_type = None
            min_func_length = 15

            if esym2['name'] == esym['name'] and esym2['paramcount'] == esym['paramcount']:
                print("Name + Paramcount {} {}".format(sym.getName(True), sym2.getName(True)))
                found = True
                match_type = 'Name:Param'
            # elif esym2['address'] == esym2['address'] and esym2['paramcount']== esym['paramcount']:
            #     print("Address + Paramcount {} {}".format(sym.getName(True),sym2.getName(True)))
            #     found = True
            if esym2['name'] == esym['name'] and esym2['length'] == esym['length']:
                print("Name + length {} {}".format(sym.getName(True), sym2.getName(True)))
                found = True
                match_type = 'Name:Length'
            # elif esym2['address'] == esym2['address'] and esym2['length'] == esym['length'] and min([esym['length'], esym2['length']]) > min_func_length:
            #     print("Address + Length {} {}".format(sym.getName(True), sym2.getName(True)))
            #     found = True
            #     match_type = 'Address:Length'
            # elif esym2['paramcount'] == esym['paramcount'] and esym2['length'] == esym['length']:
            #     print("param count + func len {} {}".format(sym.getName(True), sym2.getName(True)))
            #     found = True
            #     match_type = 'Param:Length'
            elif esym2['fullname'] == esym['fullname']:
                print("Name Exact {} {}".format(sym.getName(True), sym2.getName(True)))
                found = True
                match_type = 'Fullname'

            return found, match_type

        old_funcs = []
        new_funcs = []
        old_symbols = []
        new_symbols = []

        sym_count_diff = abs(p1.getSymbolTable().numSymbols - p2.getSymbolTable().numSymbols)

        # if sym_count_diff > 4000 and not last_attempt:
        #     # this can occur if analysis fails silenty, or the pdb was not applied
        #     # try to recover with reanalysis

        #     if p1.getSymbolTable().numSymbols > p2.getSymbolTable().numSymbols:
        #         program_to_fix = p2
        #         # delete file
        #         name = p1.getName()
        #         self.project.close(p1)
        #         self.project.getRootFolder().getFile(p2.getName()).delete()
        #         program_to_fix = self.project.importProgram(new)
        #     else:
        #         program_to_fix = p1
        #         name = p1.getName()
        #         self.project.close(p1)
        #         self.project.getRootFolder().getFile(name).delete()
        #         program_to_fix = self.project.importProgram(old)
        #         # self.project.saveAs(program_to_fix, "/", program_to_fix.getName(), True)
        #         # program_to_fix = self.project.openProgram("/", name, False)

        #     # clear current PDB loaded Ghidra/Features/PDB/src/main/java/ghidra/app/util/pdb/PdbProgramAttributes.java#L132
        #     # from ghidra.app.util.bin.format.pdb import PdbParserConstants
        #     # self.set_proginfo_option_bool(program_to_fix, PdbParserConstants.PDB_LOADED, False)

        #     self.analyze_program(program_to_fix, require_symbols=True, force_analysis=True)

        # #     from ghidra.app.util.bin.format.pdb import PdbParserConstants
        # #     self.set_proginfo_option_bool(p1, PdbParserConstants.PDB_LOADED, False)
        # #     self.analyze_program(p1, require_symbols=True, force_analysis=True)

        # #     self.set_proginfo_option_bool(p2, PdbParserConstants.PDB_LOADED, False)
        # #     self.analyze_program(p2, require_symbols=True, force_analysis=True)

        # #     self.project.close(p1)
        # #     self.project.close(p2)

        # #     # try one more time
        #     return self.diff_bins(old, new, last_attempt=True)

        assert sym_count_diff < 4000, f'Symbols counts between programs ({p1.name} and {p2.name}) are too high {sym_count_diff}! Likely bad analyiss or missing symbols! Check Ghidra analysis or pdb!'

        # first pass detect added and deleted symbols
        common_sym_prefix = ['switch', 'FUN_', 'caseD', 'local_', 'lambda']

        for sym in p1.getSymbolTable().getDefinedSymbols():
            name = sym.getName()
            if not any([common in name for common in common_sym_prefix]):
                old_symbols.append(name)

        for sym in p2.getSymbolTable().getDefinedSymbols():
            name = sym.getName()
            if not any([common in name for common in common_sym_prefix]):
                new_symbols.append(name)

        olds = set(old_symbols)
        news = set(new_symbols)

        deleted_symbols = olds.difference(news)
        print("\ndeleted symbols\n")
        for sym in deleted_symbols:
            print(sym)

        added_symbols = news.difference(olds)
        print("\nadded symbols\n")
        for sym in added_symbols:
            print(sym)

        # Next pass
        # 1. remove false positives from symbols
        # 2. Build modified functions list based on (_get_compare_key)

        from ghidra.program.model.symbol import SymbolType

        print(f'Calculating initial structural signature for all ')
        p1_funcs = {}
        p2_funcs = {}

        # count_all = 0
        # count_all2 = 0
        # for sym in p1.getSymbolTable().getDefinedSymbols():
        #     if "function".lower() in sym.getSymbolType().toString().lower():
        #         count_all += 1

        # for sym in p1.getSymbolTable().getDefinedSymbols():
        #     if sym.getSymbolType() == SymbolType.FUNCTION:
        #         count_all2 += 1

        # count_func = 0
        # for func in p1.functionManager.getFunctions(True):
        #     count_func += 1

        from time import time
        start_p1 = time()
        for sym in p1.getSymbolTable().getDefinedSymbols():
            if sym.getSymbolType() == SymbolType.FUNCTION:
                func = p1.functionManager.getFunctionAt(sym.getAddress())
                p1_funcs[func] = _get_compare_key2(sym, func)
        end_p1 = time()

        for sym in p2.getSymbolTable().getDefinedSymbols():
            if sym.getSymbolType() == SymbolType.FUNCTION:
                func = p2.functionManager.getFunctionAt(sym.getAddress())
                p2_funcs[func] = _get_compare_key2(sym, func)
        end_p2 = time()

        print(f'p1 time: {end_p1 - start_p1}')
        print(f'p2 time: {end_p2 - end_p1}')

        from ghidra.app.plugin.match import FunctionHasher
        from ghidra.app.plugin.match import MatchFunctions
        from ghidra.app.plugin.match import ExactMnemonicsFunctionHasher

        from ghidra.util.task import ConsoleTaskMonitor
        monitor = ConsoleTaskMonitor()
        one_to_one = True
        hasher = ExactMnemonicsFunctionHasher.INSTANCE
        matchedFunctions = MatchFunctions.matchFunctions(p1, p1.getMemory().initializedAddressSet, p2, p2.getMemory().initializedAddressSet,
                                                         10, one_to_one, not one_to_one, hasher, monitor)

        for match in matchedFunctions:
            print(match)

        # TODO check to see if getFunctions returns a more accurate set
        # Conside replacing with Ghidra/Features/Base/src/main/java/ghidra/app/plugin/match/MatchFunctions.java#L34
        # count = 0
        # funcs1 = p1.functionManager.getFunctions(True)
        # funcs1_check = []
        # for f in funcs1:
        #     count += 1
        #     funcs1_check.append(_get_compare_key(f.getSymbol(),f))
        # print(count)

        # print(len(old_funcs))
        # check = set(funcs1_check)

        # modified = sorted(check.difference(old))
        # for sym in modified:
        #     print(sym)

        from collections import Counter

        p1_funcs_vals = Counter(p1_funcs.values())
        p2_funcs_vals = Counter(p1_funcs.values())

        count_non_unique = 0
        for key, val in p1_funcs_vals.items():
            if val > 1:
                count_non_unique += 1
                print(key, val)
        print(f'non-unique p1: {count_non_unique}')
        count_non_unique = 0
        for key, val in p2_funcs_vals.items():
            if val > 1:
                count_non_unique += 1
                print(key, val)
        print(f'non-unique p2: {count_non_unique}')

        old_func_set = set(p1_funcs.values())
        new_func_set = set(p2_funcs.values())

        modified_old = sorted(old_func_set.difference(new_func_set))
        modified_new = sorted(new_func_set.difference(old_func_set))

        matching_compare_keys = sorted(old_func_set.intersection(new_func_set))
        print(f'modified_old: {len(modified_old)}')
        print(f'modified_new: {len(modified_new)}')
        print(f'matching_compare_keys: {len(matching_compare_keys)}')

        # account for compare_key match types
        # TODO account for hashes this!!
        # for sym in matching_compare_keys:
        #     all_match_types.append('Hash')

        # FUNCTION_MINIMUM_SIZE_DEFAULT = 10

        # from ghidra.app.plugin.match import FunctionHasher

        # if (!func.isThunk() && func.getBody().getNumAddresses() >= minimumFunctionSize) {
        # 		hashFunction(monitor, functionHashes, func, hasher, true);
        # }

        # hasher = FunctionHasher()

        # for key in matching_compare_keys:

        #     hasher.hash()

        # for key in

        p1_modified = []
        p2_modified = []

        p1_name_to_func = {}
        p2_name_to_func = {}

        for func, compare_key in p1_funcs.items():
            if compare_key in modified_old:
                p1_modified.append(func.getSymbol())
                key = (func.getName(True), func.parameterCount)
                p1_name_to_func.setdefault(key, []).append(func)

        for func, compare_key in p2_funcs.items():
            if compare_key in modified_new:
                p2_modified.append(func.getSymbol())
                key = (func.getName(True), func.parameterCount)
                p2_name_to_func.setdefault(key, []).append(func)

        # for key in p1_name_to_func.keys():
        #     if p2_name_to_func.get(key):
        #         assert len(p1_name_to_func[key]) == len(p2_name_to_func[key])

        print("\nmodified_old_modified")
        for sym in p1_modified:
            print(sym)

        print("\nmodified_new_modified")
        for sym in p2_modified:
            print(sym)

        # Find modified functions based on compare_key
        # for sym in p1.getSymbolTable().getDefinedSymbols():

        #     if "function".lower() in sym.getSymbolType().toString().lower():
        #         func = p1.functionManager.getFunctionAt(sym.getAddress())
        #         if (_get_compare_key2(sym, func)) in modified_old:
        #             p1_modified.append(sym)

        # for sym in p2.getSymbolTable().getDefinedSymbols():

        #     if "function".lower() in sym.getSymbolType().toString().lower():
        #         func = p2.functionManager.getFunctionAt(sym.getAddress())
        #         if (_get_compare_key2(sym, func)) in modified_new:
        #             p2_modified.append(sym)

        matched = []
        unmatched = []
        matches = []

        print("\nMatching functions...")

        hashes = []

        # for sym in p1_modified:
        #     for sym2 in p2_modified:

        #         if sym2 in matched:
        #                 continue

        #         func = p1.functionManager.getFunctionAt(sym.getAddress())
        #         func2 = p2.functionManager.getFunctionAt(sym2.getAddress())

        #         # reset iterator
        #         mnemonics = []
        #         mnemonics2 = []

        #         code_units = func.getProgram().getListing().getCodeUnits(func.getBody(), True)
        #         code_units2 = func2.getProgram().getListing().getCodeUnits(func2.getBody(), True)

        #         #print("\nMnemonic Bulker")
        #         for code in code_units:
        #             mnemonics.append(code.getMnemonicString())

        #         for code in code_units2:
        #             mnemonics2.append(code.getMnemonicString())

        #         fhash = hashlib.sha256(''.join(mnemonics).encode('UTF-8')).hexdigest()
        #         fhash2 = hashlib.sha256(''.join(mnemonics2).encode('UTF-8')).hexdigest()

        #         hashes.append(fhash)
        #         hashes.append(fhash2)

        #         if fhash ==  fhash2:
        # print("whata!?!")

        # match by name and paramcount
        for sym in p1_modified:

            if sym in matched:
                continue

            func = sym.getProgram().functionManager.getFunctionAt(sym.getAddress())

            key = (func.getName(True), func.parameterCount)

            if p2_name_to_func.get(key):

                func2 = p2_name_to_func[key][0]

                if len(p2_name_to_func[key]) > 1:

                    for func in p1_name_to_func[key]:

                        if func.getSymbol() in matched:
                            continue

                        for func2 in p2_name_to_func[key]:

                            if func2.getSymbol() in matched:
                                continue
                            # fname, num_basic_blocks, num_edges_of_blocks, num_call_subfunctions, func.body.numAddresses, func.parameterCount

                            _, _, _, func2_num_calls, _, _ = p2_funcs[func2]
                            _, _, _, func_num_calls, _, _ = p1_funcs[func]

                            if func2_num_calls == func_num_calls:
                                sym = func.getSymbol()
                                sym2 = func2.getSymbol()
                                print(f"FullName + Paramcount + NumCalls {sym.getName(True)} {sym2.getName(True)}")
                                match_type = 'FullName:Param:NumCalls'
                                matched.append(sym)
                                matched.append(sym2)
                                matches.append([sym, sym2, match_type])

                else:
                    sym2 = func2.getSymbol()
                    print(f"FullName + Paramcount {sym.getName(True)} {sym2.getName(True)}")
                    match_type = 'FullName:Param'
                    matched.append(sym)
                    matched.append(sym2)
                    matches.append([sym, sym2, match_type])

        # match by name and paramcount
        # for sym in p1_modified:
        #     for sym2 in p2_modified:

        #         if sym in matched or sym2 in matched:
        #             continue

        #         func = p1.functionManager.getFunctionAt(sym.getAddress())
        #         func2 = p2.functionManager.getFunctionAt(sym2.getAddress())

        #         # esym = self.enhance_sym(sym)
        #         # esym2 = self.enhance_sym(sym2)

        #         # if esym2['fullname'] == esym['fullname'] and esym2['paramcount']== esym['paramcount']:

        #         if sym.getName(True) == sym2.getName(True) and func.parameterCount == func2.parameterCount:
        #             print("FullName + Paramcount {} {}".format(sym.getName(True), sym2.getName(True)))
        #             print(_get_compare_key2(sym, sym.getProgram().functionManager.getFunctionAt(sym.getAddress())))
        #             print(_get_compare_key2(sym2, sym2.getProgram().functionManager.getFunctionAt(sym.getAddress())))
        #             match_type = 'FullName:Param'
        #             matched.append(sym)
        #             matched.append(sym2)
        #             matches.append([sym, sym2, match_type])

        for sym in p1_modified:
            found = False

            if sym in matched:
                continue

            sym2 = DiffUtility.getSymbol(sym, p2)

            if sym2 and sym.getName(True) == sym2.getName(True):
                found = True
                match_type = 'Direct'
                print(f"direct getsymbol match {sym.getName(True)} {sym2.getName(True)}")
            else:
                for sym2 in p2_modified:
                    if sym2 in matched:
                        continue

                    func = sym.getProgram().functionManager.getFunctionAt(sym.getAddress())
                    ck1 = _get_compare_key(sym, func)

                    func2 = sym2.getProgram().functionManager.getFunctionAt(sym2.getAddress())
                    ck2 = _get_compare_key(sym2, func2)

                    if ck1[4] == ck2[4]:
                        found = True
                        match_type = 'MneumonicOrdered:Hash'
                        print(f"{match_type} match {sym.getName(True)} {sym2.getName(True)}")

                    if found:
                        break

            if found:
                matched.append(sym)
                matched.append(sym2)
                matches.append([sym, sym2, match_type])
            else:
                print(f"Deleted func found: {sym}")
                print(
                    f"Deleted func found: {_get_compare_key(sym,sym.getProgram().functionManager.getFunctionAt(sym.getAddress()))}")
                unmatched.append(sym)
                # matched.append(sym)  # TODO check this

        for sym in p2_modified:
            found = False
            match_type = None

            if sym in matched:
                continue

            sym2 = DiffUtility.getSymbol(sym, p1)

            if sym2 and sym.getName(True) == sym2.getName(True):
                found = True
                match_type = 'Direct'
                print(f"direct getsymbol match {sym.getName(True)} {sym2.getName(True)}")
            else:
                for sym2 in p1_modified:
                    if sym2 in matched:
                        continue

                    esym = self.enhance_sym(sym)
                    esym2 = self.enhance_sym(sym2)
                    found, match_type = _syms_match(esym, esym2)

                    if found:
                        break

            if found:
                matched.append(sym)
                matched.append(sym2)
                matches.append([sym, sym2, match_type])
            else:
                print(f"Added func found: {sym}")
                unmatched.append(sym)

        print(len(p1_modified))
        print(len(p2_modified))

        matches = sorted(matches, key=lambda x: str(x[0]))

        # Update symbols using match knowledge
        for match in matches:
            print(f"{match[0].getName(True)} {match[1].getName(True)} {match[2]}")

            if match[0].getName() in deleted_symbols:
                deleted_symbols.remove(match[0].getName())
            if match[1].getName() in added_symbols:
                added_symbols.remove(match[1].getName())

        return [deleted_symbols, added_symbols, unmatched, matches, []]


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='A simple Ghidra binary diffing tool')

    parser.add_argument('old', nargs=1, help='Path to older version of binary "/somewhere/bin.old"')
    parser.add_argument('new', action='append', nargs='+',
                        help="Path to new version of binary '/somewhere/bin.new'. For multiple binaries add oldest to newest")
    parser.add_argument('-o', '--output-path', help='Output path for resulting diff', default='.output_diffs')

    GhidraDiffEngine.add_ghidra_args_to_parser(parser)

    args = parser.parse_args()

    print(args)

    output_path = pathlib.Path(args.output_path)
    output_path.mkdir(exist_ok=True)

    binary_paths = args.old + [bin for sublist in args.new for bin in sublist]

    binary_paths = [pathlib.Path(path) for path in binary_paths]

    project_name = f'{args.project_name}-{binary_paths[0].name}-{binary_paths[1].name}'

    d = GhidraStructualDiff(True, MAX_MEM=True, threaded=True)

    d.setup_project(binary_paths, args.project_location, project_name, args.symbols_path)

    d.analyze_project()

    diffs = []

    # pair up binaries with the n-1 version
    for i in range(len(binary_paths)-1):
        diffs.append((binary_paths[i], binary_paths[i+1]))

    # add a diff of the first and last binary for full coverage
    if not binary_paths[1] == binary_paths[-1]:
        diffs.append((binary_paths[0], binary_paths[-1]))

    for diff in diffs:
        pdiff = d.diff_bins(diff[0], diff[1])
        pdiff_json = json.dumps(pdiff)

        print(pdiff['stats'])
        assert d.validate_diff_json(pdiff_json) is True

        diff_name = f"{pathlib.Path(diff[0]).name}_to_{pathlib.Path(diff[1]).name}_diff"
        d.dump_pdiff_to_dir(diff_name, pdiff, args.output_path)
