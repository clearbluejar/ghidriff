import argparse
import json
import pathlib
import hashlib

from typing import List, Tuple, TYPE_CHECKING

from .ghidra_diff_engine import GhidraDiffEngine

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


class GhidraSimpleDiff(GhidraDiffEngine):
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

        def _get_compare_key(sym: 'ghidra.program.model.symbol.Symbol', func: 'ghidra.program.model.listing.Function') -> tuple:
            """
            Builds tuple from symbol (parent, name, refcount, length, paramcount)
            """
            # from ghidra.app.plugin.match import ExactBytesFunctionHasher
            # from ghidra.app.plugin.match import FunctionHasher
            # from ghidra.util.task import ConsoleTaskMonitor

            # hasher = FunctionHasher

            # fhash = hasher.hash(func2,ConsoleTaskMonitor())

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

            return (sym.getParentNamespace().toString().split('@')[0], sym.getName(True), sym.getReferenceCount(), func.body.numAddresses, func.parameterCount, fhash)
            # return (cu_count, sym.getReferenceCount(), func.body.numAddresses, func.parameterCount, fhash)

        def _syms_match(esym, esym2) -> Tuple[bool, str]:
            found = False
            match_type = None
            min_func_length = 15

            # if esym2['name'] == esym['name'] and esym2['paramcount'] == esym['paramcount']:
            #     print("Name + Paramcount {} {}".format(sym.getName(True), sym2.getName(True)))
            #     found = True
            #     match_type = 'Name:Param'
            # elif esym2['address'] == esym2['address'] and esym2['paramcount']== esym['paramcount']:
            #     print("Address + Paramcount {} {}".format(sym.getName(True),sym2.getName(True)))
            #     found = True
            if esym2['name'] == esym['name'] and esym2['length'] == esym['length']:
                print("Name + length {} {}".format(sym.getName(True), sym2.getName(True)))
                found = True
                match_type = 'Name:Length'
            elif esym2['address'] == esym2['address'] and esym2['length'] == esym['length'] and min([esym['length'], esym2['length']]) > min_func_length:
                print("Address + Length {} {}".format(sym.getName(True), sym2.getName(True)))
                found = True
                match_type = 'Address:Length'
            elif esym2['paramcount'] == esym['paramcount'] and esym2['length'] == esym['length']:
                print("param count + func len {} {}".format(sym.getName(True), sym2.getName(True)))
                found = True
                match_type = 'Param:Length'
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
        common_sym_prefix = ['switch', 'FUN_', 'caseD', 'local_']

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

        for sym in p1.getSymbolTable().getDefinedSymbols():
            key = sym.getName()
            if key in deleted_symbols:
                print("{} {} {}".format(sym.getName(), sym.getAddress(), sym.getParentNamespace()))
                sym2 = DiffUtility.getSymbol(sym, p2)

                if sym2 and sym.getName(True) == sym2.getName(True):
                    print(f"Removing {sym} from deleted, found match {sym2} in p2")
                    deleted_symbols.remove(key)

            if "function".lower() in sym.getSymbolType().toString().lower():
                func = p1.functionManager.getFunctionAt(sym.getAddress())

                if "FUN_" in func.name and ignore_FUN:
                    # ignore FUN_
                    continue
                old_funcs.append(_get_compare_key(sym, func))

        for sym in p2.getSymbolTable().getDefinedSymbols():
            key = sym.getName()
            if key in added_symbols:
                print("{} {}".format(sym.getName(), sym.getAddress()))
                sym2 = DiffUtility.getSymbol(sym, p1)

                if sym2 and sym.getName(True) == sym2.getName(True):
                    print(f"Removing {sym} from deleted, found match {sym2} in p1")
                    added_symbols.remove(key)

            if "function".lower() in sym.getSymbolType().toString().lower():
                func = p2.functionManager.getFunctionAt(sym.getAddress())
                if "FUN_" in func.name and ignore_FUN:
                    # ignore FUN_
                    continue
                new_funcs.append(_get_compare_key(sym, func))

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

        old_func_set = set(old_funcs)
        new_func_set = set(new_funcs)

        modified_old = sorted(old_func_set.difference(new_func_set))
        modified_new = sorted(new_func_set.difference(old_func_set))

        matching_compare_keys = sorted(old_func_set.intersection(new_func_set))

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

        print("\nmodified_old_modified")
        for sym in modified_old:
            print(sym)

        print("\nmodified_new_modified")
        for sym in modified_new:
            print(sym)

        p1_modified = []
        p2_modified = []

        # Find modified functions based on compare_key
        for sym in p1.getSymbolTable().getDefinedSymbols():

            if "function".lower() in sym.getSymbolType().toString().lower():
                func = p1.functionManager.getFunctionAt(sym.getAddress())
                if (_get_compare_key(sym, func)) in modified_old:
                    p1_modified.append(sym)

        for sym in p2.getSymbolTable().getDefinedSymbols():

            if "function".lower() in sym.getSymbolType().toString().lower():
                func = p2.functionManager.getFunctionAt(sym.getAddress())
                if (_get_compare_key(sym, func)) in modified_new:
                    p2_modified.append(sym)

        print("\nmodified_old_modified")
        for sym in p1_modified:
            print(sym)

        print("\nmodified_new_modified")
        for sym in p2_modified:
            print(sym)

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
            for sym2 in p2_modified:

                if sym2 in matched:
                    continue

                func = p1.functionManager.getFunctionAt(sym.getAddress())
                func2 = p2.functionManager.getFunctionAt(sym2.getAddress())

                # esym = self.enhance_sym(sym)
                # esym2 = self.enhance_sym(sym2)

                # if esym2['fullname'] == esym['fullname'] and esym2['paramcount']== esym['paramcount']:

                if sym.getName(True) == sym2.getName(True) and func.parameterCount == func2.parameterCount:
                    print("FullName + Paramcount {} {}".format(sym.getName(True), sym2.getName(True)))
                    match_type = 'FullName:Param'
                    matched.append(sym)
                    matched.append(sym2)
                    matches.append([sym, sym2, match_type])

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
                print(f"Deleted func found: {sym}")
                unmatched.append(sym)

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

        # translate matches to expected
        expected_matched = []
        for sym, sym2, match_type in matches:
            expected_matched.append([sym, sym2, [match_type]])

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

    d = GhidraSimpleDiff(True, MAX_MEM=True, threaded=True)

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
