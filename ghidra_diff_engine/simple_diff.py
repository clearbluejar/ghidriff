import argparse
import json
import pathlib
import difflib
from time import time
from collections import Counter
import hashlib

from typing import List, Union, Tuple, TYPE_CHECKING

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

    def diff_bins(
            self,            
            old: Union[str, pathlib.Path],
            new: Union[str, pathlib.Path],
            ignore_FUN: bool = False
    ) -> dict:
        """
        Diff the old and new binary from the GhidraProject.
        ignore_FUN : skip nameless functions matching names containing "FUN_". Useful for increasing speed of diff. 
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

            #fhash = hasher.hash(func2,ConsoleTaskMonitor())

            fhash = ''
            if ( not func.isThunk() and func.getBody().getNumAddresses() >= 10):
                 # reset iterator
                code_units = func.getProgram().getListing().getCodeUnits(func.getBody(), True)
                
                mnemonics = []

                #print("\nMnemonic Bulker")
                for code in code_units:
                    mnemonics.append(code.getMnemonicString())

                
                fhash = hashlib.sha256(''.join(mnemonics).encode('UTF-8')).hexdigest()              
        

            return (sym.getParentNamespace().toString().split('@')[0],sym.getName(),sym.getReferenceCount(),func.body.numAddresses,func.parameterCount,fhash)

        def _syms_match(esym, esym2) -> Tuple[bool, str]:
            found = False
            match_type = None
            min_func_length = 15

            # if esym2['name'] == esym['name'] and esym2['paramcount']== esym['paramcount']:
            #     print("Name + Paramcount {} {}".format(sym.getName(True),sym2.getName(True)))
            #     found = True     
            #     match_type = 'Name:Param'
            # elif esym2['address'] == esym2['address'] and esym2['paramcount']== esym['paramcount']:
            #     print("Address + Paramcount {} {}".format(sym.getName(True),sym2.getName(True)))
            #     found = True
            if esym2['name'] == esym['name'] and esym2['length'] == esym['length']:
                print("Name + length {} {}".format(sym.getName(True),sym2.getName(True)))
                found = True
                match_type = 'Name:Length'
            elif esym2['address'] == esym2['address'] and esym2['length'] == esym['length'] and min([esym['length'],esym2['length']]) > min_func_length:
                print("Address + Length {} {}".format(sym.getName(True),sym2.getName(True)))
                found = True
                match_type = 'Address:Length'
            elif esym2['paramcount']== esym['paramcount'] and esym2['length'] == esym['length']:
                print("param count + func len {} {}".format(sym.getName(True),sym2.getName(True)))
                found = True
                match_type = 'Param:Length'
            elif esym2['fullname'] == esym['fullname']:
                print("Name Exact {} {}".format(sym.getName(True),sym2.getName(True)))
                found = True
                match_type = 'Fullname'

            return found,match_type

        start = time()

        print(len(self.esym_memo))

        # reset pdiff
        self.pdiff = {}

        old = pathlib.Path(old)
        new = pathlib.Path(new)
   
        
        p1 = self.project.openProgram("/", old.name, False)
        p2 = self.project.openProgram("/", new.name, False)
        
        print("Loaded old program: {}".format(p1.getName()))
        print("Loaded new program: {}".format(p2.getName()))
        
        old_funcs = []
        new_funcs = []
        old_symbols = []
        new_symbols = []


        assert abs(p1.getSymbolTable().numSymbols - p2.getSymbolTable().numSymbols) < 4000, 'Symbols counts between programs are too high! Check Ghidra analysis or pdb!'

        # first pass detect added and deleted symbols
        for sym in p1.getSymbolTable().getDefinedSymbols():
            name = sym.getName()
            if "switch" not in name:
                old_symbols.append(name)

        for sym in p2.getSymbolTable().getDefinedSymbols():
            name = sym.getName()
            if "switch" not in name:
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
                print("{} {} {}".format(sym.getName(),sym.getAddress(), sym.getParentNamespace()))
                sym2 = DiffUtility.getSymbol(sym,p2)                
                
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
                sym2 = DiffUtility.getSymbol(sym,p1)
                
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
                    print("FullName + Paramcount {} {}".format(sym.getName(True),sym2.getName(True)))                    
                    match_type = 'FullName:Param'
                    matched.append(sym)
                    matched.append(sym2)
                    matches.append([sym,sym2,match_type])


        for sym in p1_modified:
            found = False

            if sym in matched:
                continue
            
            sym2 = DiffUtility.getSymbol(sym,p2)

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
                    found,match_type = _syms_match(esym, esym2)
                        
                    if found:
                        break

            if found:
                matched.append(sym)
                matched.append(sym2)
                matches.append([sym,sym2,match_type])
            else:
                print(f"Not found! {_get_compare_key(sym, sym.getProgram().functionManager.getFunctionAt(sym.getAddress()))}")
                unmatched.append(sym)


        for sym in p2_modified:
            found = False
            match_type = None

            if sym in matched:
                continue
            
            sym2 = DiffUtility.getSymbol(sym,p1)
            
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
                    found,match_type = _syms_match(esym, esym2)
                        
                    if found:
                        break

            if found:
                matched.append(sym)
                matched.append(sym2)
                matches.append([sym,sym2,match_type])
            else:
                print(f"Not found! {_get_compare_key(sym, sym.getProgram().functionManager.getFunctionAt(sym.getAddress()))}")
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

        symbols = {}
        funcs = {}
        symbols['added'] = []
        symbols['deleted'] = []

        deleted_funcs = []
        added_funcs = []
        modified_funcs = []
        all_match_types = []

        print("\ndeleted symbols\n")

        deleted_symbols_full = []

        for sym in p1.getSymbolTable().getDefinedSymbols():
            if sym.getName() in deleted_symbols:
                deleted_symbols_full.append(sym)
        
        for sym in deleted_symbols_full:
            symbols['deleted'].append(self.enhance_sym(sym))

        print("\nadded symbols\n")

        added_symbols_full = []

        for sym in p2.getSymbolTable().getDefinedSymbols():
            if sym.getName() in added_symbols:
                added_symbols_full.append(sym)

        for sym in added_symbols_full:
            print(sym)
            symbols['added'].append(self.enhance_sym(sym))

        for lost in unmatched:
            elost = self.enhance_sym(lost)

            # deleted func
            if lost.getProgram().getName() == p1.getName():
                deleted_funcs.append(elost)
            else:
                added_funcs.append(elost)

        for match in matches:

            diff_type = []
            diff = ''
            only_code_diff = ''
            
            ematch_1 = self.enhance_sym(match[0])
            ematch_2 = self.enhance_sym(match[1])
            match_type = match[2]

            old_code = ematch_1['code'].splitlines(True)
            new_code = ematch_2['code'].splitlines(True)

            old_code_no_sig = ematch_1['code'].split('{',1)[1].splitlines(True) if ematch_1['code'] else ''
            new_code_no_sig = ematch_2['code'].split('{',1)[1].splitlines(True) if ematch_2['code'] else ''

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

            diff = ''.join(list(difflib.unified_diff(old_code,new_code,lineterm='\n',fromfile=match[0].getProgram().getName(),tofile=match[1].getProgram().getName())))
            only_code_diff = ''.join(list(difflib.unified_diff(old_code_no_sig,new_code_no_sig,lineterm='\n',fromfile=match[0].getProgram().getName(),tofile=match[1].getProgram().getName()))) # ignores name changes
            
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
            assert len(diff_type) > 0

            modified_funcs.append({'old': ematch_1, 'new': ematch_2, 'diff':diff, 'diff_type': diff_type, 'ratio': ratio, 'i_ratio': instructions_ratio, 'm_ratio': mnemonics_ratio, 'b_ratio': blocks_ratio, 'match_type': match_type})

            # add match_type stats
            all_match_types.append(match_type)
            
        # account for compare_key match types
        for sym in matching_compare_keys:
            all_match_types.append('Hash')

        # Set funcs
        funcs['added'] = added_funcs
        funcs['deleted'] = deleted_funcs
        funcs['modified'] = modified_funcs

        # TODO Build Call Graphs

        # Set pdiff
        elapsed = time() - start
        self.pdiff['stats'] = {'added_funcs_len': len(added_funcs), 'deleted_funcs_len': len(deleted_funcs), 'modified_funcs_len': len(modified_funcs), 'added_symbols_len': len(symbols['added']), 'deleted_symbols_len': len(symbols['deleted']), 'diff_time': elapsed, 'match_types': Counter(all_match_types) }
        self.pdiff['symbols'] = symbols
        self.pdiff['functions'] = funcs

        self.pdiff['old_meta'] = self.get_metadata(p1)
        self.pdiff['new_meta'] = self.get_metadata(p2)

        # analysis options used (just check p1, same used for both)
        self.pdiff['analysis_options'] = self.get_analysis_options(p1)

        self.project.close(p1)
        self.project.close(p2)

        return self.pdiff


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='A simple Ghidra binary diffing tool')

    parser.add_argument('old', nargs=1, help='Path to older version of binary "/somewhere/bin.old"')
    parser.add_argument('new', action='append', nargs='+', help="Path to new version of binary '/somewhere/bin.new'. For multiple binaries add oldest to newest")
    parser.add_argument('-o', '--output-path', dest="output_path",
                        help='Path to store diffing results', default='.diffs')    
    GhidraDiffEngine.add_ghidra_args_to_parser(parser)

    args = parser.parse_args()
    binary_paths = args.old + [bin for sublist in args.new for bin in sublist]

    d = GhidraSimpleDiff(True)

    d.setup_project(binary_paths, args.project_location, args.project_name)

    d.setup_symbols(args.symbols_path)

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

        d.dump_pdiff_to_dir(diff_name,pdiff,args.output_path)
