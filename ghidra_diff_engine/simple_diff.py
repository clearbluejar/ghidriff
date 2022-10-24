import argparse
from dataclasses import dataclass
import json
import pathlib
import difflib
from time import time

from typing import List, Union, Tuple, TYPE_CHECKING

from .ghidra_diff_engine import GhidraDiffEngine

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *

class GhidraSimpleDiff(GhidraDiffEngine):
    """
    An Ghidra Diff implementation using simple comparison mechanisms
    """


    def diff_bins(
            self,            
            old: Union[str, pathlib.Path],
            new: Union[str, pathlib.Path]
    ) -> dict:
        """Diff the old and new binary from the GhidraProject"""

        def _get_compare_key(sym: 'ghidra.program.model.symbol.Symbol', func: 'ghidra.program.model.listing.Function') -> tuple:            
            return (sym.getParentNamespace().toString().split('@')[0],sym.getName(),sym.getReferenceCount(),func.body.numAddresses,func.parameterCount)

        def _syms_match(esym, esym2) -> Tuple[bool, str]:
            found = False
            match_type = None
            min_func_length = 15

            if esym2['name'] == esym['name'] and esym2['paramcount']== esym['paramcount']:
                print("Name + Paramcount {} {}".format(sym.getName(True),sym2.getName(True)))
                found = True     
                match_type = 'Name:Param'
            # elif esym2['address'] == esym2['address'] and esym2['paramcount']== esym['paramcount']:
            #     print("Address + Paramcount {} {}".format(sym.getName(True),sym2.getName(True)))
            #     found = True
            elif esym2['name'] == esym['name'] and esym2['length'] == esym['length']:
                print("Name + length {} {}".format(sym.getName(True),sym2.getName(True)))
                found = True
                match_type = 'Name:Length'
            elif esym2['address'] == esym2['address'] and esym2['length'] == esym['length'] and min([esym['length'],esym2['length']]) > min_func_length:
                print("Address {} {}".format(sym.getName(True),sym2.getName(True)))
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
                print("{} {}".format(sym.getName(),sym.getAddress()))
                sym2 = p2.getSymbolTable().getSymbol(sym.getName(),sym.getAddress(),sym.getParentNamespace())
                if sym2:
                    print("Removing {} from deleted, found match {} {} in p2".format(sym,sym2))
                    deleted_symbols.remove(key)
                
            if "function".lower() in sym.getSymbolType().toString().lower():
                func = p1.functionManager.getFunctionAt(sym.getAddress())
                old_funcs.append(_get_compare_key(sym, func))

        for sym in p2.getSymbolTable().getDefinedSymbols():
            key = sym.getName()        
            if key in added_symbols:
                print("{} {}".format(sym.getName(), sym.getAddress()))
                sym2 = p1.getSymbolTable().getSymbol(
                    sym.getName(), sym.getAddress(), sym.getParentNamespace())
                if sym2:
                    print(
                        "Removing {} from deleted, found match {} in p1".format(sym, sym2))
                    added_symbols.remove(key)

            if "function".lower() in sym.getSymbolType().toString().lower():
                func = p2.functionManager.getFunctionAt(sym.getAddress())                
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

        old = set(old_funcs)
        new = set(new_funcs)

        modified_old = sorted(old.difference(new))
        modified_new = sorted(new.difference(old))

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


        for sym in p1_modified:
            found = False

            if sym in matched:
                continue

            sym2 = p2.getSymbolTable().getSymbol(sym.getName(), sym.getAddress(), sym.getParentNamespace())
            
            if sym2:
                found = True                
                match_type = 'Direct'
                print("direct getsymbol match {} {}".format(sym.getName(True),sym2.getName(True)))
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

            print(f"Not yet matched p2 {sym}")
            sym2 = p1.getSymbolTable().getSymbol(sym.getName(),sym.getAddress(),sym.getParentNamespace())

            if sym2:
                found = True                
                match_type = 'Direct'
                print("direct getsymbol match {} {}".format(sym.getName(True),sym2.getName(True)))
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
            print("{} {} {}".format(match[0].getName(True),match[1].getName(True),match[2]))
        
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

        print("\ndeleted symbols\n")
        for sym in deleted_symbols:
            print(sym)
            symbols['deleted'].append(str(sym))

        print("\nadded symbols\n")
        for sym in added_symbols:
            print(sym)
            symbols['added'].append(str(sym))

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
            if ematch_1 is None or ematch_2 is None:
                print("Symbol enhancing failed. One side is dead here.")
                match_0_name = match[0].getName(True)
                match_0_type = match[0].getSymbolType().toString()
                match_1_name = match[1].getName(True)
                match_1_type = match[1].getSymbolType().toString()
                print("match[0] is {} type {}".format(match_0_name, match_0_type))
                print("match[0] is {} type {}".format(match_1_name, match_1_type))
                if (match_0_name == match_1_name and
                   (match_0_type is "Function" or "Label") and
                   (match_1_type is "Function" or "Label")):
                    continue
                else:
                    assert False

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

            modified_funcs.append({'old': ematch_1, 'new': ematch_2, 'diff':diff, 'diff_type': diff_type, 'ratio': ratio, 'm_ratio': mnemonics_ratio, 'b_ratio': blocks_ratio, 'match_type': match_type})


        

        # Set funcs
        funcs['added'] = added_funcs
        funcs['deleted'] = deleted_funcs
        funcs['modified'] = modified_funcs

        # Set pdiff
        elapsed = time() - start
        self.pdiff['stats'] = {'added_funcs_len': len(added_funcs), 'deleted_funcs_len': len(deleted_funcs), 'modified_funcs_len': len(modified_funcs), 'added_symbols_len': len(symbols['added']), 'deleted_symbols_len': len(symbols['deleted']), 'diff_time': elapsed }
        self.pdiff['symbols'] = symbols
        self.pdiff['functions'] = funcs

        self.pdiff['old_meta'] = self.get_metadata(p1)
        self.pdiff['new_meta'] = self.get_metadata(p2)

        self.project.close(p1)
        self.project.close(p2)

        return self.pdiff


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='A simple Ghidra binary diffing tool')

    parser.add_argument('old', nargs=1, help='Path to older version of binary "/somewhere/bin.old"')
    parser.add_argument('new', action='append', nargs='+', help="Path to new version of binary '/somewhere/bin.new'. For multiple binaries add oldest to newest")

    GhidraDiffEngine.add_default_args_to_parser(parser)

    args = parser.parse_args()

    print(args)

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
