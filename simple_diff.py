import argparse
from dataclasses import dataclass
import json
import pathlib
import difflib
from time import time

from typing import List, Union, TYPE_CHECKING

from ghidra_diff_engine import GhidraDiffEngine

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *

class GhidraSimpleDiff(GhidraDiffEngine):
    """
    An Ghidra Diff implementation using simple comparison mechanisms
    """

    def __init__(self,verbose=False) -> None:
        super().__init__(verbose)

    def diff_bins(
            self,            
            old: Union[str, pathlib.Path],
            new: Union[str, pathlib.Path]
    ) -> dict:
        """Diff the old and new binary from the GhidraProject"""

        def _get_compare_key(sym: 'ghidra.program.model.symbol.Symbol', func: 'ghidra.program.model.listing.Function') -> tuple:
            return (sym.getParentNamespace().toString().split('@')[0],sym.getName(),sym.getReferenceCount(),func.body.numAddresses,func.parameterCount)

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


        # first pass detect added and deleted funcs

        for sym in p1.getSymbolTable().getDefinedSymbols():
            
            name = sym.getName()
            if "switch" not in name:
                old_symbols.append(sym.getName())	
                #old_symbols.append((sym.getName(),sym.getSymbolType().toString()))

        for sym in p2.getSymbolTable().getDefinedSymbols():
            #new_symbols.append((sym.getName(),sym.getSymbolType().toString()))
            name = sym.getName()
            if "switch" not in name:
                new_symbols.append(sym.getName())	
                
            

        olds = set(old_symbols)
        news = set(new_symbols)
        
        deleted_symbols = olds.difference(news)
        #print("deleted symbols: {}".format(deleted_symbols))
        print("\ndeleted symbols\n")
        for sym in deleted_symbols:
            print(sym)

        added_symbols = news.difference(olds)
        #print("added symbols: {}".format(added_symbols))
        print("\nadded symbols\n")
        for sym in added_symbols:
            print(sym)

        # Next pass remove false positives from symbols 
        # Build modified functions list based on (_get_compare_key)        
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

            sym2 = p2.getSymbolTable().getSymbol(
                sym.getName(), sym.getAddress(), sym.getParentNamespace())
            
            if sym2:
                found = True
                print("direct getsymbol match {} {}".format(
                    sym.getName(True), sym2.getName(True)))
                matched.append(sym)
                matched.append(sym2)
                matches.append([sym, sym2])
            else:
                for sym2 in p2_modified:
                    if found or sym2 in matched:
                    #if found:
                        continue
                    esym = self.enhance_sym(sym)
                    esym2 = self.enhance_sym(sym2)
                    if sym2.getName() == sym.getName() and esym2['paramcount']== esym['paramcount']:
                        print("Name + Paramcount {} {}".format(sym.getName(True),sym2.getName(True)))
                        found = True
                        #sym.getReferenceCount(),func.body.numAddresses,func.parameterCount
                    elif sym2.getName() == sym.getName() and esym2['length'] == esym['length']:
                        print("Name + length {} {}".format(sym.getName(True),sym2.getName(True)))
                        found = True
                    elif sym2.getAddress() == sym.getAddress() and esym2['length'] == esym['length']:
                        print("Address {} {}".format(sym.getName(True),sym2.getName(True)))
                        found = True
                    elif esym2['paramcount']== esym['paramcount'] and esym2['length'] == esym['length']:
                        print("param count + func len {} {}".format(sym.getName(True),sym2.getName(True)))
                        found = True                
                    elif sym2.getName(True) == sym.getName(True):
                        print("Name Exact {} {}".format(sym.getName(True),sym2.getName(True)))
                        found = True
                    
                    if found:
                        matched.append(sym)
                        matched.append(sym2)
                        matches.append([sym,sym2])
                        break


            if not found:
                print("Not found! {}".format(sym.getName(True)))                      
                # newsym = p2.getSymbolTable().getSymbol(sym.getID())            
                # if newsym:
                #     # TODO make this a match
                #     print("Maybe found? {}".format(newsym.getName(True)))            
                unmatched.append(sym)


        for sym in p2_modified:
            found = False

            if sym in matched:
                print(f"Already matched p2 {sym}")
                continue

            print(f"Not yet matched p2 {sym}")
            sym2 = p1.getSymbolTable().getSymbol(sym.getName(),sym.getAddress(),sym.getParentNamespace())

            if sym2:
                found = True
                print("direct getsymbol match {} {}".format(sym.getName(True),sym2.getName(True)))			
                matched.append(sym)
                matched.append(sym2)
                matches.append([sym,sym2])
            else:
                for sym2 in p1_modified:				
                    if found or sym2 in matched:
                        continue
                
                    esym = self.enhance_sym(sym)
                    esym2 = self.enhance_sym(sym2)
                    if sym2.getName() == sym.getName() and esym2['paramcount'] == esym['paramcount']:
                        print("Name + Paramcount {} {}".format(sym.getName(True),sym2.getName(True)))
                        found = True
                        #sym.getReferenceCount(),func.body.numAddresses,func.parameterCount
                    elif sym2.getName() == sym.getName() and esym2['length'] == esym['length']:
                        print("Name + length {} {}".format(sym.getName(True),sym2.getName(True)))
                        #found = True
                    elif sym2.getAddress() == sym.getAddress() and esym2['length'] == esym['length'] and esym2['paramcount'] == esym['paramcount']:
                        print("Address {} {}".format(sym.getName(True),sym2.getName(True)))
                        found = True
                    elif esym2['paramcount']== esym['paramcount'] and esym2['length'] == esym['length']:
                        print("param count + func len {} {}".format(sym.getName(True),sym2.getName(True)))
                        found = True             
                    elif sym2.getName(True) == sym.getName(True):
                        print("Name Exact {} {}".format(sym.getName(True),sym2.getName(True)))
                        found = True
                        
                    if found:
                        matched.append(sym)
                        matched.append(sym2)
                        matches.append([sym,sym2])
                        break
            
            if not found:
                print("Not found! {}".format(sym.getName(True)))
                unmatched.append(sym)

        print(len(p1_modified))
        print(len(p2_modified))


        matches = sorted(matches, key=lambda x: str(x[0]))


        # Update symbols using match knowledge
        for match in matches:
            print("{} {}".format(match[0].getName(True),match[1].getName(True)))
        
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
                diff_type.append('signature')

            if ematch_1['address'] != ematch_2['address']:
                diff_type.append('address')

            if len(set(ematch_1['calling']).difference(set(ematch_2['calling']))) > 0:
                diff_type.append('calling funcs')

            if len(set(ematch_1['called']).difference(set(ematch_2['called']))) > 0:
                diff_type.append('called funcs')

            if ematch_1['parent'] != ematch_2['parent']:
                diff_type.append('parent')

            # if no differences were found, there should not be a match (see modified func ident)
            assert len(diff_type) > 0

            modified_funcs.append({'old': ematch_1, 'new': ematch_2, 'diff':diff, 'diff_type': diff_type, 'ratio': ratio})


        

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


    group = parser.add_argument_group('Ghidra options')
    group.add_argument('-p', '--project-location', dest="project_location",
                    help='Ghidra Project Path', default='.ghidra_projects')
    group.add_argument('-n', '--project-name', dest="project_name",
                    help='Ghidra Project Name', default='diff_project')
    group.add_argument('-s', '--symbols-path', dest="symbols_path",
                    help='Ghidra local symbol store directory', default='.symbols')
    group.add_argument('-o', '--output-path', dest="output_path",
                    help='Directory to output results', default='.diffs')   

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
