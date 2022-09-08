import argparse
import pathlib
from typing import Union, TYPE_CHECKING

import pyhidra

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *

def setup_project(
        binary_paths: [Union[str, pathlib.Path]],
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


def setup_symbols(symbols_path: Union[str, pathlib.Path]) -> None:
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
    symbolServerService = SymbolServerService(localSymbolStore, List.of(msSymbolServer));

    PdbPlugin.saveSymbolServerServiceConfig(symbolServerService);




def analyze_project(project: "ghidra.base.project.GhidraProject") -> None:
    """
    Analyzes all files found within the project
    """

    from ghidra.program.flatapi import FlatProgramAPI


    for domainFile in project.getRootFolder().getFiles():
        print(domainFile)    

        program = project.openProgram("/", domainFile.getName(), False)        



        from ghidra.app.plugin.core.analysis import PdbAnalyzer;
        from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer;
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
    

def diff_bins(
        project: "ghidra.base.project.GhidraProject",
        old: Union[str, pathlib.Path],
        new: Union[str, pathlib.Path]
) -> str:
    """Diff the old and new binary from the GhidraProject"""

    from ghidra.util.task import ConsoleTaskMonitor
    import difflib
    import json

    esym_memo = {}
    def enhance_sym(sym):

        if sym not in esym_memo:

            prog = sym.getProgram()

            listing = prog.getListing().getFunctionAt(sym.getAddress())
            func = prog.functionManager.getFunctionAt(sym.getAddress())
            if not sym.getSymbolType().toString().lower() == "function" and not listing and not func:
                print("not a func. {} type {}".format(sym.getName(True),sym.getSymbolType().toString()))
                return None

            ifc.openProgram(prog)
            func = prog.functionManager.getFunctionAt(sym.getAddress())

            called_funcs = []
            for f in func.getCalledFunctions(ConsoleTaskMonitor()):
                called_funcs.append(f.toString())

            calling_funcs = []
            for f in func.getCallingFunctions(ConsoleTaskMonitor()):
                calling_funcs.append(f.toString())

                
            results = ifc.decompileFunction(func,1,ConsoleTaskMonitor()).getDecompiledFunction()
            code = results.getC() if results else ""
            
            esym_memo[sym] = { 'name': sym.getName(), 'refcount': sym.getReferenceCount(), 'length': func.body.numAddresses, 'called': called_funcs,'calling': calling_funcs, 'paramcount': func.parameterCount, 'address': str(sym.getAddress()),'sig':str(func.getSignature(False)),'code':code}

        return esym_memo[sym]
    
    from ghidra.app.decompiler import DecompInterface
    ifc = DecompInterface()

    p1 = project.openProgram("/", old, False)
    p2 = project.openProgram("/", new, False)

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

    # Next pass remove false positives from symbols and build modified list (ref count and func length changes)

    for sym in p1.getSymbolTable().getDefinedSymbols():
        #key = (sym.getName(),sym.getSymbolType().toString())
        key = sym.getName()
        if key in deleted_symbols:
            print("{} {}".format(sym.getName(),sym.getAddress()))
            sym2 = p2.getSymbolTable().getSymbol(sym.getName(),sym.getAddress(),sym.getParentNamespace())
            sym2_data = p2.getListing().getDataAt(sym.getAddress())
            if sym2_data:
                print(sym2_data)
                print("***")
            if sym2 or sym2_data:
                print("Removing {} from deleted, found match {} {} in p2".format(sym,sym2,sym2_data))
                deleted_symbols.remove(key)
            

        if "function".lower() in sym.getSymbolType().toString().lower():
            func = p1.functionManager.getFunctionAt(sym.getAddress())			
            #if func.body.numAddresses < 100: # fix this later?
            #	continue
            # called_func_len = len(func.getCalledFunctions(ConsoleTaskMonitor()))
            # calling_func_len = len(func.getCallingFunctions(ConsoleTaskMonitor()))
            # old_funcs.append((sym.toString(),sym.getReferenceCount(),func.body.numAddresses,called_func_len,calling_func_len,func.parameterCount))
            old_funcs.append((sym.getName(),sym.getReferenceCount(),func.body.numAddresses,func.parameterCount))



    for sym in p2.getSymbolTable().getDefinedSymbols():
        key = sym.getName()
    #    key = (sym.getName(),sym.getSymbolType().toString())
        if key in added_symbols:
            print("{} {}".format(sym.getName(),sym.getAddress()))
            sym2 = p1.getSymbolTable().getSymbol(sym.getName(),sym.getAddress(),sym.getParentNamespace())
            # sym2_data = p1.getListing().getDataAt(sym.getAddress())
            # if sym2_data:
            # 	print(sym2_data)
            # 	print("***")
            if sym2 or sym2_data:
                print("Removing {} from deleted, found match {} in p1".format(sym,sym2))
                added_symbols.remove(key)

        if "function".lower() in sym.getSymbolType().toString().lower():
            func = p2.functionManager.getFunctionAt(sym.getAddress())
            # if func.body.numAddresses < 100: #fix this later?
            # 	continue
            # called_func_len = len(func.getCalledFunctions(ConsoleTaskMonitor()))
            # calling_func_len = len(func.getCallingFunctions(ConsoleTaskMonitor()))
            # if "I_RpcTransVerify" in sym.toString():
            # 	print(func.getSignature(False))
            # new_funcs.append((sym.toString(),sym.getReferenceCount(),func.body.numAddresses,called_func_len,calling_func_len,func.parameterCount))
            new_funcs.append((sym.getName(),sym.getReferenceCount(),func.body.numAddresses,func.parameterCount))
            


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

    # reiterate through symbols and pull out details

    deleted_enhanced = []
    added_enhanced = []
    old_enhanced = []
    new_enhanced = []

    p1_modified = []
    p2_modified = []


    #ifc.openProgram(p1)

    for sym in p1.getSymbolTable().getDefinedSymbols():

        if "function".lower() in sym.getSymbolType().toString().lower():		
            func = p1.functionManager.getFunctionAt(sym.getAddress())
            # called_func_len = len(func.getCalledFunctions(ConsoleTaskMonitor()))
            # calling_func_len = len(func.getCallingFunctions(ConsoleTaskMonitor()))
            # if (sym.toString(),sym.getReferenceCount(),func.body.numAddresses,called_func_len,calling_func_len,func.parameterCount) in modified_old:
            if (sym.getName(),sym.getReferenceCount(),func.body.numAddresses,func.parameterCount) in modified_old:

                p1_modified.append(sym)
                # sym2 = p2.getSymbolTable().getSymbol(sym.getName(),sym.getAddress(),sym.getParentNamespace())
                # # match found
                # if sym2:
                # 	print("Found match {} {}".format(func,sym2))
                # # else:
                # # 	func2 = p2.getSymbolTable().getSymbol(sym.getName(),sym.getParentNamespace())
                # # 	if func2:
                # # 		print("Found partial match {}".format(func2))
                

                # results = ifc.decompileFunction(func,1,ConsoleTaskMonitor()).getDecompiledFunction()
                # code = results.getC() if results else ""		
                # #code = "delete this line" if results else ""	
                # called_func_len = len(func.getCalledFunctions(ConsoleTaskMonitor()))
                # calling_func_len = len(func.getCallingFunctions(ConsoleTaskMonitor()))
                # old_enhanced.append((sym.getName(),sym.getReferenceCount(),func.body.numAddresses,called_func_len,calling_func_len,func.parameterCount,func.body.minAddress,sym.getAddress(),func.getSignature(False),code))

    #ifc.openProgram(p2)


    for sym in p2.getSymbolTable().getDefinedSymbols():	
        
        if "function".lower() in sym.getSymbolType().toString().lower():		
            func = p2.functionManager.getFunctionAt(sym.getAddress())

            # called_func_len = len(func.getCalledFunctions(ConsoleTaskMonitor()))
            # calling_func_len = len(func.getCallingFunctions(ConsoleTaskMonitor()))
            # if (sym.toString(),sym.getReferenceCount(),func.body.numAddresses,called_func_len,calling_func_len,func.parameterCount) in modified_new:
            if (sym.getName(),sym.getReferenceCount(),func.body.numAddresses,func.parameterCount) in modified_new:			
                p2_modified.append(sym)
                
                
                # sym2 = p1.getSymbolTable().getSymbol(sym.getName(),sym.getAddress(),sym.getParentNamespace())
                # # match found
                # if sym2:
                # 	print("Found match {} {}".format(func,sym2))
                # results = ifc.decompileFunction(func,1,ConsoleTaskMonitor()).getDecompiledFunction()
                
                # code = results.getC() if results else ""
                # #code = "delete this line" if results else ""		
                # called_func_len = len(func.getCalledFunctions(ConsoleTaskMonitor()))
                # calling_func_len = len(func.getCallingFunctions(ConsoleTaskMonitor()))
                # new_enhanced.append((sym.getName(),sym.getReferenceCount(),func.body.numAddresses,called_func_len,calling_func_len,func.parameterCount,func.body.minAddress,sym.getAddress(),func.getSignature(False),code))


    matched = []
    unmatched = []
    matches = []


    for sym in p1_modified:
        found = False

        if sym in matched:
            continue

        esym = enhance_sym(sym)

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
                esym2 = enhance_sym(sym2)
                if sym2.getAddress() == sym.getAddress():
                    print("Address {} {}".format(sym.getName(True),sym2.getName(True)))
                    found = True
                elif sym2.getName() == sym.getName() and esym2['paramcount']== esym['paramcount']:
                    print("Name + Paramcount {} {}".format(sym.getName(True),sym2.getName(True)))
                    found = True
                    #sym.getReferenceCount(),func.body.numAddresses,func.parameterCount
                elif esym2['paramcount']== esym['paramcount'] and esym2['length'] == esym['length']:
                    print("param count + func len {} {}".format(sym.getName(True),sym2.getName(True)))
                    found = True
                elif sym2.getName() == sym.getName() and esym2['length'] == esym['length']:
                    print("Name + length {} {}".format(sym.getName(True),sym2.getName(True)))
                    found = True
                elif sym2.getName(True) == sym.getName(True):
                    print("Name Exact  {} {}".format(sym.getName(True),sym2.getName(True)))
                    found = True
                if found:
                    matched.append(sym)
                    matched.append(sym2)
                    matches.append([sym,sym2])


        if not found:
            newsym = p2.getSymbolTable().getSymbol(sym.getID())
            print("Not found! {}".format(sym.getName(True)))
            print("Maybe found? {}".format(newsym.getName(True)))
            
            unmatched.append(sym)


    for sym in p2_modified:
        found = False

        if sym in matched:
            continue

        esym = enhance_sym(sym)

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
                #if found:
                    continue
            esym2 = enhance_sym(sym2)
            if sym2.getAddress() == sym.getAddress():
                print("Address {} {}".format(sym.getName(True),sym2.getName(True)))
                found = True
            elif sym2.getName() == sym.getName() and esym2['paramcount']== esym['paramcount']:
                print("Name + Paramcount {} {}".format(sym.getName(True),sym2.getName(True)))
                found = True
                #sym.getReferenceCount(),func.body.numAddresses,func.parameterCount
            elif esym2['paramcount']== esym['paramcount'] and esym2['length'] == esym['length']:
                print("param count + func len {} {}".format(sym.getName(True),sym2.getName(True)))
                found = True
            elif sym2.getName() == sym.getName() and esym2['length'] == esym['length']:
                print("Name + length {} {}".format(sym.getName(True),sym2.getName(True)))
                found = True
            elif sym2.getName(True) == sym.getName(True):
                print("Name Exact  {} {}".format(sym.getName(True),sym2.getName(True)))
                found = True
                
                #sym.getReferenceCount(),func.body.numAddresses,func.parameterCount


                if found:
                    matched.append(sym)
                    matched.append(sym2)
                    matches.append([sym,sym2])
        
        if not found:
            
            newsym = p1.getSymbolTable().getSymbol(sym.getID())
            print("Not found! {}".format(sym.getName(True)))
            print("Maybe found? {}".format(newsym.getName(True)))
            unmatched.append(sym)





    print(len(p1_modified))
    print(len(p2_modified))

    print(unmatched)
    print(matched)
    print(matches)    
    matches = sorted(matches, key=lambda x: str(x[0]))

    # print("\nmodified_old_modified")
    # for sym in old_enhanced:
    # 	print(sym)


    # print("\nmodified_new_modified")
    # for sym in new_enhanced:
    # 	print(sym)


    # print("\nmodified_old_modified")
    # for sym in old_enhanced:
    # 	print(sym)


    print("\nmatches")
    for match in matches:
        print("{} {}".format(match[0].getName(True),match[1].getName(True)))
        # fix up symbols with now match functions
        if match[0].getName() in deleted_symbols:
            deleted_symbols.remove(match[0].getName())
        if match[1].getName() in added_symbols:
            added_symbols.remove(match[1].getName())

    symbols = {}
    pdiff = {}
    symbols['added'] = []
    symbols['deleted'] = []

    #print("deleted symbols: {}".format(deleted_symbols))
    print("\ndeleted symbols\n")
    for sym in deleted_symbols:
        print(sym)
        symbols['deleted'].append(str(sym))

    #print("added symbols: {}".format(added_symbols))
    print("\nadded symbols\n")
    for sym in added_symbols:
        print(sym)
        symbols['added'].append(str(sym))

    result = {}
    diff_text = ''
    deleted_text = ''
    added_text = ''

    funcs = {}
    deleted_funcs = []
    added_funcs = []
    modified_funcs = []
    modified_funcs_short = []


    for lost in unmatched:
        text = ''
        elost = enhance_sym(lost)

        # deleted func
        if lost.getProgram().getName() == p1.getName():
            deleted_funcs.append(elost)		
            old_code = elost['code'].splitlines(True)
            new_code = ''.splitlines(True)		
        # added func
        else:
            added_funcs.append(elost)		
            old_code = ''.splitlines(True)		
            new_code = elost['code'].splitlines(True)		

        diff = ''.join(list(difflib.unified_diff(old_code,new_code,lineterm='\n',fromfile=p1.getName(),tofile=p2.getName())))

        text += "## {}\n".format(elost['name'])
        text += "```diff\n"
        text += diff
        text += "```\n"
        text += "\n"

        if lost.getProgram().getName() == p1.getName():		
            deleted_text += text
        else:
            added_text += text


    diff_text += "# Deleted\n"
    diff_text += deleted_text
    diff_text += "# Added\n"
    diff_text += added_text
    diff_text += "# Modified\n"

    for match in matches:
        diff_type = []
        ematch_1 = enhance_sym(match[0])
        ematch_2 = enhance_sym(match[1])


        old_code = ematch_1['code'].splitlines(True)
        new_code = ematch_2['code'].splitlines(True)

        


        old_code_no_sig = ematch_1['code'].split('{',1)[1].splitlines(True) if ematch_1['code'] else ''
        new_code_no_sig = ematch_2['code'].split('{',1)[1].splitlines(True) if ematch_2['code'] else ''

        ratio = difflib.SequenceMatcher(None, old_code_no_sig, new_code_no_sig).ratio()    

        print(ematch_1['sig'])
        print(ematch_2['sig'])	
        diff = ''.join(list(difflib.unified_diff(old_code,new_code,lineterm='\n',fromfile=match[0].getProgram().getName(),tofile=match[1].getProgram().getName())))
        only_code_diff = ''.join(list(difflib.unified_diff(old_code_no_sig,new_code_no_sig,lineterm='\n',fromfile=match[0].getProgram().getName(),tofile=match[1].getProgram().getName()))) # ignores name changes
        #print(only_code_diff)
        print(len(diff))
        #print(diff)
        if len(only_code_diff) > 0:
            diff_text += "## {}\n".format(ematch_1['sig'])
            diff_text += "```diff\n"
            diff_text += diff
            diff_text += "```\n"
            diff_text += "\n"

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

        modified_funcs.append({'old': ematch_1, 'new': ematch_2, 'diff':diff, 'diff_type': diff_type, 'ratio': ratio})

        modified_funcs_short.append({'name': [ematch_1['name'], ematch_2['name']], 'length': [ematch_1['length'], ematch_2['length']], 'ratio': ratio, 'diff_type': diff_type })


    funcs['added'] = added_funcs
    funcs['deleted'] = deleted_funcs
    funcs['modified'] = modified_funcs
    funcs['modified_short'] = modified_funcs_short


    pdiff['symbols'] = symbols
    pdiff['functions'] = funcs
    pdiff['stats'] = {'added_funcs_len': len(added_funcs), 'deleted_funcs_len': len(deleted_funcs), 'modified_funcs_len': len(modified_funcs), 'added_symbols_len': len(added_symbols), 'deleted_symbols_len': len(deleted_symbols) }

    path = "{}_to_{}_diff".format(p1.getName(),p2.getName())
    print(path)

    #print(diff_text)

    with open(path+'.md','w') as f:
        f.write(diff_text)

    #print(pdiff)

    with open(path+'.json', 'w') as f:
        json.dump(pdiff, f,)


    name = p1.getName().split('.')[0]
    major_build = p1.getName().split('.')[5]
    p1_minor = '.'.join(p1.getName().split('.')[3:7])
    p2_minor = '.'.join(p2.getName().split('.')[3:7])

    jd_path = name + '-' + major_build + '.json'

    json_pdiffs = {}
    import os

    print(jd_path)
    if os.path.exists(jd_path):
        with open(jd_path, "r") as f:
            json_pdiffs = json.load(f)

    #json_pdiffs.append({ p1_minor + '-' + p2_minor : pdiff })

    json_pdiffs[p1_minor + '-' + p2_minor] = pdiff

    with open(jd_path, 'w') as f:
        json.dump(json_pdiffs, f)            

    project.close(p1)
    project.close(p2)




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

args = parser.parse_args()

print(args)

binary_paths = args.old + [bin for sublist in args.new for bin in sublist]

pyhidra.start(True)

project = setup_project(binary_paths, args.project_location, args.project_name)

setup_symbols(args.symbols_path)

analyze_project(project)

diffs = []

# pair up binaries with the n-1 version
for i in range(len(binary_paths)-1):
    diffs.append((binary_paths[i], binary_paths[i+1]))

# add a diff of the first and last binary for full coverage
if not binary_paths[1] == binary_paths[-1]:
    diffs.append((binary_paths[0], binary_paths[-1])) 




for diff in diffs:
    diff_bins(project, diff[0], diff[1])
