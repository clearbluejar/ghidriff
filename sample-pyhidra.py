import os
import pyhidra

#### Section to make autocomplete work
try:
    import ghidra
    from ghidra_builtins import *	
except:
    pass
####

PROJECT_NAME = os.getenv('PROJECT_NAME')
PROJECT_LOCATION = os.path.join(os.getenv('GHIDRA_PROJECTS_PATH'),PROJECT_NAME)

pyhidra.start(True) # setting Verbose output

with pyhidra.open_program("/bin/ls", project_name=PROJECT_NAME, project_location=PROJECT_LOCATION) as flat_api:
   
    prog = flat_api.getCurrentProgram()

    print("Program Info:")
    program_name = prog.getName()
    creation_date = prog.getCreationDate()
    language_id = prog.getLanguageID()
    compiler_spec_id = prog.getCompilerSpec().getCompilerSpecID()
    print("Program: {}: {}_{} ({})\n".format(program_name, language_id, compiler_spec_id, creation_date))

    # Get info about the current program's memory layout
    print("Memory layout:")
    print("Imagebase: " + hex(prog.getImageBase().getOffset()))
    for block in prog.getMemory().getBlocks():
        start = block.getStart().getOffset()
        end = block.getEnd().getOffset()
        print("{} [start: 0x{}, end: 0x{}]".format(block.getName(), start, end))