#TODO write a description for this script
#@author 
#@category Functions
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here

#### Section to make autocomplete work
try:
    import ghidra
    from ghidra_builtins import *
except:
    pass
####

import ghidra_bridge

#### Start ghidra-bridge-server before we are able to connect so we can pass args 
import os
import subprocess

def is_port_in_use(port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

GHIDRA_HEADLESS = os.getenv('GHIDRA_HEADLESS')
PROJECT_NAME = os.getenv('PROJECT_NAME')
PROJECT_PATH = os.path.join(os.getenv('GHIDRA_PROJECTS_PATH'),PROJECT_NAME)
GHIDRA_BRIDGE_INSTALL_DIR = os.getenv('GHIDRA_BRIDGE_INSTALL_DIR')

BINARY = "ls"

args = [GHIDRA_HEADLESS, PROJECT_PATH, PROJECT_NAME, '-scriptPath', GHIDRA_BRIDGE_INSTALL_DIR, "-postscript", 'ghidra_bridge_server.py', BINARY]
print(' '.join(args))

proc = None
BRIDGE_PORT = 4768
try:
    proc = subprocess.Popen (args, shell=False, preexec_fn=os.setsid)

    # Wait for ghidra_bridge_server to be ready
    import time
    while not is_port_in_use(BRIDGE_PORT):
        time.sleep(1)
        print("waiting for ghidra_bridge_server...")



    with ghidra_bridge.GhidraBridge(namespace=globals(), response_timeout=4, ):
        project = state.getProject()
        projectData = project.getProjectData()
        rootFolder = projectData.getRootFolder()

        print(project)
        print(projectData)
        print(rootFolder)

        prog = askProgram("program")
        
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
    
    # Give time for bridge connection to close
    time.sleep(2)
finally:
    # Terminate ghidra_bridge_server to prevent another one starting next time
    import signal
    print(f"Shutting down ghidra_bridge_server : {proc.pid}")
    os.killpg(os.getpgid(proc.pid), signal.SIGINT)