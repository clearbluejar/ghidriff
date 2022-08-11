import os
import subprocess

# Env vars from launch.json 
GHIDRA_HEADLESS = os.getenv('GHIDRA_HEADLESS')
PROJECT_NAME = os.getenv('PROJECT_NAME')
PROJECT_PATH = os.path.join(os.getenv('GHIDRA_PROJECTS_PATH'),PROJECT_NAME)

# Project Path Needs to exist
if not os.path.exists(PROJECT_PATH):
    os.mkdir(PROJECT_PATH)

BINARY_PATH = "/bin/ls"

# Arguments for Ghidra's Headless Analyzer
args = [GHIDRA_HEADLESS, PROJECT_PATH, PROJECT_NAME, "-import", BINARY_PATH, "-overwrite"]

print(args)

subprocess.run(args)