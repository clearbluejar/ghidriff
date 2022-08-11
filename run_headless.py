import os
import subprocess

# env vars from launch.json 
GHIDRA_HEADLESS = os.getenv('GHIDRA_HEADLESS')
PROJECT_NAME = os.getenv('PROJECT_NAME')
PROJECT_PATH = os.path.join(os.getenv('GHIDRA_PROJECTS_PATH'),PROJECT_NAME)

SCRIPT = 'sample.py'
BINARY = "ls"

# Create Properties File to pass arguments to script
PROPERTIES_PATH = os.path.basename(SCRIPT).strip('.py') + '.properties'
PROPERTIES_TEMPLATE = '''program={BINARY}'''

with open(PROPERTIES_PATH, 'w') as f:
    f.write(PROPERTIES_TEMPLATE.format(BINARY=BINARY))

# Arguments for Ghidra's Headless Analyzer
args = [GHIDRA_HEADLESS, PROJECT_PATH, PROJECT_NAME, "-postscript", SCRIPT]

print(args)
print(PROPERTIES_TEMPLATE.format(BINARY=BINARY))

subprocess.run(args)
