# Create local venv
python3 -m venv .env
source .env/bin/activate

# Download latest pyi typings for Ghidra Version
pip install ghidra-stubs

# Install pyhdira
pip install pyhidra

# If arm64 os, need to build native binaries for Ghidra
if uname -a | grep -q 'aarch64'; then
    $GHIDRA_INSTALL_DIR/support/buildNatives
fi