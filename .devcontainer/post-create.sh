# Create local venv
python3 -m venv .env
source .env/bin/activate

# Download latest pyi typings for Ghidra Version
PYI_WHL_DOWNLOAD_URL=$(curl -s https://api.github.com/repos/clearbluejar/ghidra-pyi-generator/releases | jq -r ".[] | .assets[] | .browser_download_url" | grep "${GHIDRA_VERSION}" | grep whl)

# Ensure have valid versions
if [ -z "$PYI_WHL_DOWNLOAD_URL" ] || [ -z "$GHIDRA_VERSION" ]; then
    echo "Error: Failed to get PYI_WHL_DOWNLOAD_URL:${PYI_WHL_DOWNLOAD_URL} filtering on GHIDRA_VERSION:${GHIDRA_VERSION}"
    RELEASES=$(curl -s https://api.github.com/repos/clearbluejar/ghidra-pyi-generator/releases | jq -r ".[] | .assets[] | .browser_download_url")
    echo "Possible releases here: ${RELEASES}"
    exit 1 ## error out if they are empty
fi

echo $PYI_WHL_RELEASE_URLS
echo $PYI_WHL_DOWNLOAD_URL
pip install "${PYI_WHL_DOWNLOAD_URL}"

# Install ghidra-bridge
pip install ghidra_bridge

# Install bridge scripts to local dir
python -m ghidra_bridge.install_server .ghidra_bridge

# Install pyhdira
pip install pyhidra

# If arm64 os, need to build native binaries for Ghidra
if uname -a | grep -q 'aarch64'; then
    $GHIDRA_INSTALL_DIR/support/buildNatives
fi

# update requirements.txt with latest
pip freeze > requirements.txt