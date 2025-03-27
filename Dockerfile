# From https://github.com/clearbluejar/ghidra-python
FROM ghcr.io/clearbluejar/ghidra-python:11.3.1ghidra3.12python-bookworm

ENV GHIDRA_INSTALL_DIR=/ghidra

USER vscode
WORKDIR /home/vscode/

# install latest from pip
RUN pip install ghidriff

# point absolute ghidriffs dir to user
# this supports absoulte mapping "docker run --rm -it -v ${PWD}/ghidriffs:/ghidriffs ghidriff /bin/cat1 /bin/cat2"
RUN ln -s /ghidriffs /home/vscode/

ENTRYPOINT ["/home/vscode/.local/bin/ghidriff"]

