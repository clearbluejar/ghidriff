from pathlib import Path
import ghidriff
import os
import pytest
import pyhidra


def test_bogus_ghidra_install_dir(monkeypatch):

    monkeypatch.setenv("GHIDRA_INSTALL_DIR", "/somebogusplace")
    print(os.getenv('GHIDRA_INSTALL_DIR'))
    pyhidra.start()
