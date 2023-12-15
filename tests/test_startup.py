from ghidriff import GhidraDiffEngine
# from mock import patch
from pytest import MonkeyPatch
import pytest


def test_pyhidra_start():
    import pyhidra
    pyhidra.start(verbose=True)


def test_ghidra_install_dir():
    import os
    install_dir = os.getenv("GHIDRA_INSTALL_DIR")
    assert install_dir == "/ghidra"


# @pytest.fixture
# def setup_bogus_env(mon):


# @patch('pyhidra.GHIDRA_INSTALL_DIR', "/someboguspath"):
# def test_bogus_ghidra_install_dira():
#     with pytest.raises(FileNotFoundError):
#         import pyhidra as err_pyhidra
#         err_pyhidra.start(verbose=True)


# def test_ghidra_install_dir():
#     # import sys
#     # sys.modules.pop('pyhidra')
#     with MonkeyPatch.context() as mp:
#         mp.delenv("GHIDRA_INSTALL_DIR")

#         import pyhidra
#         # print(os.getenv("GHIDRA_INSTALL_DIR"))
#         with pytest.raises(SystemExit) as pytest_wrapped_e:
#             launcher = pyhidra.start(verbose=True)
#         assert pytest_wrapped_e.type == SystemExit
#         #assert pytest_wrapped_e.value.code == 42
#     import os
#     print(os.getenv("GHIDRA_INSTALL_DIR"))
#     # from importlib import reload
#     # reload(pyhidra)
#     import sys
#     del sys.modules['pyhidra']


# @pytest.mark.forked
# def test_bogus_ghidra_install_dir():
#     # monkeypatch.setenv("GHIDRA_INSTALL_DIR", '/someboguspath')
#     import os

#     with MonkeyPatch.context() as mp:
#         mp.delenv('GHIDRA_INSTALL_DIR')
#         print(os.getenv("GHIDRA_INSTALL_DIR"))

#         launcher = None

#         # with pytest.raises(SystemExit):
#         import pyhidra
#         mp.setattr(pyhidra.constants, 'GHIDRA_INSTALL_DIR', '/someboguspath')
#         print(pyhidra.constants)
#         print(os.getenv("GHIDRA_INSTALL_DIR"))
#         launcher = pyhidra.start(verbose=True)

#         assert launcher == None

    #     launcher = pyhidra.start(verbose=True)
    #     print(launcher.check_ghidra_version())

# det test_file_not_exist():
