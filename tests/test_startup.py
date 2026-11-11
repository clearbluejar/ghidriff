from ghidriff import GhidraDiffEngine
# from mock import patch
from pytest import MonkeyPatch
import pytest


@pytest.mark.forked
def test_pyghidra_start():
    """
    runs forked: a JVM started in the pytest process would deadlock every later forked test
    """
    import pyghidra
    pyghidra.start(verbose=True)


def test_ghidra_install_dir():
    import os
    from pathlib import Path
    install_dir = os.getenv("GHIDRA_INSTALL_DIR")
    assert install_dir, "GHIDRA_INSTALL_DIR is not set"
    assert (Path(install_dir) / 'Ghidra' / 'application.properties').is_file()


# @pytest.fixture
# def setup_bogus_env(mon):


# @patch('pyghidra.GHIDRA_INSTALL_DIR', "/someboguspath"):
# def test_bogus_ghidra_install_dira():
#     with pytest.raises(FileNotFoundError):
#         import pyghidra as err_pyghidra
#         err_pyghidra.start(verbose=True)


# def test_ghidra_install_dir():
#     # import sys
#     # sys.modules.pop('pyghidra')
#     with MonkeyPatch.context() as mp:
#         mp.delenv("GHIDRA_INSTALL_DIR")

#         import pyghidra
#         # print(os.getenv("GHIDRA_INSTALL_DIR"))
#         with pytest.raises(SystemExit) as pytest_wrapped_e:
#             launcher = pyghidra.start(verbose=True)
#         assert pytest_wrapped_e.type == SystemExit
#         #assert pytest_wrapped_e.value.code == 42
#     import os
#     print(os.getenv("GHIDRA_INSTALL_DIR"))
#     # from importlib import reload
#     # reload(pyghidra)
#     import sys
#     del sys.modules['pyghidra']


# @pytest.mark.forked
# def test_bogus_ghidra_install_dir():
#     # monkeypatch.setenv("GHIDRA_INSTALL_DIR", '/someboguspath')
#     import os

#     with MonkeyPatch.context() as mp:
#         mp.delenv('GHIDRA_INSTALL_DIR')
#         print(os.getenv("GHIDRA_INSTALL_DIR"))

#         launcher = None

#         # with pytest.raises(SystemExit):
#         import pyghidra
#         mp.setattr(pyghidra.constants, 'GHIDRA_INSTALL_DIR', '/someboguspath')
#         print(pyghidra.constants)
#         print(os.getenv("GHIDRA_INSTALL_DIR"))
#         launcher = pyghidra.start(verbose=True)

#         assert launcher == None

    #     launcher = pyghidra.start(verbose=True)
    #     print(launcher.check_ghidra_version())

# det test_file_not_exist():
