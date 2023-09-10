import pyhidra

def test_pyhidra_start():
    pyhidra.start(verbose=True)

def test_ghidra_install_dir():
    import os
    install_dir = os.getenv("GHIDRA_INSTALL_DIR")
    assert install_dir == "/ghidra"

#from ghidriff import GhidraDiffEngine
# from pytest import MonkeyPatch

# @pytest.fixture
# def setup_bogus_env(mon):
# from mock import patch

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
        


# def test_bogus_ghidra_install_dir():
#     #monkeypatch.setenv("GHIDRA_INSTALL_DIR", '/someboguspath')        
#     import os
#     print(os.getenv("GHIDRA_INSTALL_DIR"))
#     with MonkeyPatch.context() as mp:        
#         with pytest.raises(FileNotFoundError):                                    
#             import pyhidra
#             #mp.setattr(pyhidra.constants,'GHIDRA_INSTALL_DIR', '/someboguspath')            
#             pyhidra.start(verbose=True)

        


    
    #     launcher = pyhidra.start(verbose=True)
    #     print(launcher.check_ghidra_version())

#det test_file_not_exist():