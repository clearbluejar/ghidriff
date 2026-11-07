import re
import hashlib
from pathlib import Path
from struct import unpack
from functools import lru_cache


@lru_cache(None)
def sha1_file(path: str) -> str:
    # https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
    # BUF_SIZE is totally arbitrary, change for your app!
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

    path = Path(path)

    sha1 = hashlib.sha1()

    with path.open('rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha1.update(data)

    return f'{sha1.hexdigest()}'


# get pe data for url gen
# https://github.com/m417z/winbindex/blob/gh-pages/data/extract_data_from_pe_files.py
def get_pe_extra_data(path: Path):

    path = Path(path)

    with path.open('rb') as handle:
        # Get PE offset (@60, DWORD) from DOS header
        handle.seek(60, 0)
        offset = handle.read(4)
        offset = unpack('<I', offset)[0]

        handle.seek(offset + 4, 0)
        word = handle.read(2)
        machine = unpack('<H', word)[0]

        handle.seek(offset + 8, 0)
        dword = handle.read(4)
        timestamp = unpack('<I', dword)[0]

        handle.seek(offset + 0x50, 0)
        dword = handle.read(4)
        image_size = unpack('<I', dword)[0]

    return {
        'machine': machine,
        'timestamp': timestamp,
        'image_size': image_size,
    }


def get_microsoft_download_url(filename, timestamp, virtual_size):

    assert filename is not None
    assert timestamp is not None
    assert virtual_size is not None

    timestamp = format(timestamp, '08X')
    virtual_size = format(virtual_size, 'X')

    return f'https://msdl.microsoft.com/download/symbols/{filename}/{timestamp}{virtual_size}/{filename}'


# utils from PyGhidra

def get_private_class(path: str):
    from java.lang import ClassLoader
    from jpype import JClass

    gcl = ClassLoader.getSystemClassLoader()
    return JClass(path, loader=gcl)


def set_field(cls, fname, value, obj=None):
    cls = cls.class_
    field = cls.getDeclaredField(fname)
    field.setAccessible(True)
    field.set(obj, value)
    field.setAccessible(False)


# asm diff normalization

def mask_asm_target(kind: str) -> str:
    """Placeholder for an address-dependent operand in a normalized instruction"""
    return f'<{kind}>'


# default-named symbols embed the build specific address, e.g. FUN_18a2b3c4d, LAB_..., DAT_...
_ASM_DEFAULT_NAME_RE = re.compile(r'\b((?:thunk_)?(?:FUN|LAB|DAT|PTR|UNK|SUB|EXT|JMP|XREF|switchD|caseD|s|u)_(?:\w*_)?)[0-9a-fA-F]{5,}\b')
# bare absolute address; immediates are written #0x.. on arm and are left alone
_ASM_ABS_ADDR_RE = re.compile(r'(?<![#\w])0x[0-9a-fA-F]{5,}\b')


def normalize_asm_text(text: str) -> str:
    """
    Remove build specific addresses from one rendered instruction line (regex pass).
    Idempotent. Also used as the fallback when operand objects are unavailable.
    """
    text = _ASM_DEFAULT_NAME_RE.sub(lambda m: m.group(1) + 'ADDR', text)
    text = _ASM_ABS_ADDR_RE.sub('<addr>', text)
    return re.sub(r'\s+', ' ', text).strip()
