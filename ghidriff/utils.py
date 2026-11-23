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


def get_field(obj, fname):
    """Read a private field of a Java object"""
    field = obj.getClass().getDeclaredField(fname)
    field.setAccessible(True)
    return field.get(obj)


def get_method(obj, name: str):
    """A private method of a Java object, by name"""
    method = next(m for m in obj.getClass().getDeclaredMethods() if m.getName() == name)
    method.setAccessible(True)
    return method


# symbol names that are renumbered between builds

# compiler-generated block names carry a per-build sequence number:
# ___foo_block_invoke.339, ___foo_block_invoke_2.12, ___block_literal_global.89, ___Block_byref_object_copy_.79
_SEQUENCE_SUFFIX_RE = re.compile(r'(block_invoke(?:_\d+)?|block_literal_global|Block_byref_object_(?:copy|dispose)_)(?:\.\d+)+')
# compiler-outlined helpers are renumbered between builds (_OUTLINED_FUNCTION_1 -> _OUTLINED_FUNCTION_2)
_OUTLINED_RE = re.compile(r'(_OUTLINED_FUNCTION_)\d+')


def stable_symbol_name(name: str) -> str:
    """A symbol name without the parts the compiler renumbers from build to build."""
    return _SEQUENCE_SUFFIX_RE.sub(r'\1', _OUTLINED_RE.sub(r'\1#', name))


def get_build_commit():
    """
    The git commit this ghidriff was built from, or None: a source checkout's HEAD, else the
    commit pip recorded for an install from git (PEP 610 direct_url.json).
    """
    import json
    import subprocess

    try:
        root = Path(__file__).resolve().parent.parent
        if (root / '.git').exists():
            out = subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'], capture_output=True, text=True, timeout=5)
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip()
    except Exception:
        pass

    try:
        from importlib.metadata import distribution
        text = distribution('ghidriff').read_text('direct_url.json')
        if text:
            return (json.loads(text).get('vcs_info') or {}).get('commit_id')
    except Exception:
        pass

    return None


# asm diff normalization

def mask_asm_target(kind: str) -> str:
    """Placeholder for an address-dependent operand in a normalized instruction"""
    return f'<{kind}>'


# default-named symbols embed the build specific address, e.g. FUN_18a2b3c4d, LAB_..., DAT_...
_ASM_DEFAULT_NAME_RE = re.compile(r'\b((?:thunk_)?(?:FUN|LAB|DAT|PTR|UNK|SUB|EXT|JMP|XREF|switchD|caseD|s|u)_(?:\w*_)?)[0-9a-fA-F]{5,}\b')
# bare absolute address; immediates are written #0x.. on arm and are left alone
_ASM_ABS_ADDR_RE = re.compile(r'(?<![#\w])0x[0-9a-fA-F]{5,}\b')


_ASM_BARE_BASE_RE = re.compile(r'^\[([a-z]\w*)\]$')


def mask_zero_page_offset(operand: str, adrp_regs: set) -> str:
    """
    A load or store straight off an adrp page register (`ldr x0,[x8]`) addresses page offset 0.
    Render it like any other page offset (`[x8, #<imm>]`), so a global that moves to or from
    offset 0 between builds does not show as a changed instruction.
    """
    m = _ASM_BARE_BASE_RE.match(operand.strip())
    if m and m.group(1) in adrp_regs:
        return operand.replace(f'[{m.group(1)}]', f'[{m.group(1)}, #{mask_asm_target("imm")}]')
    return operand


def normalize_asm_text(text: str) -> str:
    """
    Remove build specific addresses from one rendered instruction line (regex pass).
    Idempotent. Also used as the fallback when operand objects are unavailable.
    """
    text = _ASM_DEFAULT_NAME_RE.sub(lambda m: m.group(1) + 'ADDR', text)
    text = _ASM_ABS_ADDR_RE.sub('<addr>', text)
    return re.sub(r'\s+', ' ', text).strip()
