"""
Normalized low p-code hash per function (L_sym_lin), used to detect changed logic in
matched functions whose size and reference count did not change.

Ported from the patch-diffing prototype (pcode_hash.py) with these changes:
  - memory operands are symbolized from the instruction's data references
    (Instruction.getReferencesFrom) rather than by tracking ADRP pages by hand,
    so cross-block ADRP, zero-offset loads and neighbour-symbol folds hash alike
  - direct and GOT references to the same symbol produce the same token
  - BuildRoots / com.apple.xbs UUID paths and __DATE__/__TIME__ strings are masked
  - `.N` suffixes are stripped from block_invoke / block_literal_global names
  - each token keeps its constants separately so a pair can be classified
    (classify_pair) instead of only compared
"""

import bisect
import hashlib
import re
from collections import Counter
from typing import List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    import ghidra

U64 = (1 << 64) - 1

# hex runs inside names are build specific (FUN_..., __stub_fffffff00aa31c88, ...)
_HEXRUN = re.compile(r'(?<=[_.:$])[0-9a-fA-F]{3,}|0x[0-9a-fA-F]+|[0-9a-fA-F]{8,}')
_BLOCK_SUFFIX = re.compile(r'(block_invoke|block_literal_global)(\.\d+)+')
# compiler-outlined helpers are renumbered between builds (_OUTLINED_FUNCTION_1 -> _OUTLINED_FUNCTION_2)
_OUTLINED = re.compile(r'(_OUTLINED_FUNCTION_)\d+')
_BUILD_PATHS = [
    # older builds use a UUID, iOS/macOS 27 an opaque token (BuildRoots/4~CWFdugDfP269.../)
    (re.compile(r'/AppleInternal/Library/BuildRoots/[^/]+/'), '/AppleInternal/Library/BuildRoots/<UUID>/'),
    (re.compile(r'/Library/Caches/com\.apple\.xbs/[^/]+/'), '/Library/Caches/com.apple.xbs/<UUID>/'),
]
_DATE = re.compile(r'^[A-Z][a-z]{2} [ \d]\d \d{4}$')  # __DATE__  "Nov  7 2026"
_TIME = re.compile(r'^\d{2}:\d{2}:\d{2}$')  # __TIME__  "12:34:56"

# constant placeholder inside a Token template (never present in names or strings, see _clean_*)
_PH = '\x1f'

# change classes that are build noise rather than logic, never surfaced by the gate
NOISE_CLASSES = {'shift', 'imm-id', 'build-path'}

_WIDE_IMM_MNEMONICS = {'mov', 'movk', 'movz', 'movn'}


def _clean_name(name: str) -> str:
    name = _OUTLINED.sub(r'\1#', name)
    return _BLOCK_SUFFIX.sub(r'\1', _HEXRUN.sub('#', name)).replace(_PH, ' ')


def _clean_string(value: str) -> str:
    for pattern, repl in _BUILD_PATHS:
        value = pattern.sub(repl, value)
    if _DATE.match(value):
        return '<DATE>'
    if _TIME.match(value):
        return '<TIME>'
    return value.replace(_PH, ' ')


class Token:
    """One p-code op: a constant-free template plus the constants it carries."""

    __slots__ = ('template', 'consts')

    def __init__(self, template: str, consts: Tuple[Tuple[int, int, str], ...]):
        self.template = template
        # (value, size, mnemonic of the instruction it came from)
        self.consts = consts

    def text(self) -> str:
        parts = self.template.split(_PH)
        out = [parts[0]]
        for (value, size, _), part in zip(self.consts, parts[1:]):
            out.append(f'#{value:x}:{size}' + part)
        return ''.join(out)


class PcodeHasher:
    """Per-program hasher; caches symbol tokens across functions."""

    def __init__(self, program: 'ghidra.program.model.listing.Program'):
        from ghidra.program.model.block import BasicBlockModel
        from ghidra.program.model.pcode import PcodeOp

        self.PcodeOp = PcodeOp
        self.prog = program
        self.fm = program.getFunctionManager()
        self.listing = program.getListing()
        self.st = program.getSymbolTable()
        self.mem = program.getMemory()
        self.ram = program.getAddressFactory().getDefaultAddressSpace()
        self.bbm = BasicBlockModel(program)
        self.symcache = {}

        blocks = []
        for block in self.mem.getBlocks():
            if not block.getStart().isMemoryAddress() or block.isOverlay():
                continue
            blocks.append((block.getStart().getOffset() & U64, block.getEnd().getOffset() & U64))
        blocks.sort()
        self.blk_starts = [start for start, _ in blocks]
        self.blks = blocks

        self.callee_saved = set()
        for name in [f'x{i}' for i in range(19, 30)]:
            reg = program.getRegister(name)
            if reg is not None:
                self.callee_saved.add(reg.getOffset())

        self.branchy = {PcodeOp.BRANCH, PcodeOp.CBRANCH}
        self.cally = {PcodeOp.CALL}
        self.keep_input0 = {PcodeOp.LOAD, PcodeOp.STORE, PcodeOp.CALLOTHER}

    # ------------------------------------------------------------------ symbols
    def _in_mem(self, value: int) -> bool:
        if value < 0x1000:
            return False
        i = bisect.bisect_right(self.blk_starts, value) - 1
        return i >= 0 and self.blks[i][0] <= value <= self.blks[i][1]

    def _addr(self, value: int):
        value &= U64
        try:
            return self.ram.getAddress(value - (1 << 64) if value >= (1 << 63) else value)
        except Exception:
            return None

    def _is_got(self, addr) -> bool:
        block = self.mem.getBlock(addr)
        return block is not None and 'got' in block.getName().lower()

    def symtok(self, addr, depth: int = 0) -> str:
        """Relocation-invariant token for a memory address."""
        key = (str(addr), depth)
        if key in self.symcache:
            return self.symcache[key]
        tok = 'A'
        try:
            func = self.fm.getFunctionAt(addr)
            if func is not None:
                if func.isThunk():
                    thunked = func.getThunkedFunction(True)
                    if thunked is not None:
                        func = thunked
                tok = ('X:' if func.isExternal() else 'F:') + _clean_name(func.getName())
            else:
                data = self.listing.getDataAt(addr)
                if data is not None and data.hasStringValue():
                    tok = 'S:' + _clean_string(str(data.getValue()))[:80]
                else:
                    sym = self.st.getPrimarySymbol(addr)
                    if sym is not None and str(sym.getSource()) != 'DEFAULT':
                        tok = 'D:' + _clean_name(sym.getName())
                    elif data is not None and data.isPointer() and depth == 0:
                        value = data.getValue()
                        if value is not None:
                            if value.isExternalAddress():
                                ext = self.st.getPrimarySymbol(value)
                                tok = 'P>X:' + (ext.getName() if ext else '?')
                            elif value.isMemoryAddress():
                                tok = 'P>' + self.symtok(value, 1)
        except Exception:
            tok = 'A'
        tok = tok.replace('\n', ' ')
        self.symcache[key] = tok
        return tok

    def reftok(self, addr) -> str:
        """Token for a data reference target; a GOT slot is replaced by what it points at."""
        if self._is_got(addr):
            data = self.listing.getDataAt(addr)
            if data is not None and data.isPointer():
                value = data.getValue()
                if value is not None and (value.isMemoryAddress() or value.isExternalAddress()):
                    if value.isExternalAddress():
                        ext = self.st.getPrimarySymbol(value)
                        return 'X:' + (ext.getName() if ext else '?')
                    return self.symtok(value)
        return self.symtok(addr)

    # ---------------------------------------------------------------- tokens
    def tokens(self, func: 'ghidra.program.model.listing.Function') -> List[Token]:
        PcodeOp = self.PcodeOp
        from ghidra.util.task import TaskMonitor

        raw_blocks = []
        it = self.bbm.getCodeBlocksContaining(func.getBody(), TaskMonitor.DUMMY)
        while it.hasNext():
            block = it.next()
            raw_blocks.append((block.getMinAddress().getOffset() & U64, block))
        raw_blocks.sort(key=lambda x: x[0])

        ren = {}
        toks = []

        def var(vn, opc, pos, ins_refs, mnemonic, consts):
            if vn is None:
                return '_'
            size = vn.getSize()
            if vn.isConstant():
                value = vn.getOffset() & U64
                if pos == 0 and opc in self.keep_input0:
                    return f'c{value}:{size}'  # space id / userop index: stable
                if size >= 4 and self._in_mem(value):
                    return self.symtok(self._addr(value)) + f':{size}'
                if size == 8 and value >= (1 << 44) and (value >> 48) != 0xffff:
                    return 'TP:8'  # arm64e chained-fixup / PAC-tagged pointer
                consts.append((value, size, mnemonic))
                return _PH
            if vn.isRegister() or vn.isUnique():
                key = ('r' if vn.isRegister() else 'u', vn.getOffset())
                if key not in ren:
                    ren[key] = len(ren)
                return f'{key[0]}{ren[key]}:{size}'
            space = vn.getAddress().getAddressSpace()
            if vn.isAddress() and space.isMemorySpace():
                if pos == 0 and opc in self.branchy:
                    return 'L'
                if pos == 0 and opc in self.cally:
                    return self.symtok(vn.getAddress())
                return 'M[' + self.symtok(vn.getAddress()) + f']:{size}'
            if space.isStackSpace():
                key = ('s', vn.getOffset())
                if key not in ren:
                    ren[key] = len(ren)
                return f's{ren[key]}:{size}'
            return f'o:{space.getName()}:{size}'

        pages = {}  # register offset -> ADRP page value, carried across blocks in address order

        def reg_tok(reg):
            key = ('r', reg.getOffset())
            if key not in ren:
                ren[key] = len(ren)
            return f'r{ren[key]}:{reg.getMinimumByteSize()}'

        for _, block in raw_blocks:
            for ins in self.listing.getInstructions(block, True):
                mnemonic = str(ins.getMnemonicString()).lower()
                ops = list(ins.getPcode())

                if mnemonic == 'adrp':
                    # the page alone means nothing; the instruction completing the address names the target
                    out = ops[0].getOutput() if ops else None
                    for op in ops:
                        o = op.getOutput()
                        if o is not None and o.isRegister():
                            for vn in op.getInputs():
                                if vn.isConstant():
                                    pages[o.getOffset()] = vn.getOffset() & U64
                    toks.append(Token('ADRP ' + var(out, None, -1, False, mnemonic, []) + ' = PAGE', ()))
                    continue

                # target addresses: Ghidra's data references to named things, plus the tracked ADRP page + offset.
                # A reference to an unnamed address carries no information and is not always present on both
                # sides, so it is ignored.
                targets = [ref.getToAddress() for ref in ins.getReferencesFrom()
                           if ref.isMemoryReference() and not ref.getReferenceType().isFlow()
                           and ref.getToAddress().isMemoryAddress() and self.reftok(ref.getToAddress()) != 'A']
                address_inputs = {op.getInput(1).getOffset() for op in ops
                                  if op.getOpcode() in (PcodeOp.LOAD, PcodeOp.STORE) and op.getInput(1).isUnique()}
                alias = {}  # unique -> base register, for address arithmetic folded into the REF token
                dropped = set()  # unique offsets whose defining COPY/INT_ADD is dropped
                uconst = {}  # AArch64 lifts `add xD, xB, #imm` as `COPY u = #imm; INT_ADD xD = xB, u`
                for op in ops:
                    o = op.getOutput()
                    if op.getOpcode() == PcodeOp.COPY and o is not None and o.isUnique() and op.getInput(0).isConstant():
                        uconst[o.getOffset()] = op.getInput(0).getOffset() & U64
                    if op.getOpcode() != PcodeOp.INT_ADD or o is None:
                        continue
                    a, b = op.getInput(0), op.getInput(1)
                    if not a.isRegister():
                        continue
                    if b.isConstant():
                        imm = b.getOffset() & U64
                    elif b.isUnique() and b.getOffset() in uconst:
                        imm = uconst[b.getOffset()]
                    else:
                        continue
                    on_page = a.getOffset() in pages and imm < 0x1000
                    if on_page and not targets:
                        targets.append(self._addr(pages[a.getOffset()] + imm))
                    # fold only the arithmetic that forms the referenced address
                    if o.isUnique() and (on_page or (targets and imm < 0x1000 and o.getOffset() in address_inputs)):
                        alias[o.getOffset()] = a
                        dropped.add(o.getOffset())
                        if b.isUnique():
                            dropped.add(b.getOffset())
                if not targets:
                    # zero page offset: `ldr x0, [x8]` straight off the page register
                    for op in ops:
                        if op.getOpcode() in (PcodeOp.LOAD, PcodeOp.STORE):
                            base = op.getInput(1)
                            if base.isRegister() and base.getOffset() in pages:
                                targets.append(self._addr(pages[base.getOffset()]))
                ref_tokens = sorted({self.reftok(t) for t in targets if t is not None})

                dest = ins.getRegister(0) if ins.getNumOperands() > 0 else None
                is_got = bool(targets) and all(t is not None and self._is_got(t) for t in targets)
                if ref_tokens and dest is not None and (mnemonic == 'add' or (mnemonic in ('ldr', 'ldur') and is_got)):
                    # direct `add xD, xB, #off` and GOT `ldr xD, [xB, #off]` both materialise the symbol's address
                    toks.append(Token(f'ADDR {reg_tok(dest)} = ' + ' '.join(ref_tokens), ()))
                else:
                    for op in ops:
                        opc = op.getOpcode()
                        o = op.getOutput()
                        if o is not None and o.isUnique() and o.getOffset() in dropped and opc in (PcodeOp.INT_ADD, PcodeOp.COPY):
                            continue  # address arithmetic folded into the REF token
                        consts = []
                        ins_t = []
                        for i, vn in enumerate(op.getInputs()):
                            if vn is not None and vn.isUnique() and vn.getOffset() in alias:
                                vn = alias[vn.getOffset()]
                            ins_t.append(var(vn, opc, i, bool(ref_tokens), mnemonic, consts))
                        out_t = var(op.getOutput(), opc, -1, False, mnemonic, []) if op.getOutput() is not None else ''
                        toks.append(Token(f'{PcodeOp.getMnemonic(opc)} {out_t} = ' + ' '.join(ins_t), tuple(consts)))
                    if ref_tokens:
                        toks.append(Token('REF ' + ' '.join(ref_tokens), ()))

                # a register overwritten by this instruction no longer holds a page; calls clobber caller-saved
                for op in ops:
                    o = op.getOutput()
                    if o is not None and o.isRegister():
                        pages.pop(o.getOffset(), None)
                    if op.getOpcode() in (PcodeOp.CALL, PcodeOp.CALLIND):
                        for k in [k for k in pages if k not in self.callee_saved]:
                            pages.pop(k)

        return toks


def hash_tokens(toks: List[Token]) -> str:
    if not toks:
        return 'EMPTY'
    return hashlib.sha1('\n'.join(tok.text() for tok in toks).encode()).hexdigest()[:16]


def classify_pair(old: List[Token], new: List[Token]) -> Tuple[str, list]:
    """
    Classify how two token lists differ.
    Returns (change_class, const_deltas) where change_class is one of
      'same'     identical
      'const'    same structure, only constants differ
      'imm-id'   only wide immediates materialised by mov/movk differ (typed-malloc ids, PAC discriminators)
      'code'     structure differs
    'shift' is assigned later across the whole binary (see shift_deltas).
    const_deltas lists (old, new) for each differing constant.
    """
    if [t.text() for t in old] == [t.text() for t in new]:
        return 'same', []
    if len(old) != len(new) or any(a.template != b.template or len(a.consts) != len(b.consts) for a, b in zip(old, new)):
        return 'code', []
    deltas = []
    wide_only = True
    for a, b in zip(old, new):
        for (va, sa, ma), (vb, _, _) in zip(a.consts, b.consts):
            if va != vb:
                deltas.append((va, vb))
                if not (ma in _WIDE_IMM_MNEMONICS and (ma == 'movk' or max(va, vb) >= 0x10000)):
                    wide_only = False
    return ('imm-id' if wide_only else 'const'), deltas


def shift_deltas(classified: List[Tuple[str, list]], min_functions: int = 2) -> set:
    """Deltas shared by every changed constant of a function, recurring in >= min_functions functions."""
    per_function = Counter()
    for change_class, deltas in classified:
        if change_class != 'const' or not deltas:
            continue
        ds = {(b - a) & U64 for a, b in deltas}
        if len(ds) == 1:
            per_function[next(iter(ds))] += 1
    return {d for d, n in per_function.items() if n >= min_functions}
