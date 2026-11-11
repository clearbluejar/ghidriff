"""
Recover AArch64 switch tables that Ghidra's analysis leaves unresolved.

Apple's compilers bound a switch index and then clamp it again before the table load
(Spectre hardening):

    cmp   w16, #0xa
    b.hi  default
    cmp   x16, #0xa
    csel  x16, x16, xzr, ls
    adrp  x17, table@PAGE
    add   x17, x17, table@PAGEOFF
    ldrsw x16, [x17, x16, LSL #2]
    adr   x17, base
    add   x16, x17, x16
    br    x16

Ghidra 12.x recovers at most one case of such a switch, so the remaining case code is
never disassembled, the function body is truncated at the `br`, and two builds whose
real difference sits inside the cases look identical (an "exact" match that is never
diffed). This module recognises the pattern, reads the table, and applies the same
fix as Ghidra's SwitchOverride script: computed-jump references, a JumpTable override
for the decompiler, disassembly of the targets, and a function body fixup.
"""

import re
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    import ghidra

REPAIR_OPTION = 'ghidriff switch repair'
REPAIR_VERSION = '1'

MAX_CASES = 1024
WALK_BACK = 16

# element size and signedness of the table load
_TABLE_LOADS = {'ldrsw': (4, True), 'ldr': (4, False), 'ldrh': (2, False), 'ldrsh': (2, True),
                'ldrb': (1, False), 'ldrsb': (1, True)}
_REG = r'[wx](\d+)'
_ADD_RE = re.compile(rf'^add x(\d+),x(\d+),{_REG}(?:, (?:LSL|SXTW|UXTW) #0x([0-9a-f]+))?$')
_ADR_RE = re.compile(r'^adr x(\d+),0x([0-9a-f]+)$')
_LOAD_RE = re.compile(rf'^(ldrsw|ldr|ldrh|ldrsh|ldrb|ldrsb) {_REG},\[x(\d+), {_REG}(?:, (?:LSL|UXTW|SXTW) #0x[0-9a-f]+)?\]$')
_CMP_RE = re.compile(rf'^cmp {_REG},#0x([0-9a-f]+)$')


def _text(ins) -> str:
    return str(ins).strip()


def _unresolved_computed_jump(ins) -> bool:
    flow = ins.getFlowType()
    if not (flow.isJump() and flow.isComputed()):
        return False
    targets = [ref for ref in ins.getReferencesFrom() if ref.getReferenceType().isComputed()]
    return len(targets) <= 1


def _recover_table(program, br) -> Optional[List['ghidra.program.model.address.Address']]:
    """Return the case targets of the switch ending at `br`, or None if it is not the pattern."""
    listing = program.getListing()
    m = re.match(r'^br x(\d+)$', _text(br))
    if not m:
        return None
    jump_reg = m.group(1)

    prev = []
    ins = br
    for _ in range(WALK_BACK):
        ins = listing.getInstructionBefore(ins.getAddress())
        if ins is None:
            break
        prev.append(ins)

    add = base = load = None
    shift = 0
    off_reg = base_reg = idx_reg = None
    for ins in prev:
        t = _text(ins)
        if add is None:
            am = _ADD_RE.match(t)
            if am and am.group(1) == jump_reg:
                add = ins
                base_reg, off_reg = am.group(2), am.group(3)
                shift = int(am.group(4), 16) if am.group(4) else 0
            continue
        if base is None:
            dm = _ADR_RE.match(t)
            if dm and dm.group(1) == base_reg:
                base = program.getAddressFactory().getDefaultAddressSpace().getAddress(int(dm.group(2), 16))
                continue
        if load is None:
            lm = _LOAD_RE.match(t)
            if lm and lm.group(2) == off_reg:
                load = ins
                elem, signed = _TABLE_LOADS[lm.group(1)]
                idx_reg = lm.group(4)
                continue
        if load is not None and base is not None:
            break
    if add is None or base is None or load is None:
        return None

    table = None
    for ref in load.getReferencesFrom():
        if ref.getReferenceType().isRead() and ref.getToAddress().isMemoryAddress():
            table = ref.getToAddress()
    if table is None:
        return None

    # bound: `cmp idx, #K` followed by b.hi (K+1 cases) or b.hs/b.cs (K cases), before the load
    count = None
    seen_load = False
    for ins in prev:
        if ins == load:
            seen_load = True
            continue
        if not seen_load:
            continue
        cm = _CMP_RE.match(_text(ins))
        if cm and cm.group(1) == idx_reg:
            nxt = listing.getInstructionAfter(ins.getAddress())
            cond = _text(nxt).split(' ')[0] if nxt is not None else ''
            if cond in ('b.hi', 'b.ls'):
                count = int(cm.group(2), 16) + 1
            elif cond in ('b.hs', 'b.cs', 'b.lo', 'b.cc'):
                count = int(cm.group(2), 16)
            elif cond == 'csel' and _text(nxt).endswith(',ls'):
                count = int(cm.group(2), 16) + 1
            if count is not None:
                break
    if count is None or not 1 < count <= MAX_CASES:
        return None

    mem = program.getMemory()
    targets = []
    for i in range(count):
        a = table.add(i * elem)
        if elem == 4:
            v = mem.getInt(a)
            v = v if signed else v & 0xffffffff
        elif elem == 2:
            v = mem.getShort(a)
            v = v if signed else v & 0xffff
        else:
            v = mem.getByte(a)
            v = v if signed else v & 0xff
        tgt = base.add(v << shift) if v >= 0 else base.subtract(-v << shift)
        block = mem.getBlock(tgt)
        if block is None or not block.isExecute():
            return None
        targets.append(tgt)
    return targets


def _jump_table(addr, dests):
    from ghidra.program.model.pcode import JumpTable
    try:
        return JumpTable(addr, dests, True, 0)  # Ghidra >= 12.1, as in its SwitchOverride script
    except TypeError:
        return JumpTable(addr, dests, True)  # Ghidra <= 12.0


def _repair_one(program, ins, listing, fm, logger) -> bool:
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.app.cmd.function import CreateFunctionCmd
    from ghidra.program.model.symbol import RefType, SourceType
    from ghidra.util.task import TaskMonitor
    from java.util import ArrayList

    targets = _recover_table(program, ins)
    if not targets:
        return False
    func = fm.getFunctionContaining(ins.getAddress())
    for tgt in targets:
        if listing.getInstructionAt(tgt) is None:
            DisassembleCommand(tgt, None, True).applyTo(program, TaskMonitor.DUMMY)
    for tgt in sorted(set(str(t) for t in targets)):
        ins.addOperandReference(0, program.getAddressFactory().getAddress(tgt), RefType.COMPUTED_JUMP, SourceType.ANALYSIS)
    if func is not None:
        dests = ArrayList()
        for tgt in targets:
            dests.add(tgt)
        _jump_table(ins.getAddress(), dests).writeOverride(func)
        CreateFunctionCmd.fixupFunctionBody(program, func, TaskMonitor.DUMMY)
    if logger is not None:
        logger.debug(f'switch repair: {func} br at {ins.getAddress()}: {len(targets)} cases')
    return True


def repair_switches(program, logger=None, max_rounds: int = 5) -> int:
    """
    Recover hardened AArch64 switch tables in `program`. Returns the number of switches
    repaired. Must be called with the program writable; records REPAIR_OPTION so a
    program is repaired once.
    """
    if 'AARCH64' not in str(program.getLanguageID()).upper():
        return 0
    info = program.getOptions('Program Information')
    if info.getString(REPAIR_OPTION, '') == REPAIR_VERSION:
        return 0

    listing = program.getListing()
    fm = program.getFunctionManager()
    repaired = 0
    tx = program.startTransaction('ghidriff switch repair')
    try:
        done = set()
        for _ in range(max_rounds):
            found = 0
            # collect first: repairing disassembles new code into the listing being walked
            candidates = [ins for ins in listing.getInstructions(True)
                          if str(ins.getMnemonicString()) == 'br' and _unresolved_computed_jump(ins)
                          and str(ins.getAddress()) not in done]
            for ins in candidates:
                done.add(str(ins.getAddress()))
                try:
                    if _repair_one(program, ins, listing, fm, logger):
                        found += 1
                except Exception as err:  # one bad table must not abort analysis
                    if logger is not None:
                        logger.warning(f'switch repair: skipped br at {ins.getAddress()}: {err}')
            repaired += found
            if found == 0:
                break
        info.setString(REPAIR_OPTION, REPAIR_VERSION)
    finally:
        program.endTransaction(tx, True)

    if logger is not None:
        logger.info(f'switch repair: recovered {repaired} unresolved AArch64 switch tables in {program.getName()}')
    return repaired
