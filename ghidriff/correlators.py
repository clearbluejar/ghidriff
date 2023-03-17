from typing import List, Tuple, TYPE_CHECKING
from jpype import JImplements, JOverride
from ghidra.app.plugin.match import FunctionHasher


if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


@JImplements(FunctionHasher, deferred=True)
class StructuralGraphHasher:
    """
    Hash function using Graph Centric Comparison of function control flow graphs (thank you 2004 halvar)
    Hash calculates a 3-tuple measurement from each node (function cfg) in the program
    (num_basic_blocks, num_edges_of_blocks, num_call_subfunctions)
    There are several other properties (length, refcount, paramcount) added to this hash, as it is meant to be run with one_to_many = True
    Based on "Structural Comparison of Executable Objects" by Halvar Flake
    """

    MIN_FUNC_LEN = 10
    MATCH_TYPE = 'StructuralGraphHash'

    @JOverride
    def hash(self, func: 'ghidra.program.model.listing.Function', monitor: 'ghidra.util.task.TaskMonitor') -> int:

        from ghidra.program.model.block import BasicBlockModel
        from ghidra.program.model.symbol import SourceType
        from ghidra.program.model.symbol import SymbolUtilities

        # graph structure vars
        num_basic_blocks = 0
        num_edges_of_blocks = 0
        num_call_subfunctions = 0

        sym = func.symbol

        # # skip func like FUN_ and LAB_, or local symbols like switch
        if sym.getSource() == SourceType.DEFAULT:
            fname = ''
        else:
            fname = SymbolUtilities.getCleanSymbolName(sym.getName(True), sym.address)

        basic_model = BasicBlockModel(func.getProgram(), True)
        basic_blocks = basic_model.getCodeBlocksContaining(func.getBody(), monitor)

        for block in basic_blocks:
            num_edges_of_blocks += block.getNumDestinations(monitor)
            num_basic_blocks += 1

            code_units = func.getProgram().getListing().getCodeUnits(block, True)
            for code in code_units:
                # TODO verify BL instruction for ARM https://developer.arm.com/documentation/den0013/d/Application-Binary-Interfaces/Procedure-Call-Standard?lang=en
                if code.mnemonicString == 'CALL' or code.mnemonicString == 'BL':
                    num_call_subfunctions += 1

        return hash((fname, num_basic_blocks, num_edges_of_blocks, num_call_subfunctions, func.body.numAddresses, func.parameterCount, sym.referenceCount))

    @ JOverride
    def commonBitCount(self, funcA: 'ghidra.program.model.listing.Function', funcB: 'ghidra.program.model.listing.Function', monitor: 'ghidra.util.task.TaskMonitor') -> int:
        raise NotImplementedError


@JImplements(FunctionHasher, deferred=True)
class StructuralGraphExactHasher:
    """
    Hash function using Graph Centric Comparison of function control flow graphs (thank you 2004 halvar)
    Hash calculates a 3-tuple measurement from each node (function cfg) in the program
    (num_basic_blocks, num_edges_of_blocks, num_call_subfunctions)
    Based on "Structural Comparison of Executable Objects" by Halvar Flake
    """

    MIN_FUNC_LEN = 10
    MATCH_TYPE = 'StructuralGraphExactHash'

    @JOverride
    def hash(self, func: 'ghidra.program.model.listing.Function', monitor: 'ghidra.util.task.TaskMonitor') -> int:

        from ghidra.program.model.block import BasicBlockModel

        num_basic_blocks = 0
        num_edges_of_blocks = 0
        num_call_subfunctions = 0

        basic_model = BasicBlockModel(func.getProgram(), True)
        basic_blocks = basic_model.getCodeBlocksContaining(func.getBody(), monitor)

        for block in basic_blocks:
            num_edges_of_blocks += block.getNumDestinations(monitor)
            num_basic_blocks += 1

            code_units = func.getProgram().getListing().getCodeUnits(block, True)
            for code in code_units:
                # TODO verify BL instruction for ARM https://developer.arm.com/documentation/den0013/d/Application-Binary-Interfaces/Procedure-Call-Standard?lang=en
                if code.mnemonicString == 'CALL' or code.mnemonicString == 'BL':
                    num_call_subfunctions += 1

        return hash((num_basic_blocks, num_call_subfunctions, num_edges_of_blocks))

    @ JOverride
    def commonBitCount(self, funcA: 'ghidra.program.model.listing.Function', funcB: 'ghidra.program.model.listing.Function', monitor: 'ghidra.util.task.TaskMonitor') -> int:
        raise NotImplementedError


@ JImplements(FunctionHasher, deferred=True)
class BulkInstructionsHasher:
    """
    Hash from instructions sorted and hashed
    Order of instructions is ignored
    Based on https://github.com/threatrack/ghidra-patchdiff-correlator#bulk-instructions-match
    """

    MIN_FUNC_LEN = 10
    MATCH_TYPE = 'BulkInstructionHash'

    @ JOverride
    def hash(self, func: 'ghidra.program.model.listing.Function', monitor: 'ghidra.util.task.TaskMonitor') -> int:

        instructions = []

        # reset iterator
        code_units = func.getProgram().getListing().getCodeUnits(func.getBody(), True)

        for code in code_units:
            instructions.append(code.toString())

        return hash(tuple(sorted(instructions)))

    @ JOverride
    def commonBitCount(self, funcA: 'ghidra.program.model.listing.Function', funcB: 'ghidra.program.model.listing.Function', monitor: 'ghidra.util.task.TaskMonitor') -> int:
        raise NotImplementedError


@ JImplements(FunctionHasher, deferred=True)
class BulkMnemonicHasher:
    """
    Hash from function mnemonics sorted
    Order of instructions is ignored
    Based on https://github.com/threatrack/ghidra-patchdiff-correlator#bulk-mnemonics-match
    """

    MIN_FUNC_LEN = 10
    MATCH_TYPE = 'BulkMnemonicHash'

    @ JOverride
    def hash(self, func: 'ghidra.program.model.listing.Function', monitor: 'ghidra.util.task.TaskMonitor') -> int:

        mnemonics = []

        # reset iterator
        code_units = func.getProgram().getListing().getCodeUnits(func.getBody(), True)

        for code in code_units:
            mnemonics.append(code.getMnemonicString())

        return hash(tuple(sorted(mnemonics)))

    @ JOverride
    def commonBitCount(self, funcA: 'ghidra.program.model.listing.Function', funcB: 'ghidra.program.model.listing.Function', monitor: 'ghidra.util.task.TaskMonitor') -> int:
        raise NotImplementedError


@ JImplements(FunctionHasher, deferred=True)
class BulkBasicBlockMnemonicHasher:
    """
    Hash from function basic blocks mnemonics sorted
    Order of basic blocks mnemonics is ignored
    Based on https://github.com/threatrack/ghidra-patchdiff-correlator#bulk-basic-block-mnemonics-match
    """

    MIN_FUNC_LEN = 10
    MATCH_TYPE = 'BulkBasicBlockMnemonicHash'

    @ JOverride
    def hash(self, func: 'ghidra.program.model.listing.Function', monitor: 'ghidra.util.task.TaskMonitor') -> int:

        from ghidra.program.model.block import BasicBlockModel

        basic_model = BasicBlockModel(func.getProgram(), True)
        basic_blocks = basic_model.getCodeBlocksContaining(func.getBody(), monitor)
        blocks = []

        for block in basic_blocks:
            code_units = func.getProgram().getListing().getCodeUnits(block, True)
            for code in code_units:
                blocks.append(code.getMnemonicString())

        return hash(tuple(sorted(blocks)))

    @ JOverride
    def commonBitCount(self, funcA: 'ghidra.program.model.listing.Function', funcB: 'ghidra.program.model.listing.Function', monitor: 'ghidra.util.task.TaskMonitor') -> int:
        raise NotImplementedError


@JImplements(FunctionHasher, deferred=True)
class NamespaceNameParamHasher:
    """
    Simply return Name with Namespace and Param Hash matches
    DO NOT RUN THIS with one_to_many = TRUE
    """

    MIN_FUNC_LEN = 10
    MATCH_TYPE = 'NamespaceNameParamHash'
    FIRST_RUN = True

    @JOverride
    def hash(self, func: 'ghidra.program.model.listing.Function', monitor: 'ghidra.util.task.TaskMonitor') -> int:

        return hash((func.getName(True), func.parameterCount))

    @ JOverride
    def commonBitCount(self, funcA: 'ghidra.program.model.listing.Function', funcB: 'ghidra.program.model.listing.Function', monitor: 'ghidra.util.task.TaskMonitor') -> int:
        raise NotImplementedError


@JImplements(FunctionHasher, deferred=True)
class NameParamHasher:
    """
    Simply return Name and Param Hash matches
    No namespace included
    DO NOT RUN THIS with one_to_many = TRUE
    """

    MIN_FUNC_LEN = 10
    MATCH_TYPE = 'NameParamHash'
    FIRST_RUN = True

    @JOverride
    def hash(self, func: 'ghidra.program.model.listing.Function', monitor: 'ghidra.util.task.TaskMonitor') -> int:

        return hash((func.getName(), func.parameterCount))

    @ JOverride
    def commonBitCount(self, funcA: 'ghidra.program.model.listing.Function', funcB: 'ghidra.program.model.listing.Function', monitor: 'ghidra.util.task.TaskMonitor') -> int:
        raise NotImplementedError


@JImplements(FunctionHasher, deferred=True)
class NameParamRefHasher:
    """
    Hash based on name param and number of refs

    DO NOT RUN THIS with one_to_many = TRUE
    """

    MIN_FUNC_LEN = 10
    MATCH_TYPE = 'NameParamHash'
    FIRST_RUN = True

    @JOverride
    def hash(self, func: 'ghidra.program.model.listing.Function', monitor: 'ghidra.util.task.TaskMonitor') -> int:

        return hash((func.getName(True), func.parameterCount, func.symbol.referenceCount))

    @ JOverride
    def commonBitCount(self, funcA: 'ghidra.program.model.listing.Function', funcB: 'ghidra.program.model.listing.Function', monitor: 'ghidra.util.task.TaskMonitor') -> int:
        raise NotImplementedError


@JImplements(FunctionHasher, deferred=True)
class SigCallingCalledHasher:
    """
    Hash based on signature, called, and calling functions ignoring FUN_*

    DO NOT RUN THIS with one_to_many = TRUE
    This should be run very late in the game
    """

    MIN_FUNC_LEN = 10
    MATCH_TYPE = 'SigCallingCalledHasher'
    FIRST_RUN = True

    @JOverride
    def hash(self, func: 'ghidra.program.model.listing.Function', monitor: 'ghidra.util.task.TaskMonitor') -> int:

        called = [called.toString() for called in func.getCalledFunctions(monitor) if "FUN_" not in called.toString()]
        calling = [calling.toString() for calling in func.getCalledFunctions(monitor)
                   if "FUN_" not in calling.toString()]

        sig = func.getSignature().toString().replace(func.name, '')

        return hash((tuple(sorted(called)), tuple(sorted(calling)), sig))

    @ JOverride
    def commonBitCount(self, funcA: 'ghidra.program.model.listing.Function', funcB: 'ghidra.program.model.listing.Function', monitor: 'ghidra.util.task.TaskMonitor') -> int:
        raise NotImplementedError
