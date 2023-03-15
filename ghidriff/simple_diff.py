import hashlib

from typing import List, Tuple, TYPE_CHECKING

from .ghidra_diff_engine import GhidraDiffEngine

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


class SimpleDiff(GhidraDiffEngine):
    """
    An Ghidra Diff implementation using simple comparison mechanisms
    """

    def find_matches(
        self,
        p1: "ghidra.program.model.listing.Program",
        p2: "ghidra.program.model.listing.Program",
        ignore_FUN: bool = False,
    ) -> dict:
        """
        Find matching and unmatched functions between p1 and p2
        """

        from ghidra.program.util import DiffUtility

        def _get_compare_key(sym: 'ghidra.program.model.symbol.Symbol', func: 'ghidra.program.model.listing.Function') -> tuple:
            """
            Builds tuple from symbol (parent, name, refcount, length, paramcount)
            """
            fhash = ''
            cu_count = 0
            if (not func.isThunk() and func.getBody().getNumAddresses() >= 10):
                # reset iterator
                code_units = func.getProgram().getListing().getCodeUnits(func.getBody(), True)

                mnemonics = []

                # Mnemonic Bulker
                for code in code_units:
                    mnemonics.append(code.getMnemonicString())
                    cu_count += 1

                fhash = hashlib.sha256(''.join(mnemonics).encode('UTF-8')).hexdigest()

            return (sym.getParentNamespace().toString().split('@')[0], sym.getName(True), sym.getReferenceCount(), func.body.numAddresses, func.parameterCount, fhash)

        def _syms_match(esym, esym2) -> Tuple[bool, str]:
            found = False
            match_type = None
            min_func_length = 15

            if esym2['name'] == esym['name'] and esym2['length'] == esym['length']:
                self.logger.info("Name + length {} {}".format(sym.getName(True), sym2.getName(True)))
                found = True
                match_type = 'Name:Length'
            elif esym2['address'] == esym2['address'] and esym2['length'] == esym['length'] and min([esym['length'], esym2['length']]) > min_func_length:
                self.logger.info("Address + Length {} {}".format(sym.getName(True), sym2.getName(True)))
                found = True
                match_type = 'Address:Length'
            elif esym2['paramcount'] == esym['paramcount'] and esym2['length'] == esym['length']:
                self.logger.info("param count + func len {} {}".format(sym.getName(True), sym2.getName(True)))
                found = True
                match_type = 'Param:Length'
            elif esym2['fullname'] == esym['fullname']:
                self.logger.info("Name Exact {} {}".format(sym.getName(True), sym2.getName(True)))
                found = True
                match_type = 'Fullname'

            return found, match_type

        old_funcs = []
        new_funcs = []
        old_symbols = []
        new_symbols = []

        # first pass detect added and deleted symbols
        common_sym_prefix = ['switch', 'FUN_', 'caseD', 'local_']

        for sym in p1.getSymbolTable().getDefinedSymbols():
            name = sym.getName()
            if not any([common in name for common in common_sym_prefix]):
                old_symbols.append(name)

        for sym in p2.getSymbolTable().getDefinedSymbols():
            name = sym.getName()
            if not any([common in name for common in common_sym_prefix]):
                new_symbols.append(name)

        olds = set(old_symbols)
        news = set(new_symbols)

        deleted_symbols = olds.difference(news)
        self.logger.info("\ndeleted symbols\n")
        for sym in deleted_symbols:
            self.logger.info(sym)

        added_symbols = news.difference(olds)
        self.logger.info("\nadded symbols\n")
        for sym in added_symbols:
            self.logger.info(sym)

        # Next pass
        # 1. remove false positives from symbols
        # 2. Build modified functions list based on (_get_compare_key)

        for sym in p1.getSymbolTable().getDefinedSymbols():
            key = sym.getName()
            if key in deleted_symbols:
                self.logger.info("{} {} {}".format(sym.getName(), sym.getAddress(), sym.getParentNamespace()))
                sym2 = DiffUtility.getSymbol(sym, p2)

                if sym2 and sym.getName(True) == sym2.getName(True):
                    self.logger.info(f"Removing {sym} from deleted, found match {sym2} in p2")
                    deleted_symbols.remove(key)

            if "function".lower() in sym.getSymbolType().toString().lower():
                func = p1.functionManager.getFunctionAt(sym.getAddress())

                if "FUN_" in func.name and ignore_FUN:
                    # ignore FUN_
                    continue
                old_funcs.append(_get_compare_key(sym, func))

        for sym in p2.getSymbolTable().getDefinedSymbols():
            key = sym.getName()
            if key in added_symbols:
                self.logger.info("{} {}".format(sym.getName(), sym.getAddress()))
                sym2 = DiffUtility.getSymbol(sym, p1)

                if sym2 and sym.getName(True) == sym2.getName(True):
                    self.logger.info(f"Removing {sym} from deleted, found match {sym2} in p1")
                    added_symbols.remove(key)

            if "function".lower() in sym.getSymbolType().toString().lower():
                func = p2.functionManager.getFunctionAt(sym.getAddress())
                if "FUN_" in func.name and ignore_FUN:
                    # ignore FUN_
                    continue
                new_funcs.append(_get_compare_key(sym, func))

        old_func_set = set(old_funcs)
        new_func_set = set(new_funcs)

        modified_old = sorted(old_func_set.difference(new_func_set))
        modified_new = sorted(new_func_set.difference(old_func_set))

        matching_compare_keys = sorted(old_func_set.intersection(new_func_set))

        self.logger.info("\nmodified_old_modified")
        for sym in modified_old:
            self.logger.info(sym)

        self.logger.info("\nmodified_new_modified")
        for sym in modified_new:
            self.logger.info(sym)

        p1_modified = []
        p2_modified = []

        # Find modified functions based on compare_key
        for sym in p1.getSymbolTable().getDefinedSymbols():

            if "function".lower() in sym.getSymbolType().toString().lower():
                func = p1.functionManager.getFunctionAt(sym.getAddress())
                if (_get_compare_key(sym, func)) in modified_old:
                    p1_modified.append(sym)

        for sym in p2.getSymbolTable().getDefinedSymbols():

            if "function".lower() in sym.getSymbolType().toString().lower():
                func = p2.functionManager.getFunctionAt(sym.getAddress())
                if (_get_compare_key(sym, func)) in modified_new:
                    p2_modified.append(sym)

        self.logger.info("\nmodified_old_modified")
        for sym in p1_modified:
            self.logger.info(sym)

        self.logger.info("\nmodified_new_modified")
        for sym in p2_modified:
            self.logger.info(sym)

        matched = []
        unmatched = []
        matches = []

        self.logger.info("\nMatching functions...")

        # match by name and paramcount
        for sym in p1_modified:
            for sym2 in p2_modified:

                if sym2 in matched:
                    continue

                func = p1.functionManager.getFunctionAt(sym.getAddress())
                func2 = p2.functionManager.getFunctionAt(sym2.getAddress())

                if sym.getName(True) == sym2.getName(True) and func.parameterCount == func2.parameterCount:
                    self.logger.info("FullName + Paramcount {} {}".format(sym.getName(True), sym2.getName(True)))
                    match_type = 'FullName:Param'
                    matched.append(sym)
                    matched.append(sym2)
                    matches.append([sym, sym2, match_type])

        for sym in p1_modified:
            found = False

            if sym in matched:
                continue

            sym2 = DiffUtility.getSymbol(sym, p2)

            if sym2 and sym.getName(True) == sym2.getName(True):
                found = True
                match_type = 'Direct'
                self.logger.info(f"direct getsymbol match {sym.getName(True)} {sym2.getName(True)}")
            else:
                for sym2 in p2_modified:
                    if sym2 in matched:
                        continue

                    esym = self.enhance_sym(sym)
                    esym2 = self.enhance_sym(sym2)
                    found, match_type = _syms_match(esym, esym2)

                    if found:
                        break

            if found:
                matched.append(sym)
                matched.append(sym2)
                matches.append([sym, sym2, match_type])
            else:
                self.logger.info(f"Deleted func found: {sym}")
                unmatched.append(sym)

        for sym in p2_modified:
            found = False
            match_type = None

            if sym in matched:
                continue

            sym2 = DiffUtility.getSymbol(sym, p1)

            if sym2 and sym.getName(True) == sym2.getName(True):
                found = True
                match_type = 'Direct'
                self.logger.info(f"direct getsymbol match {sym.getName(True)} {sym2.getName(True)}")
            else:
                for sym2 in p1_modified:
                    if sym2 in matched:
                        continue

                    esym = self.enhance_sym(sym)
                    esym2 = self.enhance_sym(sym2)
                    found, match_type = _syms_match(esym, esym2)

                    if found:
                        break

            if found:
                matched.append(sym)
                matched.append(sym2)
                matches.append([sym, sym2, match_type])
            else:
                self.logger.info(f"Added func found: {sym}")
                unmatched.append(sym)

        self.logger.info(len(p1_modified))
        self.logger.info(len(p2_modified))

        matches = sorted(matches, key=lambda x: str(x[0]))

        # Update symbols using match knowledge
        for match in matches:
            self.logger.info(f"{match[0].getName(True)} {match[1].getName(True)} {match[2]}")

            if match[0].getName() in deleted_symbols:
                deleted_symbols.remove(match[0].getName())
            if match[1].getName() in added_symbols:
                added_symbols.remove(match[1].getName())

        return [unmatched, matches, []]
