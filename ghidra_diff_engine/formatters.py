import functools
def _del_from_added_sublist(data:dict, root_key:str, leaf_key:str):
    """Deletes leaf_key from every entry in the added list"""
    if data[root_key].get("added"):
        new_added_list=[]
        for added in data[root_key].get("added"):
            if added.get(leaf_key, None) == None:
                new_added_list.append(added)
                continue
            a = added
            del a[leaf_key]
            new_added_list.append(a)
        data[root_key].update({"added": new_added_list}) 
    return data
    
def _del_from_modified_sublist(data:dict, root_key:str, leaf_key:str):
    """Deletes leaf_key from every entry in the modified list"""
    if not data[root_key].get("modified"):
        return data

    new_modified_list=[]
    for modified_entry in data[root_key].get("modified"):
        old = modified_entry["old"]
        del old[leaf_key]
        new = modified_entry["new"]
        del new[leaf_key]
        modified_entry["old"] = old
        modified_entry["new"] = new
        new_modified_list.append(modified_entry)
    data[root_key].update({"modified": new_modified_list}) 
    return data

def _del_diff_keys(data:dict, key:str):
    assert "symbols" in data.keys()
    assert "functions" in data.keys()

    data = _del_from_added_sublist(data, "symbols", key)
    data = _del_from_added_sublist(data, "functions", key)
    data = _del_from_modified_sublist(data, "functions", key)
    return data

def _remove_instructions(data:dict) -> dict:
    return _del_diff_keys(data,"instructions")

def _remove_blocks(data:dict) -> dict:
    return _del_diff_keys(data,"blocks")

def _remove_mnemonics(data:dict) -> dict:
    return _del_diff_keys(data,"mnemonics")

def _remove_code(data:dict) -> dict:
    return _del_diff_keys(data,"code")





class DiffFormatter():
    FORMATTING_FUNCTIONS = []
    @staticmethod
    def map_funcs(obj, func_list):
        return [func(obj) for func in func_list]

    @classmethod
    def format(cls, data:dict):
        """Apply all functions in __class__.FORMATTING_FUNCTIONS in a sequence"""
        return functools.reduce(lambda o, func: func(o), cls.FORMATTING_FUNCTIONS, data)


class AssemblyRemoverDiffFormatter(DiffFormatter):
    FORMATTING_FUNCTIONS = [_remove_instructions, _remove_blocks, _remove_mnemonics]

class CodeRemoverDiffFormatter(DiffFormatter):
    FORMATTING_FUNCTIONS = [_remove_instructions, _remove_blocks, _remove_mnemonics, _remove_code]





