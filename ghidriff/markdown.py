import difflib
import re
from textwrap import dedent
from typing import List, Tuple, Union, TYPE_CHECKING
import logging

from mdutils.tools.Table import Table
from mdutils.mdutils import MdUtils
from mdutils.tools.TableOfContents import TableOfContents


class GhidriffMarkdown:

    def __init__(self, logging=logging.INFO) -> None:
        self.logger = self.setup_logger(level=logging)

    def setup_logger(self, level: int = logging.INFO) -> logging.Logger:
        """
        Setup Class Instance Logger
        """
        logging.basicConfig(
            format='%(levelname)-5s| %(name)s | %(message)s',
            datefmt='%H:%M:%S'
        )

        logger = logging.getLogger(__package__)
        logger.setLevel(level)

        return logger

    def _wrap_with_diff(self, diff: str) -> str:

        text = ''
        text += "```diff\n"
        text += diff
        text += "\n```\n"
        text += "\n"

        return text

    def _wrap_with_code(self, code: str, style='') -> str:
        text = ''
        text += f"```{style}" + "\n"
        text += code
        text += "\n```\n"
        text += "\n"

        return text

    def _wrap_with_details(self, diff: str, summary: str = None) -> str:

        text = ''
        text += "<details>\n"
        if summary:
            text += f"<summary>{summary}</summary>"
        text += diff
        text += "\n</details>\n"

        return text

    def gen_esym_table(self, old_name, esym) -> str:

        table_list = []
        table_list.extend(['Key', old_name])
        column_len = len(table_list)

        skip_keys = ['code', 'instructions', 'mnemonics', 'blocks', 'parent']
        count = 1
        for key in esym:
            if key in skip_keys:
                continue
            table_list.extend([key, esym[key]])
            count += 1

        diff_table = Table().create_table(columns=column_len, rows=count, text=table_list, text_align='center')

        return diff_table

    def gen_esym_table_diff(self, old_name, new_name, modified) -> str:
        diff_table = ''

        table_list = []
        table_list.extend(['Key', old_name, new_name])
        column_len = len(table_list)

        skip_keys = ['code', 'instructions', 'mnemonics', 'blocks', 'parent']
        count = 1
        for key in modified['old']:
            if key in skip_keys:
                continue
            if key in modified['diff_type']:
                diff_key = f"`{key}`"
            else:
                diff_key = f"{key}"

            table_list.extend([diff_key, modified['old'][key], modified['new'][key]])
            count += 1

        diff_table = Table().create_table(columns=column_len, rows=count,
                                          text=table_list, text_align='center')

        return diff_table

    def gen_esym_table_diff_meta(self, old_name, new_name, modified) -> str:
        diff_table = ''

        table_list = []
        table_list.extend(['Key', f"{old_name} - {new_name}"])
        column_len = len(table_list)

        keys = ['diff_type', 'ratio', 'i_ratio', 'm_ratio', 'b_ratio', 'match_types']
        count = 1
        for key in keys:
            table_list.extend([key, modified[key]])
            count += 1

        diff_table = Table().create_table(columns=column_len, rows=count, text=table_list, text_align='center')

        return diff_table

    def gen_esym_key_diff(self, esym: dict, esym2: dict, key: str, n=3) -> str:
        """
        Generate a difflib unified diff from two esyms and a key
        n is the number of context lines for diff lib to wrap around the found diff
        """
        diff = ''

        diff += '\n'.join(difflib.unified_diff(esym[key], esym2[key],
                          fromfile=f'old {key}', tofile=f'new {key}', lineterm='', n=n))

        return self._wrap_with_diff(diff)

    def gen_code_table_diff_html(self, old_code, new_code, old_name, new_name) -> str:
        """
        Generates side by side diff in HTML
        """

        if isinstance(old_code, str):
            old_code = old_code.splitlines(True)
        if isinstance(new_code, str):
            new_code = new_code.splitlines(True)

        diff_html = ''.join(list(difflib.HtmlDiff(tabsize=4).make_table(
            old_code, new_code, fromdesc=old_name, todesc=new_name)))
        diff_html = dedent(diff_html) + '\n'

        return diff_html

    def gen_table_from_dict(self, headers: list, items: dict):

        table = ''

        table_list = []
        table_list.extend(headers)
        column_len = len(table_list)

        count = 1
        for key, values in items.items():
            table_list.extend([key, values])
            count += 1

        table = Table().create_table(columns=column_len, rows=count, text=table_list, text_align='center')

        return table

    def gen_strings_diff(self, deleted_strings: dict, added_strings: dict):

        added = [item['name'] for item in added_strings]

        deleted = [item['name'] for item in deleted_strings]

        diff = '\n'.join(list(difflib.unified_diff(deleted, added,
                                                   lineterm='\n', fromfile='deleted strings', tofile='added strings')))

        return self._wrap_with_diff(diff)

    def gen_mermaid_diff_flowchart(self, pdiff: dict, max_section_funcs: int = 25) -> str:

        diff_flow = '''
```mermaid

flowchart LR

{modified_links}

subgraph {new_bin}
    {new_modified}
    {added_sub}
end

subgraph {old_bin}
    {old_modified}
    {deleted_sub}
end

```'''

        added = []
        deleted = []
        modified_links = []
        old_modified = []
        new_modified = []

        old_bin = pdiff['old_meta']['Program Name']
        new_bin = pdiff['new_meta']['Program Name']

        for i, func in enumerate(pdiff['functions']['added']):
            if func['external']:
                # remove :: from external names
                name = func['fullname'].replace('::', '-')
            else:
                name = func['name']
            added.append(self._clean_md_header(name))

            if max_section_funcs and i > max_section_funcs:
                msg = f"{len(pdiff['functions']['added']) - max_section_funcs}_more_added_funcs_omitted..."
                added.append(self._clean_md_header(msg))
                break

        for i, func in enumerate(pdiff['functions']['deleted']):
            if func['external']:
                name = func['fullname'].replace('::', '-')
            else:
                name = func['name']
            deleted.append(self._clean_md_header(name))

            if max_section_funcs and i > max_section_funcs:
                msg = f"{len(pdiff['functions']['deleted']) - max_section_funcs}_more_deleted_funcs_omitted..."
                deleted.append(self._clean_md_header(msg))
                break

        modified_code_funcs = [func for func in pdiff['functions']['modified'] if 'code' in func['diff_type']]

        for i, modified in enumerate(modified_code_funcs):

            if max_section_funcs and i > max_section_funcs:
                modified_links.append(
                    f"{old_bin}<--{len(modified_code_funcs) - max_section_funcs}ommited-->{new_bin}")
                break

            old_modified.append(self._clean_md_header(
                f"{modified['old']['name']}-{modified['old']['paramcount']}-old"))
            new_modified.append(self._clean_md_header(
                f"{modified['new']['name']}-{modified['old']['paramcount']}-new"))
            modified_links.append(
                f"{self._clean_md_header(modified['old']['name'])}-{modified['old']['paramcount']}-old<--Match {int(modified['b_ratio']*100)}%-->{self._clean_md_header(modified['new']['name'])}-{modified['old']['paramcount']}-new")

        deleted_sub = ''
        added_sub = ''
        if len(deleted) > 0:
            deleted_sub = '''subgraph Deleted\ndirection LR\n{}\nend'''.format('\n    '.join(deleted))
        if len(added) > 0:
            added_sub = '''subgraph Added\ndirection LR\n{}\nend'''.format('\n    '.join(added))

        return diff_flow.format(old_bin=old_bin, new_bin=new_bin, added_sub=added_sub, deleted_sub=deleted_sub, modified_links='\n'.join(modified_links), old_modified='\n'.join(old_modified), new_modified='\n'.join(new_modified))

    def gen_mermaid_pie_from_dict(self, data: dict, title: str, skip_keys: list = None, include_keys: list = None) -> str:
        """
        Generate basic mermaidjs Pie chart from dict
        skip_keys: [ 'skipkey1', 'skipkey45'] List of keys to skip from Dict
        includes_keys: ['random_key1', 'otherkey2'] - Only include these keys
        Default: include all keys and values from dict.
        """

        pie_template = '''
```mermaid
pie showData
    title {title}
{rows}
```
'''
        rows = []

        for key, value in data.items():

            row = None

            if skip_keys and key in skip_keys:
                continue

            if include_keys:
                if key in include_keys:
                    row = f'"{self._clean_md_header(key)}" : {value}'
            else:
                row = f'"{self._clean_md_header(key)}" : {value}'

            if row:
                rows.append(row)

        return pie_template.format(title=title, rows='\n'.join(rows))

    def _clean_md_header_lower(self, text):
        return re.sub('[^a-z0-9_\-]', '', text.lower().replace(' ', '-'))

    def _clean_md_header(self, text):
        return re.sub('[^A-Za-z0-9_\-]', '', text.replace(' ', '-'))

    def gen_diff_md(
        self,
        pdiff: Union[str, dict],
        title=None,
        side_by_side: bool = False,
        max_section_funcs: int = None,
    ) -> str:
        """
        Generate Markdown Diff from pdiff match results
        """

        self.logger.info(f"Generating markdown from {pdiff['stats']}")

        # use max passed into function, revert to class if it exists
        if not max_section_funcs:
            max_section_funcs = self.max_section_funcs

        self.logger.debug(f"max_section_funcs: {max_section_funcs}")

        if isinstance(pdiff, str):
            pdiff = json.loads(pdiff)

        funcs = pdiff['functions']

        old_name = pdiff['old_meta']['Program Name']
        new_name = pdiff['new_meta']['Program Name']

        if title:
            title = title
        else:
            title = f"{old_name}-{new_name} Diff"

        md = MdUtils('diff', title=title)

        # change title to atx style
        md.title = md.header.choose_header(level=1, title=title, style='atx')

        md.new_header(1, 'Visual Chart Diff')
        md.new_paragraph(self.gen_mermaid_diff_flowchart(pdiff))
        md.new_paragraph(self.gen_mermaid_pie_from_dict(
            pdiff['stats'], 'Function Similarity', include_keys=['matched_funcs_len', 'unmatched_funcs_len']))

        # Create Metadata section
        md.new_header(1, 'Metadata')

        md.new_header(2, 'Ghidra Diff Engine')

        md.new_header(3, 'Command Line')
        known_cmd, extra_cmd, full_cmd = self.gen_diff_cmd_line(old_name, new_name)
        md.new_header(4, 'Known Command Line', add_table_of_contents='n')
        md.new_paragraph(self._wrap_with_code(known_cmd))
        md.new_header(4, 'Extra Args', add_table_of_contents='n')
        md.new_paragraph(self._wrap_with_code(extra_cmd))
        md.new_header(4, 'All Args', add_table_of_contents='n')
        md.new_paragraph(self._wrap_with_code(full_cmd))

        md.new_header(3, 'Ghidra Analysis Options', add_table_of_contents='n')
        md.new_paragraph(self._wrap_with_details(self.gen_table_from_dict(
            ['Analysis Option', 'Value'], pdiff['analysis_options'])))

        md.new_header(2, 'Binary Metadata Diff')
        md.new_paragraph(self._wrap_with_diff(self.gen_metadata_diff(pdiff)))

        md.new_header(2, 'Diff Stats')
        md.new_paragraph(self.gen_table_from_dict(['Stat', 'Value'], pdiff['stats']))
        md.new_paragraph(self.gen_mermaid_pie_from_dict(pdiff['stats']['match_types'], 'Match Types'))
        md.new_paragraph(self.gen_mermaid_pie_from_dict(pdiff['stats'], 'Diff Stats', include_keys=[
                         'added_funcs_len', 'deleted_funcs_len', 'modified_funcs_len']))
        md.new_paragraph(self.gen_mermaid_pie_from_dict(
            pdiff['stats'], 'Symbols', include_keys=['added_symbols_len', 'deleted_symbols_len']))
        md.new_paragraph(self.gen_mermaid_pie_from_dict(
            pdiff['stats'], 'Strings', include_keys=['added_strings_len', 'deleted_strings_len']))

        # Create Strings Section
        md.new_header(2, 'Strings')
        md.new_header(3, 'Strings Diff', add_table_of_contents='n')
        md.new_paragraph(self.gen_strings_diff(pdiff['strings']['deleted'], pdiff['strings']['added']))

        # Create Deleted section
        md.new_header(1, 'Deleted')

        for i, esym in enumerate(funcs['deleted']):

            if i > max_section_funcs:
                md.new_header(2, 'Max Deleted Section Functions Reached Error')
                md.new_line(f"{len(funcs['deleted']) - max_section_funcs} Deleted Functions Ommited...")
                self.logger.warn(f'Max Deleted Section Functions {max_section_funcs} Reached')
                self.logger.warn(f"{len(funcs['deleted']) - max_section_funcs} Functions Ommited...")
                break

            if esym['external']:
                md.new_header(2, esym['fullname'])
            else:
                md.new_header(2, esym['name'])
            md.new_header(3, "Function Meta", add_table_of_contents='n')
            md.new_paragraph(self.gen_esym_table(old_name, esym))

            # only show code if not above section max
            if len(funcs['deleted']) < max_section_funcs:
                old_code = esym['code'].splitlines(True)
                new_code = ''.splitlines(True)
                diff = ''.join(list(difflib.unified_diff(old_code, new_code,
                                                         lineterm='\n', fromfile=old_name, tofile=new_name)))
                md.new_paragraph(self._wrap_with_diff(diff))

        # Create Added section
        md.new_header(1, 'Added')

        for i, esym in enumerate(funcs['added']):

            if i > max_section_funcs:
                md.new_header(2, 'Max Added Section Functions Reached Error')
                md.new_line(f"{len(funcs['added']) - max_section_funcs} Added Functions Ommited...")
                self.logger.warn(f'Max Added Section Functions {max_section_funcs} Reached')
                self.logger.warn(f"{len(funcs['added']) - max_section_funcs} Functions Ommited...")
                break

            if esym['external']:
                md.new_header(2, esym['fullname'])
            else:
                md.new_header(2, esym['name'])
            md.new_header(3, "Function Meta", add_table_of_contents='n')
            md.new_paragraph(self.gen_esym_table(new_name, esym))

            # only show code if not above section max
            if len(funcs['added']) < max_section_funcs:
                old_code = ''.splitlines(True)
                new_code = esym['code'].splitlines(True)
                diff = ''.join(list(difflib.unified_diff(old_code, new_code,
                                                         lineterm='\n', fromfile=old_name, tofile=new_name)))
                md.new_paragraph(self._wrap_with_diff(diff))

        # Create Modified section
        md.new_header(1, 'Modified')
        md.new_paragraph(f"*Modified functions contain code changes*")
        for i, modified in enumerate(funcs['modified']):

            if i > max_section_funcs:
                md.new_header(2, 'Max Modified Section Functions Reached Error')
                md.new_line(f"{len(funcs['modified']) - max_section_funcs} Functions Ommited...")
                self.logger.warn(f'Max Modified Section Functions {max_section_funcs} Reached')
                self.logger.warn(f"{len(funcs['modified']) - max_section_funcs} Functions Ommited...")
                break

            diff = None

            if modified['old']['external']:
                old_func_name = modified['old']['name']
            else:
                old_func_name = modified['old']['fullname']

            # selectively include matches
            if 'code' in modified['diff_type']:

                md.new_header(2, old_func_name)

                md.new_header(3, "Match Info", add_table_of_contents='n')
                md.new_paragraph(self.gen_esym_table_diff_meta(old_name, new_name, modified))

                md.new_header(3, "Function Meta Diff", add_table_of_contents='n')
                md.new_paragraph(self.gen_esym_table_diff(old_name, new_name, modified))

                if 'called' in modified['diff_type']:
                    md.new_header(3, "Called Diff", add_table_of_contents='n')
                    md.new_paragraph(self.gen_esym_key_diff(modified['old'], modified['new'], 'called', n=0))
                if 'calling' in modified['diff_type']:
                    md.new_header(3, "Calling Diff", add_table_of_contents='n')
                    md.new_paragraph(self.gen_esym_key_diff(modified['old'], modified['new'], 'calling', n=0))

                md.new_header(3, f"{old_func_name} Diff", add_table_of_contents='n')
                md.new_paragraph(self._wrap_with_diff(modified['diff']))

                # only include side by side diff if requested (this adds html to markdown and considerable size)
                if side_by_side:
                    md.new_header(3, f"{old_func_name} Side By Side Diff", add_table_of_contents='n')
                    html_diff = self.gen_code_table_diff_html(
                        modified['old']['code'], modified['new']['code'], old_name, new_name)
                    md.new_paragraph(self._wrap_with_details(html_diff))

        # Create Slightly Modified secion
        # slightly as in no code changes but other relevant changes.
        slight_mods = ['refcount', 'length', 'called', 'calling', 'name', 'fullname']

        md.new_header(1, 'Modified (No Code Changes)')
        md.new_paragraph(f"*Slightly modified functions have no code changes, rather differnces in:*")
        md.new_list(slight_mods)

        # skip this section (as it is mostly a bonus) if this markdown is already too big
        too_big = max_section_funcs < (len(funcs['added']) + len(funcs['deleted']) + len(funcs['modified']))

        if too_big:
            md.new_header(2, 'Section Skipped')
            md.new_paragraph(
                f"**This section was skipped because markdown was too big. Adjust max_section_funcs: {max_section_funcs} to a higher number.**")
        else:
            for modified in funcs['modified']:

                mods = set(slight_mods).intersection(set(modified['diff_type']))

                if 'code' not in modified['diff_type'] and len(mods) > 0:

                    if modified['old']['external']:
                        old_func_name = modified['old']['fullname']
                        new_func_name = modified['old']['fullname']
                    else:
                        old_func_name = modified['old']['name']
                        new_func_name = modified['old']['name']

                    if old_func_name.startswith('FUN_') or new_func_name.startswith('FUN_'):

                        ignore_called = False
                        ignore_calling = False

                        if len(modified['old']['called']) > 0 and len(modified['new']['called']) > 0:
                            called_set = set(modified['old']['called']).difference(modified['new']['called'])
                            ignore_called = all('FUN_' in name for name in list(called_set))

                        if len(modified['old']['calling']) > 0 and len(modified['new']['calling']) > 0:
                            calling_set = set(modified['old']['calling']).difference(modified['new']['calling'])
                            ignore_calling = all('FUN_' in name for name in list(calling_set))

                        # skip name and fullname changes
                        if len(mods.difference(['name', 'fullname'])) == 0:
                            continue
                        # if all called are FUN_ skip
                        elif 'called' in modified['diff_type'] and 'calling' in modified['diff_type'] and ignore_called and ignore_calling:
                            continue
                        elif 'calling' in modified['diff_type'] and ignore_calling:
                            continue
                        elif 'called' in modified['diff_type'] and called_set:
                            continue

                    md.new_header(2, old_func_name)

                    md.new_header(3, "Match Info", add_table_of_contents='n')
                    md.new_paragraph(self.gen_esym_table_diff_meta(old_name, new_name, modified))

                    md.new_header(3, "Function Meta Diff", add_table_of_contents='n')
                    md.new_paragraph(self.gen_esym_table_diff(old_name, new_name, modified))

                    if 'called' in modified['diff_type']:
                        md.new_header(3, "Called Diff", add_table_of_contents='n')
                        md.new_paragraph(self.gen_esym_key_diff(modified['old'], modified['new'], 'called', n=0))
                    if 'calling' in modified['diff_type']:
                        md.new_header(3, "Calling Diff", add_table_of_contents='n')
                        md.new_paragraph(self.gen_esym_key_diff(modified['old'], modified['new'], 'calling', n=0))

        # add credit
        md.new_paragraph(self.gen_credits())

        # generate TOC and set style to atx
        md.table_of_contents += md.header.choose_header(level=1, title='TOC', style='atx')
        md.table_of_contents += TableOfContents().create_table_of_contents(md._table_titles, depth=3)

        # md.new_table_of_contents('TOC', 3)

        return md.get_md_text()
