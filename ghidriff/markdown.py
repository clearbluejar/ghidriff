import difflib
import re
from textwrap import dedent
from typing import List, Tuple, Union, TYPE_CHECKING
import logging
import json

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
            text += f"<summary>{summary}</summary>\n"
        text += '\n'
        text += diff
        text += "\n</details>\n"

        return text

    def _wrap_list_with_details(self, items: list, max_items: int = 10) -> str:

        data = None
        if isinstance(items, list):
            if len(items) > max_items:
                show_items = [item for i, item in enumerate(items) if i <= max_items]
                hide_itmes = [item for i, item in enumerate(items) if i > max_items]
                data = f'<details><summary>Expand for full list:<br>{"<br>".join(show_items)}</summary>{"<br>".join(hide_itmes)}</details>'
            else:
                data = f'{"<br>".join(items)}'
        else:
            # do nothing
            data = items

        return data

    def gen_esym_table(self, old_name, esym, max_items=10) -> str:

        table_list = []
        table_list.extend(['Key', old_name])
        column_len = len(table_list)

        skip_keys = ['code', 'instructions', 'mnemonics', 'blocks', 'parent']
        count = 1
        for key in esym:
            if key in skip_keys:
                continue

            if isinstance(esym[key], list):
                data = self._wrap_list_with_details(esym[key], max_items)
            else:
                data = esym[key]

            table_list.extend([key, data])
            count += 1

        diff_table = Table().create_table(columns=column_len, rows=count, text=table_list, text_align='center')

        return diff_table

    def gen_esym_table_diff(self, old_name, new_name, modified, max_items=10) -> str:
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

            if isinstance(modified['old'][key], list):
                data = self._wrap_list_with_details(modified['old'][key], max_items)
                data2 = self._wrap_list_with_details(modified['new'][key], max_items)
            else:
                data = modified['old'][key]
                data2 = modified['new'][key]

            table_list.extend([diff_key, data, data2])

            # table_list.extend([diff_key, modified['old'][key], modified['new'][key]])
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
            val = modified[key]
            if isinstance(val,list):
                val = ','.join(val)
            table_list.extend([key, val])
            count += 1

        diff_table = Table().create_table(columns=column_len, rows=count, text=table_list, text_align='center')

        return diff_table

    def gen_esym_key_diff(self, esym: dict, esym2: dict, key: str, exclude=None, n=3) -> str:
        """
        Generate a difflib unified diff from two esyms and a key
        n is the number of context lines for diff lib to wrap around the found diff
        """
        diff = ''

        if exclude:
            items = [item for item in esym[key] if re.search(exclude, item) is None]
            items2 = [item for item in esym2[key] if re.search(exclude, item) is None]
        else:
            items = esym[key]
            items2 = esym2[key]

        diff += '\n'.join(difflib.unified_diff(items, items2,
                          fromfile=f"{esym['fullname']} {key}", tofile=f"{esym2['fullname']} {key}", lineterm='', n=n))

        return self._wrap_with_diff(diff)

    @staticmethod
    def gen_combined_sxs_html_from_pdiff(pdiff: dict) -> str:
        """
        pdiff: Standard pdiff from ghidriff
        """

        def _add_header(line: str):
            # print(line)
            pass

        sxs_diff_htmls = []

        for mod in pdiff['functions']['modified']:

            if 'code' not in mod['diff_type']:
                continue

            old_code = mod['old']['code']
            new_code = mod['new']['code']
            old_name = mod['old']['fullname']
            new_name = mod['new']['fullname']

            sxs_diff_html = GhidriffMarkdown.gen_code_table_diff_html(
                old_code, new_code, old_name, new_name)

            sxs_diff_htmls.append([mod['old']['name'], sxs_diff_html])

        table_htmls = [table[1] for table in sxs_diff_htmls]

        charset = 'utf-8'

        html_diff = difflib.HtmlDiff(tabsize=4)
        html = (html_diff._file_template % dict(
            styles=html_diff._styles,
            legend=dedent(html_diff._legend),
            table="\n".join(table_htmls),
            charset=charset)).encode(charset, 'xmlcharrefreplace').decode(charset)

        for line in html.splitlines(True):

            _add_header(line)

        return html

    @staticmethod
    def gen_sxs_html_from_pdiff(pdiff: dict) -> list:
        """
        pdiff: Standard pdiff from ghidriff
        """

        sxs_diff_htmls = []

        for mod in pdiff['functions']['modified']:

            if 'code' not in mod['diff_type']:
                continue

            old_code = mod['old']['code']
            new_code = mod['new']['code']
            old_name = mod['old']['fullname']
            new_name = mod['new']['fullname']

            sxs_diff_html = GhidriffMarkdown.gen_code_table_diff_html(
                old_code, new_code, old_name, new_name, bottom=pdiff['html_credits'])

            sxs_diff_htmls.append([mod['old']['name'], sxs_diff_html])

        return sxs_diff_htmls

    @ staticmethod
    def gen_code_table_diff_html(old_code,
                                 new_code,
                                 old_name,
                                 new_name,
                                 html_type='file',
                                 dedent_table: bool = True,
                                 bottom=None,
                                 tabsize=2
                                 ) -> str:
        """
        Generates side by side diff in HTML
        dedent_table: True will dedent the indented table so it renders the html table in markdown
        type: 
            - inline Simply return table,style,and legend withiout html and body tags
            - table only - just return table with no style
            - full - return difflib html template complete
        """

        charset = 'utf-8'

        if isinstance(old_code, str):
            old_code = old_code.splitlines(True)
        if isinstance(new_code, str):
            new_code = new_code.splitlines(True)

        match html_type:
            case 'inline':
                styles = '<style type="text/css">%(styles)s\n</style>' % dict(
                    styles=difflib.HtmlDiff(tabsize=tabsize)._styles)
                table = difflib.HtmlDiff(tabsize=tabsize).make_table(
                    old_code, new_code, fromdesc=old_name, todesc=new_name)

                diff_html = styles + table
                diff_html.encode(charset, 'xmlcharrefreplace').decode(charset)
            case 'table-only':
                diff_html = difflib.HtmlDiff(tabsize=4).make_table(
                    old_code, new_code, fromdesc=old_name, todesc=new_name)
            case 'file':
                diff_html = difflib.HtmlDiff(tabsize=tabsize).make_file(
                    old_code, new_code, fromdesc=old_name, todesc=new_name)
            case _:
                raise NotImplementedError

        if dedent_table:
            diff_html = diff_html.splitlines(True)

            # handle dedent of table so that it renders in markdown
            start_table = None
            end_table = None
            for i, line in enumerate(diff_html):
                if line.find('<table class="diff"') != -1:
                    start_table = i
                if line.find('</table>') != -1:
                    end_table = i

                if start_table and end_table:
                    break

            pre_table = ''.join(diff_html[:start_table])
            post_table = ''.join(diff_html[end_table+1:])

            table = dedent(''.join(diff_html[start_table:end_table+1]))

            diff_html = pre_table + table + post_table

        if html_type == 'file' and bottom:
            needle = '</body>'
            loc = diff_html.find(needle)
            diff_html = diff_html[:loc] + bottom + diff_html[loc:]

        return diff_html + '\n'

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

        added = [f'{item["name"]}\n' for item in added_strings]

        deleted = [f'{item["name"]}\n' for item in deleted_strings]

        diff = ''.join(list(difflib.unified_diff(deleted, added,
                                                 lineterm='\n', fromfile='deleted strings', tofile='added strings')))

        return self._wrap_with_diff(diff)

    def gen_metadata_diff(
        self,
        pdiff: Union[str, dict]
    ) -> str:
        """Generate binary metadata diff"""

        if isinstance(pdiff, str):
            pdiff = json.loads(pdiff)

        old_meta = pdiff['old_meta']
        new_meta = pdiff['new_meta']

        old_text = ''
        old_name = f"{old_meta['Program Name']} Meta"

        new_text = ''
        new_name = f"{new_meta['Program Name']} Meta"

        for i in old_meta:
            self.logger.debug(f"{i}: {old_meta[i]}")
            old_text += f"{i}: {old_meta[i]}\n"

        for i in new_meta:
            self.logger.debug(f"{i}: {new_meta[i]}")
            new_text += f"{i}: {new_meta[i]}\n"

        diff = ''.join(list(difflib.unified_diff(old_text.splitlines(True), new_text.splitlines(
            True), lineterm='\n', fromfile=old_name, tofile=new_name, n=100)))

        return diff

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
                f"{modified['old']['fullname']}-{modified['old']['paramcount']}-old"))
            new_modified.append(self._clean_md_header(
                f"{modified['new']['fullname']}-{modified['old']['paramcount']}-new"))
            modified_links.append(
                f"{self._clean_md_header(modified['old']['fullname'])}-{modified['old']['paramcount']}-old<--Match {int(modified['b_ratio']*100)}%-->{self._clean_md_header(modified['new']['fullname'])}-{modified['old']['paramcount']}-new")

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

    def gen_pe_download_cmd(self, pdiff: dict) -> str:
        """
        Generates Windows PE file download command        
        """

        def _decode_arch(proc, addr_size):
            arch = None
            if proc == 'x86':
                if addr_size == '64':
                    arch = 'x64'
                else:
                    arch = proc
            else:
                if addr_size == '64':
                    arch = 'arm64'
                else:
                    arch = 'arm'

            return arch

        old_url = pdiff['old_pe_url']
        new_url = pdiff['new_pe_url']

        # PE Property[OriginalFilename]: localspl.dll
        old_filename = pdiff['old_meta']['PE Property[OriginalFilename]'].lower()
        new_filename = pdiff['new_meta']['PE Property[OriginalFilename]'].lower()

        # PE Property[ProductVersion]: 10.0.22000.795
        old_ver = pdiff['old_meta']['PE Property[ProductVersion]']
        new_ver = pdiff['new_meta']['PE Property[ProductVersion]']

        # Processor: x86
        # Address Size: 64
        old_arch = _decode_arch(pdiff['old_meta']['Processor'], pdiff['old_meta']['Address Size'])
        new_arch = _decode_arch(pdiff['new_meta']['Processor'], pdiff['new_meta']['Address Size'])

        old_dl = f"wget {old_url} -O {old_filename}.{old_arch}.{old_ver}"
        new_dl = f"wget {new_url} -O {new_filename}.{new_arch}.{new_ver}"

        dl_cmd = "\n".join((old_dl, new_dl))

        return dl_cmd

    def gen_diff_md(
        self,
        pdiff: Union[str, dict],
        title=None,
        side_by_side: bool = False,
        max_section_funcs: int = None,
        include_code: bool = False
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
            pdiff['stats'], f"Function Matches - {pdiff['stats']['func_match_overall_percent']}",
            include_keys=['matched_funcs_len', 'unmatched_funcs_len']))
        md.new_paragraph(self.gen_mermaid_pie_from_dict(
            pdiff['stats'],
            f"Matched Function Similarity - {pdiff['stats']['match_func_similarity_percent']}",
            include_keys=['matched_funcs_with_code_changes_len', 'matched_funcs_with_non_code_changes_len', 'matched_funcs_no_changes_len']))

        # Create Metadata section
        md.new_header(1, 'Metadata')

        md.new_header(2, 'Ghidra Diff Engine')

        md.new_header(3, 'Command Line')
        known_cmd, extra_cmd, full_cmd = self.gen_diff_cmd_line(old_name, new_name)
        md.new_header(4, 'Captured Command Line', add_table_of_contents='n')
        md.new_paragraph(self._wrap_with_code(known_cmd))
        md.new_header(4, 'Verbose Args', add_table_of_contents='n')        
        md.new_paragraph(self._wrap_with_details(self._wrap_with_code(full_cmd)))

        if pdiff.get('old_pe_url') is not None and pdiff.get('new_pe_url') is not None:
            md.new_header(4, 'Download Original PEs')
            md.new_paragraph(self._wrap_with_code(self.gen_pe_download_cmd(pdiff)))

        md.new_header(2, 'Binary Metadata Diff')
        md.new_paragraph(self._wrap_with_diff(self.gen_metadata_diff(pdiff)))

        md.new_header(2, 'Program Options')
        skip_options = 'Program Information'  # options duplicate metadta
        for key in pdiff['program_options'].keys():
            for opt_name in pdiff['program_options'][key]:
                if opt_name in skip_options:
                    continue
                # md.new_header(3, f'Ghidra {key} {opt_name.capitalize()} Options', add_table_of_contents='n')
                if pdiff['program_options'][key][opt_name] is not None:
                    md.new_paragraph(self._wrap_with_details(self.gen_table_from_dict(
                        [f'{opt_name.capitalize()} Option', 'Value'], pdiff['program_options'][key][opt_name]), f'Ghidra {key} {opt_name.capitalize()} Options'))

                else:
                    md.new_paragraph(f'*No {opt_name.capitalize()} set.*')

        md.new_header(2, 'Diff Stats')
        md.new_paragraph(self.gen_table_from_dict(['Stat', 'Value'], pdiff['stats']))
        md.new_paragraph(self.gen_mermaid_pie_from_dict(pdiff['stats']['match_types'], 'Match Types'))
        md.new_paragraph(self.gen_mermaid_pie_from_dict(pdiff['stats'], 'Diff Stats', include_keys=[
                         'added_funcs_len', 'deleted_funcs_len', 'modified_funcs_len']))
        md.new_paragraph(self.gen_mermaid_pie_from_dict(
            pdiff['stats'], 'Symbols', include_keys=['added_symbols_len', 'deleted_symbols_len']))

        # Create Strings Section
        md.new_header(2, 'Strings')
        if len(pdiff['strings']['deleted']) > 0 or len(pdiff['strings']['added']):
            md.new_paragraph(self.gen_mermaid_pie_from_dict(
                pdiff['stats'], 'Strings', include_keys=['added_strings_len', 'deleted_strings_len']))

            md.new_header(3, 'Strings Diff', add_table_of_contents='n')
            md.new_paragraph(self.gen_strings_diff(pdiff['strings']['deleted'], pdiff['strings']['added']))
        else:
            md.new_paragraph('*No string differences found*\n')

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
                                                         lineterm='\n', fromfile=esym['fullname'], tofile=esym['fullname'])))
                if len(diff) > 0:
                    md.new_paragraph(self._wrap_with_diff(diff))
                else:
                    md.new_paragraph(f"*No code available for {esym['fullname']}*")

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
                                                         lineterm='\n', fromfile=esym['fullname'], tofile=esym['fullname'])))
                if len(diff) > 0:
                    md.new_paragraph(self._wrap_with_diff(diff))
                else:
                    md.new_paragraph(f"*No code available for {esym['fullname']}*")

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
                    md.new_header(3, f"{old_func_name} Called Diff", add_table_of_contents='n')
                    md.new_paragraph(self.gen_esym_key_diff(modified['old'], modified['new'], 'called', n=0))
                if 'calling' in modified['diff_type']:
                    md.new_header(3, f"{old_func_name} Calling Diff", add_table_of_contents='n')
                    md.new_paragraph(self.gen_esym_key_diff(modified['old'], modified['new'], 'calling', n=0))

                md.new_header(3, f"{old_func_name} Diff", add_table_of_contents='n')
                md.new_paragraph(self._wrap_with_diff(modified['diff']))

                if include_code:
                    md.new_header(3, f"{old_func_name} Code", add_table_of_contents='n')
                    md.new_paragraph(self._wrap_with_code(modified['old']['code'], 'c'))
                    md.new_paragraph(self._wrap_with_code(modified['new']['code'], 'c'))

                # only include side by side diff if requested (this adds html to markdown and considerable size)
                if side_by_side:
                    md.new_header(3, f"{old_func_name} Side By Side Diff", add_table_of_contents='n')
                    html_diff = GhidriffMarkdown.gen_code_table_diff_html(
                        modified['old']['code'], modified['new']['code'], old_name, new_name, html_type='inline')
                    md.new_paragraph(html_diff)

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
                        md.new_header(3, f"{old_func_name} Called Diff", add_table_of_contents='n')
                        md.new_paragraph(self.gen_esym_key_diff(modified['old'], modified['new'], 'called', n=0))
                    if 'calling' in modified['diff_type']:
                        md.new_header(3, f"{old_func_name} Calling Diff", add_table_of_contents='n')
                        md.new_paragraph(self.gen_esym_key_diff(modified['old'], modified['new'], 'calling', n=0))

        # add credit
        md.new_paragraph(pdiff['md_credits'])

        # generate TOC and set style to atx
        md.table_of_contents += md.header.choose_header(level=1, title='TOC', style='atx')
        md.table_of_contents += TableOfContents().create_table_of_contents(md._table_titles, depth=3)

        return md.get_md_text()
