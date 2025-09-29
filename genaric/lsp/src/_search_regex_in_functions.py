# UpdraftPlus_Options::user_can_manage

import re
import json
import argparse
import colorama
import debugpy

colorama.init()

DECORATOR_MODES = ['search-match', 'filepath-match']

parser = argparse.ArgumentParser(description='Generate a list of functions from a list of files')
parser.add_argument('--search-regex', '-s', type=str, help='The regex to search for in the files')
parser.add_argument('--match-file-regex', '-mf', type=str, help='Only search files that match this regex')
parser.add_argument('--ignore-file-regex', '-if', type=str, help='Ignore files that match this regex')
parser.add_argument('--append-decorator', '-ad', type=str, help='Append a decorator to the function, example unicode characters: 🎯💥🟢🔴🟩❗❌🔀📰🌈💲')
parser.add_argument('--remove-decorator', '-rd', type=str, help='Remove the decorator from the function')
parser.add_argument('--decorator-mode', '-dm', nargs="?", choices=DECORATOR_MODES, default='search-match', help=f'The mode to use for the decorator.')
parser.add_argument('--output-all-functions', '-oaf', action='store_true', help='Output all functions')
parser.add_argument('--debug', '-d', action='store_true', help='Print debug information')


args = parser.parse_args()



if args.append_decorator and len(args.append_decorator) != 1:
    resp = input(f"Append decorator should be a single unicode character, are you sure you want to use '{args.append_decorator}' as a decorator? This may cause unexpected results. (y/n): ")
    
    if resp.lower() != 'y':
        exit(0)



if args.debug:
    debugpy.listen(5678)
    print("Waiting for debugger attach")
    debugpy.wait_for_client()


functions_filepath = './.vscode/ext-static-analysis/functions_html.json'
functions = json.loads(open(functions_filepath, 'r').read())

if len(functions) == 0:
    print("No functions found")
    print("Ensure functions are in file: ./.vscode/ext-static-analysis/functions_html.json")
    exit(0)

functions_map = {}
functions_by_id_map = {}
for f in functions:
    functions_map.setdefault(f['filepath'].split("#")[0], []).append(f)
    functions_by_id_map[f['id']] = f


decorator_updated = False
for filepath in functions_map.keys():
    if args.match_file_regex and not re.search(args.match_file_regex, filepath):
        continue

    if args.ignore_file_regex and re.search(args.ignore_file_regex, filepath):
        continue


    # search for regex in file, print line number 
    content = open(filepath, 'r').read()

    if args.search_regex and not re.search(args.search_regex, content):
        # print(f"{filepath}: {args.search_regex}")
        # no match found in file
        continue


    # with open(filepath, 'r') as file:
    #     lines = file.readlines()
    #     for i, line in enumerate(lines):
    #         if re.search(args.search_regex, line):
    #             print(f"{filepath}:{i+1}: {line.strip()}")
    content_arr = content.split('\n')


    in_lines = []
    for i, line in enumerate(content_arr):
        if args.search_regex and re.search(args.search_regex, line):
            # print(f"{filepath}:{i+1}: {line.strip()}")
            in_lines.append(i+1)

    in_functions = {}
    not_in_functions = []
    for f in functions_map[filepath]:
        not_in_function = True

        for line in in_lines:
            if f['startLine'] <= line and f['endLine'] >= line:
                in_functions.setdefault(f['id'], []).append(line)
                not_in_function = False
                break

        

        if args.decorator_mode == 'search-match' and not not_in_function: 
            if args.append_decorator and args.append_decorator not in f['decorator']:
                f['decorator'] = args.append_decorator
                decorator_updated = True

            if args.remove_decorator and f['decorator']:
                f['decorator'] = f['decorator'].replace(args.remove_decorator, '')
                decorator_updated = True

        elif args.decorator_mode == 'filepath-match' and args.match_file_regex:
            if args.append_decorator and args.append_decorator not in f['decorator']:
                f['decorator'] = args.append_decorator
                decorator_updated = True

            if args.remove_decorator and f['decorator']:
                f['decorator'] = f['decorator'].replace(args.remove_decorator, '')
                decorator_updated = True
        
        # if any([f['startLine'] <= line and f['endLine'] >= line for line in in_lines]):
            # in_functions.setdefault(f, []).append((filepath, in_lines))
        
        if not_in_function:
            not_in_functions.append(f)


    if not in_functions and not args.output_all_functions:
        continue
    
    print(colorama.Fore.CYAN + f"Evaluating: {filepath}: {args.search_regex}" + colorama.Style.RESET_ALL)
    
    print(colorama.Fore.GREEN + "In functions:" + colorama.Style.RESET_ALL)
    for f_id in in_functions:
        f = functions_by_id_map[f_id]

        f_str = f.get('qualifiedName', f.get('functionName', ''))
        print(f"{f['filepath']}: {colorama.Fore.YELLOW}{f_str}{colorama.Style.RESET_ALL} {f['decorator']}")
        for i, line in enumerate(in_functions[f_id]):
            line_content = content_arr[line - 1].strip()
            line_content = re.sub(args.search_regex, colorama.Fore.RED + r'\g<0>' + colorama.Style.RESET_ALL, line_content)
            # print(f"\t{filepath.split('#')[0]}:{line}: {line_content}")
            print(f"\t{line}: {line_content}")
            

    print(colorama.Fore.RED + "Not in functions:" + colorama.Style.RESET_ALL)
    for f in not_in_functions:
        f_str = f.get('qualifiedName', f.get('functionName', ''))
        print(f"{f['filepath']}: {colorama.Fore.YELLOW}{f_str}{colorama.Style.RESET_ALL} {f['decorator']}")
    print("\n\n")
    



if decorator_updated:
    open(functions_filepath, 'w').write(json.dumps(functions, indent=4))