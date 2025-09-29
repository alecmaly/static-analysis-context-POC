import json
import os
import sys
import argparse
import re 
import debugpy
import datetime

# BASE_DIR = "~/Desktop/static-analysis-context-POC/genaric/lsp/"  # "./"

# create argument
parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('--project-dir', "-d", type=str, default=".", help='The project directory')
parser.add_argument('--remove-empty-functions', "-rm", action='store_true', help='Remove empty functions')
parser.add_argument('--ignore-callees-regex', "-icaller", type=str, help='Ignore callees that match this regex')
parser.add_argument('--ignore-callers-regex', "-icallee", type=str, help='Ignore callers that match this regex')
parser.add_argument('--ignore-callers-and-callees-regex', "-iall", type=str, help='Ignore callers and callees that match this regex')
parser.add_argument('--always-keep-regex', "-ak", type=str, default="", help='Always keep callees that match this regex')
parser.add_argument('--show-top-n', "-n", type=int, default=10, help='Show top n callers and callees')
parser.add_argument("--remove-dup-empty-functions", "-rd", action="store_true", help="Remove duplicate empty functions")
parser.add_argument('--pause', "-p", action='store_true', help='Pause to show details before processing data')
parser.add_argument('--debug', action='store_true', help='Debug mode')
args = parser.parse_args()

if args.debug:
    debugpy.listen(("0.0.0.0", 5678))
    print("Waiting for debugger attach")
    debugpy.wait_for_client()

BASE_DIR = "./.vscode/ext-static-analysis/cache"
# try:
#     BASE_DIR = args.project_dir
#     BASE_DIR = os.path.expanduser(args.project_dir)

#     BASE_DIR = os.path.expanduser(BASE_DIR)
#     BASE_DIR = os.path.abspath(BASE_DIR)
#     print(BASE_DIR)
# except:
#     pass

# make BASE_DIR absolute
BASE_DIR = os.path.abspath(BASE_DIR) + "/"
print(f"Using BASE_DIR: {BASE_DIR}")


def tryReadJson(file_path):
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return []
    
function_calls = tryReadJson(f'{BASE_DIR}function_calls.json')
functions = tryReadJson(f'{BASE_DIR}functions_html.json')


empty_functions = {}
functions_with_body = {}
functions_map = {}
for f in functions:
    functions_map[f['id']] = f
    f['entrypoint_callstacks'] = []
    f['exit_callstacks'] = []
    f['other_callstacks'] = []
    f['body_size'] = f['endLine'] - f['startLine']

    if f['body_size'] == 0:
        empty_functions[f['id']] = True
    else:
        functions_with_body[f['functionName']] = True

      


new_function_calls = {}
removed_callers = {}
removed_callees = {}
for caller in function_calls:
    if args.remove_dup_empty_functions:
        if empty_functions.get(caller, None) and caller.split(',')[0] in functions_with_body:
            removed_callers[caller] = True
            continue

    if args.ignore_callers_regex:
        if re.search(args.ignore_callers_regex, caller) and not (args.always_keep_regex and re.search(args.always_keep_regex, caller)):
            removed_callers[caller] = True
            continue
    
    if args.ignore_callers_and_callees_regex:
        if re.search(args.ignore_callers_and_callees_regex, caller) and not (args.always_keep_regex and re.search(args.always_keep_regex, caller)):
            removed_callers[caller] = True
            continue


    callees = function_calls[caller]

    if args.remove_empty_functions:
        if empty_functions.get(caller, None):
            removed_callers[caller] = True
            continue

        callees = [callee for callee in callees if callee not in empty_functions]


    if args.ignore_callees_regex:
        callees_to_remove = []
        callees_to_keep = []
        for callee in callees:
            if args.remove_dup_empty_functions:
                if empty_functions.get(callee, None) and callee.split(',')[0] in functions_with_body:
                    removed_callees[callee] = True
                    continue

            if re.search(args.ignore_callees_regex, callee) and not (args.always_keep_regex and re.search(args.always_keep_regex, callee)):
                removed_callees[callee] = True
            else:
                callees_to_keep.append(callee)

        new_function_calls[caller] = callees_to_keep
        continue

    if args.ignore_callers_and_callees_regex:
        callee_to_remove = []
        callees_to_keep = []
        for callee in callees:
            if args.remove_dup_empty_functions:
                if empty_functions.get(callee, None) and callee.split(',')[0] in functions_with_body:
                    removed_callees[callee] = True
                    continue

            if re.search(args.ignore_callers_and_callees_regex, callee) and not (args.always_keep_regex and re.search(args.always_keep_regex, callee)):
                removed_callees[callee] = True
            else:
                callees_to_keep.append(callee)
        
        new_function_calls[caller] = callees_to_keep
        continue


    new_function_calls[caller] = callees


# top 5 number of callers and callees, print
caller_count = {}
callee_count = {}

for caller in function_calls:
    caller_count[caller] = len(function_calls[caller])
    for callee in function_calls[caller]:
        if callee not in callee_count:
            callee_count[callee] = 0
        callee_count[callee] += 1

print(f"\nRemoved {len(removed_callers)} callers")
for caller in removed_callers:
    print(f"{caller_count[caller]} - {caller}")

print(f"\nRemoved {len(removed_callees)} callees")
for callee in removed_callees:
    print(f"{callee_count[callee]} - {callee}")



function_calls = new_function_calls
# top 5 number of callers and callees, print
caller_count = {}
callee_count = {}

for caller in function_calls:
    caller_count[caller] = len(function_calls[caller])
    for callee in function_calls[caller]:
        if callee not in callee_count:
            callee_count[callee] = 0
        callee_count[callee] += 1

caller_count = {k: v for k, v in sorted(caller_count.items(), key=lambda item: item[1], reverse=True)}
callee_count = {k: v for k, v in sorted(callee_count.items(), key=lambda item: item[1], reverse=True)}


print(f"\nTop {args.show_top_n} number of callers")
print("\n".join([f"{caller_count[caller]} - {caller}" for caller in list(caller_count.keys())[:args.show_top_n]]))

print(f"\nTop {args.show_top_n} number of callees")
print("\n".join([f"{callee_count[callee]} - {callee}" for callee in list(callee_count.keys())[:args.show_top_n]]))

if args.pause:
    input('Press enter to continue')


start = datetime.datetime.now()

is_caller_map = {}
is_callee_map = {}
for caller in function_calls:
    is_caller_map[caller] = True
    for callee in function_calls[caller]:
        is_callee_map[callee] = True

def is_subsequence(arr, other_arr):
    len_arr = len(arr)
    len_other_arr = len(other_arr)

    # If first list is larger, it can't be a subsequence
    if len_arr > len_other_arr:
        return False

    # Use a sliding window to check if arr is a subsequence of other_arr
    for i in range(len_other_arr - len_arr + 1):
        if other_arr[i:i+len_arr] == arr:
            return True

    return False


def remove_subsequences(callstacks):
    # return [arr for arr in callstacks if not any(is_subsequence(arr, other_arr) for other_arr in callstacks if other_arr != arr)] 
    # Sort callstacks by length (longest first)
    sorted_callstacks = sorted(callstacks, key=len, reverse=True)

    # Use a set to track arrays that are not subsequences
    unique_callstacks = []

    for i, arr in enumerate(sorted_callstacks):
        if all(not is_subsequence(arr, other_arr) for other_arr in sorted_callstacks[:i]):
            unique_callstacks.append(arr)

        if i % 2000 == 0:
            print("remove_subsequences", i, len(sorted_callstacks))

    # The result is the unique callstacks
    return unique_callstacks



callstacks = []
for function in functions:
    if is_caller_map.get(function['id'], None) and not is_callee_map.get(function['id'], None):
        callstacks.append([function['id']])



while True:
    new_callstacks = []
    for callstack in callstacks:
        if callstack[-1] in function_calls:
            callees_found = 0
            for callee in function_calls[callstack[-1]]:
                if callee in callstack:
                    continue
                new_callstack = callstack.copy()
                new_callstack.append(callee)
                new_callstacks.append(new_callstack)
                callees_found += 1
            if callees_found == 0:
                new_callstacks.append(callstack)
        else:
            new_callstacks.append(callstack)

    print(f"before: {len(callstacks)} {len(new_callstacks)}")
    # if len(new_callstacks) > 50000:
    #     new_callstacks = remove_subsequences(new_callstacks)
    #     # new_callstacks = [arr for arr in new_callstacks if not any(is_subsequence(arr, other_arr) for other_arr in new_callstacks if other_arr != arr)]
    #     print(f"after: {len(callstacks)} {len(new_callstacks)}\n")

    if new_callstacks == callstacks:
        break
    callstacks = new_callstacks


print("callstacks", len(callstacks))
print("finishing finding callstacks")
callstacks = [arr for arr in callstacks if len(arr) > 1]
print(f"after removing singular nodes: {len(callstacks)}")
# callstacks = [arr for arr in callstacks if not any(is_subsequence(arr, other_arr) for other_arr in callstacks if other_arr != arr)]
print("finished cleaning") 
callstacks.sort(key=lambda arr_of_funcs: ''.join([f for f in arr_of_funcs])) 

open(f'{BASE_DIR}callstacks.json', 'w').write(json.dumps(callstacks))

print('Time to get callstacks: ', datetime.datetime.now() - start)                                                                   


print('done')

for i_c, callstack in enumerate(callstacks):
    for i_f, f_id in enumerate(callstack):
        if f_id not in functions_map:
            continue
        
        if i_f == 0:
           functions_map[f_id]['entrypoint_callstacks'].append(i_c)
        elif i_f == len(callstack) - 1:
            functions_map[f_id]['exit_callstacks'].append(i_c)
        else:
            functions_map[f_id]['other_callstacks'].append(i_c)

open(f'{BASE_DIR}functions_html.json', 'w').write(json.dumps(functions))


print('Time to update functions: ', datetime.datetime.now() - start)




### build inheritance graph
def get_name_from_id(id):
    return ",".join(id.split(",")[:-1])

def build_node(id, type="class"):
    name = get_name_from_id(id)
    filepath = id.split(",")[-1]
    
    return {
        "classes": "l1",
        "data": {
            "id": f"{name}",
            "type": type,
            "title": f"{name} <a href='file://{filepath}'>1</a>",
            "content": id,
            "isCollapsed": True
        }
    }


class_inheritance_relationships = json.loads(open(f'{BASE_DIR}class_inheritance.json', 'r').read())

nodes = set()
edges = set()
for parent_id in class_inheritance_relationships:
    nodes.add(json.dumps(build_node(parent_id)))
    for child_id in class_inheritance_relationships[parent_id]:
        nodes.add(json.dumps(build_node(child_id)))
        edge = {
            "data": {
                "source": get_name_from_id(parent_id),
                "target": get_name_from_id(child_id)
            }
        }
        edges.add(json.dumps(edge))

nodes = [json.loads(n) for n in nodes]
edges = [json.loads(e) for e in edges]

graph = {
    "nodes": nodes,
    "edges": edges
}

open(f'{BASE_DIR}inheritance_graph.json', 'w').write(json.dumps(graph))

print('time to build inheritance graph: ', datetime.datetime.now() - start)



###########





