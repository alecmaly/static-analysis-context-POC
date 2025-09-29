import os
import json

functions_map = {}
functions_filepath = './.vscode/ext-static-analysis/functions_html.json'
BASE_DIR = os.getcwd()
if os.path.exists(functions_filepath):
    functions = json.loads(open(functions_filepath, 'r').read())
    for f in functions:
        functions_map.setdefault(f['filepath'].split("#")[0], []).append(f)



# given file path and line number, return function
def get_function(filepath, line):
    for f in functions_map.get(filepath, []):
        if f['filepath'].split('#')[0] == filepath and f['startLine'] <= line and f['endLine'] >= line:
            return f
    return {}

