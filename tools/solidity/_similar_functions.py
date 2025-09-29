import json
from collections import defaultdict

##
## Outputs functions with the same name, check for logic that is not properly mirrored across functions
##

functions = json.loads(open('./.vscode/ext-static-analysis/functions_html.json').read())

# Create a dictionary to hold the counts of each `functionName`
function_name_counts = defaultdict(list)

ignore_list = ['constructor', 'initialize', '/interface', '/test']

seen_functions = []
# Populate the dictionary with function names and their corresponding IDs
for entry in functions:
    if entry['id'] in seen_functions:
        continue
    seen_functions.append(entry['id'])

    if not any(ignore_str in entry['id'].lower() for ignore_str in ignore_list):
        function_name = entry['functionName']
        function_id = f"(SLOC: {entry['endLine'] - entry['startLine']}) {entry['decorator']} | {entry['id']}"
        function_name_counts[function_name].append(function_id)

# Sort the dictionary by the length of the list of IDs (number of matches)
sorted_function_names = sorted(function_name_counts.items(), key=lambda x: len(x[1]), reverse=True)

# Print the results
for function_name, ids in sorted_function_names:
    # more than one function & at least one function is in scope
    if len(ids) > 1 and any('🎯' in id for id in ids):
        print(f"({len(ids)}) {function_name}")
        for function_id in ids:
            print(f"\t{function_id}")
