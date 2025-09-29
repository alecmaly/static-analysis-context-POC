import json
# for solidity

callstacks = json.loads(open('./.vscode/ext-static-analysis/callstacks.json', 'r').read())
functions = json.loads(open('./.vscode/ext-static-analysis/functions_html.json', 'r').read())

output = {}

function_lookup = {}
for f in functions:
    function_lookup[f['id']] = f


for callstack in callstacks:
    modifiers_in_chain = set()
    for function_id in callstack:
        f = function_lookup.get(function_id, None)
        if not f:
            continue

        for mod in f['modifiers']:
            modifiers_in_chain.add(mod)

        function_output = output.get(function_id)

        if not function_output:
            output[function_id] = {
                'callstack_count': 0,
                'modifiers_counts': {}
            }

        for mod in modifiers_in_chain:
            output[function_id]['modifiers_counts'].setdefault(mod, 0)
            output[function_id]['modifiers_counts'][mod] += 1

        output[function_id]['callstack_count'] += 1


        # function_output.setdefault()
        # CODE HERE
        # print(modifiers_in_chain)

for func_id in output:
    func_data = output[func_id]
    f = function_lookup[func_id]
    for mod in func_data['modifiers_counts']:
        mod_count = func_data['modifiers_counts'][mod]
        usage_ratio = mod_count / func_data['callstack_count']

        if usage_ratio < 1 and usage_ratio > .5:
            print(mod, " - ", round(usage_ratio, 2), " - ",  f['qualifiedName'], f['decorator'], " -- ", f['filepath'])

