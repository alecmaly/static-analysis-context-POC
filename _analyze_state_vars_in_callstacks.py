import json

var_read_write_mappings = json.loads(open('./.vscode/ext-static-analysis/func_state_var_read_written_mapping.json').read())
callstacks = json.loads(open('./.vscode/ext-static-analysis/callstacks.json', 'r').read())
functions = json.loads(open('./.vscode/ext-static-analysis/functions_html.json', 'r').read())

functions_map = {}
for f in functions:
    functions_map[f['id']] = f


def get_func_decription(f_id):
    f = functions_map[f_id]
    return f"{f['qualifiedName']} | {f['decorator']} {f['modifiers']}"


vars = list(set([mapping.split("~")[0] for mapping in var_read_write_mappings]))





for var in vars:
    interesting_function_relationships = set()
    for callstack in callstacks:
        seen_read = False
        seen_write = False

        related_functions = set()
        for f_id in callstack:
            key = f"{var}~{f_id}"
            var_read_write_in_func = var_read_write_mappings.get(key, "")

            # if first time seeing WRITE, mark and continue
            # this should avoid marking variables that are read/written in the same function
            if "(w)" in var_read_write_in_func and not seen_write:
                seen_write = True
                if f_id not in related_functions:
                    related_functions.add(f"{var_read_write_in_func} {get_func_decription(f_id)}")
                continue

            if "(r)" in var_read_write_in_func:
                seen_read = True
                if f_id not in related_functions:
                    related_functions.add(f"{var_read_write_in_func} {get_func_decription(f_id)}")
        related_functions_str = " <-> ".join(related_functions)
        
        if seen_read and seen_write and '🎯' in related_functions_str and all([word not in related_functions_str for word in ['constructor']]):
            interesting_function_relationships.add(related_functions_str)

    if interesting_function_relationships:
        print(f"'{var}' in function pairs:")
        for related_function in interesting_function_relationships:
            print(f"\t{related_function}")
            # print(interesting_function_relationships[related_function])




