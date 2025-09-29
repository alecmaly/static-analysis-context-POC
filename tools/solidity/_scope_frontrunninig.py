
import json 
from bs4 import BeautifulSoup
import re

scopes = json.loads(open('./.vscode/ext-static-analysis/scope_summaries_html.json').read())
MAX_LOOPS = 50


scope_var_map = {}
var_scope_map = {}
scope_map = {}

for scope in scopes:
    scope_map[scope['id']] = scope
    soup = BeautifulSoup(scope['state_vars_html'], 'html.parser')
    vars = soup.find_all("span")

    interesting_vars = []
    for var in vars:
        write_counter = 0
        seen_funcs = []
        output = ""

        next = var.next_element
        i = 0
        while True:
            if not next or next.name == 'span':
                break
            
            if next.name == 'div' and  all(word in next.text for word in ["(w)", "🎯"]) and all(word not in next.text.lower() for word in ["constructor", "initialize", "❌", "requires",  "collapsable-2"]):
                try:
                    func_name = next.next_element.next_element['href'].split(",")[0]

                    if func_name not in seen_funcs or True:
                        write_counter += 1
                        seen_funcs.append(func_name)
                        output += "\t\t" + next.text + "\n"
                except:
                    ""

            next = next.next_element

        # 1 write may let admins frontrun SET funtions
        if write_counter >= 1:
            var_output = f"{write_counter} |  {var.text}\n{output}"
            scope_var_map.setdefault(scope['id'], []).append(var_output)
            var_scope_map.setdefault(var_output, []).append(scope['id'])
            interesting_vars.append(var_output)

    # if interesting_vars:
    #     print(scope['name'], " -- ", scope['id'])
    #     for interesting_var in interesting_vars:
    #         print(f"\t{interesting_var}")

for scope_id in scope_var_map:
    scope = scope_map[scope_id]

    unique_var_output = [var_output for var_output in scope_var_map[scope_id] if len(var_scope_map[var_output]) == 1]

    if unique_var_output:
        print(scope['name'], " -- ", scope['id'])
        for interesting_var in unique_var_output:
            print(f"\t{interesting_var}")

print("-" * 100)
print("-" * 100)

for output_var in var_scope_map:
    scope_ids = var_scope_map[output_var]

    if len(scope_ids) <= 1:
        continue

    print("\n".join(scope_ids))
    print(output_var)
