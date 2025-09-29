import json
import zlib
from bs4 import BeautifulSoup

# zlib.compress(s.get('scope_summary_html', '').encode()).hex()

# NOTE: Should we include both read and write state var icons?

fs_state_var_interactions_map = {}

scopes = json.load(open("./.vscode/ext-static-analysis/scope_summaries_html.json", "r"))
for s in scopes:
    scope_summary_html = zlib.decompress(bytes.fromhex(s.get('scope_summary_html', ''))).decode()
    soup = BeautifulSoup(scope_summary_html, 'html.parser')
    # get divs with (w) or (r) or (r*) in text
    divs = soup.find_all('div')
    for d in divs:
        if "(w)" in d.text:
            input_element = d.find_next('a')  # get next anchor tag
            f_id = input_element.get('data-scope')
            fs_state_var_interactions_map[f_id] = "🔴"   # write to state var in function

        elif "(r)" in d.text or "(r*)" in d.text:
            input_element = d.find_next('a')
            f_id = input_element.get('data-scope')
            if fs_state_var_interactions_map.get(f_id, None) != "🔴":
                fs_state_var_interactions_map[f_id] = "🟢"



functions = json.load(open("./.vscode/ext-static-analysis/functions_html.json", "r"))
for f in functions:
    f_id = f.get('id')
    decorator_to_add = fs_state_var_interactions_map.get(f_id, "")
    if not decorator_to_add in f['decorator']:
        print(f"Adding decorator ({decorator_to_add}) to function {f_id}")
        f['decorator'] += decorator_to_add
    # print(f)

# Save the modified functions back to the file
with open("./.vscode/ext-static-analysis/functions_html.json", "w") as f:
    f.write(json.dumps(functions, indent=4))



# could go back and update scopes html to include decoratos