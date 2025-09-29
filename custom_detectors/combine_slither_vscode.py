# this script combines callstacks / function summaries output by custom detectors for use in vs code extension
# resolves issue of detector running on multiple sublists of code for some reason
import json
import regex
import glob
import base64
import debugpy

# debugpy.listen(5678)
# debugpy.wait_for_client()


scope_summary_compare_html = """
function isEmptyOrUndefined(obj) {
    return obj === undefined || (Object.keys(obj).length === 0 && obj.constructor === Object);
}

// window.func_state = {}
let btn = document.querySelector('#compare-func-state-btn')
btn.style.position = "sticky"
btn.style.top = "0px"
btn.style.float = "right"
btn.style.zIndex = "999"
btn.innerHTML = isEmptyOrUndefined(window.func_state) ? 'Set Func 1 Changes' : `Compare Func 1 Changes: (${window.func_state.func_orig})`
btn.onclick = function() {
    function collectStateChanges() {
        // return Array.from(scope_detail.querySelectorAll('[type="checkbox"][id*="~"]'))
        //   .filter(e => {return e.checked})
        //   .map(c => {return {id: c.id, var: c.id.split("~")[0], text: c.parentElement.textContent.trim(), html: c.parentElement.innerHTML.trim()}})
        //// .filter(e => { return e.text.includes("(w)") })

        let vars = Array.from(scope_detail.querySelectorAll('[type="checkbox"][id*="~"]'))
            .filter(e => {return e.checked})
            .map(c => {return {id: c.id, var: c.id.split("~")[0], text: c.parentElement.textContent.trim(), html: c.parentElement.innerHTML.trim()}})

        let modifiers = Array.from(scope_detail.querySelectorAll('[id^="modifier-"]'))
            .filter(e => {return e.checked})
            .map(v => { return {id: v.id, var: v.id, text: v.id, html: v.id }})

        return [].concat(vars).concat(modifiers)
    }

    let scope_detail = document.querySelector('#scope-detail')
    if (isEmptyOrUndefined(window.func_state)) {
        window.func_state = {}
        window.func_state.func_orig = `${document.querySelector('#scope-detail').querySelector('h2').innerText}.${document.querySelector('#highlight-functionName-btn').getAttribute('value')}`
        window.func_state.state_orig = collectStateChanges()
        document.querySelector('#compare-func-state-btn').innerHTML = `Compare Func 1 Changes: (${window.func_state.func_orig})`
        return
    }
    
    let func_orig = window.func_state.func_orig
    let state_orig = window.func_state.state_orig
    window.func_state = {}

    scope_detail = document.querySelector('#scope-detail')
    let func_new = `${document.querySelector('#scope-detail').querySelector('h2').innerText}.${document.querySelector('#highlight-functionName-btn').getAttribute('value')}`
    let state_new = collectStateChanges()

    // show diffs included/excluded from each
    let diff_included = state_new.filter(e => {return !state_orig.find(e2 => { return e.id === e2.id  })})
    let diff_excluded = state_orig.filter(e => {return !state_new.find(e2 => { return e.id === e2.id  })})
    
    // group by variable, output differences
    function groupMap(map) {
        return map.reduce((acc, cur) => {
            if (acc[cur.var]) {
                acc[cur.var].push(cur)
            } else {
                acc[cur.var] = [cur]
            }
            return acc
        }, {})
    }
    let diff_included_grouped = groupMap(diff_included)
    let diff_excluded_grouped = groupMap(diff_excluded)

    // update output() to collect html instead of text and return a string instead of console.log
    function output(map1, map2) {
        function arr_to_html(prefix, arr, filter_str) {
            return arr && arr.length > 0 ? arr
                .filter(e => { return e.html.includes(filter_str) })
                .map(e => { return prefix + e.html + "<br>" })
                .join("") : ""
        }

        let out = `<br><br><h2>Variable Changes</h2><br><h3 style='position: sticky; top: 50px; background-color: var(--vscode-editor-background); padding: 5px 0px 5px 0px'>${func_new} <> ${func_orig}</h3>`

        Array.from([...new Set(Object.keys(map1).concat(Object.keys(map2)))]).forEach((v) => {
            out += `<h4>${v}</h4>`

            // written
            out_written = arr_to_html("< ", map1[v], "(w)")
            out_written += arr_to_html("> ", map2[v], "(w)")
            if (out_written) { out += out_written + "<br>" }

            // read
            out += arr_to_html("< ", map1[v], "(r)")
            out += arr_to_html("> ", map2[v], "(r)")

            // modifiers
            out_modifiers = arr_to_html("< ", map1[v], "modifier-")
            out_modifiers += arr_to_html("> ", map2[v], "modifier-")
            if (out_modifiers) { out += out_modifiers + "<br>" }

            
            out += "<br>"
        })
        return out
    }

    debugger
    let html = output(diff_included_grouped, diff_excluded_grouped)
    let new_div = document.createElement('div')
    new_div.innerHTML = html

    document.querySelector('#scope-detail').appendChild(new_div)
    new_div.scrollIntoView({behavior: "smooth", block: "start", inline: "nearest"})
    main_module.AddEventListeners(new_div)
}


document.querySelector('#scope-detail').insertBefore(btn, document.querySelector('.content'))
"""
scope_summary_compare_html_b64 = base64.b64encode(scope_summary_compare_html.encode('utf-8')).decode('utf-8')



num_callstacks_per_file = {}

# append callstacks.html
file_list = glob.glob('./.vscode/ext-slither-cache/callstacks_*.html')

combined_callstacks = []
for filename in file_list:
    callstacks = open(filename, 'r').readlines()
    for callstack_str in callstacks:
        if callstack_str.strip() != "":
            combined_callstacks.append(callstack_str.strip())
open('./.vscode/ext-static-analysis/callstacks.html', 'w').write("\n".join(combined_callstacks))



# append callstacks.json
file_list = glob.glob('./.vscode/ext-slither-cache/callstacks_*.json')
file_list = sorted(file_list, key=lambda x: int(x.split('_')[-1].split('.')[0]))


combined_callstacks = []
index = 0
for filename in file_list:
    index += 1
    callstacks = open(filename, 'r').read()
    callstacks = json.loads(callstacks)
    for callstack in callstacks:
        combined_callstacks.append(callstack)
    num_callstacks_per_file[index] = len(callstacks)
open('./.vscode/ext-static-analysis/callstacks.json', 'w').write(json.dumps(combined_callstacks))



# append callstack_edge_colors.json
file_list = glob.glob('./.vscode/ext-slither-cache/func_call_edge_colors_*.json')
file_list = sorted(file_list, key=lambda x: int(x.split('_')[-1].split('.')[0]))

func_edge_colors = {}
index = 0
for filename in file_list:
    index += 1
    funcPairs = open(filename, 'r').read()
    funcPairs = json.loads(funcPairs)
    for funcPair in funcPairs:
        color = funcPairs[funcPair]
        func_edge_colors[funcPair] = color
open('./.vscode/ext-static-analysis/func_call_edge_colors.json', 'w').write(json.dumps(func_edge_colors))



# combine functions_html + change indexes by offset
completed_ids = []

file_list = glob.glob('./.vscode/ext-slither-cache/functions_html_*.json')
file_list = sorted(file_list, key=lambda x: int(x.split('_')[-1].split('.')[0]))

combined_functions = []
index = 0
callstack_offset = 0
for filename in file_list:
    index += 1
    functions = open(filename, 'r').read()
    functions = json.loads(functions)
    for f in functions:
        new_callstack_offsets = []
        for i in f["entrypoint_callstacks"]:
            new_callstack_offsets.append(i + callstack_offset)
        f["entrypoint_callstacks"] = new_callstack_offsets
        new_callstack_offsets = []
        for i in f["exit_callstacks"]:
            new_callstack_offsets.append(i + callstack_offset)
        f["exit_callstacks"] = new_callstack_offsets
        new_callstack_offsets = []
        for i in f["other_callstacks"]:
            new_callstack_offsets.append(i + callstack_offset)
        f["other_callstacks"] = new_callstack_offsets

        func_scope_unique_id = f"{f['id']}~{f['scope_id']}"
        if func_scope_unique_id not in completed_ids:
            # print(f"f is unique when ignoring prop1 and prop2: {f['id']}")
            if '🎯' not in f['decorator']:
                f['reviewed'] = True
            combined_functions.append(f)
            completed_ids.append(func_scope_unique_id)

    callstack_offset += int(num_callstacks_per_file[index])

open('./.vscode/ext-static-analysis/functions_html.json', 'w').write(json.dumps(combined_functions))




## state vars
file_list = glob.glob('./.vscode/ext-slither-cache/func_state_var_read_written_mapping_*.json')
file_list = sorted(file_list, key=lambda x: int(x.split('_')[-1].split('.')[0]))
combined_func_var_mapping = {}
for filename in file_list:
    func_var_mappings = open(filename, 'r').read()
    func_var_mappings = json.loads(func_var_mappings)
    for func_var_mapping in func_var_mappings:
        combined_func_var_mapping[func_var_mapping] = ''.join(func_var_mappings[func_var_mapping])

open('./.vscode/ext-static-analysis/func_state_var_read_written_mapping.json', 'w').write(json.dumps(combined_func_var_mapping))




## text highlights
file_list = glob.glob('./.vscode/ext-slither-cache/texthighlights_*.json')
file_list = sorted(file_list, key=lambda x: int(x.split('_')[-1].split('.')[0]))
combined_texthighlights = {}
seen_location = {}
for filename in file_list:
    file_texthighlights = open(filename, 'r').read()
    file_texthighlights = json.loads(file_texthighlights)
    for file in file_texthighlights:
        decorations = file_texthighlights[file]
        for decoration in decorations:
            for loc in decorations[decoration]:
                if str(loc) not in seen_location:
                    combined_texthighlights \
                        .setdefault(file, {}) \
                        .setdefault(decoration, []) \
                        .append(loc)
                seen_location[str(loc)] = True

open('./.vscode/ext-static-analysis/decorations.json', 'w').write(json.dumps(combined_texthighlights))




## import statements
file_list = glob.glob('./.vscode/ext-slither-cache/source_import_tuples_*.json')
file_list = sorted(file_list, key=lambda x: int(x.split('_')[-1].split('.')[0]))
combined_import_mapping = {}
for filename in file_list:
    import_mappings = json.loads(open(filename, 'r').read())
    for import_mapping in import_mappings:
        combined_import_mapping[import_mapping] = import_mappings[import_mapping]

open('./.vscode/ext-static-analysis/source_import_tuples.json', 'w').write(json.dumps(combined_import_mapping))




#### TESTING ######
# combine scope summary html + change indexes by offset
completed_ids = []

file_list = glob.glob('./.vscode/ext-slither-cache/scope_summaries_html_*.json')
file_list = sorted(file_list, key=lambda x: int(x.split('_')[-1].split('.')[0]))

combined_scope_summaries = []
index = 0
for filename in file_list:
    scopes = open(filename, 'r').read()
    scopes = json.loads(scopes)

    for scope in scopes:
        if scope['id'] not in completed_ids:
                # print(f"f is unique when ignoring prop1 and prop2: {f['id']}")
            combined_scope_summaries.append(scope)
            completed_ids.append(scope['id'])

# marge similar variable read/writes for scope summaries
# - TO DO: Improve by matching .varibles? (may result in false positives, is this ok?)
# - test w/ ditto : \.ethescrowed (\+=|=)     @ BidOrdersFacet

combined_scope_summaries_varHTML_with_lookups = {}
counter = 0
MIN_LENGTH = 3
functions_with_lookups = []
for scope in combined_scope_summaries:
    # if "/test" in scope['id']:
    #     continue

    new_lines = []
    num_items = len(scope['state_vars_html'].split("</div>"))
    lines_to_append = []
    seen_contracts = []
    for i, line in enumerate(scope['state_vars_html'].split("</div>")):
        line = line.split("</div>")[-1]

        if "Set Var" in line or i == num_items - 1:
            # add lines to append to newlines
            for l in lines_to_append:
                # don't include contracts that wee've seen, they were probably inherited and thus a line exists for it already
                if any([f">{c}." in l for c in seen_contracts]):
                    continue
                new_lines.append(l)
            lines_to_append = []
            # new_lines.append(f"{i} SDFSDFSD")
    
        new_lines.append(line)
        matches = regex.search("(?<=href='#).*?(?=')", line)
        function_id = matches.group() if matches else ''

        matches = regex.findall("(?<=\\d'>)(.+?)\\.", line)
        contract = matches[-1] if matches else ''
        if contract not in seen_contracts:
            seen_contracts.append(contract)
        # print(contract)

        if "(w)" not in line and "(r*)" not in line:
            continue

        # try tokenizing instead and look for all tokens? more false positives?
        var_name = "|".join(line.split("</a>")[-1].split("|")[1:]).strip().split("+=")[0].split("-=")[0].split("|=")[0].split("^=")[0].split("=")[0].strip()  # dirty af, will only work for (w) write operations
        var_beginning_bracket = var_name.split("[")[0]  # very specific, maybe check before . as well? May not be as accurate for diamond pattern?
        var_beginning_period = var_name.split(".")[0]  # very specific, maybe check before . as well? May not be as accurate for diamond pattern?
        var_end = "." + var_name.split(".")[-1] + " " if "." in var_name else "nsadcisdfo"  # \.validator(?![a-z_1-9])


        for lookup_scope in combined_scope_summaries:
            if scope['id'] == lookup_scope['id']: # or "/test" in lookup_scope['id']:
                continue
            
            for lookup_line in lookup_scope['state_vars_html'].split("</div>"):
                lookup_line = lookup_line.split("</span>")[-1]  # remove var names that may be prefixed

                # skip if output function is same as current function
                if function_id in lookup_line or f">{scope['name']}." in lookup_line:
                    continue


                # if "(w)" in lookup_line and (var_name and (len(var_name) >= MIN_LENGTH and var_name in lookup_line) or (var_end and len(var_end) >= MIN_LENGTH and var_end in lookup_line) or (var_beginning_bracket and len(var_beginning_bracket) >= MIN_LENGTH and var_beginning_bracket in lookup_line) or (var_beginning_period and len(var_beginning_period) >= MIN_LENGTH and var_beginning_period in lookup_line)):
                if ("(w)" in lookup_line or "(r*)" in lookup_line) and (
                    (var_end and len(var_end) >= MIN_LENGTH and var_end in lookup_line) or 
                    (var_name and (len(var_name) >= MIN_LENGTH and var_name in lookup_line.split('=')[0]))
                ):
                    # print(f"~~{var_name}")
                    replaced_line = lookup_line.replace("<div class='collapsable'>", f"<div class='collapsable-2'>{'&emsp;' * 4}(🔀?{var_name}?) ")

                    if var_name and len(var_name) >= MIN_LENGTH:
                        replaced_line = replaced_line.replace(var_name, f"<b>{var_name}</b>")
                    if var_beginning_bracket and len(var_beginning_bracket) >= MIN_LENGTH:
                        replaced_line = replaced_line.replace(var_beginning_bracket, f"<b>{var_beginning_bracket}</b>")
                    if var_beginning_period and len(var_beginning_period) >= MIN_LENGTH:
                        replaced_line = replaced_line.replace(var_beginning_period, f"<b>{var_beginning_period}</b>")
                    if var_end and len(var_end) >= MIN_LENGTH:
                        replaced_line = replaced_line.replace(var_end, f"<b>{var_end}</b>")


                    # replace inherited (i) marker if present to prevent duplicates in output being picked up from scpes that inherit and do not inherit
                    replaced_line = replaced_line.replace("(i) ", "")

                    if replaced_line not in lines_to_append:
                        lines_to_append.append(replaced_line)
                        if function_id not in functions_with_lookups:
                            functions_with_lookups.append(function_id)



    
    combined_scope_summaries_varHTML_with_lookups[scope['id']] = "</div>".join(new_lines)
    print(f"{counter} / {len(combined_scope_summaries)}")
    counter += 1


# collect num inherited from each scope
scope_num_inheritors_map = {}
scope_num_inheritors_recursive_map = {}

for scope in combined_scope_summaries:
    scope_num_inheritors_map[scope['id']] = []
    scope_num_inheritors_recursive_map[scope['id']] = []
    for scope2 in combined_scope_summaries:
        if scope['id'] == scope2['id']:
            continue
        if scope['id'] in scope2['inherits'] and scope2['id'] not in scope_num_inheritors_map[scope['id']]:
            scope_num_inheritors_map[scope['id']].append(scope2['id'])
        if scope['id'] in scope2['inherits_recursive'] and scope2['id'] not in scope_num_inheritors_recursive_map[scope['id']]:
            scope_num_inheritors_recursive_map[scope['id']].append(scope2['id'])



for scope in combined_scope_summaries:
    scope['inherits_from'] = scope_num_inheritors_map[scope['id']]
    scope['inherits_from_recursive'] = scope_num_inheritors_recursive_map[scope['id']]
    before = len(scope["scope_summary_html"])
    scope['state_vars_html'] = combined_scope_summaries_varHTML_with_lookups.get(scope['id'], scope['state_vars_html'])
    scope["scope_summary_html"] = f"""
        <h2>Compare Funcs</h2>
        <button id="compare-func-state-btn" value="exec:{scope_summary_compare_html_b64}" data-auto="true">Load Script</button>
        <h2>Fuzz Testing</h2>
        {scope['fuzz_testing_html']}
        <h2>Storage Slots</h2>
        {scope['storage_slots_html']}
        <h2>State Vars</h2>
        {scope['state_vars_html']}
        <h2>Modifiers</h2>
        {scope['modifiers_html']}
        <h2>Functions</h2>
        {scope['functions_html']}
        <script>
            {scope_summary_compare_html}
        </script>
    """
    scope['modifiers_html'] = ''
    scope['functions_html'] = ''
    after = len(scope["scope_summary_html"])
    print(f"{before} -> {after}")


#### END TESTING ######

open('./.vscode/ext-static-analysis/scope_summaries_html.json', 'w').write(json.dumps(combined_scope_summaries))



## add lookup icon to functions
icon = '🔀'
functions = json.loads(open('./.vscode/ext-static-analysis/functions_html.json', 'r').read())
for f in functions:
    if f['id'] in functions_with_lookups and icon not in f['decorator']:
        f['decorator'] = f"{icon}{f['decorator']}"

open('./.vscode/ext-static-analysis/functions_html.json', 'w').write(json.dumps(functions))





