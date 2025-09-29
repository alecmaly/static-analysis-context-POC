import os
import json
import uuid
import myfunctions
import argparse
import debugpy

# TODO: take in scope and out of scope regex params, add unicode

parser = argparse.ArgumentParser(description='Convert semgrep output to detector results')
parser.add_argument('--append-to-detector-resluts', '-a', action='store_true', help='Append to existing detector results')
parser.add_argument('--base-dir', '-b', type=str, help='Base directory of the project', default=os.getcwd())
parser.add_argument('--debug', '-de', action='store_true', help='Debug mode')
args = parser.parse_args()

if args.debug:
    debugpy.listen(5678)
    print("Waiting for debugger attach")
    debugpy.wait_for_client()



functions_filepath = './.vscode/ext-static-analysis/functions_html.json'
functions_map = {}
if os.path.exists(functions_filepath):
    functions = json.loads(open(functions_filepath, 'r').read())
    for f in functions:
        functions_map.setdefault(f['filepath'].split("#")[0], []).append(f)


# given file path and line number, return function
def get_function(filepath, line):
    for f in functions_map.get(filepath, []):
        if f['filepath'].split('#')[0] == filepath and f['startLine'] <= line and f['endLine'] >= line:
            f_str = ""
            if 'scopeName' in f:
                f_str = f"{f['scopeName']}."
            return f"{f_str}{f['functionName']}"
    return ""



data = json.loads(open('semgrep.json', 'r').read())




# get current directory pwd

def translate_impact(severity):
    if severity == "ERROR":
        return "High"
    elif severity == "WARNING":
        return "Medium"
    elif severity == "INFO":
        return "Informational"
    else:
        return "Low"

results = []
for i, result in enumerate(data['results']):

    if result['extra']['metadata'].get('category', 'security') != "security":
        print("skipping: ", result['extra']['metadata'].get('category') )
        continue
    
    impact = translate_impact(result['extra']['severity'])

    end_column = result['end']['col'] if result['end']['line'] == result['start']['line'] else 999

    f = myfunctions.get_function(os.path.join(args.base_dir, result['path']), result['start']['line'])
    f_str = f"{f.get('scopeName', '')}.{f.get('functionName', '')} | {f.get('decorator', '')}" if f else ""

    
    obj = {
        "id": uuid.uuid4().hex,
        "check": result['check_id'],
        "description": f"{f_str if f_str else result['path'].split('/')[-1]} | {result['extra']['lines'].strip()}\n\n{result['extra']['message']}",
        "impact": impact,
        "confidence": result['extra']['metadata'].get('confidence', "ERROR"),
        "elements": [
            {
                "source_mapping": {
                    "filename_relative": result['path'],
                    "starting_column": result['start']['col'],
                    "ending_column": result['end']['col'],
                    "lines": [
                        result['start']['line'],
                        result['end']['line']
                    ]
                }

            }
        ]
    }

    results.append(obj)

    if i % 500 == 0:
        print(i, " / ", len(data['results']))



output_filepath = './.vscode/ext-detectors/detector-results.json'

if args.append_to_detector_resluts and os.path.exists(output_filepath):
    if os.path.exists(output_filepath):
        existing = json.loads(open(output_filepath, 'r').read())
        results = existing + results

# create directory if not exists
if not os.path.exists('./.vscode/ext-detectors'):
    os.makedirs('./.vscode/ext-detectors')

open(output_filepath, 'w').write(json.dumps(results))