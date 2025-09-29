import json
import uuid
import os
import argparse
import debugpy
import myfunctions

parser = argparse.ArgumentParser(description='Convert grep output to detector results')
parser.add_argument('--description', '-d', type=str, help='Description of the detector results', default="")
parser.add_argument('--check', '-c', type=str, help='Check of the detector results', required=True)
parser.add_argument('--title', '-t', type=str, help='Title of the detector results', default='testing')
parser.add_argument('--impact', '-i', type=str, help='Impact of the detector results', default='Informational', choices=['Informational', 'Low', 'Medium', 'High', 'Critical', 'i', 'l', 'm', 'h', 'c'])
parser.add_argument('--confidence', '-co', type=str, help='Confidence of the detector results', default='Low', choices=['Low', 'Medium', 'High', 'l', 'm', 'h'])
parser.add_argument('--append-to-detector-resluts', '-a', action='store_true', help='Append to existing detector results')
parser.add_argument('--base-dir', '-b', type=str, help='Base directory of the project', default=os.getcwd())
parser.add_argument('--debug', '-de', action='store_true', help='Debug mode')
args = parser.parse_args()

if args.debug:
    debugpy.listen(5678)
    print("Waiting for debugger attach")
    debugpy.wait_for_client()



# grep -rnEI --exclude-dir={.git,node_modules} "Module2" . | awk -F: '{print $1 ":" $2 ":" index($0, $4)}' > grep-output.txt


impact_confidence_map = {
    'i': 'Informational',
    'l': 'Low',
    'm': 'Medium',
    'h': 'High',
    'c': 'Critical'
}
args.impact = impact_confidence_map[args.impact] if args.impact in impact_confidence_map else args.impact
args.confidence = impact_confidence_map[args.confidence] if args.confidence in impact_confidence_map else args.confidence





# grep -rinHE "(sqrtp.*tick|tick.*sqrtp)" . |cut -d':' -f1-2 |grep "\.sol:" > grep-output.txt
ignore_paths = ['mock/', 'mocks/', 'test/', 'interfaces/', 'lib/', 'libraries/', 'intf/', 'audits/', 'dependencies/', 'packages/']
keep_paths = [] # ['bridge', 'vault', 'stake']


detectors = []
for line in open('grep-output.txt', 'r').readlines():
    try:
        line = line.strip()
        filepath = line.split(':')[0]
        line_num = line.split(':')[1]
        col = line.split(':')[2]

        content = ":".join(line.split(':')[3:]).strip()
        print("line", content)

        abs_path = os.path.join(args.base_dir, filepath.replace("./", ""))



        print(abs_path, line_num, col)
        f = myfunctions.get_function(abs_path, int(line_num))
        
        f_str = f"{f.get('scopeName', '')}.{f.get('functionName', '')} | {f.get('decorators', '')}" if f else filepath.split("/")[-1]

        if any([ignore_path in filepath.lower() for ignore_path in ignore_paths]):
            continue
        
        # skip if not desired path
        if len(keep_paths) > 0:
            if not any([keep_path in filepath.lower() for keep_path in keep_paths]):
                continue

        relative_filepath = filepath.replace('./', '')


        ele = {
            "elements": [
            {
                "type": "function",
                "name": "constructor",
                "source_mapping": {
                    "filename_relative": f"{relative_filepath}",
                    "filename_absolute": f"{args.base_dir}/{relative_filepath}",
                    "filename_short": f"{relative_filepath}",
                    "lines": [
                        int(line_num)
                    ],
                    "starting_column": int(col),
                    "ending_column": int(col)
                }
            }
            ],
            "description": f"{f_str} | {line_num.zfill(4)}: {content} | {args.description}",
            "id": f"{str(uuid.uuid4())}",
            "first_markdown_element": f"{relative_filepath}#L{line_num}",
            "check": f"{args.check}",
            "impact": args.impact,
            "confidence": args.confidence
        }
        detectors.append(ele)
        # print(ele)

        # print(f"{relative_filepath}#L{line}")
    except Exception as e:
        print(f'fail: {line} ...', e)


# print(detectors)

## TODO: args for custom name, etc.


if not os.path.exists('./.vscode/ext-detectors'):
    os.makedirs('./.vscode/ext-detectors')


output_file = f'./.vscode/ext-detectors/detector-results.json'
if args.append_to_detector_resluts and os.path.exists(output_file):
    existing_detectors = json.loads(open(output_file, 'r').read())
    existing_detectors.extend(detectors)
    detectors = existing_detectors



open(output_file, 'w').write(json.dumps(detectors))