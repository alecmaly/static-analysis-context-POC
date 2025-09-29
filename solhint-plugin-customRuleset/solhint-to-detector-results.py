import json
import uuid

### To run:
# solhint `find ./wormhole -name "*.sol" -type f` -c .solhint.json -f unix -c |tee solhint_output.txt
# python3 solhint-to-slither-results.py


# [
#   {
#     "elements": [
#       {
#         "type": "function",
#         "name": "constructor",
#         "source_mapping": {
#           "filename_relative": "solidity_test_files/test2.sol",
#           "filename_absolute": "~/Desktop/static-analysis-context-POC/solidity_test_files/test2.sol",
#           "filename_short": "solidity_test_files/test2.sol",
#           "lines": [
#             89,
#             90
#           ],
#           "starting_column": 5,
#           "ending_column": 6
#         }
#       }
#     ],
#     "description": "~ testContract.constructor | P  >  (0) tainted vars in testContract.constructor() (solidity_test_files/test2.sol#89-90)",
#     "markdown": "~ testContract.constructor | P  >  (0) tainted vars in [testContract.constructor()](solidity_test_files/test2.sol#L89-L90)",
#     "first_markdown_element": "solidity_test_files/test2.sol#L89-L90",
#     "id": "0b0b005f5a5b9d63b8506f5d38f11f81dcd688a2aef94a9a26dacd73e5c53420",
#     "check": "CD--TaintedVariableUsed_rollup",
#     "impact": "Informational",
#     "confidence": "Medium"
#   }
# ]

solhint_to_slither_detector_mapping = {
    'unchecked-block': 'CD--ComplexUncheckedBlock',
    'explicit-cast': 'var-read-using-this',
    'interesting-functions-and-parameters': 'CD--InterestingFunctionCallsAndParameterUsage',
    'check-return-value': 'CD--ReturnValueNotUsed'
}


ignore_paths = ['mock/', 'mocks/', 'test/', 'interfaces/', 'lib/', 'libraries/', 'intf/', 'audits/', 'dependencies/', 'packages/']
keep_paths = ['bridge', 'vault', 'stake']


detectors = []
for line in open('solhint_output.txt', 'r').readlines():
    try:
        line = line.strip()
        # print(line)
        filepath = line.split(':')[0].strip()
        line_num = line.split(':')[1].strip()
        col = line.split(':')[2].strip()
        details = ":".join(line.split(':')[2:])
        # print(details)

        if any([ignore_path in filepath.lower() for ignore_path in ignore_paths]):
            continue
        
        # skip if not desired path
        if len(keep_paths) > 0:
            if not any([keep_path in filepath.lower() for keep_path in keep_paths]):
                continue

        detection = details.split('/')[-1].replace(']', '').strip()
        # print(detection)
        slither_detector = solhint_to_slither_detector_mapping[detection]

        relative_filepath = filepath.replace('./', '')


        ele = {
            "elements": [
            {
                "type": "function",
                "name": "constructor",
                "source_mapping": {
                    "filename_relative": f"{relative_filepath}",
                    "filename_absolute": f"~/Desktop/immunify/all/{relative_filepath}",
                    "filename_short": f"{relative_filepath}",
                    "lines": [
                        int(line_num)
                    ],
                    "starting_column": int(col),
                    "ending_column": int(col)
                }
            }
            ],
            "description": f"{relative_filepath}#L{line_num} : {details}",
            "id": f"{str(uuid.uuid4())}",
            "first_markdown_element": f"{relative_filepath}#L{line_num}",
            "check": f"{slither_detector}",
            "impact": "Informational",
            "confidence": "Medium"
        }
        detectors.append(ele)
        # print(ele)

        # print(f"{relative_filepath}#L{line}")
    except Exception as e:
        print('fail: ', e)


# print(detectors)
open('./.vscode/detector-results.json', 'w').write(json.dumps(detectors))