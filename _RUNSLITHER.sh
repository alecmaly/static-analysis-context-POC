## find solidity version in all files in scope (quickly identify proper solc version)
# find ./src/contracts -name "*.sol" -exec grep 'pragma' {} \; | sort | uniq

src_dir=$(find . -maxdepth 1 -type d \( -name "src" -o -name "contracts" \) -exec basename {} \;)


mkdir -p .vscode/ext-slither-cache
mkdir -p .vscode/ext-static-analysis/graphs
mkdir -p .vscode/ext-detectors
mkdir -p slither_summary_output

# copy search templates for VS code Static Analysis extension
cp ~/Desktop/static-analysis-context-POC/genaric/vscode-static-analysis-extension/assets/search_templates.json ./.vscode/ext-static-analysis/search_templates.json

## STEP 1: Run address lookup script
# python3 ~/Desktop/static-analysis-context-POC/tools/solidity/_download_chromedriver.py
# chmod +x ./.vscode/chromedriver-linux64/chromedriver
python3 ~/Desktop/static-analysis-context-POC/tools/solidity/getContractAtAddressofNetwork.py -t "./$src_dir" # | tee ./.vscode/_addressLookup.txt


## Step 2: get dependeencies
# slither . --detect CD--Dependencies --ignore-compile

## Step 3: remove test contracts
# find . -type f -name "*.t.sol" -exec sh -c 'mv "$0" "${0}.bak"' {} \;


## STEP 4: run slither, compile project
find ./$src_dir -type f | grep -Eiv "(test|mock|interface)" | sed "s#^\./##g" | tee scope.txt
include_paths="($(cat scope.txt | tr '\n' '|' | sed 's/|$//g'))"
# include_paths="(test.sol)" 
# filter_paths="(dev/|script/|scripts/|interfaces/|mocks/|test/|cache/|audits/|artifacts/|lib/|node_modules/|misc/|deployments/)"

rm detector-results.json 2>/dev/null
# --ignore-compile because it should be compiled from slither-doctor
# slither . --filter-paths "$filter_paths" --json detector-results.json --ignore-compile # --compile-force-framework hardhat
slither . --include-paths "$include_paths" --json detector-results.json --ignore-compile --exclude CD--Dependencies --detect CD--TaintedVariableUsed_rollup # --solc-remaps "@=node_modules/@ tapioca-sdk=node_modules/tapioca-sdk"  # --compile-force-framework hardhat
# jq cmd + move into .vscode
jq '.results.detectors' detector-results.json > ./.vscode/detector-results.json
jq '.results.detectors' detector-results.json > ./.vscode/detector-results.json.bak


python3 ~/Desktop/static-analysis-context-POC/custom_detectors/minimize_slither-results.py # minimize detector-results.json for use in VS Code slither extension
python3 ~/Desktop/static-analysis-context-POC/custom_detectors/combine_slither_vscode.py  # combine output from custom sliter detector for use in VS Code function summary extension
python3 ~/Desktop/static-analysis-context-POC/tools/solidity/_scope_summaries_to_html.py # consolidate scope summaries .html
cat ./.vscode/_scope_summaries.html |grep -oE ">[^<]*?\.[^<]*? = " | rev | cut -d'.' -f1 | rev | sort | uniq -c | sort -nr | tee ./.vscode/_parameter_counts.txt
python3 ~/Desktop/static-analysis-context-POC/tools/solidity/_getInterestingAccessControlFunctions.py | tee ./.vscode/_interestingAccessControlFunctions.txt
python3 ~/Desktop/static-analysis-context-POC/tools/solidity/_scope_frontrunninig.py | tee ./.vscode/_frontrunning.txt
python3 ~/Desktop/static-analysis-context-POC/tools/solidity/_similar_functions.py | tee ./.vscode/_similar_functions.txt
python3 ~/Desktop/static-analysis-context-POC/_analyze_state_vars_in_callstacks.py | tee ./.vscode/_similar_functions_by_state_var_callstacks.txt
python3 ~/Desktop/static-analysis-context-POC/tools/solidity/_buildInheritanceGraphsFromScopeSummaries.py



rm detector-results.json 2>/dev/null
# --ignore-compile because it should be compiled from slither-doctor
# slither . --filter-paths "$filter_paths" --json detector-results.json --ignore-compile # --compile-force-framework hardhat
slither . --include-paths "$include_paths" --json detector-results.json --ignore-compile --exclude CD--Dependencies # --solc-remaps "@=node_modules/@ tapioca-sdk=node_modules/tapioca-sdk"  # --compile-force-framework hardhat
# jq cmd + move into .vscode
jq '.results.detectors' detector-results.json > ./.vscode/ext-detectors/detector-results.json




## STEP 5: restore test files
# find . -type f -name "*.t.sol.bak" -exec sh -c 'mv "$0" "${0%.bak}"' {} \;



## STEP 6: Get function relationships
# slither . --filter-paths "$filter_paths" --detect CD--InterestingFunctionCallChain --ignore-compile | tee relationships.txt # --compile-force-framework hardhat
# slither . --include-paths "$include_paths" --detect CD--InterestingFunctionCallChain --ignore-compile | tee relationships.txt 


## STEP 7: run slither-summary #### (OLD - if only using for inheritance graph - already done w/ slither)
# ~/Desktop/static-analysis-context-POC/tools/slither-summary.sh "$filter_paths"


## STEP 8: run process-function-summary.py ?     ### ???
cd slither_summary_output
python3 ~/Desktop/static-analysis-context-POC/tools/process-function-summary.py





### COPY DEPENDENCIES
# new_root="../../../../"
# output_dir="${new_root}output"
# pushd .; mkdir $output_dir; cd $output_dir; forge init; popd;
# python3 ~/Desktop/static-analysis-context-POC/tools/solidity/_copyDependencies.py -o $output_dir "~/Desktop/cantina/blast/blast-optimism/packages/contracts-bedrock/src/L2/Blast.sol"
# code $output_dir



### TOOLS
# python3 ~/Desktop/static-analysis-context-POC/tools/_search_regex_in_functions.py -s "UpdraftPlus_Options::user_can_manage"
# python3 ~/Desktop/static-analysis-context-POC/tools/_search_regex_in_functions.py -s "(_POST|_REQUEST|_GET)" -ad "💥"


