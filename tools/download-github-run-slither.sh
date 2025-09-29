#!/bin/bash

github_url=$1


github_url="https://github.com/IPOR-Labs/ipor-power-tokens"

### STEP 1: Download github repo
git clone "$github_url"

repo_dir=`echo "$github_url" | rev | cut -d'/' -f1 | rev`
cd $repo_dir

# has solidity files
sol_files=`find . -name "*.sol" | grep -v test`


echo $sol_files

if [ ! -z "$sol_files" ]; then
    # does not have has .sol files, stop

    # STEP 2: install dependencies
    yarn
    foundryup
    make

    ## STEP 3: Run slither doctor (compiile)
    # solc,truffle,embark,dapp,etherlime,etherscan,vyper,waffle,brownie,solc-json,buidler,hardhat,foundry,standard,archive

    # check if current directory contains hardhat config file
    if [ -e hardhat.config.js ] || [ -e hardhat.config.ts ]; then
        # The current directory contains a hardhat.config.js file
        slither_args=" --compile-force-framework hardhat"
    else
        slither_args=""
    fi

    slither-doctor . $slither_args




    # ## STEP 4: Run slither (--ignore-compile)
    # filter_paths="(interfaces/|mocks/|test/|cache/|audits/|artifacts/|lib/|node_modules/)"

    # rm detector-results.json 2>/dev/null
    # # --ignore-compile because it should be compiled from slither-doctor
    # slither . --filter-paths "$filter_paths" --json detector-results.json --ignore-compile $slither_args # --compile-force-framework hardhat
    # # jq cmd + move into .vscode
    # mkdir -p .vscode
    # mkdir -p "../slither_results/$repo_dir"
    # jq '.results.detectors' detector-results.json > ./.vscode/detector-results.json
    # jq '.results.detectors' detector-results.json > "../slither_results/$repo_dir/detector-results.json"

elif
    # remove repo
    cd ".."
    rm -rf "./$repo_dir"
fi
