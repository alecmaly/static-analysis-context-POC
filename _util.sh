# add to .bashrc

function update_echidna_and_medusa() {
    pushd .
    cd /tmp

    # user defined variables
    destination_path="~/.local/bin" # should be in PATH
    
    # local vars
    tmp_filename="output.tar.gz"
    
    # Define associative array with repo keys and filename_regex values
    declare -A repos=( ["crytic/echidna"]="linux.tar.gz$" ["crytic/medusa"]="medusa-linux-x64.tar.gz" )
    
    # Loop through associative array
    for repo in "${!repos[@]}"; do
        filename_regex="${repos[$repo]}"
        
        # Fetch the latest release file URL using GitHub API
        file_url=$(curl -s "https://api.github.com/repos/$repo/releases/latest" | jq --arg filename_regex "$filename_regex" -r '.assets[] | select(.name | test($filename_regex)).browser_download_url')
        
        if [ ! -z "$file_url" ]; then
            echo "Downloading and extracting $repo..."
            
            # Download, extract, and clean up
            wget -O "$tmp_filename" "$file_url"
            tar -xvf "$tmp_filename"
            rm "$tmp_filename"
            
            # Move to destination path
            # Determine the executable name from repo for moving
            executable_name=$(echo "$repo" | awk -F '/' '{print $2}')
            mv "$executable_name"* "$destination_path" -f
        else
            echo "No matching release found for $repo."
        fi
    done

    echidna --version
    medusa --version

    popd
}

function cpslither() {
    cp ~/Desktop/static-analysis-context-POC/_RUNSLITHER.sh .
}

function cpsa() {
    cp ~/Desktop/static-analysis-context-POC/genaric/lsp/_RUNSTATICANALYSIS.sh .
}


function init_web3_fuzz() {
    git init

    forge install foundry-rs/forge-std --no-commit &
    forge install Recon-Fuzz/chimera --no-commit &
    forge install crytic/properties --no-commit &
    forge install immunefi-team/forge-poc-templates --no-commit &

    wait

    # git clone https://github.com/Recon-Fuzz/create-chimera-app.git /tmp/create-chimera-app
    # cp -r /tmp/create-chimera-app/test .

    mkdir -p test
    cp -r ~/Desktop/static-analysis-context-POC/solidity/fuzzing/recon ./test


    cat <<EOF > foundry.toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
no_match_contract = "CryticTester"

evm_version = 'shanghai'

# # Ankr RPC endpoints (https://www.ankr.com/rpc/)
# [rpc_endpoints]
# eth = "${ETH_RPC_URL}"
# gnosis = "${GNOSIS_RPC_URL}"
# polygon = "${POLYGON_RPC_URL}"

# local examples
# ~/Desktop/static-analysis-context-POC/solidity/fuzzing




# See more config options https://github.com/foundry-rs/foundry/blob/master/crates/config/README.md#all-options
EOF


    cat <<EOF > remappings.txt
forge-std/=lib/forge-std/src/
@chimera/=lib/chimera/src/
@forge-poc-templates=lib/forge-poc-templates/src/
@crytic_properties=lib/properties/contracts/
EOF



    # mkdir -p test
    # cp -r ~/Desktop/static-analysis-context-POC/solidity/fuzzing ./test
    # find ./test -type f -name "*.t.sol" -exec sh -c 'mv "$0" "${0}.bak"' {} \;

    # echidna & medusa configs
    cp ~/Desktop/static-analysis-context-POC/solidity/fuzzing/echidna/echidna.yml .
    wget https://raw.githubusercontent.com/Recon-Fuzz/create-chimera-app/main/medusa.json -O medusa.json 
}