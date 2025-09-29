###
### Recursively iterates over target folder, adding comment with address lookup location from: https://blockscan.com/address
###
### Usage: 
### python3 "~/Desktop/static-analysis-context-POC/tools/getContractAtAddressofNetwork.py" -t "~/Desktop/code4rena/2023-03-neotokyo/contracts"


import os
import re
import argparse
import json
import pyperclip
import subprocess

# https://blockscan.com/address/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48

def add_chain_address_comments(target_folder, address_file, chain = None):
    # Define the regular expression pattern to match
    pattern = re.compile(r'0x[a-fA-F0-9]{40}(?![a-fA-F0-9])')

    valid_file_extensions = ('.js', '.sol')
    excluded_file_extensions = ('.t.sol')

    # Load the address details from the JSON file
    addr_details = {}
    addr_file_exists = False
    if os.path.exists(address_file):
        addr_file_exists = True
        addr_details = json.loads(open(address_file, 'r').read())
        address_file_f = open("./.vscode/_addressLookup.txt", 'w')

    addresses = set()
    # Iterate through all files in the target folder recursively
    for root, dirs, files in os.walk(target_folder):
        files = [f for f in files if f.endswith(valid_file_extensions) and not f.endswith(excluded_file_extensions)]
        for file in files:
            if "test" in os.path.join(root, file):
                continue
            
            # Open each file for reading and writing
            with open(os.path.join(root, file), 'r+') as f:
                # Read each line in the file
                lines = f.readlines()
                f.seek(0)  # Reset file pointer to start of file
                
                # Iterate through each line in the file
                line_num = 1
                for line in lines:
                    # Check if the line contains the regex pattern
                    match = pattern.search(line)
                    if match:
                        # If the line matches, append the blockchain information to the end of the line
                        addr = match.group(0)
                        addresses.add(addr)
                        # comment = get_blockscan_text(addr, chain)
                        comment = addr_details.get(addr, None)

                        if addr_file_exists:
                            line = line.rstrip('\n')
                            line += f' // LOOKUP_ADDR > {comment}\n'

                        if addr_file_exists:
                            address_file_f.write(f'## {os.path.join(root, file)}#{line_num}\n')
                            address_file_f.write(line.rstrip('\n') + "\n")
                    # Write the modified line back to the file
                        
                    f.write(line)
                    line_num += 1

                f.truncate()  # Remove any remaining content from the file
    return addresses


if __name__ == '__main__':
    # Define the command line arguments
    parser = argparse.ArgumentParser(description='Add blockchain information to Ethereum address comments in Solidity files.')
    parser.add_argument('-t', '--target_folder', required=True, type=str, help='The target folder to search for Solidity files.')
    parser.add_argument('-b', '--blockchain', required=False, type=str, help='The blockchain network to add to the comments. Defaults to all networks.')
    parser.add_argument('-af', '--address-file', default="./.vscode/addr_details.json", required=False, type=str, help='The blockchain network to add to the comments. Defaults to all networks.')

    # Parse the command line arguments
    args = parser.parse_args()

    if os.path.exists(args.address_file):
        os.remove(args.address_file)
    # Call the function to add blockchain information to matching lines in all files in the target folder
    addresses = add_chain_address_comments(args.target_folder, args.address_file, args.blockchain)

    if len(addresses) == 0:
        print("No addresses found in the target folder.")
        exit(0)

    code = f"""
// https://blockscan.com

let addresses = ['{"', '".join(addresses)}']
""" + '''

async function fetchAddressDetails(addresses) {
    const detailsMap = new Map(); // Use a Map to store address details

    // Map each address to a fetch operation
    const fetchPromises = addresses.map(async (address) => {
        try {
            const response = await fetch(`https://blockscan.com/address/${address}`);
            const html = await response.text();
            const el = document.createElement('div');
            el.innerHTML = html;
            const details = extract_detail(el); // Extract the details for the address
            detailsMap.set(address, details); // Add the details to the Map
        } catch (error) {
            console.error(`Error fetching details for address ${address}:`, error);
            detailsMap.set(address, 'Error fetching details'); // Handle errors for each address individually
        }
    });

    // Wait for all fetch operations to complete
    await Promise.all(fetchPromises);

    // Convert the Map to a JSON object for serialization
    const mapToJson = Object.fromEntries(detailsMap);
    const jsonString = JSON.stringify(mapToJson, null, 2); // Pretty print the JSON

    // Copy the JSON string to the clipboard
    console.log(jsonString)
    try {
        await navigator.clipboard.writeText(jsonString);
        console.log("JSON copied to clipboard successfully.");
    } catch (err) {
        console.error("Failed to copy JSON to clipboard:", err);
    }
}

function extract_detail(el, chain = undefined) {
    // let text = "";
    // const searchResults = el.querySelectorAll('.search-result');
    
    // searchResults.forEach(resultEle => {
    //     const chainProviderTitle = resultEle.querySelector('.search-result-title').textContent.trim();
    //     const badges = Array.from(el.querySelectorAll('.badge'))
    //                         .filter(badge => badge.textContent.trim() !== "Testnet")
    //                         .map(badge => badge.textContent.trim());
        
    //     if (badges.length < 2) return; // Skip if fewer than 2 badges
    
    //     const badgesText = badges.join(", ");
    //     const output = (!chain || badges.includes(chain)) ? `${chainProviderTitle} (${badgesText}) || ` : '';
    //     text += output;

    //     return text
    // });
    const name = el.querySelector('h1').innerText

    const explorers = !el.querySelector('[aria-labelledby="dropdownChainExplorers"]') ? [] : Array.from(el.querySelector('[aria-labelledby="dropdownChainExplorers"]').querySelector('ul').children).map(row => { return row.textContent.trim() }).filter(row => { return !row.includes("Explorers") })
    const chains = Array.from(el.querySelectorAll('.js-chain')).map(chain => { return chain.textContent.trim().replaceAll("\\n", "").replace("$", " $") }).filter(chain => { return !chain.includes("(0)") })


    const badges = Array.from(el.querySelector('section').children[0].children[1].querySelectorAll('.badge'))
                            .filter(badge => !badge.textContent.includes("unread messages") && !["Testnet", "Explorers", "Website", "Twitter", "More"].includes(badge.textContent.trim()))
                            .map(badge => badge.textContent.trim());
        
    const badgesText = badges.join(", ");
    
    return (!chain || badges.includes(chain)) ? `${name} (${badgesText}) > chains: ${chains.join(" | ")}` : '';
}


fetchAddressDetails(addresses)
    .then(jsonResult => console.log(jsonResult))
    .catch(error => console.error("Error fetching address details:", error));

'''



    
    pyperclip.copy(code)
    # print(code)
    print(f"open chrome and paste script: https://blockscan.com/")
    print(f"copy json output to address file: {args.address_file}")

    open(args.address_file, 'w').write("")
    subprocess.run(['code', args.address_file])


    input("Press Enter to continue...")
    add_chain_address_comments(args.target_folder, args.address_file, args.blockchain)
        
    
