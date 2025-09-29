import argparse
import requests
import json
import os

TOKENS = {}
TOKENS["etherscan.io"] = "4BVQ9MHEAKBH6KNB6VYWED6J79RP36IXMB"
TOKENS["bscscan.com"] = "E2NJZTRIB8VNMFA9UGSJUN4NFT6K777K6C"
TOKENS["optimistic.etherscan.io"] = "1H4IU4CV592BGSZN1GJ2ZFWQZEK9CF7TDK"
TOKENS["polygonscan.com"] = "FJA9DQJAHV5T9S26MS9JCYFM32J2JH1ARI"
TOKENS["basescan.org"] = "5M5XA1GREP3VIG16MGX4UB7CYEKYCSJ6VF"
TOKENS["arbiscan.io"] = "X17RV8VCMIE8SXRKNV1H4BHT48DI25W78Y"
TOKENS["ftmscan.com"] = "F53JJ1N1644I8JCWFZ38A1RRJGZ7Y7MRQN"
TOKENS["cronoscan.com"] = "5JZQ1MBXN3ZW849CVQGR176KXD3YFNA4V3"


DOMAIN_HOST_MAP = {}
DOMAIN_HOST_MAP["optimistic.etherscan.io"] = "api-optimistic.etherscan.io"

# The provided GetSourceCode function with some modifications
def GetSourceCode(address, DOMAIN, token, download=False, download_root_folder=None):
    HOST = DOMAIN_HOST_MAP.get(DOMAIN, f"api.{DOMAIN}")

    # pad address w/ zero's
    hex_part = address.replace("0x", "")
    address = "0x" + hex_part.zfill(40)

    if not download_root_folder:
        download_root_folder = address

    action = "getsourcecode"
    uri = f"https://{HOST}/api?module=contract&action={action}&address={address}&apikey={token}"
    resp = requests.get(uri)

    source_files = {}
    try:
        for ele in resp.json()['result']:
            try:
                try:
                    sources = json.loads(ele['SourceCode'][1:-1])['sources']
                except:
                    sources = json.loads(ele['SourceCode'])
                    
                for source_file in sources:
                    source_files[source_file] = sources[source_file]['content']
            except:
                source_files['flattened'] = ele['SourceCode']

        # download
        if download:
            for filepath in source_files.keys():
                source_code = source_files[filepath]
                os.makedirs(f"./{download_root_folder}/{'/'.join(filepath.split('/')[:-1])}", exist_ok=True)
                open(f"./{download_root_folder}/{filepath}", "w", encoding="utf-8").write(source_code)
    except Exception as e:
        print("failed to get source files / download", e)

    return resp.json()['result']

# Main part of the script to handle command-line arguments
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Download source code from a given address and domain.')

    parser.add_argument('DOMAIN', type=str, help='The domain to use')
    parser.add_argument('addresses', type=str, help='The address to query')
    parser.add_argument('--download_root_folder', "-f", type=str, help='The root folder for downloading')

    args = parser.parse_args()

    # Assuming DOMAIN_HOST_MAP is defined somewhere in the script
    DOMAIN_HOST_MAP = {'example.com': 'api.example.com'} # Replace with actual values

    TOKEN = TOKENS.get(args.DOMAIN)
    if TOKEN:
        for address in args.addresses.split(","):
            address = address.strip()
            GetSourceCode(address, args.DOMAIN, TOKEN, True, args.download_root_folder)
