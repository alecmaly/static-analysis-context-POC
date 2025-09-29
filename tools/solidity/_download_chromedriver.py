import subprocess
import json
import requests
import zipfile
import os
from urllib.request import urlopen

def get_chromium_version():
    # Command to get Chromium version
    version_command = "chromium-browser --version"
    try:
        # Execute command
        version_output = subprocess.run(version_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Parse output to get version
        version = version_output.stdout.split()[1]
        return version
    except Exception as e:
        print(f"Error getting Chromium version: {e}")
        return None

def download_webdriver(chromium_version):
    # URL to known good versions JSON
    json_url = 'https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json'
    
    try:
        # Fetch and load JSON data
        with urlopen(json_url) as response:
            data = json.loads(response.read().decode())
        
        # Find matching WebDriver
        for version_info in data['versions']:
            if version_info['version'] == chromium_version:
                for row in version_info['downloads']['chromedriver']:
                    if row['platform'] == "linux64":
                        webdriver_url = row['url']
                break
        else:
            print("Matching WebDriver not found.")
            # return
        
        # Download WebDriver
        webdriver_response = requests.get(webdriver_url)
        webdriver_filename = webdriver_url.split('/')[-1]
        
        # Define a directory to extract the WebDriver (e.g., current directory or a specific path)
        extract_to_dir = "./.vscode"  # Current directory; change as needed
        
        # Save the .zip file locally
        zip_path = os.path.join(extract_to_dir, webdriver_filename)
        with open(zip_path, 'wb') as f:
            f.write(webdriver_response.content)
        
        # Extract the .zip file
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to_dir)
        
        print(f"WebDriver downloaded and extracted to: {extract_to_dir}")
        
        # Optionally, remove the .zip file after extraction
        os.remove(zip_path)
    except Exception as e:
        print(f"Error downloading WebDriver: {e}")

def main():
    chromium_version = get_chromium_version()
    if chromium_version:
        print(f"Current Chromium version: {chromium_version}")
        download_webdriver(chromium_version)
    else:
        print("Failed to get Chromium version.")        


if __name__ == "__main__":
    main()
