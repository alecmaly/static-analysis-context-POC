import argparse
import json
import os
import shutil
from pathlib import Path

def load_imports(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def copy_file(source_path, dest_path):
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    shutil.copy(source_path, dest_path)

def process_file(file_path, dependencies, output_dir, processed_files, base_path):
    if file_path in processed_files:
        return
    processed_files.add(file_path)

    # Ensure output file path is based on the relative path from base_path to file_path
    relative_path = os.path.relpath(file_path, base_path)
    output_file_path = os.path.join(output_dir, relative_path)
    if os.path.exists(file_path):
        print(f"[+] Copying {file_path} to {output_file_path}")
        copy_file(file_path, output_file_path)
    else:
        print(f"[!] File not found: {file_path}")

    # Recursively process each dependency
    print(f"[+] Processing {file_path}")
    for source in dependencies:
        if source == file_path or source.endswith(file_path.replace("./", "")):
            for dependency in dependencies[source]:
                if not os.path.isabs(dependency):
                    dependency = os.path.join(base_path, dependency)

                process_file(dependency, dependencies, output_dir, processed_files, base_path)

def main():

    parser = argparse.ArgumentParser(description='Process Solidity files based on pre-parsed dependencies.')
    parser.add_argument('file_path', type=str, help='The Solidity file to process.')
    parser.add_argument('-o', '--output_dir', type=str, default='.', help='Output directory for processed files.')
    parser.add_argument('-d', '--dependencies_file', type=str, default='./.vscode/source_import_tuples.json', help='Path to source_import_tuples.json file.')

    args = parser.parse_args()

    dependencies = load_imports(args.dependencies_file)
    processed_files = set()
    # Use the directory of the file_path as the base path for relative dependencies
    # base_path = os.path.dirname(os.path.curdir)
    process_file(args.file_path, dependencies, args.output_dir, processed_files, ".")

if __name__ == "__main__":
    main()
