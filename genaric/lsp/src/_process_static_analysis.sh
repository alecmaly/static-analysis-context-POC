#!/bin/bash

# if $1 == "--streaming"


function process() {
    python3 /app/2_build_callstacks.py

    output_file_prefix="./.vscode/ext-static-analysis/cache"
    # TODO: keep notes and decorators in current files

    mkdir -p "./.vscode/ext-static-analysis/graphs"
    mkdir -p $output_file_prefix
    cp $output_file_prefix/functions_html.json "./.vscode/ext-static-analysis/functions_html.json"
    cp $output_file_prefix/decorations.json "./.vscode/ext-static-analysis/decorations.json"
    cp $output_file_prefix/callstacks.json "./.vscode/ext-static-analysis/callstacks.json"
    cp $output_file_prefix/scope_summaries_html.json "./.vscode/ext-static-analysis/scope_summaries_html.json"
    cp $output_file_prefix/inheritance_graph.json "./.vscode/ext-static-analysis/graphs/inheritance_graph.json"
    python3 /app/3_add_decorators.py
}


if [ "$1" == "--streaming" ]; then
    echo "Running in streaming mode..."
    while true; do
        # if file ./.vscode/ext-static-analysis/_updated_data.state exists, then run process
        if [ -f "./.vscode/ext-static-analysis/_updated_data.state" ]; then
            rm "./.vscode/ext-static-analysis/_updated_data.state"
            process
            # change permissions to allow vscode to read/write the files
            # NOTE: This allows files to be read by any user on the filesystem, share use with caution with shared environments or in directories with sensitive data
            chmod -R 777 "./.vscode/ext-static-analysis"

            touch "./.vscode/ext-static-analysis/_reload_ready.state"
        fi

        sleep 5
    done
    exit 1
fi


process

