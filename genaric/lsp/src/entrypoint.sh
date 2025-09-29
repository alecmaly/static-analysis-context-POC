#!/bin/sh

# solargraph_bin=`find /home/myuser/.local/share/gem/ruby/*/bin -name solargraph 2>/dev/null | rev | cut -d '/' -f 2- | rev` && \
# export PATH=$PATH:$solargraph_bin


# TODO: path does not work on windows, docker cannot mount to C: and source files may end up with different path
# just uses on Ubuntu for now
cat << 'EOF'
 .d8888b.  888             888    d8b                      d8888                   888                   d8b                .d8888b.                    888                     888         8888888b.                                            
d88P  Y88b 888             888    Y8P                     d88888                   888                   Y8P               d88P  Y88b                   888                     888         888   Y88b                                           
Y88b.      888             888                           d88P888                   888                                     888    888                   888                     888         888    888                                           
 "Y888b.   888888  8888b.  888888 888  .d8888b          d88P 888 88888b.   8888b.  888 888  888 .d8888b  888 .d8888b       888         .d88b.  88888b.  888888 .d88b.  888  888 888888      888   d88P 8888b.  888d888 .d8888b   .d88b.  888d888 
    "Y88b. 888        "88b 888    888 d88P"            d88P  888 888 "88b     "88b 888 888  888 88K      888 88K           888        d88""88b 888 "88b 888   d8P  Y8b `Y8bd8P' 888         8888888P"     "88b 888P"   88K      d8P  Y8b 888P"   
      "888 888    .d888888 888    888 888             d88P   888 888  888 .d888888 888 888  888 "Y8888b. 888 "Y8888b.      888    888 888  888 888  888 888   88888888   X88K   888         888       .d888888 888     "Y8888b. 88888888 888     
Y88b  d88P Y88b.  888  888 Y88b.  888 Y88b.          d8888888888 888  888 888  888 888 Y88b 888      X88 888      X88      Y88b  d88P Y88..88P 888  888 Y88b. Y8b.     .d8""8b. Y88b.       888       888  888 888          X88 Y8b.     888     
 "Y8888P"   "Y888 "Y888888  "Y888 888  "Y8888P      d88P     888 888  888 "Y888888 888  "Y88888  88888P' 888  88888P'       "Y8888P"   "Y88P"  888  888  "Y888 "Y8888  888  888  "Y888      888       "Y888888 888      88888P'  "Y8888  888     
                                                                                            888                                                                                                                                                  
                                                                                       Y8b d88P                                                                                                                                                  
                                                                                        "Y88P"                 
EOF
printf "\e[33mby alecmaly.com\e[0m\n\n"


# Check if no arguments are provided
if [ $# -eq 0 ]; then
    printf "\e[0;36m## Step 0: (Optional) Prettify files (should be used if source contains minified files)\e[0m\n"
    echo 'src_dir=`pwd` && docker run --rm -it -v $(pwd):/app/output -v "$src_dir":"$src_dir" alecmaly/sa-tool pprettier --write "src/**/*.{js}"'
    echo ""

    printf "\e[0;36m## [Option 1] Step 1: Parse codebase w/ LSP\e[0m\n"
    echo 'src_dir=`pwd` && docker run --rm -it -p 9999:9999 -v $(pwd):/app/output -v "$src_dir":"$src_dir" alecmaly/sa-tool python3 /app/1_extract_w_lsp.py -d "$src_dir" --streaming-mode -a -l all'
    echo "# in new tab, run next command"
    printf "\e[0;36m## [Option 1] Step 2: Update processing script (in new tab)\e[0m\n"
    echo 'src_dir=`pwd` && docker run --rm -it -v $(pwd):/app/output -v "$src_dir":"$src_dir" alecmaly/sa-tool /bin/bash /app/_process_static_analysis.sh --streaming'
    echo ""
    

    printf "\e[0;36m## [Option 2]Step 1: Parse codebase w/ LSP\e[0m\n"
    echo "# docker run --rm -it alecmaly/sa-tool <TARGET_REPO_URL>"
    echo "# docker run --rm -it alecmaly/sa-tool \"\$(pwd)\""
    # echo "docker run --rm -it alecmaly/sa-tool \"\$((pwd).path.replace('\\', '\\\\\\'))\""
    echo "# docker run --rm -it alecmaly/sa-tool python3 /app/1_extract_w_lsp.py"
    echo ""
    echo 'src_dir=`pwd` && docker run --rm -it -p 5678:5678 -v $(pwd):/app/output -v "$src_dir":"$src_dir" alecmaly/sa-tool python3 /app/1_extract_w_lsp.py -d "$src_dir" -l all'
    echo ""

    printf "\e[0;36m## [Option 2] Step 2: build callstacks\e[0m\n"
    echo "docker run --rm -it -v \$(pwd):/app/output alecmaly/sa-tool python3 /app/2_build_callstacks.py"
    echo ""
    
    printf "\e[0;36m## [Option 2] Step 3: move files to .vscode for extension & add decorators\e[0m\n"
    echo "mkdir -p .vscode/ext-static-analysis/graphs"
    echo "cp ./functions_html.json ./.vscode/ext-static-analysis/functions_html.json"
    echo "cp ./decorations.json ./.vscode/ext-static-analysis/decorations.json"
    echo "cp ./callstacks.json ./.vscode/ext-static-analysis/callstacks.json"
    echo "cp ./scope_summaries_html.json ./.vscode/ext-static-analysis/scope_summaries_html.json"
    echo "cp ./inheritance_graph.json ./.vscode/ext-static-analysis/graphs/inheritance_graph.json"
    echo "docker run --rm -it -v \$(pwd):/app/output alecmaly/sa-tool python3 /app/3_add_decorators.py"
    echo ""
    


    echo ""
    printf "\e[0;36m## Step 4 (Optional): Tooling\e[0m\n"
    echo 'src_dir=`pwd` && docker run --rm -it -v $(pwd):/app/output -v "$src_dir":"$src_dir" alecmaly/sa-tool python3 /app/_search_regex_in_functions.py --help'
    echo "\t# Example: search for string in functions"
    echo 'src_dir=`pwd` && docker run --rm -it -v $(pwd):/app/output -v "$src_dir":"$src_dir" alecmaly/sa-tool python3 /app/_search_regex_in_functions.py -s "UpdraftPlus_Options::user_can_manage'
    echo "\t# Example: add decorator"
    echo 'src_dir=`pwd` && docker run --rm -it -v $(pwd):/app/output -v "$src_dir":"$src_dir" alecmaly/sa-tool python3 /app/_search_regex_in_functions.py -s "(_POST|_REQUEST|_GET)" -ad "💥"'
    echo ""

    printf "\e[0;35m# Detector Tooling\e[0m\n"
    echo 'mkdir -p .vscode/ext-detectors'
    echo ""

    printf "\e[0;36m## Semgrep:\e[0m\n"
    echo 'src_dir=`pwd` && docker run --rm -it -v $(pwd):/app/output -v "$src_dir":"$src_dir" alecmaly/sa-tool semgrep scan --exclude sg-rules --json --config ../sg-rules --config auto --json-output=semgrep.json --no-git-ignore # --include "*.php"'
    echo 'src_dir=`pwd` && docker run --rm -it -v $(pwd):/app/output -v "$src_dir":"$src_dir" alecmaly/sa-tool python3 /app/semgrep-to-detector-results.py -b "$src_dir" '
    echo ""

    printf "\e[0;36m## Grep to Detectors:\e[0m\n"
    echo "\t# Example: adding if and loops to detectors"
    echo 'grep -rnEI --exclude-dir={.vscode,.git,node_modules,.json} "\\bif\\b" . | awk -F: '"'"'{print $1 ":" $2 ":" index($0, $4) ":" substr($0, index($0, $3))}'"'"' > grep-output.txt'
    echo 'src_dir=`pwd` && docker run --rm -it -v $(pwd):/app/output -v "$src_dir":"$src_dir" alecmaly/sa-tool python3 /app/grep-to-detector-results.py -b "$src_dir" -c "grep | if statements" -a'
    echo ""
    echo 'grep -rnEI --exclude-dir={.vscode,.git,node_modules,.json} "\\b(while|for|until|do)\\b" . | awk -F: '"'"'{print $1 ":" $2 ":" index($0, $4) ":" substr($0, index($0, $3))}'"'"' > grep-output.txt'
    echo 'src_dir=`pwd` && docker run --rm -it -v $(pwd):/app/output -v "$src_dir":"$src_dir" alecmaly/sa-tool python3 /app/grep-to-detector-results.py -b "$src_dir" -c "grep | loops" -a'
    echo ""
    echo 'grep -rnEI --exclude-dir={.vscode,.git,node_modules,.json} "\\b(x-)\\b" . | awk -F: '"'"'{print $1 ":" $2 ":" index($0, $4) ":" substr($0, index($0, $3))}'"'"' > grep-output.txt'
    echo 'src_dir=`pwd` && docker run --rm -it -v $(pwd):/app/output -v "$src_dir":"$src_dir" alecmaly/sa-tool python3 /app/grep-to-detector-results.py -b "$src_dir" -c "grep | x-" -a'
    echo ""


elif [ $# -eq 1 ] && [ "$1" != "sh" ] && [ "$1" != "/bin/bash" ] && [ "$1" != "/bin/sh" ]; then
    # Print a hardcoded help message
    # BASE_DOCKER_CMD="docker run alecmaly/sa-tool -v $(pwd):/app "
    echo "Parse codebase with docker:"
    echo "docker run --rm -it alecmaly/sa-tool python3 /app/1_extract_w_lsp.py"
    echo ""
    echo 'src_dir='\'$1\'' && docker run --rm -it -p 5678:5678 -v $(pwd):/app/output -v "$src_dir":"$src_dir" alecmaly/sa-tool python3 /app/1_extract_w_lsp.py -d "$src_dir" -l all'
else
    # Execute the provided command
    exec "$@"
fi
