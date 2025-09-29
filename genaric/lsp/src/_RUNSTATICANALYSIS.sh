# root="~/Desktop/static-analysis-context-POC/genaric/lsp"
cd ~/Desktop/static-analysis-context-POC/genaric/lsp


# alec@alec-VirtualBox:~/.vscode/extensions/ms-vscode.cpptools-1.21.6-linux-x64/bin$ ls -la cpptools-srv 
# -rwxrwxr-x 1 alec alec 23584720 Aug  5 21:39 cpptools-srv




# python3 ~/Desktop/static-analysis-context-POC/genaric/lsp/1_extract_w_lsp.py -d ~/Desktop/projects/java -l java
# python3 ~/Desktop/static-analysis-context-POC/genaric/lsp/1_extract_w_lsp.py -d /home/alec/Desktop/projects/c/httpd/modules/mappers/mod_rewrite.c -l c
# python3 ~/Desktop/static-analysis-context-POC/genaric/lsp/1_extract_w_lsp.py -d "~/Desktop/projects/javascript/tmp" -l typescript # --debug
python3 ~/Desktop/static-analysis-context-POC/genaric/lsp/1_extract_w_lsp.py -d "/home/alec/Desktop/projects/php/updraftplus/methods" -l php
# python3 ~/Desktop/static-analysis-context-POC/genaric/lsp/1_extract_w_lsp.py -d "~/Desktop/projects/go/example/hello" -l go 
# python3 ~/Desktop/static-analysis-context-POC/genaric/lsp/1_extract_w_lsp.py -d "~/Desktop/static-analysis-context-POC/genaric/lsp/1_extract_w_lsp.py" -l python
# python3 ~/Desktop/static-analysis-context-POC/genaric/lsp/1_extract_w_lsp.py -d "~/Desktop/projects/python/django-starter-project/apps" -l python
# python3 ~/Desktop/static-analysis-context-POC/genaric/lsp/1_extract_w_lsp.py -d "~/Desktop/projects/go/example/hello" -l go -v
# python3 ~/Desktop/static-analysis-context-POC/genaric/lsp/1_extract_w_lsp.py -d "~/Desktop/projects/vim-with-me/examples/v2/td" -l go 

# python3 ~/Desktop/static-analysis-context-POC/genaric/lsp/1_extract_w_lsp.py -d "~/Desktop/projects/vim-with-me/examples/v2/td" -l solidity

python3 ~/Desktop/static-analysis-context-POC/genaric/lsp/src/2_build_callstacks.py -iall "(/includes/|/vendor/|log,|/methods/)" -ak "(/includes/updraft|backup-module\.php)" -n 50
# python3 ~/Desktop/static-analysis-context-POC/genaric/lsp/src/2_build_callstacks.py

# cp ./functions_html.json ~/Desktop/code4rena/.vscode/ext-static-analysis/functions_html.json
# cp ./callstacks.json ~/Desktop/code4rena/.vscode/ext-static-analysis/callstacks.json
# cp ./scope_summaries_html.json ~/Desktop/code4rena/.vscode/ext-static-analysis/scope_summaries_html.json

# cp ./functions_html.json ~/Desktop/static-analysis-context-POC/.vscode/ext-static-analysis/functions_html.json
# cp ./callstacks.json ~/Desktop/static-analysis-context-POC/.vscode/ext-static-analysis/callstacks.json
# cp ./scope_summaries_html.json ~/Desktop/static-analysis-context-POC/.vscode/ext-static-analysis/scope_summaries_html.json


mkdir -p .vscode/ext-static-analysis/graphs
cp ./functions_html.json ./.vscode/ext-static-analysis/functions_html.json
cp ./callstacks.json ./.vscode/ext-static-analysis/callstacks.json
cp ./scope_summaries_html.json ./.vscode/ext-static-analysis/scope_summaries_html.json
cp ./inheritance_graph.json ./.vscode/ext-static-analysis/graphs/inheritance_graph.json





# install semgrep custom rules
git clone https://github.com/MobSF/mobsfscan.git ./sg-rules/mobsfscan &
git clone https://github.com/0xdea/semgrep-rules.git ./sg-rules/0xdea &
git clone https://github.com/trailofbits/semgrep-rules.git ./sg-rules/trailofbits &
git clone https://github.com/elttam/semgrep-rules.git ./sg-rules/elttam &
git clone https://gitlab.com/gitlab-org/security-products/sast-rules.git ./sg-rules/gitlab &
git clone https://github.com/kondukto-io/semgrep-rules.git ./sg-rules/kondukto &
git clone https://github.com/hashicorp-forge/semgrep-rules.git ./sg-rules/hashicorp-forge &
git clone https://github.com/dgryski/semgrep-go.git ./sg-rules/dgryski &
git clone https://github.com/mindedsecurity/semgrep-rules-android-security.git ./sg-rules/mindedsecurity &
git clone https://github.com/federicodotta/semgrep-rules.git ./sg-rules/federicodotta &

# git clone in background, wait for completion
wait
printf "All git clones completed\n"

mv ./sg-rules/mobsfscan/mobsfscan/rules/semgrep ./sg-rules/mobsf
rm -rf ./sg-rules/mobsfscan

# remove semgrep rules that are known to break
cat ~/Desktop/static-analysis-context-POC/tools/semgrep/todelete.txt | xargs rm


# delete broken yaml configs
# semgrep scan --validate --config ./sg-rules 2>&1 | tee errors.txt
# cat errors.txt | grep sg-rules | rev | cut -d' ' -f1 | rev | cut -d':' -f1 | sort | uniq > to_delete.txt
# cat to_delete.txt | xargs rm\

# TODO delete known problem files

# do while to_delete.txt is not empty
while true; do
    semgrep scan --validate --config ./sg-rules 2>&1 | tee errors.txt
    cat errors.txt | grep sg-rules | rev | cut -d' ' -f1 | rev | cut -d':' -f1 | sort | uniq > to_delete.txt
    cat to_delete.txt >> alldeleted.txt

    cat to_delete.txt | xargs rm

    if [ ! -s to_delete.txt ]; then
        break
    fi
done



# show high and mediums
# semgrep --severity ERROR --severity WARNING 

# semgrep scan --exclude sg-rules --json --config auto --config ./sg-rules > semgrep.json
semgrep scan --exclude sg-rules --json --config ./sg-rules --config auto > semgrep.json # --include "*.php"

mkdir -p .vscode/ext-detectors
python3 ~/Desktop/static-analysis-context-POC/tools/semgrep-to-detector-results.py






### TOOLS
# python3 ~/Desktop/static-analysis-context-POC/tools/_search_regex_in_functions.py -s "UpdraftPlus_Options::user_can_manage"
# python3 ~/Desktop/static-analysis-context-POC/tools/_search_regex_in_functions.py -s "(_POST|_REQUEST|_GET)" -ad "💥"
