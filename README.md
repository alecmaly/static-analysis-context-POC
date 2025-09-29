# Static Analysis Toolkit

# Tools

- [genaric/lsp](genaric/lsp): LSP Scanning Tool

Used to scan a codebase with its LSP, generating files with context of functions, callstacks, scopes, state variables, etc. Output is to be used in a static analysis VS Code extension. This Docker environment also has tools such as semgrep and custom scripts to convert grep and semgrep output to a format used by the detectors extension.

This is a generic solution to be used with multiple languages, with the caveat of less verbose output. More accurate, fuller context can be extracted with custom parsers such as [Slither Detector: CDTaintedVariableUsed_rollup.py](custom_detectors/slither_my_plugin/detectors/CDTaintedVariableUsed_rollup.py).

Run with:
```shell
docker run alecmaly/sa-tool
```

- [Slither Detector: CDTaintedVariableUsed_rollup.py](custom_detectors/slither_my_plugin/detectors/CDTaintedVariableUsed_rollup.py): Solidity Context Parser

This is a Slither detector used to parse Solidity for context. It can look at shadowed functions, class relationships, etc, unlike the generic LSP scanning tool that is limited to the Language Server Protocol's implementation, which can accommodate several languages. This detector is run within a template script [_RUNSLITHER.sh](_RUNSLITHER.sh) that will run other scripts and massage the data for use in the Detectors and Static Analysis Context extensions below.

- [genaric/vscode-detectors-extension](genaric/vscode-detectors-extension): Detectors Extension

A modified version of [crytic/contract-explorer](https://github.com/crytic/contract-explorer) to show output from more than Slither.

- Useful utility scripts:
    - [genaric/lsp/src/grep-to-detector-results.py](genaric/lsp/src/grep-to-detector-results.py)
    - [genaric/lsp/src/semgrep-to-detector-results.py](genaric/lsp/src/semgrep-to-detector-results.py)
    - [solhint-plugin-customRuleset/solhint-to-detector-results.py](solhint-plugin-customRuleset/solhint-to-detector-results.py)
    

- [genaric/vscode-static-analysis-extension](genaric/vscode-static-analysis-extension): Static Analysis Context Extension

Takes output from custom parser scripts such as [Slither Detector: CDTaintedVariableUsed_rollup.py](custom_detectors/slither_my_plugin/detectors/CDTaintedVariableUsed_rollup.py) or the [LSP scanning Tool](genaric/lsp) (listed above). This extension allows browsing context for functions/scopes when reviewing code by adding codelens, adding a webview, and may send events back to the LSP Scanning tool to dynamically choose when to open a file based on browsing or other user actions.


- [./tools](tools) Utility scripts for usage in scripts such as [_RUNSLITHER.sh](_RUNSLITHER.sh)


# Install Tooling (VS Code Extensions + LSP Docker Image)

Tested using Ubuntu 24.04.3 on AMD64 architecture

```bash
# Update Ubuntu and run the install script.
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl
curl https://gist.githubusercontent.com/alecmaly/fb79d21acb7e1569d002d5f756fe4043/raw/69b6d468c1212d3efe93c210ac4488215ef41a20/prep-ubuntu-for-static-analysis.sh | bash
```

At this point, we should have VS Code installed, the custom extensions, Docker, our LSP scanning Docker image, and some pre-scanned language files in `/public/example-projects` and `/public/2024-11-chainlink`

# View pre-ran projects

```bash
# solidity, more robust output
code /public/2024-11-chainlink

# LSP solution, less verbose but more language support
code /public/example_projects/asm
code /public/example_projects/bash
code /public/example_projects/c
code /public/example_projects/csharp
code /public/example_projects/go
code /public/example_projects/java
code /public/example_projects/kotllin
code /public/example_projects/lua
code /public/example_projects/php
code /public/example_projects/powershell
code /public/example_projects/python
code /public/example_projects/ruby
code /public/example_projects/rust
code /public/example_projects/solidity
code /public/example_projects/typescript
```

Static Analysis Extension: 
 - Viewable from the tab next to the Terminal
Detectors Extension:
 - Viewable via. the triangle exclimation sign on the left nav.


# Slither: custom_detectors

## Install

Custom detectors will require a custom slither install: https://github.com/alecmaly/slither
This version of Slither has an added function to determine if a current evaluated file is in scope.
Running this tooling has quite a few more steps and often takes a few trial and error loops to get working for a given codebase. I will give a brief description in a video.

**Push to slither**
```bash
# install custom detectors
cd ./custom_detectors
python3 setup.py develop
```
