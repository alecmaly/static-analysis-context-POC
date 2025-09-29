# Static Analysis Detector Viewer (Visual Studio Code Extension)
Visual Studio Code integration static analysis tool output.

## Features
* Analyze open workspaces
* View results as native Visual Studio Code information/warnings/errors
* See annotations for relevant source code for each issue
* Print detailed issue description and recommendations
* Filter issues by type (per workspace configuration)

## Requirements
* [Visual Studio Code](https://code.visualstudio.com/download)
* Data files in .vscode/ folder of workspace.

## Installation

### From source

```
git clone https://github.com/alecmaly/vscode-detectors-extension
cd vscode-detectors-extension
npm i
npm install -g vsce
vsce package
```
`vscode-detectors-extension-X.X.X.vsix` will be created.

Install the VSIX file in Visual Studio through `Extensions`, under the `...` menu.

## Getting Started

Info available via. blog @ [alecmaly.com](https://alecmaly.com), YouTube Demo video is also available [here]()

## License
AGPL-3.0


## Original Source Code

Many thanks to the original project: [https://github.com/crytic/contract-explorer](https://github.com/crytic/contract-explorer). This project was used as a base and most of the code comes from this project.


## Example Projects

Example projects are listed here: [example repo]()
Look at the .vscode/ext-detectors folder for examples on data schema.