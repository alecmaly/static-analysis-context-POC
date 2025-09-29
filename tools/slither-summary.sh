#!/bin/bash

# base_slither_cmd="slither . --filter-paths 'asdfasdf|node_modules|script/|test/|lib/|sdfsdf' --hardhat-ignore-compile"

base_slither_cmd="slither './src/**' --filter-paths '$1' --ignore-compile"


output_dir="slither_summary_output"
mkdir -p ./$output_dir

# +-----+-------------------+-------------------------------------------------------------------------------------------------------+
# | Num |      Printer      |                                              What it Does                                             |
# +-----+-------------------+-------------------------------------------------------------------------------------------------------+
# |  1  |     call-graph    |                          Export the call-graph of the contracts to a dot file                         |
# |  2  |        cfg        |                                    Export the CFG of each functions                                   |
# |  3  | constructor-calls |                                    Print the constructors executed                                    |
# |  4  |  contract-summary |                                    Print a summary of the contracts                                   |
# |  5  |  data-dependency  |                              Print the data dependencies of the variables                             |
# |  6  |    declaration    | Prototype showing the source code declaration, implementation and references of the contracts objects |
# |  7  |     dominator     |                              Export the dominator tree of each functions                              |
# |  8  |      echidna      |                                   Export Echidna guiding information                                  |
# |  9  |        evm        |                            Print the evm instructions of nodes in functions                           |
# |  10 |    function-id    |                             Print the keccak256 signature of the functions                            |
# |  11 |  function-summary |                                    Print a summary of the functions                                   |
# |  12 |   human-summary   |                            Print a human-readable summary of the contracts                            |
# |  13 |    inheritance    |                           Print the inheritance relations between contracts                           |
# |  14 | inheritance-graph |                      Export the inheritance graph of each contract to a dot file                      |
# |  15 |     modifiers     |                              Print the modifiers called by each function                              |
# |  16 |      pausable     |                             Print functions that do not use whenNotPaused                             |
# |  17 |      require      |                          Print the require and assert calls of each function                          |
# |  18 |      slithir      |                           Print the slithIR representation of the functions                           |
# |  19 |    slithir-ssa    |                           Print the slithIR representation of the functions                           |
# |  20 |   variable-order  |                             Print the storage order of the state variables                            |
# |  21 |   vars-and-auth   |                Print the state variables written and the authorization of the functions               |
# +-----+-------------------+-------------------------------------------------------------------------------------------------------+


function runPrinter() {
    # $1 = printer
    output_file="./$output_dir/$1.txt"
    $base_slither_cmd --print $1 2>&1 | tee $output_file
    sed -i '/^\(Warning\|Note\)/,+4d' $output_file  # remove compile Warning:/Note:
    sed -i '/^$/N;/^\n$/D' $output_file             # remove empty lines
}
function runPrinterDot() {
    # $1 = printer
    $base_slither_cmd --print $1
    mkdir -p ./$output_dir/$1
    # mv *.dot ./$output_dir/$1
    find . -maxdepth 1 -name "*.dot" | xargs -I{} -P8 sh -c "mv '{}' './$output_dir/$1'"
    find ./$output_dir/$1 -name "*.dot" | xargs -I{} -P8 sh -c "dot -Tpng '{}' -o '{}.png'"
}


runPrinter "inheritance"
python3 ~/Desktop/static-analysis-context-POC/tools/solidity/_slitherInheritanceTxtToGraph.py  # convert inheritance.txt to graph for VS Code extension

# runPrinter "contract-summary"
# runPrinter "function-summary"
# runPrinter "modifiers"
# runPrinter "human-summary"
# runPrinter "pausable"
# runPrinter "require"
runPrinter "data-dependency"
# runPrinter "constructor-calls"
runPrinter "variable-order"
# runPrinter "vars-and-auth"
# # runPrinter "declaration"
# runPrinter "echidna"
# # runPrinter "evm"
# runPrinter "function-id"
# runPrinter "slithir"
# runPrinter "slithir-ssa"



# runPrinterDot "cfg"
# runPrinterDot "call-graph"
# runPrinterDot "denominator"
runPrinterDot "inheritance-graph"



# ~/Desktop/static-analysis-context-POC/tools/solidity/_slitherInheritanceTxtToGraph.py