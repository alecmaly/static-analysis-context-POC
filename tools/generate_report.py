import argparse
import json
import os

from enum import Enum
 
# order is order in which output to report
class FindingCategory(Enum):
    VALID = 1
    EXCLUDED = 2


# FUNCTIONS
def print_obj_attributes(obj, max_depth=2, indent_level=0, full_path="", output_str = ""):
    if max_depth <= 0:
        return
    for attr in dir(obj):
        if not attr.startswith("_"):
            attr_value = getattr(obj, attr)
            if callable(attr_value):
                continue
            if full_path:
                path = f"{full_path}.{attr}"
            else:
                path = attr
            # print(f"{' ' * indent_level}{path}: {attr_value}")
            if isinstance(attr_value, object) and not isinstance(attr_value, (int, float, str, list, dict, tuple)):
                print_obj_attributes(attr_value, max_depth - 1, indent_level + 4, path, output_str)
                
                
# NOTE:
# Alternative to ``` + allows for hyperlinks in code blocks

# <pre>
#  <code>
#   <a href="https://github.com/gmarciani">gmarciani</a>
#  </code>
# </pre>

def getSummaryTable():
    # TO DO:
    # prefix to file
    global report_summary

    output = """
# Gas Report Summary
    """
        
    output += """
issue | instances | gas saved
---- | ---- | ----
"""
    for row in report_summary:
        output += f"{row['issue']} | {row['instances']} | {row['gas_saved']}\n"

    output += f"Total gas saved (minimum): {sum([x['gas_saved'] for x in report_summary])}\n\n"
    return output

def processResults(results, title, description, CATEGORY, GAS_SAVED="-", MARKDOWN=False, INCLUDE_SLITHER_DESCIPTION=False):
    global f
    global i
    global root_dir
    global report_summary

    id = f"[G-{i}]"
    output = f"""
## {id} {title}
{description}<br>
{len(results)} instance(s) found:"""
    obj = {
        "order": i,
        "issue": f"{id} {title}",
        "instances": len(results),
        "gas_saved": GAS_SAVED
    }
    report_summary.append(obj)
    output += getDetectionsOutput(root_dir, results, markdown=MARKDOWN, INCLUDE_SLITHER_DESCIPTION=INCLUDE_SLITHER_DESCIPTION)
    i += 1
    return {'category': CATEGORY, 'output': output}

def cache_file_lines(func):
    cache_dict = {}
    def wrapper(filepath: str, line_num_start: int, prefix_lineNumber: bool = False, num_lines: int = 1, line_num_end: int = None):
        if filepath not in cache_dict:
            with open(filepath, 'r') as file:
                cache_dict[filepath] = file.readlines()
        lines = cache_dict[filepath]
        if line_num_end == None and num_lines is not None:
            line_num_end = line_num_start + num_lines - 1
        # print(line_num_end)
        result = "".join(lines[line_num_start-1:line_num_end]).strip()
        if prefix_lineNumber:
            result = "\n".join([f"{i+line_num_start}: {line}" for i, line in enumerate(result.split("\n"))])
        return result
    return wrapper

@cache_file_lines
def read_line_range_from_file(filepath: str, line_num_start: int, prefix_lineNumber: bool = False, num_lines: int = 1, line_num_end: int = None) -> str:
    return ""


def getDetectionsOutput(root_dir, results, markdown=False, INCLUDE_SLITHER_DESCIPTION=False):

    ## NOT USED YET
    # Group results by filepath
    results_grouped_by_file = {}
    for result in results:
        filepath = result['first_markdown_element'].split('#')[0]

        if filepath not in results_grouped_by_file:
            results_grouped_by_file[filepath] = []
        results_grouped_by_file[filepath].append(result)

    # sort results by filepath
    results = sorted(results, key=lambda x: x['first_markdown_element'].split('#')[0])

    output = ""
    if not markdown: 
        for result in results:
            #  before
            desc = result['markdown'].replace('](', f']({root_dir}').replace('\t -', '-') if INCLUDE_SLITHER_DESCIPTION else ""
            output += f"""
- [{root_dir + result['first_markdown_element']}]({root_dir + result['first_markdown_element']})
{desc}
```solidity
            """
            
            # in code block
            for ele in result['elements']:
                content = read_line_range_from_file(ele['source_mapping']['filename_absolute'], ele['source_mapping']['lines'][0], True, line_num_end=ele['source_mapping']['lines'][-1])

                # print(result)
#                 f.write(f"""
# {ele['source_mapping']['lines'][0]}: {ele.get('signature', None) or ele.get('type_specific_fields', {}).get('signature', None) or ele.get('name', None)}
#             """)
                output += f"""
{content}
            """
                
            # after code block            
            output += f"""
```
            """


    if markdown: 
        for result in results:
            #  before
            desc = result['markdown'].replace('](', f']({root_dir}').replace('\t -', '-') if INCLUDE_SLITHER_DESCIPTION else ""
            output += f"""
{desc}
<pre>
    <code>"""

            # in code block
            # print(result)
            for ele in result['elements']:
                # print(ele['source_mapping']['lines'][0])
                # print(ele['source_mapping']['lines'][-1])
                
                # fix line numbers in future with real data
                content = read_line_range_from_file(ele['source_mapping']['filename_absolute'], ele['source_mapping']['lines'][0], False)
                # print(result)
                output += f"""
        <a href="{root_dir + ele['source_mapping']['filename_relative']}#{ele['source_mapping']['lines'][0]}-{ele['source_mapping']['lines'][-1]}">{ele['source_mapping']['lines'][0]}</a>: {content}
            """
                
            # after code block            
            output += f"""</code>
</pre>"""
    return output

def main():
    global root_dir
    global i
    global f
    global report_summary
    
    # read data from file
    data = json.loads(open('./.vscode/detector-results.json').read())
    data = [x for x in data if 'falsePositive' not in x or x['falsePositive'] != True]


    parser = argparse.ArgumentParser(description='Print root directory')
    parser.add_argument('-r', '--root-dir', type=str, help='The root directory', default=None, required=False)
    args = parser.parse_args()

    root_dir = args.root_dir or ''
    output = []
    i = 1

    report_summary = []

#(est savings: {GAS_SAVED_PER_INSTANCE} * {len(results)} = {GAS_SAVED_PER_INSTANCE * len(results)})
    
    # CD-GO-DefaultValue
    results = [x for x in data if x['check'] == 'CD-GO-DefaultValue']
    if results:
        title = "Setting default value at variable initialization (automated findings only show default int = 0, not boolean = False)"
        description = """Every variable assignment in Solidity costs gas. When initializing variables, we often waste gas by assigning default values that will never be used.<br>
This includes settings int/uint = 0 as well as bools = false.<br>
[reference](https://medium.com/coinmonks/gas-optimization-in-solidity-part-i-variables-9d5775e43dde#4135)"""
        output.append(processResults(results, title, description, CATEGORY=FindingCategory.VALID, GAS_SAVED=0))

    # CD-GO-EmitFromMemory
    results = [x for x in data if x['check'] == 'CD-GO-EmitFromMemory']
    if results:
        title = "Emitting from local variables instead of state variables can save gas"
        description = """Average gas saved is <u>~499 gas</u> per instance based on previous Warden's testing.<br>
[reference](https://code4rena.com/reports/2022-12-forgeries/#g-02-emitting-storage-values-instead-of-the-memory-one)"""
        output.append(processResults(results, title, description, CATEGORY=FindingCategory.VALID, GAS_SAVED=499*len(results)))


    # CD-GO-StateVarsOnlySetInConstructor
    results = [x for x in data if x['check'] == 'CD-GO-StateVarsOnlySetInConstructor']
    if results:
        title = "Emitting from local variables instead of state variables can save gas"
        description = """Avoids a Gsset (<u>20000 gas</u>) in the constructor, and replaces the first access in each transaction (Gcoldsload - <u>2100 gas</u>) and each access thereafter (Gwarmacces - <u>100 gas</u>) with a PUSH32 (<u>3 gas</u>).<br><br>
While strings are not value types, and therefore cannot be immutable/constant if not hard-coded outside of the constructor, the same behavior can be achieved by making the current contract abstract with virtual functions for the string accessors, and having a child contract override the functions with the hard-coded implementation-specific values.<br>
[reference](https://code4rena.com/reports/2022-12-tigris/#g02--state-variables-only-set-in-the-constructor-should-be-declared-immutable)"""
        output.append(processResults(results, title, description, CATEGORY=FindingCategory.VALID, GAS_SAVED=2097*len(results)))




    # CD-GO-StorageReadTwice
    results = [x for x in data if x['check'] == 'CD-GO-StorageReadTwice']
    if results:
        num_instances = sum([len(res['elements'])-1 for res in results])  # num of duplicated instances (removes first call to state var)
        title = "Cache storage values in memory to minimize SLOADs"
        description = """The code can be optimized by minimizing the number of SLOADs.<br>
SLOADs are expensive (100 gas after the 1st one) compared to MLOADs/MSTOREs (3 gas each). Storage values read multiple times should instead be cached in memory the first time (costing 1 SLOAD) and then read from this cache to avoid multiple SLOADs.<br>
[reference](https://code4rena.com/reports/2022-12-forgeries#g-03-cache-storage-values-in-memory-to-minimize-sloads)"""
        
        
        output.append(processResults(results, title, description, CATEGORY=FindingCategory.VALID, GAS_SAVED=97*num_instances, INCLUDE_SLITHER_DESCIPTION=True))






    # CD-GO-DivBy2
    results = [x for x in data if x['check'] == 'CD-GO-DivBy2']
    if results:
        title = "Division by 2 should use bitshifting"
        description = """`<x> / 2` is the same as `<x> >> 1`. While the compiler uses the `SHR` opcode to accomplish both, the version that uses division incurs an overhead of <u>20 gas</u> due to `JUMP`s to and from a compiler utility function that introduces checks which can be avoided by using `unchecked {}` around the division by two.<br>
[reference: previous report](https://code4rena.com/reports/2022-12-backed/#g10--division-by-two-should-use-bit-shifting)"""
        output.append(processResults(results, title, description, CATEGORY=FindingCategory.VALID, GAS_SAVED=20*len(results)))

    # CD-GO-ConstructorPayable
    results = [x for x in data if x['check'] == 'CD-GO-ConstructorPayable']
    if results:
        title = "Setting the `constructor` to `payable`"
        description = f"""Saves ~13 per instance<br>
[source: previous report](https://code4rena.com/reports/2022-12-caviar/#g-10-setting-the-constructor-to-payable)<br>
[github report](https://github.com/OpenZeppelin/openzeppelin-contracts/issues/3059)
        """
        output.append(processResults(results, title, description, CATEGORY=FindingCategory.VALID, GAS_SAVED=13*len(results)))

    # CD-GO-ForLoops
    results = [x for x in data if x['check'] == 'CD-GO-AssignmentToLessThan32Bytes']
    if results:
        title = "Usage of `uints`/`ints` smaller than 32 bytes (256 bits) incurs overhead"
        description = """> When using elements that are smaller than 32 bytes, your contract’s gas usage may be higher. This is because the EVM operates on 32 bytes at a time. Therefore, if the element is smaller than that, the EVM must use more operations in order to reduce the size of the element from 32 bytes to the desired size.<br>
https://docs.soliditylang.org/en/v0.8.11/internals/layout_in_storage.html

Each operation involving a `uint8` costs an extra <u>22-28 gas</u> (depending on whether the other operand is also a variable of type `uint8`) as compared to ones involving `uint256`, due to the compiler having to clear the higher bits of the memory word before operating on the `uint8`, as well as the associated stack operations of doing so. Use a larger size then downcast where needed.
[previous report](https://code4rena.com/reports/2022-12-backed/#g07--i-costs-less-gas-than-i-especially-when-its-used-in-for-loops---ii---too)"""
        output.append(processResults(results, title, description, CATEGORY=FindingCategory.VALID, GAS_SAVED=22*len(results)))


    # CD-GO-ExpandExpression
    results = [x for x in data if x['check'] == 'CD-GO-ExpandExpression']
    if results:
        title = "`<x> += <y>` costs more gas than `<x> = <x> + <y>` when <y> is a state variable"
        description = """[previous report](https://code4rena.com/reports/2022-12-caviar#g-01-x--y-costs-more-gas-than-x--x--y-for-state-variables)"""
        output.append(processResults(results, title, description, CATEGORY=FindingCategory.VALID))

    # CD-GO-CacheKeccak256
    results = [x for x in data if x['check'] == 'CD-GO-CacheKeccak256']
    if results:
        title = "`keccak256()` should only need to be called on a specific string literal once"
        description = """It should be saved to an immutable variable, and the variable used instead. If the hash is being used as a part of a function selector, the cast to `bytes4` should also only be done once.<br>
[previous report](https://code4rena.com/reports/2022-12-backed/#g04--keccak256-should-only-need-to-be-called-on-a-specific-string-literal-once)"""
        output.append(processResults(results, title, description, CATEGORY=FindingCategory.VALID))


    # CD-GO-OptimizeNames
    results = [x for x in data if x['check'] == 'CD-GO-OptimizeNames']
    if results:
        title = "Optimize names to save gas"
        description = """`public`/`external` function names and `public` member variable names can be optimized to save gas. See this [link](https://gist.github.com/IllIllI000/a5d8b486a8259f9f77891a919febd1a9) for an example of how it works. Below are the interfaces/abstract contracts that can be optimized so that the most frequently-called functions use the least amount of gas possible during method lookup. Method IDs that have two leading zero bytes can save <u>128 gas</u> each during deployment, and renaming functions to have lower method IDs will save <u>22</u> gas per call, [per sorted position shifted](https://medium.com/joyso/solidity-how-does-function-name-affect-gas-consumption-in-smart-contract-47d270d8ac92).<br>
[previous report](https://code4rena.com/reports/2022-12-backed/#g05--optimize-names-to-save-gas)"""
        output.append(processResults(results, title, description, CATEGORY=FindingCategory.VALID))

    # CD-GO-CacheKeccak256
    results = [x for x in data if x['check'] == 'CD-GO-CacheKeccak256']
    if results:
        title = "`keccak256()` should only need to be called on a specific string literal once"
        description = """It should be saved to an immutable variable, and the variable used instead. If the hash is being used as a part of a function selector, the cast to `bytes4` should also only be done once.<br>
[previous report](https://code4rena.com/reports/2022-12-backed/#g05--optimize-names-to-save-gas)"""
        output.append(processResults(results, title, description, CATEGORY=FindingCategory.VALID))

    # CD-GO-OnlyPayable
    results = [x for x in data if x['check'] == 'CD-GO-OnlyPayable']
    if results:
        title = "`only...` modifier found without payable"
        description = """If a function modifier such as `onlyOwner` is used, the function will revert if a normal user tries to pay the function. Marking the function as `payable` will lower the gas cost for legitimate callers because the compiler will not include checks for whether a payment was provided. The extra opcodes avoided are `CALLVALUE`(2),`DUP1`(3),`ISZERO`(3),`PUSH2`(3),`JUMPI`(10),`PUSH1`(3),`DUP1`(3),`REVERT`(0),`JUMPDEST`(1),`POP`(2), which costs an average of about 21 gas per call to the function, in addition to the extra deployment cost.<br>
    [source: previous report](https://code4rena.com/reports/2022-12-backed#g11--functions-guaranteed-to-revert-when-called-by-normal-users-can-be-marked-payable)"""
        output.append(processResults(results, title, description, CATEGORY=FindingCategory.EXCLUDED, GAS_SAVED=21*len(results)))

    # CD-GO-Constants-Should-Be-Private
    results = [x for x in data if x['check'] == 'CD-GO-Constants-Should-Be-Private']
    if results:
        title = "Using `private` rather than `public` for constants, saves gas"
        description = """If needed, the values can be read from the verified contract source code, or if there are multiple values there can be a single getter function that [returns a tuple](https://github.com/code-423n4/2022-08-frax/blob/90f55a9ce4e25bceed3a74290b854341d8de6afa/src/contracts/FraxlendPair.sol#L156-L178) of the values of all currently-public constants. Saves <u>3406-3606</u> gas in deployment gas due to the compiler not having to create non-payable getter functions for deployment calldata, not having to store the bytes of the value outside of where it's used, and not adding another entry to the method ID table.
TO DO: MANUALLY REMOVE ANY RESULTS THAT HAVE THE `override` modifier
[source: previous report](https://code4rena.com/reports/2022-12-backed#g11--functions-guaranteed-to-revert-when-called-by-normal-users-can-be-marked-payable)
        """
        output.append(processResults(results, title, description, CATEGORY=FindingCategory.EXCLUDED))


    # CD-GO-ForLoops
    results = [x for x in data if x['check'] == 'CD-GO-ForLoopsLength']
    if results:
        title = ".length should not be looked up in every loop of a for-loop"
        description = """The overheads outlined below are PER LOOP, excluding the first loop<br>
- storage arrays incur a Gwarmaccess (100 gas)
- memory arrays use `MLOAD` (3 gas)
- calldata arrays use `CALLDATALOAD` (3 gas)<br>
Caching the length changes each of these to a `DUP<N>` (3 gas), and gets rid of the extra `DUP<N>` needed to store the stack offset<br>
[previous report](https://code4rena.com/reports/2022-12-backed/#g14--arraylength-should-not-be-looked-up-in-every-loop-of-a-for-loop)"""
        output.append(processResults(results, title, description, CATEGORY=FindingCategory.EXCLUDED, GAS_SAVED=13*len(results)))


    # CD-GO-ForLoops
    results = [x for x in data if x['check'] == 'CD-GO-IncrementPrefix']
    if results:
        title = "`++i` & `--i` cost less gas than `i++` & `i--`, especially when used in for-loops"
        description = """Saves 5 gas per loop
[previous report](https://code4rena.com/reports/2022-12-backed/#g07--i-costs-less-gas-than-i-especially-when-its-used-in-for-loops---ii---too)"""
        output.append(processResults(results, title, description, CATEGORY=FindingCategory.EXCLUDED, GAS_SAVED=5*len(results)))






    output_str = "# Gas Optimization Results"
    # output

    
    summary_table = getSummaryTable()
    # output = summary_table + output
    f = open('report.md', 'w')
    # print summary table
    f.write(getSummaryTable())

    f.write("# Gas Optimization Results\n")
    for c in FindingCategory:
        match c:
            # case FindingCategory.VALID:
            #     f.write("## Findings")
            case FindingCategory.EXCLUDED:
                f.write("\n## Excluded Gas Optimizations\n")
                f.write("These findings are excludued as public automated tooling already reports on them. This section is provided in an effort to validate findings against other automations.")
        
        # output results of current category (VALID/EXCLUDED)
        f.write("".join([finding['output'] for finding in output if finding['category'] == c]))

    # f.write(output)
    f.close()



if __name__ == '__main__':
    main()

