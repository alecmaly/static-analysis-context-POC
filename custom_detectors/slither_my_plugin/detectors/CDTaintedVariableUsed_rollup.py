from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.variables.local_variable import LocalVariable
from slither.core.declarations.solidity_variables import SolidityVariableComposed
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations.index import Index
from slither.slithir.variables import Constant, ReferenceVariable, TemporaryVariable
from slither.core.declarations import SolidityVariableComposed
from slither.core.declarations.function import Function
from slither.core.declarations.contract import Contract
from slither.core.declarations.modifier import Modifier
from slither.core.declarations.enum import Enum
from slither.core.solidity_types import MappingType
from slither.slithir.operations.return_operation import Return

from slither.slithir.operations import Binary, Assignment, BinaryType, LibraryCall, EventCall
from slither.core.expressions.assignment_operation import (
    AssignmentOperation,
    AssignmentOperationType,
)

from slither.core.declarations.enum_contract import EnumContract
from slither.core.solidity_types import (
    ArrayType,
    MappingType,
    ElementaryType,
    UserDefinedType,
    TypeAlias,
)
from slither.core.declarations.structure_contract import StructureContract

import re
import json
import base64
import itertools
import debugpy
# import math
import subprocess

from typing import List


# import custom util functions
from slither_my_plugin.detectors._CDUtils import *


def get_func_usage(f: Function, p_self):
    global interface_func_to_impl_func
    global source_code_lines
    global function_source_map

    bases = [base for base in interface_func_to_impl_func if f in interface_func_to_impl_func[base]]

    references = set()
    for ref in f.references:
        references.add(ref)

    for (c_name, _) in bases:
        for c in [c for c in p_self.compilation_unit.contracts if c.name == c_name]:
            for related_func in [func for func in c.functions_declared if f.signature_str == func.signature_str]:
                for ref in related_func.references:
                    references.add(ref)


    calls = []
    max_loops = 20
    for ref in references:
        filepath = ref.filename.absolute
        # code = "\n".join([x.strip() for i, x in enumerate(source_code_lines[filepath]) if (i + 1) in ref.lines])
        code = ""
        try:
            for line in ref.lines:
                i = -1
                code += source_code_lines[filepath][line + i].strip()
                while True:
                    # check number of closing brackets and opening brackets are equal
                    # NOTE: should look character by character for "(" and ")" to avoid counting in strings but by lines should be good enough for most use cases
                    if code.count("(") <= code.count(")") or i > max_loops:
                        break
                    i += 1
                    code += " " + source_code_lines[filepath][line + i].strip()
            # code = "\n".join([source_code_lines[filepath][line - 1].strip() for line in ref.lines])
        except Exception as e:
            print("Error in getting function usage", e)
        
        func = None
        for func in function_source_map[filepath]:
            if ref.lines[0] in func.source_mapping.lines:
                break

        calls.append((func, ref, code))

    return calls


## Enum in Variable Function
# def get_func_source(f: Function):
#     return f'{f},{f.source_mapping.filename.absolute}#{f.source_mapping.lines[0]}:{f.source_mapping.starting_column}'
def var_contains_type(v, search_type: ArrayType | EnumContract, ReturnContext = False, visited = None):
    if not visited:
        visited = set()
    # If the variable is already checked in this recursion, return False to avoid infinite loops
    if id(v) in visited:
        return False
    visited.add(id(v))

    if ReturnContext:
        if isinstance(v, search_type):
            return True
        if hasattr(v, 'type') and isinstance(v.type, search_type):
            return True

    ret_type_to = False
    if hasattr(v, 'type_to'):
        if isinstance(v.type_to, search_type):
            ret_type_to = True
        else:
            # ReturnContext = True as we are now in mapping(), return true when pointing to EnumContract
            ret_type_to = var_contains_type(v.type_to, search_type, True, visited)

    ret_type = False
    if hasattr(v, 'type'):
        ret_type = var_contains_type(v.type, search_type, ReturnContext, visited)

    ret_elems = False
    if hasattr(v, 'elems'):
        if any(var_contains_type(v.elems[ele], search_type, ReturnContext, visited) for ele in v.elems):
            ret_elems = True

    return ret_type_to or ret_type or ret_elems


## Entrypoint callstack functions

global index
index = 0


def get_ref_or_tmp_name(var, prefix = ""):
    ## make recursive for nested reference vars
    ## can TMP vars be dereferenced? 
    if type(var) == ReferenceVariable and 'name' in dir(var.points_to):  
        return f"(REF){var.points_to.name}"
    if type(var) == TemporaryVariable:
        return f"(TMP){var}"
    # TO IMPLEMENT?  type: SolidityImportPlaceHolder
    return str(var)


def append_no_cycle(arr: list, ele: object):
    last_node = arr[0]
    for x in range(1, len(arr) - 1):
        ""

def is_subsequence(arr, other_arr):
    len_arr = len(arr)
    len_other_arr = len(other_arr)

    # If first list is larger, it can't be a subsequence
    if len_arr > len_other_arr:
        return False

    # Use a sliding window to check if arr is a subsequence of other_arr
    for i in range(len_other_arr - len_arr + 1):
        if other_arr[i:i+len_arr] == arr:
            return True

    return False


def flatten(xss):
    return [x for xs in xss for x in xs]

def build_constructor_callstacks(arr_of_constructor_callstacks):
    callstacks = []
    for callstack in arr_of_constructor_callstacks:
        last_node = callstack[-1]
        constructors = [c.constructor for c in last_node.contract.immediate_inheritance if c.constructor]
        for constructor in constructors:
            for cs in build_constructor_callstacks([callstack + [constructor]]):
                callstacks.append(cs)
    return callstacks

def get_entrypoint_callstacks(f2: Function, max_depth: int = 7):
    global interface_func_to_impl_func
    global callstacks_edge_colors
    global function_caller_callee_map
    # if "/test" in f.source_mapping.filename.absolute:
    #     return []

    ## IMPORTANT NOTE: This version of the function does not return all entrypoint functions, it may equal out at the end after all callstacks in all contracts are collected
    callstacks = []
    # if f in entrypoint_functions:
    callstacks.append([f2])

    # # append constructors
    # if f.name == "constructor":
    #     # callstacks.append([f] + flatten(constructors))
    #     for callstack in build_constructor_callstacks([[f]]):
    #         callstacks.append(callstack)
    

    # for shadowed in [shadowed for shadowed in f.functions_shadowed if shadowed.contract_declarer == f.contract_declarer and shadowed.signature_str == f.signature_str]:
    #     # TODO: should I remove/replace last node?
    #     callstacks.append([shadowed])
    
    

    # returns shadowed functions + itself (stops if it's an override function)
    def get_base_funcs(f: Function):
        f_collected = [f]

        is_override = 'override' in [m.strip() for m in re.split(r'\)| ', f.source_mapping.content.split("{")[0].split(")")[-1])]
        if is_override:
            return f_collected
        
        for f_shadowed in f.functions_shadowed:
            for f in get_base_funcs(f_shadowed):
                f_collected.append(f)
        return f_collected
    


    current_depth = 0
    while True:
        if current_depth >= max_depth:
            break

        # break if last function was an entrypoing function (breaks callstacks with multiple entrypoint functions)
        # if current_depth > 0 and all([callstack[-1].visibility in ['public', 'external'] for callstack in callstacks]):
        #     break

        current_depth += 1
        
        interesting_callstacks = []
        for current_callstack in callstacks:
            last_node = current_callstack[-1]
            
            if last_node.visibility in ['public', 'external']: # and len(current_callstack) > 1:
                interesting_callstacks.append(current_callstack)
                # continue
            
            # hasattr(obj, 'my_function'):
            # for f_child in last_node.all_internal_calls() + [f for (c, f) in last_node.all_library_calls()] + [f for (c, f) in last_node.all_high_level_calls()] + [f for (c, f) in last_node.all_low_level_calls()]:
            for f_child in [c.function for c in last_node.internal_calls] + [c.function for c in last_node.library_calls]: # + [f for (c, f) in last_node.low_level_calls]    ## low_level_calls do not have enough detail to work with
                # don't append if function to be appended (f_child) is already in callstack (i.e.: don't include cyclical function calls)
                if f_child not in current_callstack and hasattr(f_child, "all_internal_calls"):
                    interesting_callstacks.append(current_callstack + [f_child])
            # high level calls (external calls) will also map to inherited function
            for f_child in [call.function for (con, call) in last_node.high_level_calls]:
                if hasattr(f_child, "all_internal_calls"):
                    for f2 in get_base_funcs(f_child):
                        # if calling an override func, no need to lookup base (inherited) function implementations
                        is_override = 'override' in [m.strip() for m in re.split(r'\)| ', f2.source_mapping.content.split("{")[0].split(")")[-1])]
                        lookup_callee_funcs = interface_func_to_impl_func.get((f2.contract_declarer.name, f2.signature_str), [f2]) if not is_override else [f2]
                        for lookup_callee_func in lookup_callee_funcs:
                            # don't append if function to be appended (f_child) is already in callstack (i.e.: don't include cyclical function calls)
                            if get_func_source(lookup_callee_func) not in [get_func_source(f3) for f3 in current_callstack] and hasattr(lookup_callee_func, "all_internal_calls"):
                                interesting_callstacks.append(current_callstack + [lookup_callee_func])
                                function_caller_callee_map.setdefault(get_loc_id(lookup_callee_func), set()).add(f_child)
                                function_caller_callee_map.setdefault(get_loc_id(f_child), set()).add(lookup_callee_func)
                                caller = current_callstack[-1]
                                callee = lookup_callee_func

                                if not callee.contract_declarer.is_library:                                
                                    callstacks_edge_colors[f"{get_loc_id(caller)}~{get_loc_id(callee)}"] = "green"

        for callstack in interesting_callstacks:
            if callstack not in callstacks:
                callstacks.append(callstack)

    # invert all callstacks?
    return callstacks



### print sink / source callstack relationships
# def repeat_char(char: str, num_times: int) -> str:
#     return char * num_times


def get_callstacks_from_node(f_node, callstacks, search_type = None):
    callchains_w_node = []
    for index, callstack in enumerate(callstacks):
        # if len(callstack) <= 1:
        #     continue
        if search_type == "entry":
            if contractDeclarerOrEmpty(callstack[0]) == contractDeclarerOrEmpty(f_node) and callstack[0].signature_str == f_node.signature_str and index not in callchains_w_node:
                callchains_w_node.append(index)
            
        if search_type == "exit":
            if contractDeclarerOrEmpty(callstack[-1]) == contractDeclarerOrEmpty(f_node) and callstack[-1].signature_str == f_node.signature_str and index not in callchains_w_node:
                callchains_w_node.append(index)

        if search_type == "other":
            if any([contractDeclarerOrEmpty(f) == contractDeclarerOrEmpty(f_node) and f.signature_str == f_node.signature_str for f in list(callstack)[1:-1]]) and index not in callchains_w_node:
                callchains_w_node.append(index)

    
    # callchains_w_node = [arr for arr in callchains_w_node if not any(set(arr).issubset(set(other_arr)) for other_arr in callchains_w_node if other_arr != arr)]
    # callchains_w_node.sort(key=lambda arr_of_funcs: ''.join([get_descriptive_function_str(f) for f in arr_of_funcs])) 
    # for callchain in callchains_w_node:
    #     output += f"\t{callchain}\n"
    # return output

    return callchains_w_node


decorators_in_callstack = {}
## tainted variable functions

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

def is_division(ir):
    if isinstance(ir, Binary):
        if ir.type == BinaryType.DIVISION:
            return True

    if isinstance(ir, LibraryCall) and ir.function:
        if ir.function.name.lower() in [
            "div",
            "safediv",
        ]:
            if len(ir.arguments) == 2:
                if ir.lvalue:
                    return True
    return False

def is_multiplication(ir):
    if isinstance(ir, Binary):
        if ir.type == BinaryType.MULTIPLICATION:
            return True

    if isinstance(ir, LibraryCall) and ir.function:
        if ir.function.name.lower() in [
            "mul",
            "safemul",
        ]:
            if len(ir.arguments) == 2:
                if ir.lvalue:
                    return True
    return False


def is_addition(ir):
    if isinstance(ir, Binary):
        if ir.type == BinaryType.ADDITION:
            return True

    if isinstance(ir, LibraryCall) and ir.function:
        if ir.function.name.lower() in [
            "add",
            "safeadd",
        ]:
            if len(ir.arguments) == 2:
                if ir.lvalue:
                    return True
    return False

def is_subtraction(ir):
    if isinstance(ir, Binary):
        if ir.type == BinaryType.SUBTRACTION:
            return True

    if isinstance(ir, LibraryCall) and ir.function:
        if ir.function.name.lower() in [
            "sub",
            "safesub",
        ]:
            if len(ir.arguments) == 2:
                if ir.lvalue:
                    return True
    return False


def is_equality(ir):
    if isinstance(ir, Binary):
        if ir.type in [BinaryType.EQUAL, BinaryType.GREATER, BinaryType.LESS, BinaryType.GREATER_EQUAL, BinaryType.LESS_EQUAL, BinaryType.NOT_EQUAL] :
            return True

    return False


## Functions
def visit_node_all_functions(node, visited, tainted_vars):
    global var_ref_association_map
    global var_ref_written_association_map
    if node is None:
        return

    if node in visited:
        return

    visited += [node]

    for ir in node.irs:
        # track storage variables through function calls
        if 'arguments' in dir(ir) and 'function' in dir(ir) and ir.arguments and ir.function and 'parameters' in dir(ir.function):
            i = 0
            for p in ir.function.parameters:
                if p.is_storage:
                    # var_ref_written_association_map.setdefault((ir.arguments[i], p), []).append(node)
                    var_ref_association_map.setdefault((ir.arguments[i], p), []).append(node)
                i += 1

        if hasattr(ir, "lvalue") and ir.lvalue != None:
            # map relationships between variables and temp vars / refs
            if getattr(ir, "used", []):
                for var in ir.used:
                    var_ref_association_map.setdefault((var, ir.lvalue), []).append(node)
                    if var in tainted_vars and ir.lvalue not in tainted_vars:
                        tainted_vars.append(ir.lvalue)
                    # if ir.lvalue in tainted_vars and node.type.name not in ["IF"]:
                    # last ir is not a function call
                    if ir.lvalue in tainted_vars and type(node.irs[-1]) not in [EventCall, Return]:
                        if node.type.value not in ["IF", "NEW VARIABLE"] and type(node.irs[-1]) not in [LibraryCall] and 'lvalue' in dir(node.irs[-1]) and 'points_to_origin' in dir(node.irs[-1].lvalue) and 'is_storage' in dir(node.irs[-1].lvalue.points_to_origin) and node.irs[-1].lvalue.points_to_origin.is_storage:
                            var_ref_written_association_map.setdefault((var, ir.lvalue), []).append(node)
                        else:
                            var_ref_read_association_map.setdefault((var, ir.lvalue), []).append(node)
                    


    for son in node.sons:
        visit_node_all_functions(son, visited, tainted_vars)


def visit_node(node, visited, taints, tainted_locations):
    global taint_usage_mapping
    global tainted_addition
    global tainted_subtraction
    global tainted_denominator
    global tainted_multiplication
    global tainted_equality
    global nodes_output
    global KEY
    
    if node is None:
        return

    if node in visited:
        return

    visited += [node]
    # print(node.function.compilation_unit.context)
    # taints = node.slither.context[KEY]
    # taints = node.function.compilation_unit.context[KEY] if KEY in node.function.compilation_unit.context else []

    refs = {}
    for ir in node.irs:
        if isinstance(ir, Index):
            refs[ir.lvalue] = ir.variable_left
            
            read = [ir.variable_left]
        else:
            read = ir.read

        # print(f"Refs {refs}")
        # print(f"Read {[str(x) for x in ir.read]}")
        # print(f"Before {[str(x) for x in taints]}")


        # check tainted equality       
        if is_equality(ir) and node not in tainted_equality:
            if getattr(ir, "variable_left", None) in taints and getattr(ir, "variable_right", None) in taints:
                tainted_equality.append(node)

        # check tainted subtraction by tainted variable
        if is_addition(ir) and node not in tainted_addition:
            if getattr(ir, "variable_left", None) in taints:
                tainted_addition.setdefault(node, []).append(ir.variable_left)
            if getattr(ir, "variable_right", None) in taints:
                tainted_addition.setdefault(node, []).append(ir.variable_right)

        # check tainted subtraction by tainted variable
        if is_subtraction(ir) and node not in tainted_subtraction:
            if getattr(ir, "variable_left", None) in taints:
                tainted_subtraction.setdefault(node, []).append(ir.variable_left)
            if getattr(ir, "variable_right", None) in taints:
                tainted_subtraction.setdefault(node, []).append(ir.variable_right)

        # check tainted multiplication       
        if is_multiplication(ir) and node not in tainted_multiplication:
            if getattr(ir, "variable_left", None) in taints:
                tainted_multiplication.setdefault(node, []).append(ir.variable_left)
            if getattr(ir, "variable_right", None) in taints:
                tainted_multiplication.setdefault(node, []).append(ir.variable_right)

        # check tainted variable in numerator
        if is_division(ir) and getattr(ir, "variable_left", None) in taints and node not in tainted_numerator:
            tainted_numerator.setdefault(node, []).append(ir.variable_left)

        # check tainted variable in denominator
        if is_division(ir) and getattr(ir, "variable_right", None) in taints and node not in tainted_denominator:
            tainted_denominator.setdefault(node, []).append(ir.variable_right)

        if hasattr(ir, "lvalue") and ir.lvalue != None:
            if ir.lvalue not in taints:
                taints.append(ir.lvalue)
                if getattr(ir, "variable_left", None) in taints:
                    taint_usage_mapping.setdefault(ir.lvalue, []).append(ir.variable_left) 
                if getattr(ir, "variable_right", None) in taints:
                    taint_usage_mapping.setdefault(ir.lvalue, []).append(ir.variable_right)
                if getattr(ir, "rvalue", None) in taints:
                    taint_usage_mapping.setdefault(ir.lvalue, []).append(ir.rvalue)
                if any(v in taints for v in getattr(ir, "used", None)):
                    for var in ir.used:
                        taint_usage_mapping.setdefault(ir.lvalue, []).append(var)

            # if ir.lvalue and (ir.lvalue not in tainted_locations or node not in tainted_locations[ir.lvalue]):
            if ir.lvalue in taints and (ir.lvalue not in tainted_locations or node not in tainted_locations[ir.lvalue]):
                tainted_locations.setdefault(ir.lvalue, []).append(node)

        # print(f"After {[str(x) for x in taints]}")
        # print()

    # taints = [v for v in taints if not isinstance(v, (TemporaryVariable, ReferenceVariable))]
    node.function.compilation_unit.context[KEY] = list(set(taints))

    for son in node.sons:
        visit_node(son, visited, taints, tainted_locations)


def check_call(func, taints, tainted_locations):
    global interesting_tainted_function_calls
    global interesting_tainted_strict_comparisons
    modifiers = [x.name for x in func.modifiers]
    
    # [^a-z$] - prefix - tries to exclude preceeding character matches
    # [a-z$]*? - suffix - tries to match other functions (not spelled exaclty the same)
    # \( - ending - matches function call
    interesting_functions = [
        r'this\.', # this. changes msg.sender to address of contract
        r'[^a-z$]u?int(2[0-4][0-9]|25[0-5]|1?\d{1,2})\(', # casting int/uint 0-255
        r'[^a-z$]send[a-z$]*?\(',  # low level calls
        r'[^a-z$]call\(', r'[^a-z$]delegatecall\(', r'[^a-z$]staticcall\(',  # no return value check
        r'\.push\(', r'[^a-z$]splice\(',  # griefing on array
        r'[^a-z$]transfer\(', r'[^a-z$]transferFrom\(', r'[^a-z$]safeTransferFrom\(',  # no return value check, hook reentrency
        r'[^a-z$]_safeMint\(', r'[^a-z$]safeBatchTransferFrom\(', r'[^a-z$]_mintBatch\(',
        r'abi\.encodepacked\(', r'abi\.encode\(',  # signature collision w/ variable length parameters
        r'[^a-z$]supportsInterface\(', # 
        r' days', ' weeks', ' hours', ' minutes', ' seconds',
        r'[^a-z$]create\(', # should use create2() instead of create()
        # '[^a-z$]mint[a-z$]*?\(', '[^a-z$]burn[a-z$]*?\(',
        # 'debt[a-z$]*?\(', 
        # 'withdraw[a-z$]*?\(', 'deposit[a-z$]*?\(',
        # 'fee[a-z$]*?\(', 'donate[a-z$]*?\(', 'collateral[a-z$]*?\(', 'supply[a-z$]*?\('
        ]  # reduce, add 
    has_conditional_logic = ""
    detections = []
    for node in func.nodes:
        # if "uint16(" in str(node):
        #     debugpy.breakpoint()
        calling_func_name = str(node).split("(")[0].split(" ")[-1]

        interesting_functions_matches_arr = [re.search(f"{interesting_function_regex}", str(node.expression), re.IGNORECASE) for interesting_function_regex in interesting_functions]
        isInterestingFunction = any(interesting_functions_matches_arr)

        isInterestingFunctionMatches = ",".join([str(x[0].replace("(", "")) for x in interesting_functions_matches_arr if x != None])
        isInterestingFunctionPrefix = "* | " if isInterestingFunction else ""

        # TO DO : append interesting funtions?
        if isInterestingFunction and node not in interesting_tainted_function_calls:
            info = [f".Interesting Tainted Call | ({isInterestingFunctionMatches}) by {get_descriptive_function_str(node._function)} in {calling_func_name} ", node]
            # interesting_tainted_function_calls.append(info)
            interesting_tainted_function_calls.setdefault(node, []).append(info)


        # interesting strict comparisons
        if node.is_conditional():
            for ir in node.irs:
                if isinstance(ir, Binary) and ir.type in [BinaryType.EQUAL, BinaryType.NOT_EQUAL, BinaryType.LESS_EQUAL, BinaryType.GREATER_EQUAL, BinaryType.GREATER, BinaryType.LESS] and (getattr(ir, "variable_left", None) in taints or getattr(ir, "variable_right", None) in taints):
                    # interesting_tainted_strict_comparisons.append(info)
                    interesting_tainted_strict_comparisons.setdefault(node, []).append(ir)


        if 'require(' in str(node.expression).lower() or node.is_conditional() or node.contains_require_or_assert() or any("only" in mod.lower() for mod in modifiers):
            has_conditional_logic = f"R | "
            continue

        # only match on functions/calls with interesting names
        # if not any([re.match(interesting_function_regex, s) for interesting_function_regex in interesting_functions]):
        # if not any([re.search(interesting_function_regex, str(node.expression), re.IGNORECASE) for interesting_function_regex in interesting_functions]):
        #     continue

        for ir in node.irs:
            # skip EventCall "emit"
            if type(ir) == EventCall or "SOLIDITY_CALL revert " in str(ir):
                continue

            info = []
            tainted_arg_info = []
        
            # if isinstance(ir, HighLevelCall):
            if hasattr(ir, 'destination') and ir.destination in taints:
                # print(f"Call to tainted address found in {ir}")
                info += [f"\n\t - {isInterestingFunctionPrefix}{has_conditional_logic} Call to tainted addr found in ", node]
                tainted_arg_info += [f"\n\t\t- ({get_ref_or_tmp_name(ir.destination)}) -> \t"] + [val for pair in zip(tainted_locations[ir.destination], ["\n -\t\t\t"] * (len(tainted_locations[ir.destination]) - 1)) for val in pair] + [tainted_locations[ir.destination][-1]] if ir.destination in tainted_locations else []



            if hasattr(ir, 'arguments'):
                if any(arg in taints for arg in ir.arguments):
                    # print(f"Call w/ tainted arguments ({[arg.name for arg in ir.arguments if arg in taints]}) found in {ir}")
                    tainted_args = [arg for arg in ir.arguments if arg in taints]
                    info += [ f"\n\t - {isInterestingFunctionPrefix}{has_conditional_logic} Tainted args ({[arg.name for arg in tainted_args]}) found in ", node]
                    for arg in tainted_args:
                        tainted_arg_info += [f"\n\t\t- ({get_ref_or_tmp_name(arg)}) -> \t"] + [val for pair in zip(tainted_locations[arg], ["\n -\t\t\t"] * (len(tainted_locations[arg]) - 1)) for val in pair] + [tainted_locations[arg][-1]] if arg in tainted_locations else []

                # handles transfer() 
            # print(f"expression here: {ir.expression}")
            # print(dir(ir))
            # print_obj_attributes(ir, 1)
            # print([x.name for x in ir.used])
            # print([x.references for x in ir.used])
            if hasattr(ir, 'call_value') and ir.call_value in taints:
                # print(f"Call w/ tainted arguments ({ir.call_value}) found in {ir}")
                info += [ f"\n\t - {isInterestingFunctionPrefix}{has_conditional_logic} Tainted args ({ir.call_value}) found in ", node]

                # [val for pair in zip(tainted_locations[ir.call_value], ["\n"] * (len(tainted_locations[ir.call_value]) - 1)) for val in pair] + [tainted_locations[ir.call_value][-1]]
                tainted_arg_info += [f"\n\t\t - ({get_ref_or_tmp_name(ir.call_value)}) -> \t"] + [val for pair in zip(tainted_locations[ir.call_value], ["\n -\t\t\t"] * (len(tainted_locations[ir.call_value]) - 1)) for val in pair] + [tainted_locations[ir.call_value][-1]] if ir.call_value in tainted_locations else []
            
            ## catch all
            if not info:
                if hasattr(ir, 'used') and any(arg in taints for arg in ir.used):
                    # print(f"Call w/ tainted arguments ({[arg.name for arg in ir.arguments if arg in taints]}) found in {ir}")
                    tainted_vars = [arg for arg in ir.used if arg in taints]
                    info += [ f"\n\t - {isInterestingFunctionPrefix}{has_conditional_logic} Tainted vars used ({[arg.name for arg in tainted_vars]}) found in ", node]
                    for arg in tainted_vars:
                        tainted_arg_info += [f"\n\t\t- ({get_ref_or_tmp_name(arg)}) -> \t"] + [val for pair in zip(tainted_locations[arg], ["\n -\t\t\t"] * (len(tainted_locations[arg]) - 1)) for val in pair] + [tainted_locations[arg][-1]] if arg in tainted_locations else []



            # has detected 
            if info:
                ## COMMENTING OUT BELOW BECAUSE IT'S VERY VERBOSE, MAY DELETE COMPLETELY LATER + REFACTOR CODE ABOVE
                # info += ["\n\t\t- tainted vars from: "] + tainted_arg_info
                detections.append(info)  
                nodes_output.append(node)
    return detections


# def get_ref_pairs_from_var(v, association_map):
#     refs = [v]
#     pairs = []
#     i = 0
#     print(f"size {len(association_map)}")
#     while True:
#         i += 1
#         print(f"looping {i}")
#         prev_refs_length = len(refs)
#         for (var, ref) in association_map:
#             if var in refs and ref not in refs:
#                 refs.append(ref)

#                 if (var, ref) not in pairs:
#                     pairs.append((var, ref))
#         if len(refs) == prev_refs_length:
#             break

#     return pairs



def get_ref_pairs_from_var(v, association_map):
    global var_pairs_cache
    if v in var_pairs_cache:
        return var_pairs_cache[v]

    refs = [v]
    pairs = []
    while True:
        prev_refs_length = len(refs)
        for var in refs:
            for ref in association_map.get(var, []):
                if ref not in refs:
                    refs.append(ref)

                    if (var, ref) not in pairs:
                        pairs.append((var, ref))
        if len(refs) == prev_refs_length:
            break

    var_pairs_cache[v] = pairs
    return pairs



class CDTaintedVariableUsed_rollup(AbstractDetector):  # pylint: disable=too-few-public-methods
    """
    Documentation
    """

    ARGUMENT = "CD--TaintedVariableUsed_rollup"  # slither will launch the detector with slither.py --mydetector
    HELP = "Help printed by slither"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "x"

    WIKI_TITLE = "Function calls with tainted arguments"
    WIKI_DESCRIPTION = "Check transfer() and other vulnerable functions (especially in loops & without require statements)"
    WIKI_EXPLOIT_SCENARIO = "x"
    WIKI_RECOMMENDATION = "x"


    def _detect(self):
        """
        Detect Boolean constant misuses
        """
        # 5678 is the default attach port in the VS Code debug configurations. Unless a host and port are specified, host defaults to 127.0.0.1
        global index  # used for output file indexes 
        # if index != 0:
        # debugpy.listen(5678)
        # print("Waiting for debugger attach")
        # debugpy.wait_for_client()

        global callstacks_map
        global source_sinks_tuples
        global callstacks_edge_colors
        


        global source_code_lines
        source_code_lines = {}
        for filepath in self.slither.source_code:
            for line in self.slither.source_code[filepath].split("\n"):
                source_code_lines.setdefault(filepath, []).append(line)

        global function_source_map
        function_source_map = {}
        for f in self.compilation_unit.functions_and_modifiers:
            function_source_map.setdefault(f.source_mapping.filename.absolute, []).append(f)


        # source_callstacks = {}
        # sink_callstacks = {}
        callstacks_map = {}
        callstacks_edge_colors = {}
        # state_var_relationships_sources = {}
        # state_var_relationships_sinks = {}


        # # for each import_directive, collect filename of source and import into a map and output to json file
        # source_import_tuples = {}
        # for import_directive in self.compilation_unit.import_directives:
        #     source = import_directive.source_mapping.filename.absolute
        #     import_file = import_directive.filename
            
        #     source_import_tuples.setdefault(source, []).append(import_file)
        
        # open(f"./.vscode/ext-slither-cache/source_import_tuples_{index}.json", "w").write(json.dumps(source_import_tuples, indent=4))


        global function_caller_callee_map
        function_caller_callee_map = {}

        global interface_func_to_impl_func
        interface_func_to_impl_func = {}
        for f in self.compilation_unit.functions:
            # mapping real function "f" to interface function (if it exists)

            # NOTE: moving above shadowed to accomodate contracts that inherit from their own interfaces
            for f_shadowed in f.functions_shadowed:
                interface_func_to_impl_func.setdefault((f_shadowed.contract_declarer.name, f_shadowed.signature_str), []).append(f)

            # do not map override functions to inherited (virtual) functions
            # NOTE: Removing is_override logic, still want to map override functions to interface functions, is_override is checked elsewhere to prevent looking up implementations when evaluating an override function
            # is_override = 'override' in [m.strip() for m in re.split(r'\)| ', f.source_mapping.content.split("{")[0].split(")")[-1])]
            # if 'contract_declarer' in dir(f) and f.contract_declarer.is_interface or is_override:
            if 'contract_declarer' in dir(f) and f.contract_declarer.is_interface:
                continue
            
            # set interface calls to contract declarer (based on naming convention of prefixed "I")
            # TODO: REMOVE IF THIS BREAKS STUFF - unexpected function edges in graph
            if "contract_declarer" in dir(f):
                interface_func_to_impl_func.setdefault((f"I{f.contract_declarer.name}", f.signature_str), []).append(f)

        ## collect entrypoint function callchains + collect public state variable functions
        global public_state_var_functions
        for contract in self.compilation_unit.contracts:
            for pub_var_func in [v for v in contract.state_variables if v.visibility == 'public']:
                public_state_var_functions[pub_var_func.signature_str] = True

            # commented out below to build all callstacks since dynamic functions may be used and only building from known entrypoints will exclude callstacks that have no clear entrypoint
            entrypoint_functions = contract.functions # [function for function in contract.functions if function.visibility in ['public', 'external'] ]  
            entrypoint_callstacks_cache = {}  # not entrypoint callstacks anymore, will rename later
            for f in entrypoint_functions:
                callstacks = get_entrypoint_callstacks(f)
                entrypoint_callstacks_cache[f] = callstacks
                for callstack in callstacks:
                    callstacks_map.setdefault((contractDeclarerOrEmpty(f), f), set()).add(tuple(callstack))


        completed_callstacks = []
        # set variable containing all callstacks
        all_callstacks = []
        for (c, f) in callstacks_map:
            for callstack in callstacks_map[(c, f)]:
                if len(callstack) > 1 and [get_descriptive_function_html(f) for f in callstack] not in completed_callstacks:
                        all_callstacks.append(callstack)
                        completed_callstacks.append([get_descriptive_function_html(f) for f in callstack])
        # NOTE: This function removes duplicate callstacks, however, an edge case is if there are two public functions in a callchain that call eachother.
        # all_callstacks = [arr for arr in all_callstacks if not any(set(arr).issubset(set(other_arr)) for other_arr in all_callstacks if other_arr != arr)] 
        all_callstacks = [arr for arr in all_callstacks if not any(is_subsequence(arr, other_arr) for other_arr in all_callstacks if other_arr != arr)] 
        all_callstacks.sort(key=lambda arr_of_funcs: ''.join([get_descriptive_function_str(f) for f in arr_of_funcs])) 


        unique_functions = set()
        for callstack in all_callstacks:
            for f in callstack:
                unique_functions.add(f)        

        # decorator = 📰🎯💥🟢🔴
        # decorator2 = 📰🟢🔴
        for callstack in all_callstacks:
            decorator = ""
            #
            for f in callstack[::-1]:
                for_func = decorators_in_callstack.get(f, "") + decorator
                decorators_in_callstack[f] = "".join(dict.fromkeys(for_func))
                
                decorator += get_function_decorator(f, False, False)
                decorator = "".join(dict.fromkeys(decorator))


        # get all functions that call functions that modify storage param
        # this is a hahcky solution that may result in false positives
        functions_calls_and_modifies_storage_params = {}
        for contract in self.compilation_unit.contracts:
            for function in contract.functions:
                has_storage_param = any([param in function.variables_written for param in function.parameters if param.is_storage])
                calls_func_w_value = any([f.call_value for f in function.calls_as_expressions])  # updates balance
                # TODO: evaluate if we should track 'transfer' 'delegatecall' etc. as well  --  may need to mark the node itself as tainted
                if has_storage_param or calls_func_w_value:
                    functions_calls_and_modifies_storage_params[get_loc_id(function)] = True

        for callstack in all_callstacks:
            callstacks_contains_func_that_modifies_storage_param = False
            for f in callstack[::-1]:
                if get_loc_id(f) in functions_calls_and_modifies_storage_params:
                    callstacks_contains_func_that_modifies_storage_param = True
                if callstacks_contains_func_that_modifies_storage_param:
                    functions_calls_and_modifies_storage_params[get_loc_id(f)] = True
                    

        ## Start tainted logic

        global KEY
        KEY = "TAINT"
    
        
        global var_ref_association_map
        global var_ref_read_association_map
        global var_ref_written_association_map
        global nodes_output
        global interesting_tainted_function_calls
        global interesting_tainted_strict_comparisons
        global tainted_multiplication
        global tainted_numerator
        global tainted_denominator
        global tainted_addition
        global tainted_subtraction
        global tainted_equality
        global taint_usage_mapping
        global tainted_locations
        results = []


        initial_taint = [
            SolidityVariableComposed("msg.sender"), 
            SolidityVariableComposed("msg.value"), 
            SolidityVariableComposed("msg.data"), 
            SolidityVariableComposed("tx.origin"),
        ]

        texthighlights = {}
        var_colors = {}
        nodes_output = []
        interesting_tainted_function_calls = {}
        interesting_tainted_strict_comparisons = {}
        prev_taints = []
        var_ref_association_map = {}
        var_ref_read_association_map = {}
        var_ref_written_association_map = {}
        taint_usage_mapping = {}
        tainted_locations = {}
        tainted_addition = {}
        tainted_subtraction = {}
        tainted_numerator = {}
        tainted_denominator = {}
        tainted_multiplication = {}
        tainted_equality = []
        self.slither.context[KEY] = initial_taint
        while set(prev_taints) != set(self.slither.context[KEY]):
            prev_taints = self.slither.context[KEY]
            for contract in self.compilation_unit.contracts:
                # taint variables that are modifiable from public/external functions without an `only...` modifier 
                for function in contract.functions:
                    modifiers = [x.name for x in function.modifiers]
                    # NOTE / TO DO: Currently removing functions with 'only...' modifier - may want to include them and add to output
                    if not function.is_constructor and function.visibility in ['public', 'external'] and not any("only" in mod.lower() for mod in modifiers): 
                        # print(f"\nFunction {function.name}")
                        self.slither.context[KEY] = list(set(self.slither.context[KEY] + function.parameters))
                        for param in function.parameters:
                            if param in tainted_locations and function not in tainted_locations[param]: 
                                tainted_locations[param].append(function)
                        visit_node(function.entry_point, [], self.slither.context[KEY], tainted_locations)
                for function in contract.functions_and_modifiers:
                    visit_node_all_functions(function.entry_point, [], function.state_variables_read + [v for v in function.variables if 'is_storage' in dir(v) and v.is_storage])
                        # print(f"All variables tainted : {[str(v) for v in self.slither.context[KEY]]}")

        global var_pairs_cache 
        var_pairs_cache = {}

        new_var_ref_association_map = {}
        for (var, ref) in var_ref_association_map:
            new_var_ref_association_map.setdefault(var, set()).add(ref)


        # cache contract & function for lookup 
        # > inherited function .state_variables_written / .state_variables_read is not populated
        contract_func_map = {}
        functions_in_scope_callstacks = {} # functions that are in callstacks containing non-shadowed functions
        for contract in self.compilation_unit.contracts:
            for f in contract.functions_and_modifiers_declared:
                key = (contract.name, f.signature_str)
                contract_func_map[key] = f

            for f in contract.functions_and_modifiers:
                # collect functions for all callstacks where non-shadowed functions are used
                # this will still include internal state variables that are never read/written to with no entrypoint function (public/external) in the scope summary
                if not f.is_shadowed:
                    functions_in_scope_callstacks.setdefault(contract, set()).add(f)

                    for shadowed in [shadowed for shadowed in f.functions_shadowed if shadowed.contract_declarer == f.contract_declarer and shadowed.signature_str == f.signature_str]:
                        functions_in_scope_callstacks.setdefault(contract, set()).add(shadowed)
                    for callstack in [cs for cs in all_callstacks if f in cs]:
                        for f2 in callstack:
                            functions_in_scope_callstacks.setdefault(contract, set()).add(f2)




        # START highlights


        main_opacity = "0.9"
        background_opacity = "0.3"
        colors = [
            (f"rgba(139, 0, 0, {main_opacity})",    f"rgba(139, 0, 0, {background_opacity})"),    # darkred
            (f"rgba(0, 0, 255, {main_opacity})",    f"rgba(0, 0, 255, {background_opacity})"),    # blue
            (f"rgba(0, 100, 0, {main_opacity})",    f"rgba(0, 100, 0, {background_opacity})"),    # darkgreen
            (f"rgba(218, 165, 32, {main_opacity})", f"rgba(218, 165, 32, {background_opacity})"), # goldenrod
            (f"rgba(128, 0, 128, {main_opacity})",  f"rgba(128, 0, 128, {background_opacity})"),  # purple
            (f"rgba(255, 140, 0, {main_opacity})",  f"rgba(255, 140, 0, {background_opacity})"),  # darkorange
            (f"rgba(165, 42, 42, {main_opacity})",  f"rgba(165, 42, 42, {background_opacity})"),  # brown
            (f"rgba(0, 139, 139, {main_opacity})",  f"rgba(0, 139, 139, {background_opacity})"),  # darkcyan
            (f"rgba(139, 0, 139, {main_opacity})",  f"rgba(139, 0, 139, {background_opacity})"),  # darkmagenta
            (f"rgba(0, 128, 128, {main_opacity})",  f"rgba(0, 128, 128, {background_opacity})"),  # teal
            (f"rgba(128, 0, 0, {main_opacity})",    f"rgba(128, 0, 0, {background_opacity})"),    # maroon
            (f"rgba(0, 0, 128, {main_opacity})",    f"rgba(0, 0, 128, {background_opacity})"),    # navy
            (f"rgba(128, 128, 0, {main_opacity})",  f"rgba(128, 128, 0, {background_opacity})"),  # olive
            (f"rgba(0, 255, 255, {main_opacity})",  f"rgba(0, 255, 255, {background_opacity})"),  # aqua
            (f"rgba(255, 0, 255, {main_opacity})",  f"rgba(255, 0, 255, {background_opacity})")   # fuchsia
        ]


        for c in self.compilation_unit.contracts:
            storage_state_variables = []
            for f in c.functions:
                for v in f.variables:
                    if 'is_storage' in dir(v) and v.is_storage and v not in storage_state_variables:
                        storage_state_variables.append(v)


            for f in c.functions:
                params = [ref for ref in f.parameters if ref not in storage_state_variables]
                for i, param in enumerate(params):
                    var_colors \
                        .setdefault('local', {}) \
                        .setdefault(param, colors[i % len(colors)])
                    
                    for ref in [param.source_mapping] + param.references:
                        loc_obj = {
                                "name": param.name,
                                "type": "param",
                                "line": ref.lines[0],
                                "start": ref.starting_column,
                                "end": ref.ending_column
                            }
                        texthighlights \
                            .setdefault(ref.filename.absolute, {}) \
                            .setdefault(f"border: 3px dashed {colors[i % len(colors)][0]}; ::before~{i}☆~gold", []) \
                            .append(loc_obj)
                        

            state_vars = [ref for ref in c.state_variables_declared] + storage_state_variables
            for i, var in enumerate(state_vars):
                var_colors \
                    .setdefault('state', {}) \
                    .setdefault(var, colors[i % len(colors)])
                
                
                for ref in [var.source_mapping] + var.references:
                    loc_obj = {
                            "name": var.name,
                            "type": "statevar",
                            "line": ref.lines[0],
                            "start": ref.starting_column,
                            "end": ref.ending_column
                        }
                    texthighlights \
                        .setdefault(ref.filename.absolute, {}) \
                        .setdefault(f"background-color: {colors[i % len(colors)][1]}; border: 3px solid {colors[i % len(colors)][0]}; ::before~{i}★~gold", []) \
                        .append(loc_obj)
                    
                                       
        # END highlights



        # collect output
        scope_summary_html = []
        functions_summary_html = []
        state_var_read_written_map = {}
        completed = 0
        for contract in self.compilation_unit.contracts:
            variables = []
            print(f"completed {completed} / {len(self.compilation_unit.contracts)}")
            completed += 1
            # for function in contract.functions:
            solidity_variables_read_detail_map = {}
            state_variables_read_detail_map = {}
            state_variables_written_detail_map = {}
            require_state_vars_used_map = {}
            require_local_vars_used_map = {}
            functions_that_change_state = []
            state_var_potentially_written = []
            for function in functions_in_scope_callstacks.get(contract, []): # NOTE: was .functions ~ revert if breaks
            # for function in contract.functions_and_modifiers: # NOTE: was .functions ~ revert if breaks

                # NOTE: ISSUE: pulling from inherited functions may show variable usage on shadowed functions that may never be called (e.x. via. .super())
                # would need to validate they are in a callstack 
                if 'contract_declarer' in dir(function):
                    function = contract_func_map.get((function.contract_declarer.name, function.signature_str), function)
                

                if [v for v in function.state_variables_written] or any([[var for var in function.variables_written if 'is_storage' in dir(var) and var.is_storage]]) or not function.view or not function.pure:
                    functions_that_change_state.append(function)

                # capture state vars modified in function for contract overview
                local_var_tainted_map = {}

                for node in function.nodes_ordered_dominators:
                    # TO DO: super broken, fix trying to track assignments of state variable to local variables (handles singular assignments of state variables to local variables, tracks them, and marks them as a write node if writing to the local variables properties later)
                    
                    for var in node.local_variables_read:
                        s_var = local_var_tainted_map.get(var, None)
                        if s_var and not is_node_source_mapping_in_array(node, state_variables_read_detail_map.get(get_loc_id(s_var), [])):
                            state_variables_read_detail_map.setdefault(get_loc_id(s_var), []).append(node)

                    for var in node.local_variables_written:
                        s_var = local_var_tainted_map.get(var, None)
                        if s_var and not is_node_source_mapping_in_array(node, state_variables_written_detail_map.get(get_loc_id(s_var), [])):
                            state_variables_written_detail_map.setdefault(get_loc_id(s_var), []).append(node)

                    # must come after local_variables_(read|written) ^ as we mark local variables as tainted for use detection in future nodes
                    # try: 
                    if node.expression and type(node.expression) == AssignmentOperation and node.state_variables_read and node.local_variables_written:
                        local_var_tainted_map[node.local_variables_written[0]] = node.state_variables_read[0]
                    # except:
                    #     debugpy.breakpoint()

                    # track interesting local variables
                    for var in node.solidity_variables_read:
                        # if var.name in ['block.timestamp']:
                        solidity_variables_read_detail_map.setdefault(var, []).append(node)

                    for var in node.state_variables_read + [var for var in node.variables_read if 'is_storage' in dir(var) and var.is_storage]:
                        if not is_node_source_mapping_in_array(node, state_variables_read_detail_map.get(get_loc_id(var), [])):
                            state_variables_read_detail_map.setdefault(get_loc_id(var), []).append(node)
                        
                        # get all references of state variable
                        for (v, ref) in get_ref_pairs_from_var(var, new_var_ref_association_map):
                            for n in var_ref_written_association_map.get((v, ref), []):
                                if not is_node_source_mapping_in_array(n, state_variables_written_detail_map.get(get_loc_id(var), [])):
                                    state_variables_written_detail_map.setdefault(get_loc_id(var), []).append(n)
                            for n in var_ref_read_association_map.get((v, ref), []):
                                if not is_node_source_mapping_in_array(n, state_variables_read_detail_map.get(get_loc_id(var), [])):
                                    state_variables_read_detail_map.setdefault(get_loc_id(var), []).append(n)
                        
                    for var in node.state_variables_written + [var for var in node.variables_written if 'is_storage' in dir(var) and var.is_storage]:
                        if not is_node_source_mapping_in_array(node, state_variables_written_detail_map.get(get_loc_id(var), [])):
                            state_variables_written_detail_map.setdefault(get_loc_id(var), []).append(node)


                    if 'require(' in str(node.expression).lower() or node.is_conditional() or node.contains_require_or_assert():
                        for var in node.state_variables_read:
                            require_state_vars_used_map.setdefault(var, []).append(node)

                    if 'require(' in str(node.expression).lower() or node.is_conditional() or node.contains_require_or_assert():
                        for var in node.variables_read:
                            if var not in node.state_variables_read:
                                require_local_vars_used_map.setdefault(str(var), []).append(node)

            
            # sort state_variables_written_detail_map
            MAX_LINE_CHAR_PER_FILE = 20
            for key in state_variables_written_detail_map:
                # set ljust to 20 characters, padding to sort by line numbers (as strings), expected line numbers of a file to not exceed 20 characters
                state_variables_written_detail_map[key].sort(key = lambda n: f"{n.source_mapping.filename.absolute}#{str(n.source_mapping.lines[0]).ljust(MAX_LINE_CHAR_PER_FILE, '0')}")
            for key in state_variables_read_detail_map:
                # set ljust to 20 characters, padding to sort by line numbers (as strings), expected line numbers of a file to not exceed 20 characters
                state_variables_read_detail_map[key].sort(key = lambda n: f"{n.source_mapping.filename.absolute}#{str(n.source_mapping.lines[0]).ljust(MAX_LINE_CHAR_PER_FILE, '0')}")



            # for function in contract.functions_and_modifiers_declared:
            for function in contract.functions_and_modifiers:
                func_id = get_loc_id(function)
            # for function in contract.functions_declared:
                # if str(function) in ['slitherConstructorVariables', 'slitherConstructorConstantVariables']:
                #     continue

                # check only public/external functions?
                detections = check_call(function, self.slither.context[KEY], tainted_locations)

                # if detections or (function.visibility in ['public', 'external'] and not function.view and not function.pure):
                # info = [f"~ {get_descriptive_function_str(function)} ({len(detections)}) tainted vars in ", function, "\n\n"]

                state_var_read = {}
                state_var_written = {}
                for node in function.nodes_ordered_dominators:
                    for var in node.state_variables_read:
                        state_var_read.setdefault(var, set()).add(node)
                    for var in node.state_variables_written:
                        state_var_written.setdefault(var, set()).add(node)  

                    for var in [v for v in node.local_variables_read if 'is_storage' in dir(v) and v.is_storage]:
                        state_var_read.setdefault(var, set()).add(node)
                        if var not in variables:
                            variables.append(var)
                    for var in [v for v in node.local_variables_written if 'is_storage' in dir(v) and v.is_storage]:
                        state_var_written.setdefault(var, set()).add(node)
                        if var not in variables:
                            variables.append(var)

                # track variables written
                state_vars_summary_html = ""
                written_in_nodes = []
                if function.state_variables_written  + [var for var in function.variables_written if 'is_storage' in dir(var) and var.is_storage]:
                    state_vars_summary_html += "<h3>State Var written in func:</h3>"
                    for var in function.state_variables_written:
                        is_state_or_storage = type(var) == StateVariable or ('is_storage' in dir(var) and var.is_storage) 
                        storage_str = " (storage) " if 'is_storage' in dir(var) and var.is_storage else " "
                        var_color, var_color_w_opacity = var_colors['state'].get(var, ('', '')) if is_state_or_storage else var_colors['local'].get(var, ('', ''))
                        var_color_style = f"background-color: {var_color_w_opacity}; border: 3px solid {var_color}" if is_state_or_storage else f"border: 3px dashed {var_color}"
                        state_vars_summary_html += f"<button class='setStateVar' value='{var.name}~{func_id}'>Set Var</button>{storage_str}<a href='file://{var.source_mapping.filename.absolute}#{var.source_mapping.lines[0]}:{var.source_mapping.starting_column}'><span style='font-weight: bold;{var_color_style}'>{var.name}</span></a> | {var.expression if var.expression else ''}<br>"
                        
                        # output where used in current func
                        for loc in state_var_written[var]:
                            # info += [f"\t{var} @ ", loc, "\n"]
                            html_link = get_function_link(loc.function)
                            state_vars_summary_html += f"(w) {var.name} @ {html_link} <a href='file://{get_source_mapping(loc)}'>{loc.function.contract.name}.{loc.function.name}#{loc.source_mapping.lines[0]}:{loc.source_mapping.starting_column} | {get_function_decorator(loc.function)}</a> | {loc.expression if loc.expression else ''}<br>"
                            
                            calls = [call.function for (con, call) in loc.high_level_calls] + [c.function for c in loc.internal_calls]
                            loc_calls_func_w_storage_param = any([functions_calls_and_modifies_storage_params.get(get_loc_id(f), False) for f in calls if 'parameters' in dir(f)])
                            if (contract, function) == (contractDeclarerOrEmpty(loc.function), loc.function):                            
                                state_var_read_written_map.setdefault(f"{var.name}~{get_loc_id(loc.function)}", set()).add(f"(w)")

                        # output where written from other funcs
                        for loc in state_variables_written_detail_map.get(get_loc_id(var), []):
                            if (contract, function) != (contractDeclarerOrEmpty(loc.function), loc.function): # not in current function
                                html_link = get_function_link(loc.function)
                                state_vars_summary_html += f"&emsp;(w) {var.name} @ {html_link} <a href='file://{get_source_mapping(loc)}'>{contractDeclarerOrEmpty(loc.function)}.{loc.function.name}#{loc.source_mapping.lines[0]}:{loc.source_mapping.starting_column} | {get_function_decorator(loc.function)}</a> | {loc.expression if loc.expression else ''}<br>"
                                written_in_nodes.append((var, loc))
                                state_var_read_written_map.setdefault(f"{var.name}~{get_loc_id(loc.function)}", set()).add("(w)")

                        # output where read from other funcs
                        for loc in remove_duplicates(state_variables_read_detail_map.get(get_loc_id(var), []), lambda loc: get_source_mapping(loc)):
                            if (var, loc) not in written_in_nodes and (contract, function) != (contractDeclarerOrEmpty(loc.function), loc.function): # and not in current function
                                calls = [call.function for (con, call) in loc.high_level_calls] + [c.function for c in loc.internal_calls]
                                loc_calls_func_w_storage_param = any([functions_calls_and_modifies_storage_params.get(get_loc_id(f), False) for f in calls if 'parameters' in dir(f)])
                                html_link = get_function_link(loc.function)
                                state_vars_summary_html += f"&emsp;(r{'*' if loc_calls_func_w_storage_param else ''}) {var.name} @ {html_link} <a href='file://{get_source_mapping(loc)}'>{contractDeclarerOrEmpty(loc.function)}.{loc.function.name}#{loc.source_mapping.lines[0]}:{loc.source_mapping.starting_column} | {get_function_decorator(loc.function)}</a> | {loc.expression if loc.expression else ''}<br>"
                                state_var_read_written_map.setdefault(f"{var.name}~{get_loc_id(loc.function)}", set()).add(f"(r{'*' if loc_calls_func_w_storage_param else ''})")
                    
                    
                        state_vars_summary_html += "<br>"

                # track veraibles read
                
                written_in_nodes = []
                readsStateVars = False
                if function.state_variables_read or any([var for var in function.variables_read if 'is_storage' in dir(var) and var.is_storage]):
                    readsStateVars = True
                    state_vars_summary_html += "<h3>State Var used in func:</h3>"
                    for var in function.state_variables_read + [var for var in function.variables_read if 'is_storage' in dir(var) and var.is_storage]:

                        is_state_or_storage = type(var) == StateVariable or ('is_storage' in dir(var) and var.is_storage) 
                        storage_str = " (storage) " if 'is_storage' in dir(var) and var.is_storage else " "
                        var_color, var_color_w_opacity = var_colors['state'].get(var, ('', '')) if is_state_or_storage else var_colors['local'].get(var, ('', ''))
                        var_color_style = f"background-color: {var_color_w_opacity}; border: 3px solid {var_color}" if is_state_or_storage else f"border: 3px dashed {var_color}"
                        # state_vars_summary_html += f"<a href='file://{var.source_mapping.filename.absolute}#{var.source_mapping.lines[0]}:{var.source_mapping.starting_column}'>{var.name}</a> | {var.expression if var.expression else ''}<br>"
                        state_vars_summary_html += f"<button class='setStateVar' value='{var.name}~{func_id}'>Set Var</button>{storage_str}<span style='font-weight: bold;{var_color_style}'><a href='file://{var.source_mapping.filename.absolute}#{var.source_mapping.lines[0]}:{var.source_mapping.starting_column}'>{var.name}</a></span> | {var.expression if var.expression else ''}<br>"
                        
                        # output usage in function
                        for loc in state_var_read[var]:
                            # info += [f"\t{var} @ ", loc, "\n"]
                            calls = [call.function for (con, call) in loc.high_level_calls] + [c.function for c in loc.internal_calls]
                            loc_calls_func_w_storage_param = any([functions_calls_and_modifies_storage_params.get(get_loc_id(f), False) for f in calls if 'parameters' in dir(f)])

                            html_link = get_function_link(loc.function)
                            state_vars_summary_html += f"(r{'*' if loc_calls_func_w_storage_param else ''}) {var.name} @ {html_link} <a href='file://{get_source_mapping(loc)}'>{loc.function.contract.name}.{loc.function.name}#{loc.source_mapping.lines[0]}:{loc.source_mapping.starting_column} | {get_function_decorator(loc.function)}</a> | {loc.expression if loc.expression else ''}<br>"

                            if (contract, function) == (contractDeclarerOrEmpty(loc.function), loc.function):                            
                                state_var_read_written_map.setdefault(f"{var.name}~{get_loc_id(loc.function)}", set()).add(f"(r{'*' if loc_calls_func_w_storage_param else ''})")

                        # output where written in other functions
                        for loc in state_variables_written_detail_map.get(get_loc_id(var), []):
                            if (contract, function) != (contractDeclarerOrEmpty(loc.function), loc.function): # not in current function
                                html_link = get_function_link(loc.function)
                                state_vars_summary_html += f"&emsp;(w) {var.name} @ {html_link} <a href='file://{get_source_mapping(loc)}'>{contractDeclarerOrEmpty(loc.function)}.{loc.function.name}#{loc.source_mapping.lines[0]}:{loc.source_mapping.starting_column} | {get_function_decorator(loc.function)}</a> | {loc.expression if loc.expression else ''}<br>"
                                written_in_nodes.append((var, loc))
                                state_var_read_written_map.setdefault(f"{var.name}~{get_loc_id(loc.function)}", set()).add("(w)")

                        # output where read in other functions
                        for loc in remove_duplicates(state_variables_read_detail_map.get(get_loc_id(var), []), lambda loc: get_source_mapping(loc)):
                            if (contract, function) != (contractDeclarerOrEmpty(loc.function), loc.function): # not in current function
                                calls = [call.function for (con, call) in loc.high_level_calls] + [c.function for c in loc.internal_calls]
                                loc_calls_func_w_storage_param = any([functions_calls_and_modifies_storage_params.get(get_loc_id(f), False) for f in calls if 'parameters' in dir(f)])

                                html_link = get_function_link(loc.function)
                                state_vars_summary_html += f"&emsp;(r{'*' if loc_calls_func_w_storage_param else ''}) {var.name} @ {html_link} <a href='file://{get_source_mapping(loc)}'>{contractDeclarerOrEmpty(loc.function)}.{loc.function.name}#{loc.source_mapping.lines[0]}:{loc.source_mapping.starting_column} | {get_function_decorator(loc.function)}</a> | {loc.expression if loc.expression else ''}<br>"
                                written_in_nodes.append((var, loc))
                                state_var_read_written_map.setdefault(f"{var.name}~{get_loc_id(loc.function)}", set()).add(f"(r{'*' if loc_calls_func_w_storage_param else ''})")
                    
                        state_vars_summary_html += "<br>"

                if function.solidity_variables_read:
                    state_vars_summary_html += "<h3>Solidity Var used in func:</h3>"
                    for var in function.solidity_variables_read:
                        state_vars_summary_html += f"{var.name}<br>"
                        # output usage in functions
                        for loc in solidity_variables_read_detail_map.get(var, []):
                            # info += [f"\t{var} @ ", loc, "\n"]
                            html_link = get_function_link(loc.function)
                            state_vars_summary_html += f"{var.name} @ {html_link} <a href='file://{get_source_mapping(loc)}'>{loc.function.contract.name}.{loc.function.name}#{loc.source_mapping.lines[0]}:{loc.source_mapping.starting_column} | {get_function_decorator(loc.function)}</a> | {loc.expression if loc.expression else ''}<br>"
                        state_vars_summary_html += "<br>"

                # END INSERT ENTRYPOINT CALLCHAINS

                # START CHECKBOXES TO CHECK
                checkbox_ids_to_check = []
                for var in function.state_variables_read + function.state_variables_written:
                    checkbox_ids_to_check.append(f"statevar-{var.signature_str}")
                    # checkbox_ids_to_check.append(f"statevar-storage-{var.name}")

                for mod in function.modifiers:
                    checkbox_ids_to_check.append(f"modifier-{mod.signature_str}")
                # END CHECKBOXES TO CHECK
                

                tainted_locations_html = ""
                for d in detections:
                    # info += d
                    if "tainted" in d[0].lower():
                        tainted_locations_html += d[0].replace('\n','<br>').replace('\t', '&emsp;')
                        loc = f"{d[1].source_mapping.filename.absolute}#{d[1].source_mapping.lines[0]}:{d[1].source_mapping.starting_column}"
                        tainted_locations_html += f"<a href='file://{loc}'>{loc}</a>"
                

                ## collect for HTML output
                # PoolManager.updateTrancheTokenMetadata 
                entrypoint_callstacks_indexes = get_callstacks_from_node(function, all_callstacks, 'entry')
                exit_callstacks_indexes = get_callstacks_from_node(function, all_callstacks, 'exit')
                other_callstacks_indexes = get_callstacks_from_node(function, all_callstacks, 'other')
                tainted_locations_count = sum(["tainted" in d[0].lower() for d in detections])


                externalCalls = "🌀 = has external calls\n" if function.external_calls_as_expressions else ""
                has_array_type_parameter = '💤 = has array params, check if duplicates are handled\n' if any([var_contains_type(p, ArrayType, ReturnContext=True) for p in function.parameters]) else ''
                function_notes = f"{externalCalls}{has_array_type_parameter}"


                filepath = f"{function.source_mapping.filename.absolute}#{function.source_mapping.lines[0]}:{function.source_mapping.starting_column}"

                parameters = "(" + ", ".join([f"{p.type}{f' {p.location} ' if p.location in ['storage', 'calldata'] else ' '}{p.name}" for p in function.parameters]) + ")" if function.parameters else "" 
                return_types =  "(" + ", ".join([f"{p.type}{f' {p.location} ' if p.location in ['storage', 'calldata'] else ' '}{p.name}" for p in function.returns]) + ")" if function.returns else "" 


                shadows_functions_html = ""
                for f in contract.functions:
                    if function == f:
                        continue
                    if f.is_shadowed and f.name == function.name:
                        shadows_functions_html += f"{get_descriptive_function_html(f)}<br>"
                if shadows_functions_html:
                    shadows_functions_html = f"<h3>Shadowed Functions:</h3>{shadows_functions_html}"

                # external calls data
                external_calls_html = ""
                for call in [c for c in function.high_level_calls if type(c[1]) != LibraryCall]:
                    external_calls_html += f"<a href='file://{get_source_mapping(call[1].node)}'>{call[1].node.source_mapping.content}</a><br>"
                for call in function.low_level_calls:
                    external_calls_html += f"<a href='file://{get_source_mapping(call.node)}'>{call.node.source_mapping.content}</a><br>"
                
                if external_calls_html:
                    external_calls_html = f"<h3>External Calls</h3>{external_calls_html}<br><br>"


                f_obj = {
                    "id": func_id,
                    "functionName": function.name,
                    "scope_id": get_loc_id(contract),
                    "scopeName": f"{contract.name}",
                    "functionParameters": parameters,
                    "functionReturns": return_types,
                    "startLine": function.source_mapping.lines[0],
                    "endLine": function.source_mapping.lines[-1],
                    "startCol": function.source_mapping.starting_column,
                    "filepath": f"{filepath}",
                    "filepath_body": f"{filepath}",
                    "qualifiedName_full": "",
                    "qualifiedName": f"{str(contractDeclarerOrEmpty(function))}.{str(function)}",
                    "filename": function.source_mapping.filename.absolute.split("/")[0],
                    "decorator": f"📰{get_function_decorator(function)}" if readsStateVars else "" + get_function_decorator(function),
                    "function_notes": function_notes,
                    "modifiers": [str(m.name) for m in function.modifiers],
                    "entrypoint_callstacks": entrypoint_callstacks_indexes,
                    "exit_callstacks": exit_callstacks_indexes,
                    "other_callstacks": other_callstacks_indexes,
                    "state_vars_summary_html": state_vars_summary_html,
                    "function_summary_html": f"{function.signature_str}<br><br>{external_calls_html}", # f"<div id='{function.name},{function.source_mapping.filename.absolute}#{function.source_mapping.lines[0]}' class='function-summary'><h2>({tainted_locations_count}) {get_descriptive_function_html(function)}</h2><br>{state_vars_summary_html}",
                    "tainted_locations_count": tainted_locations_count,
                    "tainted_locations_html": tainted_locations_html,
                    "checkbox_ids_to_check": checkbox_ids_to_check,
                    "is_inherited": function.contract != function.contract_declarer,
                    "is_shadowed": function.is_shadowed,
                    "additional_info_html": shadows_functions_html,
                    "called_at": list(set(flatten([[get_source_mapping(ref, -1) for ref in f.references] for f in [function] + list(function_caller_callee_map.get(get_loc_id(function), []))])))
                }
                functions_summary_html.append(f_obj)
                ## END collect for HTML output

                # TEMPORARILY COMMENTING OUT, CLEAN UP CODE WHEN DELETING COMPLETELY
                # res = self.generate_result(info)
                # results.append(res)
                nodes_output.append(function)



            immutable_vars = []
            # get variables of contract + inherited contracts
            # variables = []
            for inherited_contract in contract.inheritance_reverse:
                for v in inherited_contract.variables:
                    if (v.is_constant or v.is_immutable) and v not in immutable_vars:
                        immutable_vars.append(v)
                    elif not v.is_constant and not v.is_immutable and v not in variables:
                        variables.append(v)

            for v in contract.variables:
                if (v.is_constant or v.is_immutable) and v not in immutable_vars:
                    immutable_vars.append(v)
                elif not v.is_constant and not v.is_immutable and v not in variables:
                    variables.append(v)

            
            # get storage slots of variables
            storage_slots_html = f"forge inspect {contract.source_mapping.filename.relative}:{contract.name} storage<br><br>"

            # prefix storage slots with immutable and constant vars
            if immutable_vars:
                storage_slots_html += "<h3>Immutable and Constant Vars</h3>"
            for v in immutable_vars:
                ## UPDATE HERE
                is_state_or_storage = type(v) == StateVariable or ('is_storage' in dir(v) and v.is_storage) 
                storage_str = " (storage) " if 'is_storage' in dir(v) and v.is_storage else " "
                var_color, var_color_w_opacity = var_colors['state'].get(v, ('', '')) if is_state_or_storage else var_colors['local'].get(v, ('', ''))
                var_color_style = f"background-color: {var_color_w_opacity}; border: 3px solid {var_color}" if is_state_or_storage else f"border: 3px dashed {var_color}"
                storage_slots_html += f"<span><input type='checkbox' id='statevar-{v.signature_str}' style='vertical-align: middle'>{storage_str}<a href='file://{v.source_mapping.filename.absolute}#{v.source_mapping.lines[0]}:{v.source_mapping.starting_column}'><span style='font-weight: bold;{var_color_style}'>{v.name}</span></a> | {v.expression if v.expression else ''}</span><br>"
                
                written_in_nodes = []

                for loc in state_variables_written_detail_map.get(get_loc_id(v), []):
                    html_link = get_function_link(loc.function)
                    loc_text = f"<a value='{get_loc_id(loc.function)}' href='file://{get_source_mapping(loc)}'>{get_descriptive_function_str(loc._function)}#L{loc.source_mapping.lines[0]}</a> | {str(loc.expression)}"
                    storage_slots_html += f"<div class='collapsable'>&emsp;<input type='checkbox' id='{v.name}~{get_loc_id(loc.function)}' style='vertical-align: middle'></input>{'(i) ' if loc._function.is_declared_by(contract) else ''}(w) {html_link} {loc_text}</div>"
                    written_in_nodes.append((v, loc))
                    

                possible_write_html = ""
                read_html = ""
                for loc in remove_duplicates(state_variables_read_detail_map.get(get_loc_id(v), []), lambda loc: get_source_mapping(loc)):
                    if (v, loc) in written_in_nodes:
                        continue
                    html_link = get_function_link(loc.function)
                    loc_text = f"<a value='{get_loc_id(loc.function)}' href='file://{get_source_mapping(loc)}'>{get_descriptive_function_str(loc._function)}#L{loc.source_mapping.lines[0]}</a> | {str(loc.expression)}"
                    # attempt to find passed by reference variables and if they are written to - will not find complex cases or multiple levels of calls
                    calls = [call.function for (con, call) in loc.high_level_calls] + [c.function for c in loc.internal_calls]
                    loc_calls_func_w_storage_param = any([functions_calls_and_modifies_storage_params.get(get_loc_id(f), False) for f in calls if 'parameters' in dir(f)])
                    html = f"<div class='collapsable'>&emsp;<input type='checkbox' id='{v.name}~{get_loc_id(loc.function)}' style='vertical-align: middle'>{'(i) ' if loc._function.is_declared_by(contract) else ''}(r{'*' if loc_calls_func_w_storage_param else ''}) {html_link} {loc_text}</div>"
                    if loc_calls_func_w_storage_param:
                        possible_write_html += html
                        state_var_potentially_written.append(v)
                    else:
                        read_html += html

                storage_slots_html += possible_write_html
                storage_slots_html += read_html



                storage_slots_html += f"<br>"
            if immutable_vars:
                storage_slots_html += "<br>"

            # Run the command and capture its output
            try:
                result = subprocess.run(["forge", "inspect", f"{contract.source_mapping.filename.relative}:{contract.name}", "storage", "--json"], capture_output=True, text=True)
                storage = json.loads(result.stdout)['storage']
            except:
                storage = []

            headers = ['cb', 'label', 'type', 'slot', 'offset']

            storage_slots_html += "<table><tr>"
            for h in headers:
                storage_slots_html += f"<th>{h}</th>"
            storage_slots_html += "</tr>"

            # add data
            for row in storage:
                storage_slots_html += "<tr>"
                for k in headers:
                    if k == 'cb':
                        storage_slots_html += f"<td><input style='vertical-align: middle' type='checkbox' id='statevar-toc-{row['label']}'></input></td>"
                    else:
                        data = f"<td>{str(row[k])}</td>"
                        if k == 'label':
                            data = f"<td><a href='scrollTo:[id^=\"statevar-{row[k]}(\"]:1'>{str(row[k])}</a></td>"
                            

                        storage_slots_html += data
                storage_slots_html += "</tr>"
            storage_slots_html += "</table>"

            # size_sum = 0
            # slot_index = 0
            # storage_slots_html += f"{slot_index} | "
            # # [v.name for v in contract.variables if not v.is_constant and not v.is_immutable]
            # try:
            #     for v in variables:
            #         size, _ = v.type.storage_size
            #         size_sum += size
            #         # start new slot if doesn't fit in current slot
            #         if size_sum > 32:
            #             slot_index += 1
            #             size_sum = size_sum - 32
            #             storage_slots_html += f"<br>{slot_index} | "
            #         # add var info
            #         storage_slots_html += f"<input style='vertical-align: middle' type='checkbox' {'checked' if v.name in [v.name for v in contract.variables] else ''}></input> {v.contract.name}.{v.name} ({str(v.type)}) - {size} | "
            #         # append blank slots
            #         while size_sum > 32:
            #             slot_index += math.floor(size_sum / 32)
            #             storage_slots_html += f"<br>... {slot_index} | "
            #             size_sum = 0
            # except:
            #     storage_slots_html += "<br>Error parsing storage slots"
                



            fuzz_template_file_content = f"""
// SPDX-License-Identifier: GPL-2.0
pragma solidity ^0.8.0;

import {{BaseTargetFunctions}} from "@chimera/BaseTargetFunctions.sol";
import {{BeforeAfter}} from "./BeforeAfter.sol";
import {{Properties}} from "./Properties.sol";
import {{vm}} from "@chimera/Hevm.sol";

import "{contract.source_mapping.filename.absolute}";

abstract contract TargetFunctions is BaseTargetFunctions, Properties, BeforeAfter {{

    {contract.name} c_{contract.name.lower()};

    // constructor() {get_function_decorator(contract.constructor, True, decorators_in_callstack)}
    constructor({", ".join([f"{p.type} {p.location} {p.name}" for p in f.parameters])}) {{
        // c_{contract.name.lower()} = {contract.name}(0x000000000000000000);     // address of deployed contract - set rpc_url
        c_{contract.name.lower()} = new {contract.name}(); // TODO: Add parameters here
    }}

    function send_eth(uint256 amount) public {{
        // if ERC tokens are involved, consider creating functions to send those as well directly to the contract (using .transfer())
        vm.prank(msg.sender);
        (bool sent, bytes memory data) = address(c_{contract.name.lower()}).call{{value: msg.value}}("");
        require(sent, "Failed to send Ether");
    }}
"""
            for f in [f for f in contract.functions if f.is_implemented and f.visibility in ['public', 'external'] and f.name not in ['constructor']]:
                ## comment out if want to include pure/view functions in fuzzing template, commenting out to reduce clutter
                if f.pure or f.view:
                    continue
                
                return_var_options = "abcdefghijklmnopqrstuvwxyz"
                return_var_poiner = 0

                params = ", ".join([f"{p.type} {p.location if type(p.type) != ElementaryType else ''} {p.name}" for p in f.parameters])
                params_no_types = ", ".join([f"{p.name}" for p in f.parameters])

                returns = []
                for ret in f.returns:
                    ret_location = f" {ret.location} " if type(ret.type) != ElementaryType else " "
                    if ret.name:
                        returns.append(f"{ret.type}{ret_location}{ret.name}")
                    else:
                        # TODO: remove 'memoroy' from uint256, address, etc.
                        returns.append(f"{ret.type}{ret_location}{return_var_options[return_var_poiner]}")
                        return_var_poiner += 1
                returns = ", ".join(returns)

                fuzz_template_file_content += f"""
    // {f"(inherited by {f.contract})" if f.contract != f.contract_declarer else ""} {f.contract_declarer.name}.{f.name} {get_function_decorator(f, True, decorators_in_callstack)} \t\t\t file://{f.source_mapping.filename.absolute}#{f.source_mapping.lines[0]}:{f.source_mapping.starting_column}
    {"/*" if f.pure or f.view else ""} function {f.contract.name}{"_i_" if f.contract != f.contract_declarer else "_"}{f.name}({params}) public {{
        vm.prank(msg.sender);
        {f"({returns}) = " if returns else ""}c_{f.contract.name.lower()}.{f.name}({params_no_types});
    }} {"*/" if f.pure or f.view else ""}
"""
            fuzz_template_file_content += "}"
            fuzz_template_file_content_b64 = base64.b64encode(fuzz_template_file_content.encode('utf-8')).decode('utf-8')
            fuzz_testing_html = f"<button data-filename='TargetFunctions.sol' value='openfile://{fuzz_template_file_content_b64}'>Fuzz Template</button>"


            # vs code contract summary
            contract_summary_obj = {
                "id": get_loc_id(contract),
                "name": f"{contract.name}",
                "type": f"{contract.contract_kind}",
                "state_vars_html": "",
                "inherits": [get_loc_id(c) for c in contract.immediate_inheritance if c != None],
                "inherits_recursive": [get_loc_id(c) for c in contract.inheritance if c != None],
                "backgroundColor": "yellow" if contract.is_library else "",
                "storage_slots_html": storage_slots_html,
                "fuzz_testing_html": fuzz_testing_html
            }

            scope_state_variables = []
            # for v in contract.state_variables:
            for v in variables:
                # hyperlink w/ source mapping?
                written_in_nodes = []
                
                is_state_or_storage = type(v) == StateVariable or ('is_storage' in dir(v) and v.is_storage)
                storage_str = ' (storage) ' if 'is_storage' in dir(v) and v.is_storage else ''
                var_color, var_color_w_opacity = var_colors['state'].get(v, ('', '')) if is_state_or_storage else var_colors['local'].get(v, ('', ''))
                var_color_style = f"background-color: {var_color_w_opacity}; border: 3px solid {var_color}" if is_state_or_storage else f"border: 3px dashed {var_color}"
                hasMappingToEnum = '🔶 ' if var_contains_type(v, EnumContract) else ''
                var_text = f"{hasMappingToEnum}{'(i) ' if 'is_declared_by' in dir(v) and not v.is_declared_by(contract) else ''}{'(const) ' if v.is_constant else ''}{'(immutable) ' if 'is_immutable' in dir(v) and v.is_immutable else ''}{v.canonical_name}"
                var_html = f"<span><button class='setStateVar' value='{v.name}~{func_id}'>Set Var</button>{storage_str}<input type='checkbox' id='statevar-{v.signature_str}' style='vertical-align: middle'><span style='font-weight: bold;{var_color_style}'><a href='file://{v.source_mapping.filename.absolute}#{v.source_mapping.lines[0]}:{v.source_mapping.starting_column}'>{var_text}</a></span> | {v.expression if v.expression else ''}</span>"

                for loc in state_variables_written_detail_map.get(get_loc_id(v), []):
                    html_link = get_function_link(loc.function)
                    loc_text = f"<a value='{get_loc_id(loc.function)}' href='file://{get_source_mapping(loc)}'>{get_descriptive_function_str(loc._function)}#L{loc.source_mapping.lines[0]}</a> | {str(loc.expression)}"
                    var_html += f"<div class='collapsable'>&emsp;<input type='checkbox' id='{v.name}~{get_loc_id(loc.function)}' style='vertical-align: middle'></input>{'(i) ' if loc._function.is_declared_by(contract) else ''}(w) {html_link} {loc_text}</div>"
                    written_in_nodes.append((v, loc))
                    

                possible_write_html = ""
                read_html = ""
                for loc in remove_duplicates(state_variables_read_detail_map.get(get_loc_id(v), []), lambda loc: get_source_mapping(loc)):
                    if (v, loc) in written_in_nodes:
                        continue
                    html_link = get_function_link(loc.function)
                    loc_text = f"<a value='{get_loc_id(loc.function)}' href='file://{get_source_mapping(loc)}'>{get_descriptive_function_str(loc._function)}#L{loc.source_mapping.lines[0]}</a> | {str(loc.expression)}"
                    # attempt to find passed by reference variables and if they are written to - will not find complex cases or multiple levels of calls
                    calls = [call.function for (con, call) in loc.high_level_calls] + [c.function for c in loc.internal_calls]
                    loc_calls_func_w_storage_param = any([functions_calls_and_modifies_storage_params.get(get_loc_id(f), False) for f in calls if 'parameters' in dir(f)])
                    html = f"<div class='collapsable'>&emsp;<input type='checkbox' id='{v.name}~{get_loc_id(loc.function)}' style='vertical-align: middle'>{'(i) ' if loc._function.is_declared_by(contract) else ''}(r{'*' if loc_calls_func_w_storage_param else ''}) {html_link} {loc_text}</div>"
                    if loc_calls_func_w_storage_param:
                        possible_write_html += html
                        state_var_potentially_written.append(v)
                    else:
                        read_html += html
                var_html += possible_write_html + read_html
                scope_state_variables.append(var_html)
                # get all locations where set?
            contract_summary_obj['state_vars_html'] = "<br>".join(scope_state_variables)


            # create detection for state variables not read/written
            for v in variables:
                v_id = get_loc_id(v)
                if v_id not in state_variables_written_detail_map and v_id not in state_var_potentially_written:
                    info = [f"state var not written: ({v})", contract]
                    res = self.generate_result(info)
                    results.append(res)

                if v_id not in state_variables_read_detail_map:
                    info = [f"state var not read: ({v})", contract]
                    res = self.generate_result(info)
                    results.append(res)




            solidity_vars_used_str = "<br><h2>Solidity Vars Used</h2>" if len(solidity_variables_read_detail_map) > 0 else ""
            for var in solidity_variables_read_detail_map:
                solidity_vars_used_str += f"{var.name}<br>"
                # var_html = f"<span><button class='setStateVar' value='{var.name}~{func_id}'>Set Var</button> <input type='checkbox' id='statevar-{var.name}'>{var.name}</a></span>"
                # solidity_vars_used_str += var_html

                for loc in solidity_variables_read_detail_map[var]:
                    # info += [f"\t{var} @ ", loc, "\n"]
                    html_link = get_function_link(loc.function)
                    solidity_vars_used_str += f"{var.name} @ {html_link} <a href='file://{get_source_mapping(loc)}'>{loc.function.contract.name}.{loc.function.name}#{loc.source_mapping.lines[0]}:{loc.source_mapping.starting_column} | {get_function_decorator(loc.function)}</a> | {loc.expression if loc.expression else ''}<br>"
                solidity_vars_used_str += "<br>"
            contract_summary_obj['state_vars_html'] += solidity_vars_used_str


            # add external calls to scope
            external_calls_html = ""
            for function in contract.functions:
                for call in [c for c in function.high_level_calls if type(c[1]) != LibraryCall]:
                    external_calls_html += f"<a href='file://{get_source_mapping(call[1].node)}'>{get_descriptive_function_str(function)}</a> | {call[1].node.source_mapping.content}<br>"
                for call in function.low_level_calls:
                    external_calls_html += f"<a href='file://{get_source_mapping(call.node)}'>{get_descriptive_function_str(function)}</a> | {call.node.source_mapping.content}<br>"
            
            if external_calls_html:
                external_calls_html = f"<h3>External Calls</h3>{external_calls_html}<br><br>"
                contract_summary_obj['state_vars_html'] += external_calls_html


            scope_modifiers = []
            for mod in contract.modifiers:
                if mod.contract.is_interface:
                    continue
                modifier_text = f"{'(i) ' if not mod.is_declared_by(contract) else ''}{mod.canonical_name}"
                modifier_html = f"<span><input type='checkbox' id='modifier-{mod.signature_str}' style='vertical-align: middle'>&nbsp;<a href='file://{mod.source_mapping.filename.absolute}#{mod.source_mapping.lines[0]}:{mod.source_mapping.starting_column}'>{modifier_text}</a></span>"

                excluded_functions = []
                for f in contract.functions:
                    if mod in f.modifiers:
                        modifier_html += f"<div class='collapsable'>&emsp;{get_descriptive_function_html(f)}</div>"
                    elif not f.contract_declarer.is_interface and f.is_implemented and not f.is_shadowed:  # shdowed functions may be called using super() which may be an edge case to consider when manually reviewing
                        excluded_functions.append(f)
                for f in excluded_functions:
                    modifier_html += f"<div class='collapsable-2'>!&emsp;{get_descriptive_function_html(f)}</div>"
                        

                scope_modifiers.append(modifier_html)
            contract_summary_obj['modifiers_html'] = "<br>".join(scope_modifiers)
            

            scope_functions = []
            for f in contract.functions:
                if (hasattr(f, 'contract_declarer') and f.contract_declarer.is_interface) or not f.is_implemented or f.is_shadowed:
                    continue
                function_html = f"<div><input type='checkbox' style='vertical-align: middle' id='function-{get_loc_id(f)}' >&nbsp;{'(i) ' if not f.is_declared_by(contract) else ''}{get_descriptive_function_html(f)}</div>"
                
                for (caller_func, ref, code) in get_func_usage(f, self):
                    function_html += f"<div class='collapsable-2'>&emsp;&emsp;&emsp;&emsp;<a href='file://{get_source_mapping(ref)}'>{get_descriptive_function_str(caller_func)}</a> | {code}</div>"
                scope_functions.append(function_html)
            contract_summary_obj['functions_html'] = "".join(scope_functions)
            

            # this is overridden in combine_slither_vscode.py (looking for related contracts/functions)
            contract_summary_obj["scope_summary_html"] = f"""
            <h2>State Vars</h2>
            {contract_summary_obj['state_vars_html']}
            <h2>Modifiers</h2>
            {contract_summary_obj['modifiers_html']}
            <h2>Functions</h2>
            {contract_summary_obj['functions_html']}
            """

            scope_summary_html.append(contract_summary_obj)
            # END Contract Summary



        ## Other detections
        for node in tainted_equality:
            info = [f".Tainted Equality (both sides)  | {get_descriptive_function_str(node._function)} | ", node]
            res = self.generate_result(info)
            results.append(res)

        for node in tainted_addition:
            info = [f".Tainted Addition | {get_descriptive_function_str(node._function)} | {[get_ref_or_tmp_name(var) for var in tainted_addition[node]]}: ", node]
            res = self.generate_result(info)
            results.append(res)

        for node in tainted_subtraction:
            info = [f".Tainted Subtraction | {get_descriptive_function_str(node._function)} | {[get_ref_or_tmp_name(var) for var in tainted_subtraction[node]]}: ", node]
            res = self.generate_result(info)
            results.append(res)

        for node in tainted_numerator:
            info = [f".Tainted Numerator | {get_descriptive_function_str(node._function)} | {[get_ref_or_tmp_name(var) for var in tainted_numerator[node]]}: ", node]
            res = self.generate_result(info)
            results.append(res)
            
        for node in tainted_denominator:
            info = [f".Tainted Denominator | {get_descriptive_function_str(node._function)} | {[get_ref_or_tmp_name(var) for var in tainted_denominator[node]]}: ", node]
            res = self.generate_result(info)
            results.append(res)

        for node in tainted_multiplication:
            info = [f".Tainted Multiplication | {get_descriptive_function_str(node._function)} | {[get_ref_or_tmp_name(var) for var in tainted_multiplication[node]]}: ", node]
            res = self.generate_result(info)
            results.append(res)
        
        # FIX
        taints = self.slither.context[KEY]
        for node in interesting_tainted_strict_comparisons:
            info = []
            for ir in interesting_tainted_strict_comparisons[node]:
                info += [
                    f".Interesting comparison | {get_descriptive_function_str(node._function)} ({get_ref_or_tmp_name(ir.type.value)}) ({get_ref_or_tmp_name(ir.variable_left) if ir.variable_left in taints else ''} {ir.type.value} {get_ref_or_tmp_name(ir.variable_right) if ir.variable_right in taints else ''}) | ",
                    node,
                    " may be interesting.:\n\t-",
                    node._function,
                    "\n",
                ]
            # info = interesting_tainted_strict_comparisons[node][0]
            res = self.generate_result(info)
            results.append(res)  

        # FIX
        for node in interesting_tainted_function_calls:
            for info in interesting_tainted_function_calls[node]:
                res = self.generate_result(info)
                results.append(res)  

        print(
            f"All state variables tainted : {[str(v) for v in prev_taints if isinstance(v, StateVariable)]}"
        )



        index += 1

        open(f''.join([f'./.vscode/ext-slither-cache/texthighlights_{index}.json']), 'w').write(json.dumps(texthighlights))

        f = open(f'./.vscode/ext-slither-cache/callstacks_{index}.html', 'w')
        for callstack in all_callstacks:
            f.write(" > ".join([get_descriptive_function_html(f) for f in callstack]) + "<br>\n")

        open(f'./.vscode/ext-slither-cache/functions_html_{index}.json', 'w').write(json.dumps(functions_summary_html))

        open(f'./.vscode/ext-slither-cache/scope_summaries_html_{index}.json', 'w').write(json.dumps(scope_summary_html))


        all_callstack_indexes = []
        for callstack in all_callstacks:
            all_callstack_indexes.append([get_func_source(f) for f in callstack])
        open(f'./.vscode/ext-slither-cache/callstacks_{index}.json', 'w').write(json.dumps(all_callstack_indexes))


        helpHTML = """Function icons:
        🎯 = funcInScope
        🔴 = Updates state 
        ❌ = modifierRestricted (if any("only" in mod.lower() for mod in modifiers))
        🟢 = view or Pure
        💲 = payable
        🌀 = externalCalls 
        💥 = entrypoint function
        💤 = has parameter(s) with array
        🔀 = (potential) cross contract state variable
        📰 = reads state vars

        Variable Icons:
        🔶 = Has Enum in mapping()  (default value = first enum value)
        
        <a href='https://unicode-explorer.com/emoji/'>More unicode options | https://unicode-explorer.com/emoji/</a>'
        """
        helpHTML = helpHTML.replace("\n", "<br>")
        open(f'./.vscode/ext-static-analysis/help.html', 'w').write(helpHTML)



        # output state var read/written map
        # convert to array so we can dump as JSON
        for var_at in state_var_read_written_map:
            state_var_read_written_map[var_at] = list(state_var_read_written_map[var_at])
        open(f'./.vscode/ext-slither-cache/func_state_var_read_written_mapping_{index}.json', 'w').write(json.dumps(state_var_read_written_map))

        open(f'./.vscode/ext-slither-cache/func_call_edge_colors_{index}.json', 'w').write(json.dumps(callstacks_edge_colors))

        return results
