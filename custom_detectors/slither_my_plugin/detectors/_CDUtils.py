from slither.core.declarations.function import Function
from slither.core.declarations.contract import Contract
from slither.core.declarations.modifier import Modifier
from slither.slithir.operations.library_call import LibraryCall
from slither.core.declarations.solidity_variables import SolidityVariable



# import custom util functions
# from slither_my_plugin.detectors._CDUtils import *

global public_state_var_functions
public_state_var_functions = {}




# def repeat_char(char: str, num_times: int) -> str:
#     return char * num_times

def get_func_source(f: Function):
    return f'{f},{f.source_mapping.filename.absolute}#{f.source_mapping.lines[0]}:{f.source_mapping.starting_column}'



def contractDeclarerOrEmpty(f):
    try:
        return f.contract_declarer
    except:
        return ""

def get_function_decorator(function: Function, includeModifiers: bool = True, decorators_in_callstack = {}, decorator_prefix: str = ''):
    # if decorators_in_callstack is defined, include decorators in callstack

    if not function:
        return ""

    if type(function) == str:
        return function

    # has_exeternal_calls = '🌀' if any(
    #     not (type(call.called) == MemberAccess and
    #     'value' in dir(call.called.expression) and
    #     type(call.called.expression.value) == Contract and
    #     getattr(call.called.expression.value, 'contract_kind', None) == "library")
    #     for call in function.external_calls_as_expressions
    # ) else ''

    has_exeternal_calls = '🌀' if [c for c in function.high_level_calls if type(c[1]) != LibraryCall] or function.low_level_calls else ''
    potentialPublicVarFunction = '💱' if public_state_var_functions.get(function.signature_str) else '' 
    hasLowLevelCalls = '❗' if function.low_level_calls else ''
    isModifier = '🌈' if type(function) == Modifier else ''
    funcInScope = '🎯' if function.compilation_unit.core.valid_path(str(function.source_mapping)) else ''
    readsState = '🟢' if len(function.state_variables_read) > 0 else ''
    updatesState = '🔴' if len(function.state_variables_written) > 0 else ''
    modifiers = [x.name for x in function.modifiers]
    modifierRestricted = '❌' if any("only" in mod.lower() for mod in modifiers) else ''
    viewOrPure = '🟩' if function.view or function.pure else ''
    payable = '💲' if function.payable else ''
    # is_declared_function = "d" if function in function.contract.functions_declared else "i"
    is_entrypoint_function = "💥" if function.visibility in ["external", "public"] else ""
    # modifiers = f" {[str(m) for m in function.modifiers]}" if includeModifiers and len(function.modifiers) > 0 else ""
    modifiers = f" {[m.full_name.replace('()', '') for m in function.modifiers]}" if includeModifiers and len(function.modifiers) > 0 else ""
    decorator = f"{decorator_prefix}{potentialPublicVarFunction}{funcInScope}{is_entrypoint_function}{isModifier}{readsState}{updatesState}{viewOrPure}{has_exeternal_calls}{modifierRestricted}{payable}{hasLowLevelCalls}{modifiers}"


    # defaults to not including decorators in callstack
    if decorators_in_callstack:
        extra_decorators_in_callstack = ''.join([char for char in decorators_in_callstack.get(function, "") if char not in decorator])
        if extra_decorators_in_callstack:
            return f"{decorator} >> { extra_decorators_in_callstack } <<"
        
        # return f"{decorator}  >> {decorators_in_callstack.get(function)} <<"
        # return decorators_in_callstack where char is not in decorator
    return decorator
        


def get_descriptive_function_str(function: Function | str, includeModifiers: bool = True) -> str:
    if type(function) == str:
        return function

    decorator = get_function_decorator(function, includeModifiers)
    function_identifier = f"{contractDeclarerOrEmpty(function)}.{str(function)} | {decorator}"
    return function_identifier

def get_loc_id(f: Contract | Function | SolidityVariable) -> str:
    filepath = f"{f.source_mapping.filename.absolute}#{f.source_mapping.lines[0]}:{f.source_mapping.starting_column}"
    return f"{f.name},{filepath}"

def get_function_link(f: Function) -> str:
    return f"<a href='#{f.name},{f.source_mapping.filename.absolute}#{f.source_mapping.lines[0]}:{f.source_mapping.starting_column}' data-scope='{get_loc_id(f.contract_declarer) if 'contract_declarer' in dir(f) else ''}'>🔗</a>"


def get_descriptive_function_html(function: Function | str, includeModifiers: bool = True) -> str:
    if type(function) == str:
        return function

    decorator = get_function_decorator(function, includeModifiers)
    html_link = get_function_link(function)
    function_identifier = f"{html_link} <a href='file://{function.source_mapping.filename.absolute}#{function.source_mapping.lines[0]}:{function.source_mapping.starting_column}' value='{get_loc_id(function)}'>{contractDeclarerOrEmpty(function)}.{str(function)}</a> | {decorator}"
    return function_identifier


def get_source_mapping(node, add_lines = 0):
    if "source_mapping" in dir(node):
        node = node.source_mapping
    return f"{node.filename.absolute}#{int(node.lines[0]) + add_lines}:{node.starting_column}"

def is_node_source_mapping_in_array(node, arr):
    return get_source_mapping(node) in [get_source_mapping(n) for n in arr]


def remove_duplicates(lst, func):
                            seen = set()
                            return [x for x in lst if func(x) not in seen and not seen.add(func(x))]