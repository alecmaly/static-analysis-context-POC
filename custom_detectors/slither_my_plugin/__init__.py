from typing import Tuple, List, Type

# custom detectors
# from slither_my_plugin.detectors.CDInterestingConditional import CDInterestingConditional
# from slither_my_plugin.detectors.CDDelegateCallInLoop import CDDelegateCallInLoop
# # from slither_my_plugin.detectors.CDTaintedVariableUsed import CDTaintedVariableUsed
# from slither_my_plugin.detectors.CDInterestingFunctionCallsAndParameterUsage import CDInterestingFunctionCallsAndParameterUsage
from slither_my_plugin.detectors.CDTaintedVariableUsed_rollup import CDTaintedVariableUsed_rollup
# from slither_my_plugin.detectors.CDComplexUncheckedBlock import CDComplexUncheckedBlock
# from slither_my_plugin.detectors.CDDivideBeforeMultiply_modified import CDDivideBeforeMultiply_modified
# from slither_my_plugin.detectors.CDAmountUsedAfterTransfer import CDAmountUsedAfterTransfer
# from slither_my_plugin.detectors.CDRequireStatmentMessageDescrepency import CDRequireStatmentMessageDescrepency
# from slither_my_plugin.detectors.CDReturnValueNotUsed import CDReturnValueNotUsed
# from slither_my_plugin.detectors.CDMismatchingRequireVars import CDMismatchingRequireVars
# # from slither_my_plugin.detectors.CDSimilarFunctionStateChanges import CDSimilarFunctionStateChanges
# from slither_my_plugin.detectors.CDExpressionVariableMismatch import CDExpressionVariableMismatch
# from slither_my_plugin.detectors.CDVariableUsageRatio import CDVariableUsageRatio
# from slither_my_plugin.detectors.CDForLoopUnusedIteratorVariable import CDForLoopUnusedIteratorVariable
# from slither_my_plugin.detectors.CDInterestingFunctionCallChain import CDInterestingFunctionCallChain
# from slither_my_plugin.detectors.CDCallbackFunctionWithoutMsgSenderCheck import CDCallbackFunctionWithoutMsgSenderCheck
# from slither_my_plugin.detectors.CDLoops import CDLoops
# from slither_my_plugin.detectors.CDDoubleEntrypointProxyTokens import CDDoubleEntrypointProxyTokens
# from slither_my_plugin.detectors.CDTest import CDTest
# from slither_my_plugin.detectors.CDStructs import CDStructs
# from slither_my_plugin.detectors.CDUnusedParams import CDUnusedParams
# from slither_my_plugin.detectors.CDInterestingFunctionParams import CDInterestingFunctionParams
# from slither_my_plugin.detectors.CDReadUndefinedVariable import CDReadUndefinedVariable
# from slither_my_plugin.detectors.CDArrayReturnNotInitialized import CDArrayReturnNotInitialized
# from slither_my_plugin.detectors.CDDependencies import CDDependencies
# from slither_my_plugin.detectors.CDShadowedFunctionsNoSuper import CDShadowedFunctionsNoSuper



# from slither_my_plugin.detectors.CDPublicExternalFunctionsNoRequire import CDPublicExternalFunctionsNoRequire

# from slither_my_plugin.detectors.CDHelpSimplifyMath import CDHelpSimplifyMath

# # Custom Gas Optimization Detectors
# from slither_my_plugin.detectors.CDGOOnlyPayable import CDGOOnlyPayable
# from slither_my_plugin.detectors.CDGODivBy2 import CDGODivBy2
# from slither_my_plugin.detectors.CDGOPrivateConstantsSaveGas import CDGOPrivateConstantsSaveGas
# from slither_my_plugin.detectors.CDGOConstructorPayable import CDGOConstructorPayable
# from slither_my_plugin.detectors.CDGOFunctionCalledOnce import CDGOFunctionCalledOnce
# from slither_my_plugin.detectors.CDGOForLoopsLength import CDGOForLoopsLength
# from slither_my_plugin.detectors.CDGOIncrementPrefix import CDGOIncrementPrefix
# from slither_my_plugin.detectors.CDGOAssignmentToLessThan32Bytes import CDGOAssignmentToLessThan32Bytes
# from slither_my_plugin.detectors.CDGOExpandExpression import CDGOExpandExpression
# from slither_my_plugin.detectors.CDGODefaultValue import CDGODefaultValue
# from slither_my_plugin.detectors.CDGOCacheKeccak256 import CDGOCacheKeccak256
# from slither_my_plugin.detectors.CDGOOptimizeNames import CDGOOptimizeNames
# from slither_my_plugin.detectors.CDGOEmitFromMemory import CDGOEmitFromMemory
# from slither_my_plugin.detectors.CDGOStorageReadTwice import CDGOStorageReadTwice
# from slither_my_plugin.detectors.CDGOStateVarsOnlySetInConstructor import CDGOStateVarsOnlySetInConstructor
# from slither_my_plugin.detectors.CDStateVariableChangedAfterRequire import CDStateVariableChangedAfterRequire



from slither.detectors.abstract_detector import AbstractDetector
from slither.printers.abstract_printer import AbstractPrinter


def make_plugin() -> Tuple[List[Type[AbstractDetector]], List[Type[AbstractPrinter]]]:
    plugin_detectors = [
        # CDTaintedVariableUsed,
        # CDInterestingFunctionCallsAndParameterUsage,
        CDTaintedVariableUsed_rollup,
        # CDDelegateCallInLoop,
        # CDInterestingConditional,
        # CDComplexUncheckedBlock,
        # CDDivideBeforeMultiply_modified,
        # CDAmountUsedAfterTransfer,
        # CDRequireStatmentMessageDescrepency,
        # CDReturnValueNotUsed,
        # CDMismatchingRequireVars,
        # # CDSimilarFunctionStateChanges,
        # CDExpressionVariableMismatch,
        # CDVariableUsageRatio,
        # CDForLoopUnusedIteratorVariable,
        # CDInterestingFunctionCallChain,
        # CDStateVariableChangedAfterRequire,
        # CDCallbackFunctionWithoutMsgSenderCheck,
        # CDLoops,
        # CDDoubleEntrypointProxyTokens,
        # CDTest,
        # CDStructs,
        # CDUnusedParams,
        # CDInterestingFunctionParams,
        # # CDPublicExternalFunctionsNoRequire,
        # CDReadUndefinedVariable,
        # CDArrayReturnNotInitialized,
        # CDDependencies,
        # CDShadowedFunctionsNoSuper,
        
        # CDHelpSimplifyMath,
        
        # CDGOOnlyPayable,
        # CDGODivBy2,
        # CDGOPrivateConstantsSaveGas,
        # CDGOConstructorPayable,
        # CDGOFunctionCalledOnce,
        # CDGOForLoopsLength,
        # CDGOIncrementPrefix,
        # CDGOAssignmentToLessThan32Bytes,
        # CDGOExpandExpression,
        # CDGODefaultValue,
        # CDGOCacheKeccak256,
        # CDGOOptimizeNames,
        # CDGOEmitFromMemory,
        # CDGOStorageReadTwice,
        # CDGOStateVarsOnlySetInConstructor
    ]
    plugin_printers: List[Type[AbstractPrinter]] = []

    return plugin_detectors, plugin_printers
