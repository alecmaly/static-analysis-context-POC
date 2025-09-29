class ExplicitCast {
    constructor(reporter, config) {
        this.ruleId = 'explicit-cast'

        this.reporter = reporter
        this.config = config
    }

    FunctionCall(node) {
        const contract_node = traversing.findParentType(node, 'ContractDefinition')
        const function_node = traversing.findParentType(node, 'FunctionDefinition')
        let f_params = function_node.parameters.map(param => { return param.name })
        f_params.push('msg.sender')
        f_params.push('msg.value')
        f_params.push('msg.data')
        f_params.push('tx.origin')

        if (function_node.modifiers.filter(mod => { return mod.name.toLowerCase().includes('only') }).length > 0)
            return
        
        if (!['public', 'external'].includes(function_node.visibility))
            return

        const function_name = node.expression.name
        const regex = /^u?int(2[0-4][0-9]|25[0-5]|1?\d{1,2})$/

        if ((node.expression.type == "ElementaryTypeName" || node.expression.type == "ElementaryTypeNameExpression") && regex.test(function_name) ) {
            // calling func
            // const calling_func = traversing.findParentType(node, 'FunctionCall')
            // arguments
            let hasTaintedArgs = node.arguments.filter(arg => { return f_params.includes(arg.name) }).length > 0
            // console.log("tainted args: ", hasTaintedArgs)

            if (hasTaintedArgs)
                this.reporter.error(node, this.ruleId, `${contract_node.name}.${function_node.name} | Explicit cast: (${function_name}).`)
        }
    }
}

module.exports = ExplicitCast
