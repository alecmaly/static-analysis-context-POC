class TreeTraversing {
    statementNotContains(node, type) {
        const statement = this.findParentStatement(node)

        if (! statement) {
            return false
        }

        const itemOfType = this.findDownType(statement, type)

        return itemOfType !== null
    }

    findParentStatement(node) {
        while (node.parent != null && !node.parent.type.includes('Statement')) {
            node = node.parent
        }

        return node.parent
    }

    findParentType(node, type) {
        while (node.parent !== undefined && node.parent.type !== type) {
            node = node.parent
        }

        return node.parent || null
    }

    findDownType(node, type) {
        if (!node || node.type === type) {
            return node
        } else {
            return null
        }
    }

    /**
     * Traverses the tree up and checks `predicate` in each node.
     *
     * @returns {boolean}
     */
    someParent(node, predicate) {
        let parent = node.parent
        while (parent) {
            if (predicate(parent)) {
                return true
            }
            parent = parent.parent
        }

        return false
    } * findIdentifier(ctx) {
        const children = ctx.children

        for (let i = 0; i < children.length; i += 1) {
            if (children[i].constructor.name === 'IdentifierContext') {
                yield children[i]
            }
        }

        return null
    }
} TreeTraversing.typeOf = function typeOf(ctx) {
    if (! ctx) {
        return ''
    }

    const className = ctx.constructor.name
    const typeName = className.replace('Context', '')
    return typeName[0].toLowerCase() + typeName.substring(1)
}

TreeTraversing.hasMethodCalls = function hasMethodCalls(node, methodNames) {
    const text = node.memberName
    return methodNames.includes(text)
}

TreeTraversing.findPropertyInParents = function findPropertyInParents(node, property) {
    let curNode = node

    while (curNode !== undefined && ! curNode[property]) {
        curNode = curNode.parent
    }

    return curNode && curNode[property]
}


traversing = new TreeTraversing()

class InterestingFunctionsAndParameters {


    constructor(reporter, config) {
        this.ruleId = 'interesting-functions-and-parameters'

        this.reporter = reporter
        this.config = config
        this.functions = [
            // 'balance', 'balanceof', 
            'push', 
            'transferfrom', 'safetransferfrom'
        ]

        this.functions_no_params = [
            // 'balance', 'balanceof', 
            'ecrecover', 'push', '_safemint', '_mint', 'safebatchtransferfrom', '_mintbatch', 'selfdestruct', 'create', 'create2',
            'selector'
        ]

        this.parameters = [
            'decimals'
        ]
    }

    FunctionCall(node) {
        const contract_node = traversing.findParentType(node, 'ContractDefinition')
        const function_node = traversing.findParentType(node, 'FunctionDefinition')
        let f_params = function_node.parameters.map(param => { return param.name })
        f_params.push('msg.sender')
        f_params.push('msg.value')
        f_params.push('msg.data')
        f_params.push('tx.origin')


        const name = node.memberName || node.expression.memberName

        if (function_node.modifiers.filter(mod => { return mod.name.toLowerCase().includes('only') }).length > 0)
            return
    
        if (!['public', 'external'].includes(function_node.visibility))
            return

        // console.log(node)
        if (this.functions_no_params.includes(name.toLowerCase())) {
            
            this.reporter.error(node, this.ruleId, `${contract_node.name}.${function_node.name} | Interesting Function: (${name}).`)
        }


        if (this.functions.includes(name.toLowerCase())) {
            let hasTaintedArgs = node.arguments.filter(arg => { return f_params.includes(arg.name) }).length > 0
            
            console.log('tainted args: ', node.arguments.filter(arg => { return f_params.includes(arg.name) }).length)

            if (hasTaintedArgs)
                this.reporter.error(node, this.ruleId, `${contract_node.name}.${function_node.name} | Interesting Function: (${name}).`)
        }
    }

    MemberAccess(node) {
        const contract_node = traversing.findParentType(node, 'ContractDefinition')
        const function_node = traversing.findParentType(node, 'FunctionDefinition')
        const name = node.memberName

        if (function_node.modifiers.filter(mod => { return mod.name.toLowerCase().includes('owner') }).length > 0)
            return

        if (!['public', 'external'].includes(function_node.visibility))
            return

        if (this.parameters.includes(name.toLowerCase())) {
            this.reporter.error(node, this.ruleId, `${contract_node.name}.${function_node.name} | Interesting Param: (${name}).`)
        }
    }


}

module.exports = InterestingFunctionsAndParameters
