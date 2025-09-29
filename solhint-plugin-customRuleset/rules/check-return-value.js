/// start tree traversing
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

/// end tree traversing


const traversing = new TreeTraversing()

const ruleId = 'check-return-value'


class CheckReturnValue {
    constructor(reporter, config) {
        this.reporter = reporter
        this.ruleId = ruleId
        this.config = config
    }

    MemberAccess(node) {
        this.validateSend(node)
    }

    validateSend(node) {
        const contract_node = traversing.findParentType(node, 'ContractDefinition')
        const function_node = traversing.findParentType(node, 'FunctionDefinition')

        if (function_node.modifiers.filter(mod => { return mod.name.toLowerCase().includes('only') }).length > 0)
            return


        if (!['public', 'external'].includes(function_node.visibility))
            return

        const functionNames = ['send', 'call']
        if (functionNames.includes(node.memberName.toLowerCase())) {
            const hasVarDeclaration = traversing.statementNotContains(node, 'VariableDeclaration')
            const hasVarDeclarationStatement = traversing.statementNotContains(node, 'VariableDeclarationStatement')
            const hasIfStatement = traversing.statementNotContains(node, 'IfStatement')
            const hasRequire = traversing.someParent(node, this.isRequire)
            const hasAssert = traversing.someParent(node, this.isAssert)
            const hasSafeTransfer = traversing.someParent(node, this.isSafeTransfer)

            if (! hasIfStatement && ! hasVarDeclaration && ! hasRequire && ! hasAssert && ! hasSafeTransfer && ! hasVarDeclarationStatement) {
                this.reporter.error(node, this.ruleId, `${contract_node.name}.${function_node.name} |  No check on result of "${node.memberName}" call`)
            }
        }
    }

    isSafeTransfer(node) {
        return node.type === 'FunctionCall' && node.expression.name.includes('callOptionalReturn') // match (callOptionalReturn || _callOptionalReturn)
    }

    isRequire(node) {
        return node.type === 'FunctionCall' && node.expression.name === 'require'
    }

    isAssert(node) {
        return node.type === 'FunctionCall' && node.expression.name === 'assert'
    }
}

module.exports = CheckReturnValue
