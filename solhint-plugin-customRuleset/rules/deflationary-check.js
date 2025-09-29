class DeflationaryCheck {


    constructor(reporter, config) {
        this.ruleId = 'deflationary-check'

        this.reporter = reporter
        this.config = config
    }

    FunctionDefinition(node) {
        const contract_node = traversing.findParentType(node, 'ContractDefinition')
        const function_node = node

        if (function_node.modifiers.filter(mod => {return mod.name.toLowerCase().includes('only')}).length > 0) 
            return
        
        if (!['public', 'external'].includes(function_node.visibility)) 
            return

        let balanceBefore = 0
        let balanceAfter = 0
        let transfer = 0
        let transferNodes = []

        function enumerateNodes(node) {
            for (const key of Object.keys(node)) {
                const value = node[key];
                if (typeof value === 'object' && value !== null) {
                    if (value.type === 'MemberAccess') {
                        if (value.memberName.toLowerCase().includes('transfer')) {
                            transfer++
                            transferNodes.push(value)
                        }

                        if (['balance', 'balanceof'].includes(value.memberName.toLowerCase())) {
                            if (transfer === 0) 
                                balanceBefore++
                             else 
                                balanceAfter++
                        }
                    }
                    enumerateNodes(value);
                }
            }

        }
        enumerateNodes(function_node);

        // console.log("before", balanceBefore)
        // console.log("after", balanceAfter)
        // console.log("transfer", transfer)

        // console.log(balanceBefore > 0 && transfer > 0 && balanceAfter === 0)


        if (balanceBefore > 0 && transfer > 0 && balanceAfter === 0) {
            for (let transferNode of transferNodes) {
                this.reporter.error(transferNode, this.ruleId, `${contract_node.name}.${function_node.name} | Possible deflationary issue: (balance checks before + after transfer not equal).`)
            }
        }
    }
}

module.exports = DeflationaryCheck
