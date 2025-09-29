class CallbackNoMsgSenderCheck {
    constructor(reporter, config) {
        this.ruleId = 'callback-no-msgsender-check'

        this.reporter = reporter
        this.config = config
    }

    FunctionDefinition(node) {
        const contract_node = traversing.findParentType(node, 'ContractDefinition')

        if (node.modifiers.filter(mod => { return mod.name.toLowerCase().includes('only') }).length > 0)
            return
        
        if (!['public', 'external'].includes(node.visibility))
            return


        if (node.name.toLowerCase().includes("callback"))
            this.reporter.error(node, this.ruleId, `${contract_node.name}.${node.name} | callback should validate msg.sender.`)
    
    }
}

module.exports = CallbackNoMsgSenderCheck
