class UncheckedBlock {
    constructor(reporter, config) {
        this.ruleId = 'unchecked-block'

        this.reporter = reporter
        this.config = config
    }

    UncheckedStatement(node) {    
        // console.log(node)
        const contract_node = traversing.findParentType(node, 'ContractDefinition')
        const function_node = traversing.findParentType(node, 'FunctionDefinition')

        if (function_node.modifiers.filter(mod => { return mod.name.toLowerCase().includes('only') }).length > 0)
            return

        if (!['public', 'external'].includes(function_node.visibility))
            return

        let size = node.loc.end.line - node.loc.start.line
        this.reporter.error(node, this.ruleId, `${contract_node.name}.${function_node.name} |  Unchecked block size (${size}) detected.`)
    }
}

module.exports = UncheckedBlock
