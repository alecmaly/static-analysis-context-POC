var fs = require('fs');

class DumpAST {
    constructor(reporter, config) {
        this.ruleId = 'dump-ast'

        this.reporter = reporter
        this.config = config
        this.contract_map = {}
    }

    ContractDefinition(node) {
        this.contract_map[node['name']] = node
        console.log(JSON.stringify(this.contract_map))
        // fs.writeFileSync('test.json', JSON.stringify(this.contract_map))
    }
}

module.exports = DumpAST
