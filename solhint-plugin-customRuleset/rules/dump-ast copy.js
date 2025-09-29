var fs = require('fs');
const BaseChecker = require('./base-checker')
const DEFAULT_SEVERITY = 'error'
const DEFAULT_IGNORE_WARNINGS = false
const DEFAULT_OPTION = {
  ignoreWarnings: DEFAULT_IGNORE_WARNINGS
}

const ruleId = 'dump-ast'
const meta = {
  type: 'security',
  docs: {
    description: `Disallow usage of msg.value in non-payable functions.`,
    category: 'Security Rules'
  },
  isDefault: false,
  recommended: true,
  defaultSetup: [
    DEFAULT_SEVERITY, DEFAULT_OPTION
  ],
  schema: null
}

class DumpAST extends BaseChecker {
  constructor(reporter, config) {
    super(reporter, ruleId, meta)
    this.ignoreWarnings = config && config.getObjectPropertyBoolean(ruleId, 'ignoreWarnings', false)
    this.contract_map = {}
    this.function_map = {}
  }
  
  ContractDefinition(node) {
    this.contract_map[node['name']] = node
    fs.writeFileSync('test.json', JSON.stringify(this.contract_map))
  }

}

module.exports = DumpAST