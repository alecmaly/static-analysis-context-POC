class NoFoosAllowed {
    constructor(reporter, config) {
        this.ruleId = 'no-bars'

        this.reporter = reporter
        this.config = config
    }

    ContractDefinition(ctx) {
        const {name} = ctx

        if (name === 'Bar') {
            this.reporter.error(ctx, this.ruleId, 'Contracts cannot be named "Bar"')
        }
    }
}

module.exports = NoFoosAllowed
