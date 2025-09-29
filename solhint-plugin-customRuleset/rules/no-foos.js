class NoFoosAllowed {
    constructor(reporter, config) {
        this.ruleId = 'no-foos'

        this.reporter = reporter
        this.config = config
    }

    ContractDefinition(ctx) {
        const {name} = ctx

        if (name === 'Foo') {
            this.reporter.error(ctx, this.ruleId, 'Contracts cannot be named "Foo"')
        }
    }
}

module.exports = NoFoosAllowed
