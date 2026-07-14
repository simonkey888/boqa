'use strict';

const { ExternalLabAdapter, validateScenarioDefinition } = require('./base-adapter');

class JuiceShopAdapter extends ExternalLabAdapter {
  constructor() { super('OWASP Juice Shop'); }
  validate(definition) { return validateScenarioDefinition(definition); }
  compatibleChallenge(definition) {
    return this.validate(definition).valid && definition.reset_deterministic === true && definition.synthetic_credentials === true && definition.non_destructive === true;
  }
}

module.exports = { JuiceShopAdapter };
