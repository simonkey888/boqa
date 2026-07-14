'use strict';

const { ExternalLabAdapter } = require('./base-adapter');

class VulfocusAdapter extends ExternalLabAdapter {
  constructor() { super('Vulfocus'); }
  evaluateController(controller = {}) {
    if (controller.mounts_docker_socket || controller.privileged || controller.host_network) {
      return Object.freeze({ usable: false, status: 'BLOCKED_UNSAFE_DOCKER_CONTROL' });
    }
    if (!controller.external_control_plane || !controller.internal_network || !controller.flag_withheld_from_agent) {
      return Object.freeze({ usable: false, status: 'BLOCKED_ISOLATION_REQUIREMENTS_UNMET' });
    }
    return Object.freeze({ usable: true, status: 'ADAPTER_READY_NOT_EXECUTED' });
  }
  agentInput(provisioned) {
    const { flag, ground_truth, ...safe } = provisioned || {};
    return Object.freeze(safe);
  }
}

module.exports = { VulfocusAdapter };
