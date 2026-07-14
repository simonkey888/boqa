'use strict';

const { OwaspBenchmarkAdapter } = require('./owasp-benchmark');
const { NodeGoatAdapter } = require('./nodegoat');
const { JuiceShopAdapter } = require('./juice-shop');
const { VulhubAdapter } = require('./vulhub');
const { VulfocusAdapter } = require('./vulfocus');

function externalAdapters() {
  return Object.freeze([
    new OwaspBenchmarkAdapter(), new NodeGoatAdapter(), new JuiceShopAdapter(),
    new VulhubAdapter(), new VulfocusAdapter(),
  ]);
}

module.exports = { externalAdapters, OwaspBenchmarkAdapter, NodeGoatAdapter, JuiceShopAdapter, VulhubAdapter, VulfocusAdapter };
