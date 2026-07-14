'use strict';

const dns = require('dns').promises;
const http = require('http');
const net = require('net');

function connect(host, port, timeoutMs = 900) {
  return new Promise(resolve => {
    const socket = net.connect({ host, port });
    let settled = false;
    const finish = connected => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(connected);
    };
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
    socket.setTimeout(timeoutMs, () => finish(false));
  });
}

function request(url, timeoutMs = 1500) {
  return new Promise(resolve => {
    const req = http.get(url, response => {
      response.resume();
      response.once('end', () => resolve(response.statusCode));
    });
    req.once('error', () => resolve(null));
    req.setTimeout(timeoutMs, () => {
      req.destroy();
      resolve(null);
    });
  });
}

async function resolves(hostname) {
  try {
    await dns.lookup(hostname, { all: true });
    return true;
  } catch {
    return false;
  }
}

async function main() {
  const allowedUrl = process.env.P21_ALLOWED_URL;
  if (!allowedUrl) throw new Error('P21_ALLOWED_URL_REQUIRED');

  const result = {
    role: process.env.P21_PROBE_ROLE || 'unknown',
    allowed_peer_http: (await request(allowedUrl)) === 200,
    external_dns_resolved: await resolves('external.invalid.'),
    public_ip_connected: await connect('1.1.1.1', 80),
    metadata_connected: await connect('169.254.169.254', 80),
    host_gateway_connected: await connect(process.env.P21_GATEWAY_IP || '172.31.1.1', Number(process.env.P21_HOST_PORT || 18080)),
    foreign_scenario_connected: await connect(process.env.P21_FOREIGN_IP || '172.31.2.10', 8080),
  };

  const passed = result.allowed_peer_http
    && !result.external_dns_resolved
    && !result.public_ip_connected
    && !result.metadata_connected
    && !result.host_gateway_connected
    && !result.foreign_scenario_connected;

  process.stdout.write(`${JSON.stringify({ ...result, passed })}\n`);
  if (!passed) process.exitCode = 1;
}

main().catch(error => {
  process.stderr.write(`${error.code || error.message}\n`);
  process.exitCode = 1;
});
