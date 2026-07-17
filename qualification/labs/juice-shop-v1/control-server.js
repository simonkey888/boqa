'use strict';
const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://control.invalid');
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  if (url.pathname === '/health') return res.end(JSON.stringify({ status: 'ok' }));
  if (url.pathname !== '/rest/products/search' || req.method !== 'GET') { res.statusCode = 404; return res.end(JSON.stringify({ status: 'not_found' })); }
  const normalized = crypto.createHash('sha256').update(url.searchParams.get('q') || '').digest('hex').slice(0, 20);
  res.end(JSON.stringify({ status: 'ok', data: [], query: normalized }));
});
server.listen(3001, '0.0.0.0');
