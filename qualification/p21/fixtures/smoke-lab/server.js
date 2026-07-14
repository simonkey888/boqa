'use strict';

const http = require('http');

const server = http.createServer((request, response) => {
  if (request.method === 'GET' && request.url === '/health') {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ status: 'synthetic_smoke_ready' }));
    return;
  }
  response.writeHead(404, { 'content-type': 'text/plain' });
  response.end('not_found');
});

server.listen(8080, '0.0.0.0');
