#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { publicCorpus } = require('./public-corpus');

const destination = process.argv[2];
if (!destination) throw new Error('DESTINATION_REQUIRED');
fs.mkdirSync(path.dirname(path.resolve(destination)), { recursive: true });
fs.writeFileSync(destination, `${JSON.stringify(publicCorpus(), null, 2)}\n`, { mode: 0o600 });
