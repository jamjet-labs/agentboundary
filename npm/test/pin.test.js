// The wrapper must pin a Python version that matches the repo's pyproject.
// A stale pin (0.1.0 could not load the current scenarios/) broke the wrapper.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');

const wrapper = require('../bin/agentboundary.js');
const pkg = require('../package.json');

const pyproject = readFileSync(path.join(__dirname, '..', '..', 'pyproject.toml'), 'utf8');
const pyVersion = /^version\s*=\s*"([^"]+)"/m.exec(pyproject)[1];

test('npm package version equals pyproject version textually', () => {
  assert.equal(pkg.version, pyVersion);
});

test('toPythonVersion applies PEP 440 normalization', () => {
  assert.equal(wrapper.toPythonVersion('0.2.0-alpha.1'), '0.2.0a1');
  assert.equal(wrapper.toPythonVersion('0.3.0-rc.2'), '0.3.0rc2');
  assert.equal(wrapper.toPythonVersion('1.0.0'), '1.0.0');
});

test('python pin is the normalized pyproject version', () => {
  assert.equal(wrapper.PINNED_VERSION, wrapper.toPythonVersion(pyVersion));
});
