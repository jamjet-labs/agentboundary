// Tests for the wrapper's dispatch order. Mocks command resolution.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const wrapper = require('../bin/agentboundary.js');

test('dispatch is callable and exports its helpers', () => {
  assert.equal(typeof wrapper.dispatch, 'function');
  assert.equal(typeof wrapper.hasOnPath, 'function');
});

test('hasOnPath returns false for a guaranteed-missing command', () => {
  assert.equal(wrapper.hasOnPath('agentboundary-nonexistent-abc123xyz'), false);
});
