#!/usr/bin/env node
// AgentBoundary npm wrapper.
// Dispatches to the Python CLI via uvx, pipx, or python3 -m agentboundary,
// in that order. Exits with a clear install hint if none is available.
//
// This wrapper contains NO conformance logic. The Python package
// `agentboundary` on PyPI is the single source of truth.

'use strict';

const { spawnSync } = require('node:child_process');
const { existsSync } = require('node:fs');

const PINNED_VERSION = require('../package.json').version;

function hasOnPath(cmd) {
  const probe = process.platform === 'win32'
    ? spawnSync('where', [cmd], { stdio: 'ignore' })
    : spawnSync('command', ['-v', cmd], { stdio: 'ignore', shell: true });
  return probe.status === 0;
}

function runDispatch(cmd, args) {
  const result = spawnSync(cmd, args, { stdio: 'inherit' });
  if (result.error) {
    return { status: 127 };
  }
  return { status: result.status === null ? 1 : result.status };
}

function dispatch(forwardedArgs) {
  if (hasOnPath('uvx')) {
    return runDispatch('uvx', [
      '--from', `agentboundary==${PINNED_VERSION}`,
      'agentboundary',
      ...forwardedArgs,
    ]);
  }
  if (hasOnPath('pipx')) {
    return runDispatch('pipx', [
      'run',
      '--spec', `agentboundary==${PINNED_VERSION}`,
      'agentboundary',
      ...forwardedArgs,
    ]);
  }
  if (hasOnPath('python3')) {
    return runDispatch('python3', ['-m', 'agentboundary', ...forwardedArgs]);
  }
  return null;
}

function printInstallHint() {
  const msg = [
    'agentboundary requires one of `uvx`, `pipx`, or `python3` on PATH.',
    '',
    'Easiest install (uv, ~5MB):',
    '  curl -LsSf https://astral.sh/uv/install.sh | sh',
    '',
    'Then re-run:',
    '  npx agentboundary run scenarios/',
    '',
    'Docs: https://agentboundary.jamjet.dev',
  ].join('\n');
  console.error(msg);
}

function main() {
  const forwardedArgs = process.argv.slice(2);
  const result = dispatch(forwardedArgs);
  if (result === null) {
    printInstallHint();
    process.exit(1);
  }
  process.exit(result.status);
}

if (require.main === module) {
  main();
}

module.exports = { dispatch, hasOnPath };
