'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const test = require('node:test');

const bin = path.resolve(__dirname, '..', 'bin', 'aikeys.js');

function run(home, args, input, extraEnv = {}) {
  return spawnSync(process.execPath, [bin, ...args], {
    input,
    encoding: 'utf8',
    env: {
      ...process.env,
      AIKEYS_HOME: home,
      AIKEYS_PASSWORD: 'test-password',
      ...extraEnv
    }
  });
}

test('stores, gets, and renders file-vault secrets', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'aikeys-'));
  assert.equal(run(home, ['setup']).status, 0);
  assert.equal(run(home, ['set', 'demo/key', 'v1'], 'secret-value\n').status, 0);
  const got = run(home, ['get', 'demo/key', 'v1']);
  assert.equal(got.status, 0);
  assert.equal(got.stdout, 'secret-value');

  const template = path.join(home, 'example.env.template');
  const output = path.join(home, 'example.env');
  fs.writeFileSync(template, 'DEMO={{aikeys:demo/key@v1}}\n');
  assert.equal(run(home, ['render', template, output]).status, 0);
  assert.equal(fs.readFileSync(output, 'utf8'), 'DEMO=secret-value\n');
});

test('scan masks likely secrets', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'aikeys-'));
  const tree = fs.mkdtempSync(path.join(os.tmpdir(), 'aikeys-scan-'));
  fs.writeFileSync(path.join(tree, '.env'), 'OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456\n');
  const result = run(home, ['scan', tree]);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /openai|openai_api_key/);
  assert.doesNotMatch(result.stdout, /sk-abcdefghijklmnopqrstuvwxyz123456/);
});
