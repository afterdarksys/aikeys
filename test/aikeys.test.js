'use strict';

const assert = require('assert');
const crypto = require('crypto');
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

// Negative tests. A vault is only worth anything if it fails closed, so each
// case tampers with vault.json the way an attacker with disk access would and
// asserts the same thing: non-zero exit, and NOTHING on stdout. A leak here is
// worse than no vault at all, because it comes with false confidence.
function seed(secret = 'sk-TOPSECRET-value') {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'aikeys-neg-'));
  assert.equal(run(home, ['setup']).status, 0);
  assert.equal(run(home, ['set', 'demo/key', 'v1'], `${secret}\n`).status, 0);
  return { home, vaultPath: path.join(home, 'vault.json'), secret };
}

function tamper(vaultPath, mutate) {
  const vault = JSON.parse(fs.readFileSync(vaultPath, 'utf8'));
  mutate(vault.entries['demo/key'].versions.v1.encrypted);
  fs.writeFileSync(vaultPath, JSON.stringify(vault));
}

function assertFailsClosed(home, secret, label) {
  const got = run(home, ['get', 'demo/key', 'v1']);
  assert.notEqual(got.status, 0, `${label}: expected non-zero exit`);
  assert.doesNotMatch(got.stdout, new RegExp(secret), `${label}: LEAKED the secret`);
}

test('rejects a wrong vault password', () => {
  const { home, secret } = seed();
  const got = run(home, ['get', 'demo/key', 'v1'], undefined, { AIKEYS_PASSWORD: 'wrong-password' });
  assert.notEqual(got.status, 0);
  assert.doesNotMatch(got.stdout, new RegExp(secret));
});

test('rejects tampered ciphertext', () => {
  const { home, vaultPath, secret } = seed();
  tamper(vaultPath, (e) => {
    const b = Buffer.from(e.ciphertext, 'base64');
    b[0] ^= 0xff;
    e.ciphertext = b.toString('base64');
  });
  assertFailsClosed(home, secret, 'bit-flipped ciphertext');
});

test('rejects a forged auth tag', () => {
  const { home, vaultPath, secret } = seed();
  tamper(vaultPath, (e) => { e.tag = Buffer.alloc(16).toString('base64'); });
  assertFailsClosed(home, secret, 'zeroed auth tag');
});

test('rejects a swapped iv', () => {
  const { home, vaultPath, secret } = seed();
  tamper(vaultPath, (e) => { e.iv = crypto.randomBytes(12).toString('base64'); });
  assertFailsClosed(home, secret, 'swapped iv');
});

// The alg/kdf fields are recorded on every entry. Before enforcement they were
// decoration — decrypt hardcoded GCM, so rewriting them was ignored rather than
// honored. Harmless then, a downgrade vector the moment a second algorithm is
// added. These lock the fields down as controls.
test('rejects an algorithm downgrade', () => {
  const { home, vaultPath, secret } = seed();
  tamper(vaultPath, (e) => { e.alg = 'aes-256-cbc'; });
  assertFailsClosed(home, secret, 'alg downgrade');
});

test('rejects a kdf downgrade', () => {
  const { home, vaultPath, secret } = seed();
  tamper(vaultPath, (e) => { e.kdf = 'md5'; });
  assertFailsClosed(home, secret, 'kdf downgrade');
});

test('rejects truncated crypto parameters', () => {
  const { home, vaultPath, secret } = seed();
  tamper(vaultPath, (e) => { e.salt = Buffer.alloc(4).toString('base64'); });
  assertFailsClosed(home, secret, 'truncated salt');
});

test('vault and config are written 0600', () => {
  const { home } = seed();
  for (const f of ['vault.json', 'config.json']) {
    const mode = fs.statSync(path.join(home, f)).mode & 0o777;
    assert.equal(mode, 0o600, `${f} should be 0600, got ${mode.toString(8)}`);
  }
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

// Runs aikeys with stdin wired to /dev/null (the `< /dev/null` case) and the
// given env keys removed, so the parent environment cannot mask the behaviour.
function runNoInput(home, args, env = {}, unset = []) {
  const fullEnv = { ...process.env, AIKEYS_HOME: home, AIKEYS_PASSWORD: 'test-password', ...env };
  for (const k of unset) delete fullEnv[k];
  const devnull = fs.openSync('/dev/null', 'r');
  try {
    return spawnSync(process.execPath, [bin, ...args], { stdio: [devnull, 'pipe', 'pipe'], encoding: 'utf8', env: fullEnv });
  } finally {
    fs.closeSync(devnull);
  }
}

function vaultEntries(home) {
  return JSON.parse(fs.readFileSync(path.join(home, 'vault.json'), 'utf8')).entries;
}

function freshHome() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'aikeys-'));
  assert.equal(run(home, ['setup']).status, 0);
  return home;
}

test('render inserts secrets literally, including $ replacement patterns', () => {
  const home = freshHome();
  const secrets = { a: 'sk-abc$&def', b: 'x$`y', c: "p$'q", d: 'a$$b', e: '$1$<n>' };
  for (const [k, v] of Object.entries(secrets)) {
    assert.equal(run(home, ['set', `demo/${k}`], `${v}\n`).status, 0);
  }
  const template = path.join(home, 't.env');
  const output = path.join(home, 'o.env');
  fs.writeFileSync(template, Object.keys(secrets).map((k) => `${k.toUpperCase()}={{aikeys:demo/${k}}}`).join('\n') + '\n');
  assert.equal(run(home, ['render', template, output]).status, 0);
  const expected = Object.entries(secrets).map(([k, v]) => `${k.toUpperCase()}=${v}`).join('\n') + '\n';
  assert.equal(fs.readFileSync(output, 'utf8'), expected);
});

test('render does not re-expand tokens that appear inside a secret value', () => {
  const home = freshHome();
  assert.equal(run(home, ['set', 'demo/outer'], '{{aikeys:demo/inner}}\n').status, 0);
  assert.equal(run(home, ['set', 'demo/inner'], 'INNER\n').status, 0);
  const template = path.join(home, 't.env');
  const output = path.join(home, 'o.env');
  fs.writeFileSync(template, 'A={{aikeys:demo/outer}}\nB={{aikeys:demo/inner}}\n');
  assert.equal(run(home, ['render', template, output]).status, 0);
  assert.equal(fs.readFileSync(output, 'utf8'), 'A={{aikeys:demo/inner}}\nB=INNER\n');
});

test('set refuses an empty secret from non-TTY stdin and stores nothing', () => {
  const home = freshHome();
  const got = runNoInput(home, ['set', 'demo/key', 'v1'], {}, ['AIKEYS_SECRET']);
  assert.notEqual(got.status, 0);
  assert.match(got.stderr, /empty secret refused/);
  assert.doesNotMatch(got.stdout, /stored/);
  assert.deepEqual(vaultEntries(home), {});
});

test('set refuses an empty vault password and stores nothing', () => {
  const home = freshHome();
  const got = runNoInput(home, ['set', 'demo/key', 'v1'], { AIKEYS_SECRET: 'sk-some-secret' }, ['AIKEYS_PASSWORD']);
  assert.notEqual(got.status, 0);
  assert.match(got.stderr, /empty vault password refused/);
  assert.deepEqual(vaultEntries(home), {});
});

test('get refuses an empty vault password and prints nothing', () => {
  const { home, secret } = seed();
  const got = runNoInput(home, ['get', 'demo/key', 'v1'], {}, ['AIKEYS_PASSWORD']);
  assert.notEqual(got.status, 0);
  assert.match(got.stderr, /empty vault password refused/);
  assert.equal(got.stdout, '');
  assert.doesNotMatch(got.stderr, new RegExp(secret));
});

test('set rejects an unknown --store and stores nothing', () => {
  const home = freshHome();
  const got = run(home, ['set', 'demo/key', '--store', 'foo'], 'sk-value\n');
  assert.notEqual(got.status, 0);
  assert.match(got.stderr, /unknown store: foo/);
  assert.doesNotMatch(got.stdout, /stored/);
  assert.deepEqual(vaultEntries(home), {});
});

test('set --store keychain fails closed when no keychain tool exists', () => {
  const home = freshHome();
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'aikeys-nopath-'));
  const got = run(home, ['set', 'demo/key', '--store', 'keychain'], 'sk-value\n', { PATH: empty });
  assert.notEqual(got.status, 0);
  assert.match(got.stderr, /keychain store requested but no native keychain/);
  assert.doesNotMatch(got.stdout, /stored/);
  assert.deepEqual(vaultEntries(home), {});
});
