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

// Fake keychain tools. They stand in for macOS `security` / Linux `secret-tool`
// so the tests never touch a real keychain, and they log every argv so we can
// prove the secret never appears on a command line.
const KEYCHAIN_TOOL = process.platform === 'darwin' ? 'security' : 'secret-tool';
const keychainSkip = !['darwin', 'linux'].includes(process.platform) && 'native keychain paths exist only on darwin/linux';
const FAKE_KEYCHAIN = `'use strict';
const fs = require('fs');
const path = require('path');
const dir = process.env.FAKE_KEYCHAIN_DIR;
const mode = process.env.FAKE_KEYCHAIN_MODE || 'ok';
const [tool, ...args] = process.argv.slice(2);
fs.appendFileSync(path.join(dir, 'argv.log'), JSON.stringify(args) + '\\n');
fs.appendFileSync(path.join(dir, 'env.log'), JSON.stringify(['AIKEYS_PASSWORD', 'AIKEYS_SECRET'].filter((k) => k in process.env)) + '\\n');
const statePath = path.join(dir, 'state.json');
const state = fs.existsSync(statePath) ? JSON.parse(fs.readFileSync(statePath, 'utf8')) : {};
const save = () => fs.writeFileSync(statePath, JSON.stringify(state));
const stdin = () => fs.readFileSync(0, 'utf8');
const opt = (list, flag) => list[list.indexOf(flag) + 1];
function write(key, value) {
  if (mode === 'fail') { process.stderr.write('refused: ' + value + '\\n'); process.exit(1); }
  state[key] = mode === 'truncate' ? value.slice(0, 5) : value;
  save();
}
if (tool === 'security') {
  if (args[0] === '-i') {
    const line = stdin();
    fs.appendFileSync(path.join(dir, 'stdin.log'), line);
    if (mode === 'fail') { process.stderr.write('security: unknown command "' + line.trim() + '"\\n'); process.exit(1); }
    const words = line.trim().split(/\\s+/);
    write(opt(words, '-s') + '|' + opt(words, '-a'), Buffer.from(opt(words, '-X'), 'hex').toString('utf8'));
  } else if (args[0] === 'find-generic-password') {
    const key = opt(args, '-s') + '|' + opt(args, '-a');
    if (!(key in state)) process.exit(44);
    process.stdout.write(state[key] + '\\n');
  } else if (args[0] === 'delete-generic-password') {
    delete state[opt(args, '-s') + '|' + opt(args, '-a')];
    save();
  } else process.exit(2);
} else {
  const key = opt(args, 'service') + '|' + opt(args, 'account');
  if (args[0] === 'store') write(key, stdin());
  else if (args[0] === 'lookup') { if (!(key in state)) process.exit(1); process.stdout.write(state[key]); }
  else if (args[0] === 'clear') { delete state[key]; save(); }
  else process.exit(2);
}
`;

function fakeKeychain(mode = 'ok') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aikeys-fakekc-'));
  const bindir = path.join(dir, 'bin');
  fs.mkdirSync(bindir);
  fs.writeFileSync(path.join(dir, 'fake.js'), FAKE_KEYCHAIN);
  const wrapper = path.join(bindir, KEYCHAIN_TOOL);
  fs.writeFileSync(wrapper, `#!/bin/sh\nexec "${process.execPath}" "${path.join(dir, 'fake.js')}" ${KEYCHAIN_TOOL} "$@"\n`, { mode: 0o755 });
  return {
    dir,
    env: { PATH: `${bindir}:/usr/bin:/bin`, FAKE_KEYCHAIN_DIR: dir, FAKE_KEYCHAIN_MODE: mode },
    argv: () => (fs.existsSync(path.join(dir, 'argv.log')) ? fs.readFileSync(path.join(dir, 'argv.log'), 'utf8') : ''),
    state: () => (fs.existsSync(path.join(dir, 'state.json')) ? JSON.parse(fs.readFileSync(path.join(dir, 'state.json'), 'utf8')) : {})
  };
}

test('keychain store keeps the secret out of argv and reports the store used', { skip: keychainSkip }, () => {
  const home = freshHome();
  const kc = fakeKeychain();
  const secret = 'sk-argv-canary-$&-value';
  const hex = Buffer.from(secret).toString('hex');
  const set = run(home, ['set', 'demo/key', 'v1', '--store', 'keychain'], `${secret}\n`, kc.env);
  assert.equal(set.status, 0, set.stderr);
  assert.match(set.stdout, /stored demo\/key@v1 in keychain/);
  assert.ok(kc.argv().length > 0, 'fake keychain tool was not invoked');
  assert.ok(!kc.argv().includes(secret), 'secret appeared in keychain tool argv');
  assert.ok(!kc.argv().includes(hex), 'hex-encoded secret appeared in keychain tool argv');
  assert.equal(vaultEntries(home)['demo/key'].versions.v1.store, 'keychain');
  const got = run(home, ['get', 'demo/key', 'v1'], undefined, kc.env);
  assert.equal(got.status, 0, got.stderr);
  assert.equal(got.stdout, secret);
});

test('keychain write failure does not echo the secret and stores nothing', { skip: keychainSkip }, () => {
  const home = freshHome();
  const kc = fakeKeychain('fail');
  const secret = 'sk-leak-canary-value';
  const hex = Buffer.from(secret).toString('hex');
  const got = run(home, ['set', 'demo/key', '--store', 'keychain'], `${secret}\n`, kc.env);
  assert.notEqual(got.status, 0);
  for (const stream of [got.stdout, got.stderr]) {
    assert.ok(!stream.includes(secret) && !stream.includes(hex), 'secret leaked in error output');
  }
  assert.deepEqual(vaultEntries(home), {});
});

test('keychain write that silently truncates is detected and removed', { skip: keychainSkip }, () => {
  const home = freshHome();
  const kc = fakeKeychain('truncate');
  const got = run(home, ['set', 'demo/key', '--store', 'keychain'], 'sk-truncated-secret-value\n', kc.env);
  assert.notEqual(got.status, 0);
  assert.match(got.stderr, /cannot store this secret verbatim/);
  assert.deepEqual(kc.state(), {});
  assert.deepEqual(vaultEntries(home), {});
});

test('macOS keychain refuses a secret too long for security -i', { skip: process.platform !== 'darwin' && 'macOS-only line limit' }, () => {
  const home = freshHome();
  const kc = fakeKeychain();
  const got = run(home, ['set', 'demo/key', '--store', 'keychain'], `${'k'.repeat(2100)}\n`, kc.env);
  assert.notEqual(got.status, 0);
  assert.match(got.stderr, /too long for the macOS keychain/);
  assert.deepEqual(kc.state(), {});
  assert.deepEqual(vaultEntries(home), {});
});

test('render tightens an existing world-readable output to 0600 and leaves no temp files', () => {
  const { home } = seed();
  const template = path.join(home, 't.env');
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aikeys-out-'));
  const output = path.join(outDir, '.env');
  fs.writeFileSync(template, 'K={{aikeys:demo/key@v1}}\n');
  fs.writeFileSync(output, 'OLD=1\n', { mode: 0o644 });
  fs.chmodSync(output, 0o644);
  assert.equal(run(home, ['render', template, output]).status, 0);
  assert.equal(fs.statSync(output).mode & 0o777, 0o600);
  assert.deepEqual(fs.readdirSync(outDir), ['.env']);
});

test('render failure leaves an existing output untouched', () => {
  const { home } = seed();
  const template = path.join(home, 't.env');
  const output = path.join(home, 'o.env');
  fs.writeFileSync(template, 'K={{aikeys:demo/key@v1}}\nM={{aikeys:demo/missing}}\n');
  fs.writeFileSync(output, 'OLD=1\n');
  assert.notEqual(run(home, ['render', template, output]).status, 0);
  assert.equal(fs.readFileSync(output, 'utf8'), 'OLD=1\n');
});

test('vault and config rewrites tighten a loosened mode back to 0600', () => {
  const { home } = seed();
  for (const f of ['vault.json', 'config.json']) fs.chmodSync(path.join(home, f), 0o644);
  assert.equal(run(home, ['set', 'demo/other'], 'sk-another\n').status, 0);
  assert.equal(run(home, ['setup', '--force']).status, 0);
  for (const f of ['vault.json', 'config.json']) {
    assert.equal(fs.statSync(path.join(home, f)).mode & 0o777, 0o600, `${f} not 0600`);
  }
  assert.deepEqual(fs.readdirSync(home).filter((f) => f.endsWith('.tmp')), []);
});

test('agentPolicy is flagged as advisory once per home', () => {
  const home = freshHome();
  const first = run(home, ['where']);
  assert.equal(first.status, 0);
  assert.match(first.stderr, /agentPolicy .* advisory/);
  const second = run(home, ['where']);
  assert.equal(second.status, 0);
  assert.doesNotMatch(second.stderr, /agentPolicy/);
});

// Real pseudo-terminal tests. Piped stdin never reaches the interactive prompt,
// so these drive aikeys through a pty the way a person at a terminal does.
const PTY_DRIVER = `
import json, os, pty, select, sys, time
argv, steps = json.loads(sys.argv[1]), json.loads(sys.argv[2])
pid, fd = pty.fork()
if pid == 0:
    os.execv(argv[0], argv)
out = b''
def pump(until=None, timeout=15):
    global out
    end = time.time() + timeout
    while time.time() < end:
        if until is not None and until in out:
            return True
        r, _, _ = select.select([fd], [], [], 0.2)
        if fd in r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                return False
            if not chunk:
                return False
            out += chunk
    return False
for prompt, text in steps:
    if not pump(prompt.encode()):
        break
    time.sleep(0.1)
    os.write(fd, text.encode())
pump()
_, status = os.waitpid(pid, 0)
code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
print(json.dumps({'status': code, 'out': out.decode('utf8', 'replace')}))
`;
const python = spawnSync('python3', ['-c', 'import pty'], { encoding: 'utf8' }).status === 0 ? 'python3' : null;
const ptySkip = (!python || process.platform === 'win32') && 'needs python3 with the pty module';

function runPty(home, args, steps, env = {}, unset = []) {
  const fullEnv = { ...process.env, AIKEYS_HOME: home, ...env };
  for (const k of unset) delete fullEnv[k];
  const res = spawnSync(python, ['-c', PTY_DRIVER, JSON.stringify([process.execPath, bin, ...args]), JSON.stringify(steps)], { encoding: 'utf8', env: fullEnv, timeout: 60000 });
  assert.equal(res.status, 0, `pty driver failed: ${res.stderr}`);
  return JSON.parse(res.stdout);
}

test('tty: set reads a typed secret and get reads a typed password', { skip: ptySkip }, () => {
  const home = freshHome();
  const secret = 'sk-typed-at-a-tty-$&-value';
  const set = runPty(home, ['set', 'demo/key', 'v1'], [['Secret: ', `${secret}\r`]], { AIKEYS_PASSWORD: 'tty-pw' }, ['AIKEYS_SECRET']);
  assert.equal(set.status, 0, set.out);
  assert.match(set.out, /stored demo\/key@v1 in file/);
  assert.ok(!set.out.includes(secret), 'typed secret was echoed');
  const get = runPty(home, ['get', 'demo/key', 'v1'], [['Vault password: ', 'tty-pw\r']], {}, ['AIKEYS_PASSWORD']);
  assert.equal(get.status, 0, get.out);
  assert.ok(get.out.includes(secret), `get did not print the secret: ${JSON.stringify(get.out)}`);
  assert.ok(!get.out.includes('tty-pw'), 'typed password was echoed');
});

test('tty: set prompts for both secret and password when neither variable is set', { skip: ptySkip }, () => {
  const home = freshHome();
  const set = runPty(home, ['set', 'demo/key'], [['Secret: ', 'sk-two-prompts\r'], ['Vault password: ', 'pw2\r']], {}, ['AIKEYS_SECRET', 'AIKEYS_PASSWORD']);
  assert.equal(set.status, 0, set.out);
  assert.equal(run(home, ['get', 'demo/key'], undefined, { AIKEYS_PASSWORD: 'pw2' }).stdout, 'sk-two-prompts');
});

test('tty: Ctrl-D at the password prompt shows a visible refusal and exits 1', { skip: ptySkip }, () => {
  const { home } = seed();
  const got = runPty(home, ['get', 'demo/key', 'v1'], [['Vault password: ', '\x04']], {}, ['AIKEYS_PASSWORD']);
  assert.equal(got.status, 1, got.out);
  assert.match(got.out, /aikeys: empty vault password refused/);
});

test('tty: Ctrl-D at the secret prompt shows a visible refusal and stores nothing', { skip: ptySkip }, () => {
  const home = freshHome();
  const got = runPty(home, ['set', 'demo/key'], [['Secret: ', '\x04']], {}, ['AIKEYS_SECRET']);
  assert.equal(got.status, 1, got.out);
  assert.match(got.out, /aikeys: empty secret refused/);
  assert.deepEqual(vaultEntries(home), {});
});

test('set and get refuse prototype-key and malformed versions and names', () => {
  const home = freshHome();
  for (const version of ['__proto__', 'constructor', 'prototype', 'v 1', 'v1;x', 'v1/x']) {
    const set = run(home, ['set', 'demo/key', version], 'sk-value\n');
    assert.notEqual(set.status, 0, `set accepted version ${version}`);
    assert.doesNotMatch(set.stdout, /stored/);
    const get = run(home, ['get', 'demo/key', version]);
    assert.notEqual(get.status, 0, `get accepted version ${version}`);
  }
  for (const id of ['__proto__/key', 'demo/__proto__', 'constructor/prototype']) {
    assert.notEqual(run(home, ['set', id], 'sk-value\n').status, 0, `set accepted id ${id}`);
  }
  assert.deepEqual(vaultEntries(home), {});
});

test('names that shadow Object.prototype members are not found by get', () => {
  const home = freshHome();
  const got = run(home, ['get', 'demo/toString', 'hasOwnProperty']);
  assert.notEqual(got.status, 0);
  assert.match(got.stderr, /missing secret/);
});

test('a failed keychain update leaves the previous item and metadata intact', { skip: keychainSkip }, () => {
  const home = freshHome();
  const kc = fakeKeychain();
  assert.equal(run(home, ['set', 'demo/key', 'v1', '--store', 'keychain'], 'sk-original-good-value\n', kc.env).status, 0);
  const bad = run(home, ['set', 'demo/key', 'v1', '--store', 'keychain'], 'sk-replacement-value\n', { ...kc.env, FAKE_KEYCHAIN_MODE: 'truncate' });
  assert.notEqual(bad.status, 0);
  assert.match(bad.stderr, /nothing was changed/);
  const got = run(home, ['get', 'demo/key', 'v1'], undefined, kc.env);
  assert.equal(got.status, 0, got.stderr);
  assert.equal(got.stdout, 'sk-original-good-value');
  assert.deepEqual(Object.keys(kc.state()), [`aikeys|demo/key@v1`]);
});

test('keychain refuses leading or trailing whitespace before touching the store', { skip: keychainSkip }, () => {
  const home = freshHome();
  const kc = fakeKeychain();
  for (const secret of ['sk-trailing-space ', ' sk-leading-space', 'sk-trailing-tab\t']) {
    const got = run(home, ['set', 'demo/key', '--store', 'keychain'], undefined, { ...kc.env, AIKEYS_SECRET: secret });
    assert.notEqual(got.status, 0, `accepted ${JSON.stringify(secret)}`);
    assert.match(got.stderr, /leading or trailing whitespace/);
  }
  assert.equal(kc.argv(), '', 'keychain tool was invoked');
  assert.deepEqual(vaultEntries(home), {});
});

test('piped input keeps trailing spaces and loses only the final newline', () => {
  const home = freshHome();
  assert.equal(run(home, ['set', 'demo/key'], 'sk-ends-with-spaces  \n').status, 0);
  assert.equal(run(home, ['get', 'demo/key']).stdout, 'sk-ends-with-spaces  ');
});

test('keychain tool processes do not inherit AIKEYS_PASSWORD or AIKEYS_SECRET', { skip: keychainSkip }, () => {
  const home = freshHome();
  const kc = fakeKeychain();
  const got = run(home, ['set', 'demo/key', '--store', 'keychain'], undefined, { ...kc.env, AIKEYS_SECRET: 'sk-env-secret-value' });
  assert.equal(got.status, 0, got.stderr);
  const log = fs.readFileSync(path.join(kc.dir, 'env.log'), 'utf8').trim().split('\n');
  assert.ok(log.length > 0);
  for (const line of log) assert.deepEqual(JSON.parse(line), []);
});

test('a failed rename during render removes the temp file', () => {
  const { home } = seed();
  const template = path.join(home, 't.env');
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aikeys-out-'));
  const output = path.join(outDir, 'out.env');
  fs.mkdirSync(output);
  fs.writeFileSync(path.join(output, 'keep'), 'x');
  fs.writeFileSync(template, 'K={{aikeys:demo/key@v1}}\n');
  assert.notEqual(run(home, ['render', template, output]).status, 0);
  assert.deepEqual(fs.readdirSync(outDir), ['out.env']);
});

test('render replaces a symlinked output with a regular 0600 file and leaves the link target alone', { skip: process.platform === 'win32' && 'symlinks need privileges on Windows' }, () => {
  const { home } = seed();
  const template = path.join(home, 't.env');
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aikeys-out-'));
  const target = path.join(outDir, 'target.txt');
  const output = path.join(outDir, '.env');
  fs.writeFileSync(target, 'ORIGINAL\n', { mode: 0o644 });
  fs.symlinkSync(target, output);
  fs.writeFileSync(template, 'K={{aikeys:demo/key@v1}}\n');
  assert.equal(run(home, ['render', template, output]).status, 0);
  const st = fs.lstatSync(output);
  assert.ok(st.isFile() && !st.isSymbolicLink());
  assert.equal(st.mode & 0o777, 0o600);
  assert.equal(fs.readFileSync(target, 'utf8'), 'ORIGINAL\n');
});

// exec: secrets go into one child's environment and nowhere else. The child
// below reports a SHA-256 fingerprint of what it received (never the value),
// and touches a marker file so negative tests can prove it never started.
const childScript = [
  "const fs = require('fs');",
  "const crypto = require('crypto');",
  "if (process.env.MARKER) fs.writeFileSync(process.env.MARKER, 'ran');",
  "const v = process.env.DEMO_KEY;",
  "process.stdout.write(JSON.stringify({",
  "  fingerprint: v ? crypto.createHash('sha256').update(v).digest('hex') : null,",
  "  password: process.env.AIKEYS_PASSWORD ?? null,",
  "  argv: process.argv.slice(1),",
  "}));",
  "process.exit(Number(process.env.EXIT_WITH || 0));",
].join('\n');

function setExecConfig(home, mutate) {
  const configPath = path.join(home, 'config.json');
  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  mutate(config);
  fs.writeFileSync(configPath, JSON.stringify(config));
}

// Most exec tests use ad-hoc --env, which a real config must opt into.
function execSeed({ adhoc = true } = {}) {
  const { home, secret } = seed('sk-EXEC-secret-value-123');
  const marker = path.join(home, 'child-ran');
  if (adhoc) setExecConfig(home, (c) => { c.exec = { allowAdhocEnv: true }; });
  return { home, secret, marker };
}

const sha = (v) => crypto.createHash('sha256').update(v).digest('hex');

test('exec puts the secret in the child env without printing it', () => {
  const { home, secret, marker } = execSeed();
  const got = run(home, ['exec', '--env', 'DEMO_KEY=demo/key@v1', '--', process.execPath, '-e', childScript, 'x; touch pwned'], undefined, { MARKER: marker });
  assert.equal(got.status, 0, got.stderr);
  const report = JSON.parse(got.stdout);
  assert.equal(report.fingerprint, sha(secret));
  assert.ok(!got.stdout.includes(secret) && !got.stderr.includes(secret));
  // No shell: the argument arrives verbatim and is never executed.
  assert.deepEqual(report.argv, ['x; touch pwned']);
  assert.ok(!fs.existsSync(path.join(process.cwd(), 'pwned')));
});

test('exec children do not inherit AIKEYS_PASSWORD', () => {
  const { home } = execSeed();
  const got = run(home, ['exec', '--env', 'DEMO_KEY=demo/key@v1', '--', process.execPath, '-e', childScript]);
  assert.equal(JSON.parse(got.stdout).password, null);
});

test('exec passes the child exit code through', () => {
  const { home } = execSeed();
  const got = run(home, ['exec', '--env', 'DEMO_KEY=demo/key@v1', '--', process.execPath, '-e', childScript], undefined, { EXIT_WITH: '7' });
  assert.equal(got.status, 7);
});

function assertNeverRan(got, marker, secret, label) {
  assert.notEqual(got.status, 0, `${label}: expected non-zero exit`);
  assert.ok(!fs.existsSync(marker), `${label}: child must not start`);
  assert.ok(!got.stdout.includes(secret) && !got.stderr.includes(secret), `${label}: secret leaked`);
}

test('exec fails closed on a missing secret and never starts the child', () => {
  const { home, secret, marker } = execSeed();
  const got = run(home, ['exec', '--env', 'DEMO_KEY=demo/key@v1', '--env', 'OTHER_KEY=demo/missing', '--', process.execPath, '-e', childScript], undefined, { MARKER: marker });
  assertNeverRan(got, marker, secret, 'missing secret');
});

test('exec fails closed on a wrong vault password', () => {
  const { home, secret, marker } = execSeed();
  const got = run(home, ['exec', '--env', 'DEMO_KEY=demo/key@v1', '--', process.execPath, '-e', childScript], undefined, { MARKER: marker, AIKEYS_PASSWORD: 'wrong' });
  assertNeverRan(got, marker, secret, 'wrong password');
});

test('exec refuses variables that control loading or lookup', () => {
  const { home, secret, marker } = execSeed();
  for (const name of ['PATH', 'NODE_OPTIONS', 'DYLD_INSERT_LIBRARIES', 'LD_PRELOAD', 'AIKEYS_PASSWORD', 'BASH_ENV']) {
    const got = run(home, ['exec', '--env', `${name}=demo/key@v1`, '--', process.execPath, '-e', childScript], undefined, { MARKER: marker });
    assertNeverRan(got, marker, secret, name);
  }
});

test('exec refuses malformed, duplicate and prototype mappings', () => {
  const { home, secret, marker } = execSeed();
  const cases = [
    ['--env', 'lower=demo/key@v1'],
    ['--env', 'DEMO_KEY'],
    ['--env', 'DEMO_KEY=nokey'],
    ['--env', 'DEMO_KEY=__proto__/key'],
    ['--env', 'DEMO_KEY=demo/key@v1', '--env', 'DEMO_KEY=demo/key@v1'],
    ['--profile', '__proto__'],
    ['--profile', 'nope'],
    ['--bogus', 'x'],
    [],
  ];
  for (const opts of cases) {
    const got = run(home, ['exec', ...opts, '--', process.execPath, '-e', childScript], undefined, { MARKER: marker });
    assertNeverRan(got, marker, secret, JSON.stringify(opts));
  }
  const noCommand = run(home, ['exec', '--env', 'DEMO_KEY=demo/key@v1', '--']);
  assert.notEqual(noCommand.status, 0);
});

test('exec resolves a named profile from config', () => {
  const { home, secret } = execSeed();
  setExecConfig(home, (c) => { c.profiles = { studio: { DEMO_KEY: 'demo/key@v1' } }; });
  const got = run(home, ['exec', '--profile', 'studio', '--', process.execPath, '-e', childScript]);
  assert.equal(got.status, 0, got.stderr);
  assert.equal(JSON.parse(got.stdout).fingerprint, sha(secret));
});

test('exec logs names to a 0600 exec.log and never the value', () => {
  const { home, secret } = execSeed();
  assert.equal(run(home, ['exec', '--env', 'DEMO_KEY=demo/key@v1', '--', process.execPath, '-e', childScript]).status, 0);
  const logPath = path.join(home, 'exec.log');
  const log = fs.readFileSync(logPath, 'utf8');
  assert.match(log, /DEMO_KEY=demo\/key@v1/);
  assert.ok(!log.includes(secret));
  if (process.platform !== 'win32') assert.equal(fs.statSync(logPath).mode & 0o777, 0o600);
});

test('exec refuses to run when it cannot record the exec', () => {
  const { home, secret, marker } = execSeed();
  fs.mkdirSync(path.join(home, 'exec.log')); // appendFile on a directory fails
  const got = run(home, ['exec', '--env', 'DEMO_KEY=demo/key@v1', '--', process.execPath, '-e', childScript], undefined, { MARKER: marker });
  assertNeverRan(got, marker, secret, 'unwritable audit log');
});

test('exec refuses ad-hoc --env unless config opts in', () => {
  const { home, secret, marker } = execSeed({ adhoc: false });
  const got = run(home, ['exec', '--env', 'DEMO_KEY=demo/key@v1', '--', process.execPath, '-e', childScript], undefined, { MARKER: marker });
  assertNeverRan(got, marker, secret, 'ad-hoc env without opt-in');
});

test('a command-bound profile runs only its commands', () => {
  const { home, secret, marker } = execSeed({ adhoc: false });
  setExecConfig(home, (c) => {
    c.profiles = { bound: { env: { DEMO_KEY: 'demo/key@v1' }, commands: [[process.execPath, '-e', childScript]] } };
  });
  const ok = run(home, ['exec', '--profile', 'bound', '--', process.execPath, '-e', childScript, 'extra-arg']);
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(JSON.parse(ok.stdout).fingerprint, sha(secret));
  // The classic dump: same profile, different program.
  const dump = run(home, ['exec', '--profile', 'bound', '--', process.execPath, '-e', "require('fs').writeFileSync(process.env.MARKER,'ran');console.log(process.env.DEMO_KEY)"], undefined, { MARKER: marker });
  assertNeverRan(dump, marker, secret, 'unbound command');
  for (const bad of [{ env: { DEMO_KEY: 'demo/key@v1' }, commands: [] }, { env: { DEMO_KEY: 'demo/key@v1' }, commands: 'node' }, { env: ['x'] }]) {
    setExecConfig(home, (c) => { c.profiles = { bound: bad }; });
    assertNeverRan(run(home, ['exec', '--profile', 'bound', '--', process.execPath, '-e', childScript], undefined, { MARKER: marker }), marker, secret, JSON.stringify(bad));
  }
});

test('exec only sets credential-shaped names unless allowlisted', () => {
  const { home, secret, marker } = execSeed();
  assertNeverRan(run(home, ['exec', '--env', 'DEMO_THING=demo/key@v1', '--', process.execPath, '-e', childScript], undefined, { MARKER: marker }), marker, secret, 'non-credential name');
  setExecConfig(home, (c) => { c.exec.allowNames = ['DEMO_THING']; });
  assert.equal(run(home, ['exec', '--env', 'DEMO_THING=demo/key@v1', '--', process.execPath, '-e', childScript]).status, 0);
});

test('exec refuses execution, network and TLS steering names even when allowlisted', () => {
  const { home, secret, marker } = execSeed();
  const names = ['NPM_CONFIG_SCRIPT_SHELL', 'GIT_CONFIG_COUNT', 'GIT_ASKPASS', 'HTTPS_PROXY', 'ALL_PROXY', 'NODE_EXTRA_CA_CERTS',
    'NODE_TLS_REJECT_UNAUTHORIZED', 'PYTHONWARNINGS', 'PIP_INDEX_URL', 'SSL_CERT_FILE', 'CURL_CA_BUNDLE', 'EDITOR', 'SSH_ASKPASS', 'REQUESTS_CA_BUNDLE'];
  setExecConfig(home, (c) => { c.exec.allowNames = names; });
  for (const name of names) {
    assertNeverRan(run(home, ['exec', '--env', `${name}=demo/key@v1`, '--', process.execPath, '-e', childScript], undefined, { MARKER: marker }), marker, secret, name);
  }
});

test('exec never reads the vault password from piped stdin', () => {
  const { home, secret, marker } = execSeed();
  const got = run(home, ['exec', '--env', 'DEMO_KEY=demo/key@v1', '--', process.execPath, '-e', childScript], 'test-password\n', { MARKER: marker, AIKEYS_PASSWORD: '' });
  assertNeverRan(got, marker, secret, 'password on stdin');
  assert.match(got.stderr, /stdin belongs to the command/);
});

test('exec.log records are one JSON object per line and cannot be forged by a newline in cwd', { skip: process.platform === 'win32' && 'newline paths' }, () => {
  const { home } = execSeed();
  const evil = path.join(home, 'x\n2026-01-01T00:00:00Z exec forged cwd=x FAKE_KEY=a.b');
  fs.mkdirSync(evil);
  const got = spawnSync(process.execPath, [bin, 'exec', '--env', 'DEMO_KEY=demo/key@v1', '--', process.execPath, '-e', childScript], {
    cwd: evil, encoding: 'utf8', env: { ...process.env, AIKEYS_HOME: home, AIKEYS_PASSWORD: 'test-password' },
  });
  assert.equal(got.status, 0, got.stderr);
  const lines = fs.readFileSync(path.join(home, 'exec.log'), 'utf8').trim().split('\n');
  assert.equal(lines.length, 1);
  const record = JSON.parse(lines[0]);
  assert.equal(record.cwd, fs.realpathSync(evil));
  assert.deepEqual(record.map, ['DEMO_KEY=demo/key@v1']);
  assert.equal(record.argv[0], process.execPath);
});

test('a profile bound to a directory refuses to run anywhere else', () => {
  const { home, secret, marker } = execSeed({ adhoc: false });
  const allowedDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aikeys-cwd-'));
  setExecConfig(home, (c) => {
    c.profiles = { here: { env: { DEMO_KEY: 'demo/key@v1' }, commands: [[process.execPath]], cwd: [allowedDir] } };
  });
  const runIn = (cwd) => spawnSync(process.execPath, [bin, 'exec', '--profile', 'here', '--', process.execPath, '-e', childScript], {
    cwd, encoding: 'utf8', env: { ...process.env, AIKEYS_HOME: home, AIKEYS_PASSWORD: 'test-password', MARKER: marker },
  });
  assertNeverRan(runIn(home), marker, secret, 'wrong directory');
  const ok = runIn(allowedDir);
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(JSON.parse(ok.stdout).fingerprint, sha(secret));
});
