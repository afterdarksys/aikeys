#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const readline = require('readline');
const { spawn, spawnSync } = require('child_process');

const APP = 'aikeys';
const CONFIG_VERSION = 1;

// The only algorithm/KDF pair this vault will decrypt. These are recorded on
// every entry AND enforced on read: an attacker who can edit vault.json must
// not be able to talk us into a weaker primitive by rewriting the metadata.
// Threats: offline tamper of vault.json (downgrade to an unauthenticated mode,
// or to a cheap KDF), and silent corruption. Both fail closed.
const ALG = 'aes-256-gcm';
const KDF = 'scrypt';
const KEY_LEN = 32;
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const STORES = ['file', 'keychain'];
const DEFAULT_CONFIG = {
  version: CONFIG_VERSION,
  defaultStore: 'file',
  vaultFile: 'vault.json',
  keychainService: 'aikeys',
  template: {
    tokenPattern: '{{aikeys:<section>/<key>@<version>}}',
    examples: [
      'OPENAI_API_KEY={{aikeys:openai/api_key@prod}}',
      'ANTHROPIC_API_KEY={{aikeys:anthropic/api_key}}'
    ]
  },
  agentPolicy: {
    preferRender: true,
    doNotPrintSecretsInLogs: true,
    allowedCommands: [
      'aikeys get <section>/<key> [version]',
      'aikeys render <template> <output>'
    ]
  }
};

const SECRET_PATTERNS = [
  { name: 'openai', re: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  { name: 'anthropic', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { name: 'aws_access_key_id', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'generic_assignment', re: /\b([A-Z][A-Z0-9_]*(?:API|TOKEN|SECRET|KEY)[A-Z0-9_]*)\s*=\s*["']?([^"'\s#]{16,})["']?/g }
];

function main() {
  const args = process.argv.slice(2);
  const command = args.shift();
  try {
    switch (command) {
      case 'setup':
        return setup(args);
      case 'set':
      case 'put':
        return setSecret(args);
      case 'get':
        return getSecret(args);
      case 'render':
        return renderTemplate(args);
      case 'exec':
        return execWithSecrets(args);
      case 'scan':
        return scan(args);
      case 'where':
        return where();
      case 'help':
      case '--help':
      case '-h':
      case undefined:
        return help();
      default:
        fail(`unknown command: ${command}`);
    }
  } catch (err) {
    fail(err.message || String(err));
  }
}

function setup(args) {
  const force = takeFlag(args, '--force');
  const store = takeValue(args, '--store') || DEFAULT_CONFIG.defaultStore;
  if (!STORES.includes(store)) fail('--store must be file or keychain');
  ensureHome();
  const configPath = getConfigPath();
  if (fs.existsSync(configPath) && !force) fail(`${configPath} already exists; use --force to overwrite`);
  const config = { ...DEFAULT_CONFIG, defaultStore: store };
  writeJSON(configPath, config);
  if (!fs.existsSync(getVaultPath(config))) {
    writeJSON(getVaultPath(config), { version: CONFIG_VERSION, entries: {} });
  }
  console.log(`created ${configPath}`);
  console.log(`created ${getVaultPath(config)}`);
}

// Threats: silently doing nothing (exit 0, nothing stored or printed) when
// stdin is empty or closed, and encrypting under an empty password. Empty
// input from any source is refused with a non-zero exit.
async function promptHidden(label) {
  const isPassword = label.toLowerCase().includes('password');
  const fromEnv = isPassword ? process.env.AIKEYS_PASSWORD : process.env.AIKEYS_SECRET;
  let value;
  if (fromEnv) value = fromEnv;
  else if (execMode && !process.stdin.isTTY) {
    fail('exec reads the vault password only from AIKEYS_PASSWORD or a terminal; stdin belongs to the command');
  }
  // Strip only the line terminator a pipe or heredoc adds; any other
  // whitespace is part of the value.
  else if (!process.stdin.isTTY) value = fs.readFileSync(0, 'utf8').replace(/\r?\n$/, '');
  else value = await promptTTY(label);
  if (!value) fail(`empty ${label.toLowerCase()} refused`);
  return value;
}

function promptTTY(label) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
    // Mute only this interface's echo. Patching process.stderr.write would
    // also swallow our own error messages after the prompt.
    let muted = false;
    let answered = false;
    const writeToOutput = rl._writeToOutput;
    rl._writeToOutput = function (stringToWrite) {
      if (!muted) writeToOutput.call(rl, stringToWrite);
    };
    rl.question(`${label}: `, (answer) => {
      // close() emits 'close' synchronously, so record the answer first.
      answered = true;
      muted = false;
      rl.close();
      process.stderr.write('\n');
      resolve(answer);
    });
    // EOF (Ctrl-D) closes the interface without an answer; resolve empty so
    // the caller refuses it instead of the process exiting 0 with no output.
    rl.on('close', () => {
      if (answered) return;
      muted = false;
      process.stderr.write('\n');
      resolve('');
    });
    muted = true;
  });
}

// Set by exec: fd 0 is the child's, so secrets and passwords never come from it.
let execMode = false;

// Stdin can only be read once, so a password read from a pipe is kept for the
// rest of this process (render may decrypt several file-vault entries).
let vaultPassword;
async function getPassword() {
  if (vaultPassword === undefined) vaultPassword = await promptHidden('Vault password');
  return vaultPassword;
}

function setSecret(args) {
  return runAsync(async () => {
    const store = takeValue(args, '--store');
    const id = args.shift();
    const version = args.shift() || 'default';
    if (!id) fail('usage: aikeys set <section>/<key> [version] [--store file|keychain]');
    const config = readConfig();
    const resolvedStore = store || config.defaultStore || 'file';
    checkStore(resolvedStore);
    const secret = await promptHidden('Secret');
    const usedStore = await saveSecret(config, id, version, secret, resolvedStore);
    console.log(`stored ${id}@${version} in ${usedStore}`);
  });
}

function getSecret(args) {
  return runAsync(async () => {
    const id = args.shift();
    const version = args.shift() || 'default';
    if (!id) fail('usage: aikeys get <section>/<key> [version]');
    const config = readConfig();
    const secret = await loadSecret(config, id, version);
    process.stdout.write(secret);
    if (process.stdout.isTTY) process.stdout.write('\n');
  });
}

function renderTemplate(args) {
  return runAsync(async () => {
    const templatePath = args.shift();
    const outputPath = args.shift();
    if (!templatePath || !outputPath) fail('usage: aikeys render <template> <output>');
    const config = readConfig();
    const template = fs.readFileSync(templatePath, 'utf8');
    const tokenRe = /\{\{aikeys:([^}/\s]+\/[^}@\s]+)(?:@([^}\s]+))?\}\}/g;
    const secrets = new Map();
    for (const match of template.matchAll(tokenRe)) {
      const ref = `${match[1]}@${match[2] || 'default'}`;
      if (!secrets.has(ref)) secrets.set(ref, await loadSecret(config, match[1], match[2] || 'default'));
    }
    // Threats: secret corruption and token injection. A string replacement
    // would expand `$&`, `$'`, `` $` `` and `$$` inside secret values, and
    // replacing tokens one at a time would re-expand a token that appears
    // inside an earlier secret. One pass over the template with a replacer
    // function inserts every secret byte-for-byte.
    const content = template.replace(tokenRe, (token, id, version) => secrets.get(`${id}@${version || 'default'}`));
    writeFileAtomic(outputPath, content);
    console.log(`rendered ${outputPath}`);
  });
}

// Threats: a secret reaching an agent's transcript, a log or shell history
// when the agent only needed to hand it to a program. `exec` resolves named
// secrets and puts them straight into ONE child process's environment: nothing
// is printed or written to disk, and the audit log records names and argv,
// never values. It fails closed: every secret resolves before the child
// starts, so a missing, empty or undecryptable one means nothing runs. No
// shell is involved. Only credential-shaped variable names can be set (or
// names listed in config), and names that steer how programs load code, find
// executables, reach the network or trust TLS are refused outright, so a
// stored value can never redirect execution or traffic.
// A profile may bind its secrets to specific commands; then any other command
// is refused, so `exec --profile studio -- printenv` cannot dump the keys.
// Does NOT protect against: a command that is allowed printing or uploading
// the value, or an agent that can EDIT the program a bound command runs
// (package.json scripts, the script file itself) — binding narrows accidents
// and casual misuse, it is not a sandbox. Nor against code running as the same
// user (it can read the keychain as we do) or anyone holding AIKEYS_PASSWORD.
// Harnesses should also deny `aikeys get`, `aikeys set` and `security
// find-generic-password` to agents; see README.
const ENV_NAME_RE = /^[A-Z_][A-Z0-9_]*$/;
const CREDENTIAL_NAME_RE = /_(API_KEY|KEY|TOKEN|SECRET|PAT|PASSWORD)$/;
const EXEC_DENY_EXACT = new Set([
  'PATH', 'HOME', 'SHELL', 'USER', 'IFS', 'ENV', 'BASH_ENV', 'PS4', 'PROMPT_COMMAND',
  'PERL5LIB', 'PERL5OPT', 'RUBYOPT', 'RUBYLIB', 'TMPDIR',
  'EDITOR', 'VISUAL', 'PAGER', 'SSH_ASKPASS', 'SUDO_ASKPASS', 'REQUESTS_CA_BUNDLE'
]);
// Second layer behind the credential-name allowlist (config allowNames could
// otherwise re-open these): loaders, interpreters, package managers, VCS,
// TLS trust and proxies.
const EXEC_DENY_PREFIX = ['LD_', 'DYLD_', 'AIKEYS_', 'NODE_', 'NPM_CONFIG_', 'GIT_', 'PYTHON', 'PIP_', 'SSL_', 'CURL_'];
const EXEC_DENY_SUFFIX = ['_PROXY'];

function checkEnvName(name, allowNames, origin) {
  if (!ENV_NAME_RE.test(name)) fail(`${origin}: environment name must be UPPER_SNAKE_CASE: ${name}`);
  if (
    EXEC_DENY_EXACT.has(name) ||
    EXEC_DENY_PREFIX.some((prefix) => name.startsWith(prefix)) ||
    EXEC_DENY_SUFFIX.some((suffix) => name.endsWith(suffix))
  ) {
    fail(`${origin}: refusing to set ${name}; it controls how programs load, run or connect`);
  }
  if (!CREDENTIAL_NAME_RE.test(name) && !allowNames.includes(name)) {
    fail(`${origin}: ${name} does not look like a credential (…_API_KEY, _KEY, _TOKEN, _SECRET, _PAT, _PASSWORD); list it under exec.allowNames in config.json to allow it`);
  }
}

function parseEnvMapping(spec, origin, allowNames) {
  const eq = spec.indexOf('=');
  if (eq <= 0) fail(`${origin}: expected NAME=section/key[@version], got "${spec}"`);
  const name = spec.slice(0, eq);
  const ref = spec.slice(eq + 1);
  checkEnvName(name, allowNames, origin);
  const at = ref.indexOf('@');
  const id = at === -1 ? ref : ref.slice(0, at);
  const version = at === -1 ? 'default' : ref.slice(at + 1);
  validateId(id);
  validateVersion(version);
  return { name, id, version };
}

// A profile is either a flat {NAME: "section/key"} map (any command), or
// {"env": {...}, "commands": [["npm", "run", "space:art"], ...], "cwd": [...]}:
// the command must start with one of those argv prefixes, element for
// element, and — when "cwd" is given — run from one of those directories, so
// `npm run space:art` in some other project's package.json doesn't qualify.
function resolveProfile(config, profileName, command, allowNames) {
  const profiles = Object.assign(Object.create(null), config.profiles);
  const profile = RESERVED_NAMES.includes(profileName) ? undefined : profiles[profileName];
  if (!profile || typeof profile !== 'object' || Array.isArray(profile)) {
    fail(`unknown profile: ${profileName} (define it under "profiles" in ${getConfigPath()})`);
  }
  const bound = Object.prototype.hasOwnProperty.call(profile, 'env');
  const env = bound ? profile.env : profile;
  if (!env || typeof env !== 'object' || Array.isArray(env)) fail(`profile ${profileName}: "env" must be an object`);
  if (bound) {
    const commands = profile.commands;
    if (!Array.isArray(commands) || !commands.length || !commands.every((c) => Array.isArray(c) && c.length && c.every((a) => typeof a === 'string'))) {
      fail(`profile ${profileName}: "commands" must be a non-empty list of argv prefixes`);
    }
    const allowed = commands.some((prefix) => prefix.length <= command.length && prefix.every((arg, i) => arg === command[i]));
    if (!allowed) fail(`profile ${profileName} is not bound to this command; allowed: ${commands.map((c) => c.join(' ')).join(' | ')}`);
    if (profile.cwd !== undefined) {
      if (!Array.isArray(profile.cwd) || !profile.cwd.every((d) => typeof d === 'string' && path.isAbsolute(d))) {
        fail(`profile ${profileName}: "cwd" must be a list of absolute directories`);
      }
      const here = fs.realpathSync(process.cwd());
      const ok = profile.cwd.some((dir) => {
        try {
          return fs.realpathSync(dir) === here;
        } catch {
          return false; // a configured directory that no longer exists matches nothing
        }
      });
      if (!ok) fail(`profile ${profileName} only runs from: ${profile.cwd.join(' | ')}`);
    }
  }
  const mappings = [];
  for (const [name, ref] of Object.entries(env)) {
    if (typeof ref !== 'string') fail(`profile ${profileName}: ${name} must map to "section/key[@version]"`);
    mappings.push(parseEnvMapping(`${name}=${ref}`, `profile ${profileName}`, allowNames));
  }
  return mappings;
}

function execWithSecrets(args) {
  return runAsync(async () => {
    const sep = args.indexOf('--');
    if (sep === -1 || sep === args.length - 1) {
      fail('usage: aikeys exec [--profile <name>]... [--env NAME=section/key[@version]]... -- <command> [args...]');
    }
    const options = args.slice(0, sep);
    const command = args.slice(sep + 1);
    const config = readConfig();
    const execPolicy = config.exec && typeof config.exec === 'object' ? config.exec : {};
    const allowNames = Array.isArray(execPolicy.allowNames) ? execPolicy.allowNames.filter((n) => typeof n === 'string') : [];

    const mappings = [];
    while (options.length) {
      const flag = options.shift();
      const value = options.shift();
      if (!value) fail(`${flag} requires a value`);
      if (flag === '--env') {
        // Ad-hoc mappings bypass profile command binding; opt in explicitly.
        if (execPolicy.allowAdhocEnv !== true) fail('--env is disabled; use a --profile, or set exec.allowAdhocEnv: true in config.json');
        mappings.push(parseEnvMapping(value, '--env', allowNames));
      } else if (flag === '--profile') mappings.push(...resolveProfile(config, value, command, allowNames));
      else fail(`unknown exec option: ${flag}`);
    }
    if (!mappings.length) fail('exec needs at least one --env or --profile');
    const seen = new Set();
    for (const { name } of mappings) {
      if (seen.has(name)) fail(`${name} is mapped more than once`);
      seen.add(name);
    }

    // Resolve everything before starting anything. fd 0 belongs to the
    // child: never read the vault password from a pipe here.
    execMode = true;
    const env = childEnv();
    for (const { name, id, version } of mappings) {
      const value = await loadSecret(config, id, version);
      if (!value) fail(`secret ${id}@${version} is empty; refusing to run`);
      env[name] = value;
    }

    auditExec(mappings, command);
    const child = spawn(command[0], command.slice(1), { stdio: 'inherit', env, shell: false });
    // ^C and ^\ already reach the child through the terminal's process group;
    // forwarding them again would read as a second, forcing interrupt. Ignore
    // them here and pass on only the signals a supervisor sends to us alone.
    for (const signal of ['SIGINT', 'SIGQUIT']) process.on(signal, () => {});
    for (const signal of ['SIGTERM', 'SIGHUP']) process.on(signal, () => child.kill(signal));
    child.on('error', (err) => {
      // Only a failure to start is fatal; a kill() error must not orphan a
      // running child by exiting under it.
      if (child.pid === undefined) fail(`could not start ${command[0]}: ${err.code || err.message}`);
    });
    child.on('exit', (code, signal) => {
      if (signal) process.exit(128 + (os.constants.signals[signal] || 1));
      process.exit(code ?? 1);
    });
  });
}

// One JSON object per line, so a newline in a path or argument cannot forge a
// record. Names and full argv, never values. Opened without following
// symlinks and tightened to 0600 every time. Fails closed: an exec that
// cannot be recorded does not run.
function auditExec(mappings, command) {
  const record = {
    t: new Date().toISOString(),
    argv: command,
    cwd: process.cwd(),
    map: mappings.map((m) => `${m.name}=${m.id}@${m.version}`)
  };
  let fd;
  try {
    ensureHome();
    fd = fs.openSync(path.join(getHome(), 'exec.log'), fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT | (fs.constants.O_NOFOLLOW || 0), 0o600);
    fs.fchmodSync(fd, 0o600);
    fs.writeSync(fd, `${JSON.stringify(record)}\n`);
  } catch (err) {
    fail(`could not record this exec in exec.log (${err.code}); refusing to run`);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function scan(args) {
  return runAsync(async () => {
    const doImport = takeFlag(args, '--import');
    const dir = args.shift();
    if (!dir) fail('usage: aikeys scan <dir-tree> [--import]');
    const config = doImport ? readConfig() : null;
    const findings = [];
    walk(dir, (file) => {
      if (shouldSkip(file)) return;
      const text = safeRead(file);
      if (text == null) return;
      const rel = path.relative(process.cwd(), file);
      for (const pattern of SECRET_PATTERNS) {
        pattern.re.lastIndex = 0;
        let m;
        while ((m = pattern.re.exec(text))) {
          const value = pattern.name === 'generic_assignment' ? m[2] : m[0];
          const keyName = pattern.name === 'generic_assignment' ? m[1].toLowerCase() : pattern.name;
          const line = lineNumber(text, m.index);
          findings.push({ file: rel, line, name: keyName, value });
        }
      }
    });
    for (const finding of findings) {
      console.log(`${finding.file}:${finding.line} ${finding.name} ${mask(finding.value)}`);
    }
    if (doImport) {
      for (let i = 0; i < findings.length; i++) {
        const finding = findings[i];
        const id = `scan/${sanitizeKey(finding.file)}-${finding.name}-${i + 1}`;
        await saveSecret(config, id, 'imported', finding.value, config.defaultStore || 'file');
        console.log(`imported ${id}@imported`);
      }
    }
    if (!findings.length) console.log('no likely secrets found');
  });
}

function where() {
  const config = fs.existsSync(getConfigPath()) ? readConfig() : DEFAULT_CONFIG;
  console.log(`home: ${getHome()}`);
  console.log(`config: ${getConfigPath()}`);
  console.log(`vault: ${getVaultPath(config)}`);
}

function help() {
  console.log(`aikeys - API key and secret helper for AI agents

Usage:
  aikeys setup [--store file|keychain] [--force]
  aikeys set <section>/<key> [version] [--store file|keychain]
  aikeys get <section>/<key> [version]
  aikeys render <template> <output>
  aikeys exec [--profile <name>]... [--env NAME=section/key[@version]]... -- <command> [args...]
  aikeys scan <dir-tree> [--import]
  aikeys where

Template token:
  {{aikeys:section/key@version}}
  {{aikeys:section/key}}

Environment:
  AIKEYS_HOME       override ~/.apikeys
  AIKEYS_PASSWORD   non-interactive vault password
  AIKEYS_SECRET     non-interactive secret for set
`);
}

// Threats: a typo'd store name, or a keychain that is not available, silently
// landing the secret in the file vault while the user believes it is in the
// keychain. Unknown or unavailable stores fail closed; there is no fallback.
function checkStore(store) {
  if (!STORES.includes(store)) fail(`unknown store: ${store} (expected file or keychain)`);
  if (store === 'keychain' && !platformKeychainSupported()) {
    fail('keychain store requested but no native keychain is available (macOS `security` or Linux `secret-tool`); use --store file');
  }
}

// Returns the store the secret actually went to.
async function saveSecret(config, id, version, secret, store) {
  validateId(id);
  validateVersion(version);
  checkStore(store);
  if (store === 'keychain') {
    const account = `${id}@${version}`;
    keychainSet(config.keychainService || APP, account, secret);
    upsertMeta(config, id, version, { store: 'keychain', account, updatedAt: new Date().toISOString() });
    return 'keychain';
  }
  const password = await getPassword();
  const encrypted = encrypt(secret, password);
  upsertMeta(config, id, version, { store: 'file', encrypted, updatedAt: new Date().toISOString() });
  return 'file';
}

async function loadSecret(config, id, version) {
  validateId(id);
  validateVersion(version);
  const vault = readVault(config);
  const entry = vault.entries[id]?.versions[version];
  if (!entry) fail(`missing secret: ${id}@${version}`);
  if (entry.store === 'keychain') return keychainGet(config.keychainService || APP, entry.account || `${id}@${version}`);
  if (entry.store === 'file') {
    const password = await getPassword();
    return decrypt(entry.encrypted, password);
  }
  fail(`unsupported store for ${id}@${version}: ${entry.store}`);
}

function upsertMeta(config, id, version, data) {
  const vault = readVault(config);
  vault.entries[id] ||= { versions: Object.create(null) };
  vault.entries[id].versions[version] = data;
  writeJSON(getVaultPath(config), vault);
}

function encrypt(plain, password) {
  const salt = crypto.randomBytes(SALT_LEN);
  const iv = crypto.randomBytes(IV_LEN);
  const key = crypto.scryptSync(password, salt, KEY_LEN);
  const cipher = crypto.createCipheriv(ALG, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return {
    alg: ALG,
    kdf: KDF,
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64')
  };
}

function decrypt(payload, password) {
  // Enforce the recorded primitives instead of trusting them. vault.json is a
  // plain file on disk; without these checks the alg/kdf fields are decoration
  // and a tampered entry could steer decryption somewhere weaker.
  if (!payload || typeof payload !== 'object') fail('vault entry is malformed');
  if (payload.alg !== ALG) fail(`unsupported vault algorithm: ${payload.alg}`);
  if (payload.kdf !== KDF) fail(`unsupported vault kdf: ${payload.kdf}`);

  const salt = Buffer.from(payload.salt || '', 'base64');
  const iv = Buffer.from(payload.iv || '', 'base64');
  const tag = Buffer.from(payload.tag || '', 'base64');
  // Wrong-length parameters mean a corrupt or forged entry. Reject before
  // touching the cipher so failures stay uniform instead of leaking shape.
  if (salt.length !== SALT_LEN) fail('vault entry has an invalid salt');
  if (iv.length !== IV_LEN) fail('vault entry has an invalid iv');
  if (tag.length !== TAG_LEN) fail('vault entry has an invalid auth tag');

  const key = crypto.scryptSync(password, salt, KEY_LEN);
  const decipher = crypto.createDecipheriv(ALG, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext || '', 'base64')),
    decipher.final()
  ]).toString('utf8');
}

function platformKeychainSupported() {
  if (process.platform === 'darwin') return commandExists('security');
  if (process.platform === 'linux') return commandExists('secret-tool');
  return false;
}

// Threats: the secret leaking through process argv (readable by other local
// users via ps or /proc), through the keychain tool's error output, or being
// stored truncated while we report success, and a failed update destroying
// the previous good item. The secret is only ever written to the tool's stdin
// and tool output is never echoed on a failed write. Every value is first
// written to a staging item and read back; only a verified value is written
// over the real item, which is then verified again. A value that cannot be
// stored faithfully is refused before the real item is touched. Does NOT
// protect against code running as the same user, which can read the keychain
// item like we do.
const KEYCHAIN_NAME_RE = /^[A-Za-z0-9_.@\/-]+$/;
// `security -i` reads commands into a 4 KiB line buffer and splits longer
// lines, which stores a truncated secret. Stay well below it.
const SECURITY_LINE_MAX = 4000;
const STAGING_SUFFIX = '.aikeys-staging';

function keychainSet(service, account, secret) {
  if (!KEYCHAIN_NAME_RE.test(service) || !KEYCHAIN_NAME_RE.test(account)) {
    fail('keychain service and account may only use letters, numbers, dot, underscore, dash, slash, or @');
  }
  // Keychain tools add or strip line endings on output, so a value with
  // leading or trailing whitespace cannot be returned verbatim.
  if (secret !== secret.trim()) fail('the keychain store refuses secrets with leading or trailing whitespace; use --store file');
  if (process.platform !== 'darwin' && process.platform !== 'linux') {
    fail('native keychain store is not supported on this platform; use --store file');
  }
  const staging = `${account}${STAGING_SUFFIX}`;
  keychainWrite(service, staging, secret);
  const stagedOk = keychainMatches(service, staging, secret);
  keychainRemove(service, staging);
  if (!stagedOk) fail('the keychain cannot store this secret verbatim; nothing was changed. Use --store file for this secret');
  keychainWrite(service, account, secret);
  if (!keychainMatches(service, account, secret)) {
    fail(`keychain read-back of ${account} did not match after a verified staging write; the item may be damaged. Re-run set or use --store file`);
  }
}

function keychainWrite(service, account, secret) {
  let result;
  if (process.platform === 'darwin') {
    // `add-generic-password -w <secret>` puts the secret in argv, and a bare
    // trailing `-w` with the secret on stdin silently truncates it to 128
    // bytes. Interactive mode takes the whole command on stdin, and -X passes
    // the secret as hex so no quoting or escaping is involved. Its exit status
    // is only that of the last command and is 0 even when an add to a missing
    // keychain file stores nothing, which is why every write is read back.
    const line = `add-generic-password -U -s ${service} -a ${account} -X ${Buffer.from(secret, 'utf8').toString('hex')}\n`;
    if (line.length > SECURITY_LINE_MAX) fail('secret is too long for the macOS keychain store; use --store file');
    result = spawnSync('security', ['-i'], { input: line, encoding: 'utf8', env: childEnv() });
  } else {
    // secret-tool reads the secret from stdin when stdin is not a TTY.
    result = spawnSync('secret-tool', ['store', '--label', `${service}:${account}`, 'service', service, 'account', account], { input: secret, encoding: 'utf8', env: childEnv() });
  }
  // Deliberately not echoing stderr/stdout: `security -i` repeats the command
  // line (hex secret included) when it rejects it.
  if (result.status !== 0) {
    if (account.endsWith(STAGING_SUFFIX)) keychainRemove(service, account);
    fail(`keychain write failed (exit ${result.status})`);
  }
}

function keychainMatches(service, account, secret) {
  const result = keychainLookup(service, account);
  if (result.status !== 0) return false;
  const stored = Buffer.from(stripNewline(result.stdout), 'utf8');
  const expected = Buffer.from(secret, 'utf8');
  return stored.length === expected.length && crypto.timingSafeEqual(stored, expected);
}

// Best-effort removal of our own staging item; a missing item is fine.
function keychainRemove(service, account) {
  if (process.platform === 'darwin') spawnSync('security', ['delete-generic-password', '-s', service, '-a', account], { env: childEnv() });
  else spawnSync('secret-tool', ['clear', 'service', service, 'account', account], { env: childEnv() });
}

function keychainLookup(service, account) {
  if (process.platform === 'darwin') {
    return spawnSync('security', ['find-generic-password', '-s', service, '-a', account, '-w'], { encoding: 'utf8', env: childEnv() });
  }
  return spawnSync('secret-tool', ['lookup', 'service', service, 'account', account], { encoding: 'utf8', env: childEnv() });
}

function keychainGet(service, account) {
  if (process.platform !== 'darwin' && process.platform !== 'linux') fail('native keychain get is not supported on this platform');
  const result = keychainLookup(service, account);
  // Fixed message: never echo the tool's output, same rule as keychainWrite.
  if (result.status !== 0) fail(`keychain lookup failed for ${account} (exit ${result.status})`);
  return stripNewline(result.stdout);
}

// `security -w` ends its output with one newline; strip exactly that.
function stripNewline(text) {
  return text.replace(/\n$/, '');
}

// Children never need our secrets in their environment.
function childEnv() {
  const env = { ...process.env };
  delete env.AIKEYS_PASSWORD;
  delete env.AIKEYS_SECRET;
  return env;
}


function commandExists(cmd) {
  return spawnSync(process.platform === 'win32' ? 'where' : 'command', process.platform === 'win32' ? [cmd] : ['-v', cmd], { shell: process.platform !== 'win32', env: childEnv() }).status === 0;
}

function readConfig() {
  if (!fs.existsSync(getConfigPath())) fail('run `aikeys setup` first');
  const config = readJSON(getConfigPath());
  if (config.agentPolicy) noteAdvisoryPolicy();
  return config;
}

// agentPolicy is guidance for agents, not a control: the CLI cannot tell an
// agent from a human, and nothing checks allowedCommands. Say so once per
// AIKEYS_HOME so nobody mistakes it for a sandbox.
function noteAdvisoryPolicy() {
  const marker = path.join(getHome(), '.agent-policy-notice');
  if (fs.existsSync(marker)) return;
  console.error('aikeys: note: agentPolicy in config.json is advisory only and is not enforced by aikeys (shown once)');
  try {
    fs.writeFileSync(marker, '', { flag: 'wx', mode: 0o600 });
  } catch (err) {
    if (err.code !== 'EEXIST') console.error(`aikeys: could not record the agentPolicy notice (${err.code}); it will be shown again`);
  }
}

function readVault(config) {
  const vaultPath = getVaultPath(config);
  if (!fs.existsSync(vaultPath)) return { version: CONFIG_VERSION, entries: Object.create(null) };
  const vault = readJSON(vaultPath);
  // Null-prototype maps: a name can never resolve to an inherited property.
  vault.entries = Object.assign(Object.create(null), vault.entries);
  for (const id of Object.keys(vault.entries)) {
    vault.entries[id].versions = Object.assign(Object.create(null), vault.entries[id].versions);
  }
  return vault;
}

function getHome() {
  return process.env.AIKEYS_HOME || path.join(os.homedir(), '.apikeys');
}

function ensureHome() {
  fs.mkdirSync(getHome(), { recursive: true, mode: 0o700 });
}

function getConfigPath() {
  return path.join(getHome(), 'config.json');
}

function getVaultPath(config) {
  const configured = config.vaultFile || DEFAULT_CONFIG.vaultFile;
  return path.isAbsolute(configured) ? configured : path.join(getHome(), configured);
}

function readJSON(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeJSON(file, data) {
  ensureHome();
  writeFileAtomic(file, `${JSON.stringify(data, null, 2)}\n`);
}

// Threats: a crash or error mid-write leaving a truncated or empty secret
// file, and an existing file keeping a looser mode (e.g. 0644) once secrets
// are written into it. Data goes to a fresh 0600 temp file (O_EXCL) in the
// target directory, is fsynced, then renamed over the target and the
// directory fsynced, so readers see either the old file or the complete new
// one, always 0600. A symlink at the
// target is replaced, not followed. Does NOT protect against another local
// user who can already write to the target directory.
function writeFileAtomic(file, data) {
  const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${crypto.randomBytes(6).toString('hex')}.tmp`);
  let fd = fs.openSync(tmp, 'wx', 0o600);
  try {
    fs.fchmodSync(fd, 0o600);
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tmp, file);
  } catch (err) {
    // Cleanup must not mask the original error or skip removing the temp file.
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch (closeErr) {
        err.message += ` (closing the temp file also failed: ${closeErr.code})`;
      }
    }
    fs.rmSync(tmp, { force: true });
    throw err;
  }
  fsyncDir(path.dirname(file));
}

// Persist the rename itself; without this a crash can roll the directory
// entry back to the old file. Windows cannot open directories, and some
// filesystems reject fsync on one (EINVAL/ENOTSUP); those are the only
// cases skipped.
function fsyncDir(dir) {
  if (process.platform === 'win32') return;
  const dfd = fs.openSync(dir, 'r');
  try {
    fs.fsyncSync(dfd);
  } catch (err) {
    if (err.code !== 'EINVAL' && err.code !== 'ENOTSUP') throw err;
  } finally {
    fs.closeSync(dfd);
  }
}

// Threats: prototype-key names (__proto__ etc.) that make a write land on an
// object prototype, so set reports success while nothing is persisted, and
// characters that do not belong in a keychain account or template token.
const RESERVED_NAMES = ['__proto__', 'constructor', 'prototype'];

function validateVersion(version) {
  if (!/^[A-Za-z0-9_.-]+$/.test(version) || RESERVED_NAMES.includes(version)) {
    fail('version must use letters, numbers, dot, underscore, or dash, and must not be __proto__, constructor, or prototype');
  }
}

function validateId(id) {
  if (id.split('/').some((part) => RESERVED_NAMES.includes(part))) fail('secret id must not use __proto__, constructor, or prototype');
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(id)) {
    fail('secret id must look like <section>/<key> using letters, numbers, dot, underscore, or dash');
  }
}

function walk(root, eachFile) {
  const stat = fs.statSync(root);
  if (stat.isFile()) return eachFile(root);
  for (const name of fs.readdirSync(root)) {
    const file = path.join(root, name);
    const childStat = fs.lstatSync(file);
    if (childStat.isSymbolicLink()) continue;
    if (childStat.isDirectory()) walk(file, eachFile);
    else if (childStat.isFile()) eachFile(file);
  }
}

function shouldSkip(file) {
  const parts = file.split(path.sep);
  return parts.includes('.git') || parts.includes('node_modules') || parts.includes('.apikeys') || /\.(png|jpe?g|gif|pdf|zip|gz|tar|ico|woff2?)$/i.test(file);
}

function safeRead(file) {
  try {
    const stat = fs.statSync(file);
    if (stat.size > 2 * 1024 * 1024) return null;
    const buf = fs.readFileSync(file);
    if (buf.includes(0)) return null;
    return buf.toString('utf8');
  } catch {
    return null;
  }
}

function lineNumber(text, index) {
  return text.slice(0, index).split('\n').length;
}

function mask(value) {
  if (value.length <= 8) return '*'.repeat(value.length);
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}

function sanitizeKey(value) {
  return value.toLowerCase().replace(/[^a-z0-9_.-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80) || 'secret';
}

function takeFlag(args, flag) {
  const i = args.indexOf(flag);
  if (i === -1) return false;
  args.splice(i, 1);
  return true;
}

function takeValue(args, flag) {
  const i = args.indexOf(flag);
  if (i === -1) return undefined;
  const value = args[i + 1];
  if (!value) fail(`${flag} requires a value`);
  args.splice(i, 2);
  return value;
}

function fail(message) {
  console.error(`aikeys: ${message}`);
  process.exit(1);
}

function runAsync(fn) {
  fn().catch((err) => fail(err.message || String(err)));
}

main();
