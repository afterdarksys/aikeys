# aikeys

`aikeys` is a small CLI for storing API keys and secrets in a local encrypted vault or the native platform keychain, then retrieving them by stable names that AI coding agents can use without learning where secrets live.

The installed command is available as both `aikeys` and `apikeys`.

## Install locally

```sh
npm install
npm link
```

Or run directly:

```sh
node bin/aikeys.js help
```

## Setup

```sh
aikeys setup
aikeys setup --store keychain
```

This creates:

- `~/.apikeys/config.json`
- `~/.apikeys/vault.json`

The config file is intentionally JSON so agents and scripts can inspect policy and template conventions.

### `agentPolicy` is advisory

`config.json` contains an `agentPolicy` block (`preferRender`, `doNotPrintSecretsInLogs`, `allowedCommands`). It is guidance for agents to read, not an enforced control: `aikeys` cannot tell whether an agent or a person is running it, and it does not check commands against `allowedCommands`. Enforce agent restrictions in the agent harness (tool allowlists, sandboxing), not here. The CLI prints a one-time notice to stderr saying so the first time it reads a config that contains the block.

## Store and retrieve

```sh
aikeys set openai/api_key prod
aikeys get openai/api_key prod
```

For non-interactive use:

```sh
AIKEYS_PASSWORD='vault password' AIKEYS_SECRET='secret value' aikeys set openai/api_key prod
AIKEYS_PASSWORD='vault password' aikeys get openai/api_key prod
```

When stdin is not a terminal, the secret (or, for `get`, the vault password) is read from stdin; only the final line ending is removed, so other leading or trailing whitespace is kept as part of the value. Stdin can only be read once, so for `set` supply at least one of the two via its environment variable. An empty secret or password, from any source (including Ctrl-D at the prompt), is refused with a non-zero exit, and nothing is stored or printed.

Versions use the same characters as names (letters, numbers, dot, underscore, dash), and `__proto__`, `constructor` and `prototype` are refused as a section, key or version.

`--store` accepts `file` or `keychain`; anything else is an error. If `keychain` is requested and no native keychain is available, `set` fails rather than falling back to the file vault. The success message names the store the secret was written to.

## Render templates

Template file:

```env
OPENAI_API_KEY={{aikeys:openai/api_key@prod}}
ANTHROPIC_API_KEY={{aikeys:anthropic/api_key}}
```

Render it:

```sh
aikeys render .env.template .env
```

Every token is resolved first, then substituted in one pass, so secret values are inserted byte-for-byte (including `$&`, `$$` and similar sequences) and a token that happens to appear inside a secret value is not expanded.

Rendered outputs are written atomically with `0600` permissions: `aikeys` writes a new `0600` temp file in the output's directory and renames it over the target. An existing output is replaced, so its old mode (for example a world-readable `.env`) does not survive, and a failed render leaves the previous file untouched. If the output path is a symlink, render replaces the link with a regular `0600` file; the file the link pointed to is not modified. `vault.json` and `config.json` are written the same way.

## Run a command with secrets

```sh
aikeys exec --env FAL_KEY=fal/api_key -- npm run space:art
aikeys exec --profile studio -- npx tsx pipeline/produce.ts --estimate
```

`exec` resolves every named secret, then starts the command with those secrets added to its environment. This is the preferred way for an agent to use a key: the value is never printed, never written to disk, and never passes through a shell, so it cannot end up in a transcript, a log or shell history.

- It fails closed. Every secret is resolved before the command starts, so if one is missing or cannot be decrypted, the command never runs.
- The command is run directly, without a shell, and its exit code is passed through.
- `AIKEYS_PASSWORD` and `AIKEYS_SECRET` are removed from the child's environment.
- Names that change how programs are found or loaded are refused: `PATH`, `HOME`, `NODE_OPTIONS`, `PYTHONPATH`, `BASH_ENV`, and anything starting `LD_`, `DYLD_` or `AIKEYS_`, among others.
- Every run appends one line to `~/.apikeys/exec.log` (0600): time, program name, working directory, and which variable names were mapped to which secrets. Values are never logged. If the line cannot be written, the command does not run.

It does not protect against the command itself printing or uploading the value.

Profiles name a set of mappings in `config.json`:

```json
"profiles": {
  "fal": { "FAL_KEY": "fal/api_key" },
  "studio": {
    "FAL_KEY": "fal/api_key",
    "ELEVENLABS_API_KEY": "elevenlabs/api_key"
  }
}
```

A profile is all-or-nothing: if any secret in it is missing, the command does not run.

## Scan and import

```sh
aikeys scan .
aikeys scan . --import
```

The scanner reports likely secrets with masked values. `--import` stores findings under generated names such as `scan/src-config-env-openai-1@imported`.

## Storage

- `file`: AES-256-GCM encrypted entries in `~/.apikeys/vault.json`, with a password prompted at read/write time.
- `keychain`: macOS Keychain via `security`, or Linux Secret Service via `secret-tool` when present. Unsupported platforms should use `file`.

The secret is passed to `security` and `secret-tool` on stdin, never as a command-line argument. On macOS `aikeys` drives `security -i` and sends the value hex-encoded, which limits keychain secrets to roughly 1,900 bytes (less with long service or account names); longer secrets are refused (use `file`). Every keychain write goes first to a temporary staging item that is read back and compared, then deleted. Only a value that round-trips exactly is written over the real item, which is then read back again. A value the keychain cannot return verbatim is refused and the existing item, if any, is left unchanged. In practice this rejects secrets `security` prints as hex, such as values containing tabs or other non-printable characters. Secrets with leading or trailing whitespace are refused for the keychain store before anything is written; use `file` for those. The read-back is required: `security -i` reports only the exit status of its last command, and exits 0 for an add to a missing keychain file that stores nothing. Keychain service and account names may only use letters, numbers, dot, underscore, dash, slash and `@`. `security` and `secret-tool` are run with `AIKEYS_PASSWORD` and `AIKEYS_SECRET` removed from their environment.

Windows currently uses the encrypted file vault. Native Windows Credential Manager support can be added behind the same `--store keychain` interface.

## Agent skills

Agent-ready skills live in `skills/`:

- `skills/codex/aikeys-secret-access/`
- `skills/claude/aikeys-secret-access/`

See `skills/README.md` for installation notes.
