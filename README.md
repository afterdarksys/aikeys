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

When stdin is not a terminal, the secret (or, for `get`, the vault password) is read from stdin; trailing whitespace is trimmed. Stdin can only be read once, so for `set` supply at least one of the two via its environment variable. An empty secret or password, from any source, is refused with a non-zero exit, and nothing is stored or printed.

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

Rendered outputs are written atomically with `0600` permissions: `aikeys` writes a new `0600` temp file in the output's directory and renames it over the target. An existing output is replaced, so its old mode (for example a world-readable `.env`) does not survive, and a failed render leaves the previous file untouched. If the output path is a symlink, the link itself is replaced rather than followed. `vault.json` and `config.json` are written the same way.

## Scan and import

```sh
aikeys scan .
aikeys scan . --import
```

The scanner reports likely secrets with masked values. `--import` stores findings under generated names such as `scan/src-config-env-openai-1@imported`.

## Storage

- `file`: AES-256-GCM encrypted entries in `~/.apikeys/vault.json`, with a password prompted at read/write time.
- `keychain`: macOS Keychain via `security`, or Linux Secret Service via `secret-tool` when present. Unsupported platforms should use `file`.

The secret is passed to `security` and `secret-tool` on stdin, never as a command-line argument. On macOS `aikeys` drives `security -i` and sends the value hex-encoded, which limits keychain secrets to roughly 1,900 bytes (less with long service or account names); longer secrets are refused (use `file`). After every keychain write the value is read back and compared, and on a mismatch the item is deleted and `set` fails. In practice this rejects secrets `security` cannot return verbatim, such as values containing tabs or other non-printable characters. Keychain service and account names may only use letters, numbers, dot, underscore, dash, slash and `@`, so versions stored in the keychain are limited to those characters too.

Windows currently uses the encrypted file vault. Native Windows Credential Manager support can be added behind the same `--store keychain` interface.

## Agent skills

Agent-ready skills live in `skills/`:

- `skills/codex/aikeys-secret-access/`
- `skills/claude/aikeys-secret-access/`

See `skills/README.md` for installation notes.
