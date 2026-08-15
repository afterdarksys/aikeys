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

Rendered outputs are written with `0600` permissions.

## Scan and import

```sh
aikeys scan .
aikeys scan . --import
```

The scanner reports likely secrets with masked values. `--import` stores findings under generated names such as `scan/src-config-env-openai-1@imported`.

## Storage

- `file`: AES-256-GCM encrypted entries in `~/.apikeys/vault.json`, with a password prompted at read/write time.
- `keychain`: macOS Keychain via `security`, or Linux Secret Service via `secret-tool` when present. Unsupported platforms should use `file`.

Windows currently uses the encrypted file vault. Native Windows Credential Manager support can be added behind the same `--store keychain` interface.
