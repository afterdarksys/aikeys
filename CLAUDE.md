# CLAUDE.md

This repository provides `aikeys`, a local API key and secret helper intended for AI coding agents.

## Agent Rules

- Never print secret values in logs, summaries, commits, or chat.
- Prefer `aikeys render <template> <output>` over manually copying secrets into config files.
- Use `aikeys get <section>/<key> [version]` only when a tool genuinely needs the raw secret on stdout.
- Do not edit `~/.apikeys/vault.json` directly.
- Do not commit rendered files such as `.env` unless the user explicitly says the file is safe.

## Common Commands

```sh
aikeys setup
aikeys set openai/api_key prod
aikeys get openai/api_key prod
aikeys render .env.template .env
aikeys scan . --import
```

Template tokens use:

```text
{{aikeys:section/key@version}}
{{aikeys:section/key}}
```

For non-interactive automation, use `AIKEYS_PASSWORD` for encrypted vault access and `AIKEYS_SECRET` for `set`.
