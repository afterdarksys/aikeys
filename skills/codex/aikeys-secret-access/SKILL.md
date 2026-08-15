---
name: aikeys-secret-access
description: Use the aikeys CLI to safely retrieve, render, scan, and import API keys or secrets for coding tasks. Use when Codex needs to populate config files from secret templates, fetch a named API key, scan a project tree for accidental secrets, or explain how to use the repository's aikeys secret workflow without exposing raw secret values.
---

# aikeys Secret Access

## Core Rules

- Never print raw secret values in chat, logs, summaries, commits, or comments unless the user explicitly asks for the value itself.
- Prefer rendering templates with `aikeys render` over manually writing secrets into config files.
- Treat files produced by `aikeys render` as secret-bearing outputs unless the user says otherwise.
- Do not edit `~/.apikeys/vault.json` directly.
- Do not commit generated secret-bearing files such as `.env`.

## Commands

Use these commands from the project or shell environment where `aikeys` is available:

```sh
aikeys setup
aikeys set <section>/<key> [version]
aikeys get <section>/<key> [version]
aikeys render <template> <output>
aikeys scan <dir-tree>
aikeys scan <dir-tree> --import
```

`aikeys` is also exposed as `apikeys`.

## Template Workflow

Use placeholders in template files:

```text
{{aikeys:section/key@version}}
{{aikeys:section/key}}
```

Example `.env.template`:

```env
OPENAI_API_KEY={{aikeys:openai/api_key@prod}}
ANTHROPIC_API_KEY={{aikeys:anthropic/api_key}}
```

Render it with:

```sh
aikeys render .env.template .env
```

## Retrieval Workflow

When a command requires a secret in an environment variable, prefer command-local substitution and avoid echoing it:

```sh
OPENAI_API_KEY="$(aikeys get openai/api_key prod)" npm test
```

Before using this pattern, check whether shell tracing or verbose logging is enabled and disable it if needed.

## Scanning Workflow

Use `scan` to find likely exposed secrets:

```sh
aikeys scan .
```

Only use `--import` when the user wants discovered secrets added to the local vault:

```sh
aikeys scan . --import
```
