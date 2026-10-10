---
name: aikeys-secret-access
description: Use the aikeys CLI to run commands that need API keys (fal, ElevenLabs, Hedra, Anthropic...) without ever seeing the key, and to render, scan, and import secrets. Use when Claude needs to populate config files from secret templates, fetch a named API key, scan a project tree for accidental secrets, or explain how to use the repository's aikeys secret workflow without exposing raw secret values.
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
aikeys exec [--profile <name>] [--env NAME=section/key[@version]]... -- <command> [args...]
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

## Running a command that needs a key (use this first)

```sh
aikeys exec --env FAL_KEY=fal/api_key -- npm run space:art
aikeys exec --profile studio -- npx tsx pipeline/produce.ts --estimate
```

`exec` puts the secret straight into the child process's environment. You never see it, it never hits stdout or disk, and every run is recorded by name in `~/.apikeys/exec.log`. If a key is missing it fails before running anything. In that case, tell the user which `section/key` to store (`aikeys set fal/api_key --store keychain`). Don't go looking for the key in other files.

Profiles are defined under `"profiles"` in `~/.apikeys/config.json`. Run `aikeys where` to find it.

Avoid `VAR="$(aikeys get ...)" cmd`. `get` writes the raw value to stdout, so a traced shell or a mistyped command puts the secret in your transcript.

## Scanning Workflow

Use `scan` to find likely exposed secrets:

```sh
aikeys scan .
```

Only use `--import` when the user wants discovered secrets added to the local vault:

```sh
aikeys scan . --import
```
