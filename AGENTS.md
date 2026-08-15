# AGENTS.md

## aikeys Secret Access

Use `aikeys` for API keys and secrets.

Allowed patterns:

```sh
aikeys get <section>/<key> [version]
aikeys render <template> <output>
aikeys scan <dir-tree>
```

Write secrets with:

```sh
aikeys set <section>/<key> [version]
```

Template placeholders:

```text
{{aikeys:section/key@version}}
{{aikeys:section/key}}
```

Security expectations:

- Do not display secret values unless the user explicitly asks for the value itself.
- Do not commit generated secret-bearing files.
- Prefer rendering templates so config files are created just in time.
- `~/.apikeys/config.json` is readable policy/configuration; `~/.apikeys/vault.json` is managed by the CLI.
