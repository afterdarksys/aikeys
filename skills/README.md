# aikeys skills

This directory contains reusable AI-agent skills for using `aikeys` safely.

## Layout

- `codex/aikeys-secret-access/` - Codex-compatible skill folder.
- `claude/aikeys-secret-access/` - Claude-compatible skill folder.

Both skills describe the same workflow:

- retrieve named secrets with `aikeys get <section>/<key> [version]`
- render config files with `aikeys render <template> <output>`
- scan source trees with `aikeys scan <dir-tree>`
- import discovered secrets with `aikeys scan <dir-tree> --import`

## Install for Codex

Copy or symlink the Codex skill into your Codex skills directory:

```sh
mkdir -p ~/.codex/skills
ln -s "$(pwd)/skills/codex/aikeys-secret-access" ~/.codex/skills/aikeys-secret-access
```

## Install for Claude

Use the Claude skill folder as the source for Claude-compatible skill installation:

```sh
skills/claude/aikeys-secret-access
```

If your Claude environment supports local skill directories, point it at that folder or copy the folder into the configured skills path.

## Security Notes

Agents using these skills should not print raw secrets, edit `~/.apikeys/vault.json` directly, or commit rendered secret-bearing files such as `.env`.
