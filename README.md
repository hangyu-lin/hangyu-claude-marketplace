# hangyu-claude-marketplace

Personal Claude Code plugin marketplace for testing plugin setups.

## Installation

Add this marketplace to Claude Code:

```
/plugin marketplace add hangyu-lin/hangyu-claude-marketplace
```

## Available Plugins

### hello-world

**Description:** A minimal test plugin to verify marketplace installation and skill loading.

**Install:**

```
/plugin install hello-world@hangyu-lin/hangyu-claude-marketplace
```

What you get:
- `/hello-world:hello` — a simple greeting skill for testing

## Team Skills

| Team | Plugin | Description |
|------|--------|-------------|
| Menus | `/plugin install menus@hangyu-lin/hangyu-claude-marketplace` | Skills for the Menus team — see [teams/menus/README.md](teams/menus/README.md) |

## Contributing

1. Create a directory under `skills/<plugin-name>/`
2. Add a `skills/<skill-name>/skill.md` with frontmatter (name, description)
3. Optionally add `commands/<command-name>.md` for slash commands
4. Update this README with install instructions
