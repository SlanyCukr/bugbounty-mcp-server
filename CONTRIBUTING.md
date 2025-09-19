# Contributing

Thanks for your interest in contributing!

## Quick Start

- Use `uv` for all dependency management and running tools.
- Prefer small, focused pull requests with clear intent.
- Ensure linters and security checks pass before submitting.

### Setup

```bash
uv sync          # install runtime deps
uv sync --dev    # include dev tools (recommended)
uv run pre-commit install
```

### Run Servers

```bash
uv run -m src.rest_api_server                         # REST API
DEBUG=true BUGBOUNTY_MCP_PORT=8888 uv run -m src.rest_api_server
uv run -m src.mcp_server                     # MCP server
```

### Code Quality

```bash
uv run pre-commit run --all-files
uv run ruff check && uv run ruff format --check
uv run bandit -c pyproject.toml
```

## Pull Requests

- Follow existing code style and structure.
- Add or update documentation when behavior changes.
- Keep changes scoped; avoid unrelated refactors.

## For AI Coding Assistants

If you are using an AI agent to help with changes, please review:

- `AGENTS.md` — repository-specific guidance for AI assistants
- `CLAUDE.md` — context originally written for Claude Code

These documents describe project layout, commands, and conventions to ensure consistent results.
