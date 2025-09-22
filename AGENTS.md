# CRUSH.md

## CRITICAL: Use ripgrep, not grep

NEVER use grep for project-wide searches (slow, ignores .gitignore). ALWAYS use rg.

- `rg "pattern"` — search content
- `rg --files | rg "name"` — find files
- `rg -t python "def"` — language filters

## File finding

- Prefer `fd` (or `fdfind` on Debian/Ubuntu). Respects .gitignore.

## JSON

- Use `jq` for parsing and transformations.

## Agent Instructions

- Replace commands: grep→rg, find→rg --files/fd, ls -R→rg --files, cat|grep→rg pattern file
- Cap reads at 250 lines; prefer `rg -n -A 3 -B 3` for context
- Use `jq` for JSON instead of regex

## Commands

### Dependencies
- Install core deps: `uv sync`
- Install dev deps: `uv sync --dev`

### Quality Checks
- Lint: `uv run ruff check .`
- Format: `uv run ruff format .`
- Typecheck: `uv run pyright src`
- Security scan: `uv run bandit -r src`
- Docstyle: `uv run pydocstyle src`
- Pre-commit: `uv run pre-commit run --all-files`

### Testing
- Run all tests: `uv run python test_tools.py`
- Run single test (e.g., subfinder): `uv run python -c "from test_tools import test_subfinder; test_subfinder()"`

### Running Servers
- REST API: `uv run -m src.rest_api_server`
- MCP Server: `uv run -m src.mcp_server`

## Code Style Guidelines

### Formatting
- Line length: 88 characters
- Indent: 4 spaces
- Quotes: Double quotes for strings
- Use Ruff for linting and formatting (select: E, W, F, I, B, C4, UP)

### Imports
- Organize with isort: standard, third-party, local
- Absolute imports preferred
- No wildcard imports

### Typing
- Use type hints for all functions and variables
- Typecheck with Pyright (include: src, exclude: tests, tools)
- Report none for missing imports/types in dev

### Naming Conventions
- Functions/variables: snake_case
- Classes: CamelCase
- Constants: UPPER_SNAKE_CASE
- Modules: lowercase with underscores

### Docstrings
- Google convention via pydocstyle
- Include params, returns, raises where applicable

### Error Handling
- Use specific exceptions (e.g., ValueError, KeyError)
- Log errors with logger from utils
- Graceful degradation in tool executions
- Validate inputs early

### Security
- Scan with Bandit (exclude tests/tools, skip B101)
- No hardcoded secrets
- Sanitize user inputs in workflows

### General
- No comments unless explanatory
- Follow PEP 8 with Ruff extensions
- Modular design: workflows, tools, utils separation
- Use FastMCP and Flask patterns from existing code

## Subfolder AGENTS.md Files
AGENTS.md files also exist in subfolders (e.g., tools/, workflows/). When exploring a subfolder, read its local AGENTS.md (often symlinked to CLAUDE.md) for high-level context on specific tools, workflows, APIs, parameters, and usage examples. These provide modular, detailed guidance without duplicating root-level info.

## Project Overview & Architecture
This is a Bug Bounty MCP Server focused on bug bounty hunting workflows and REST API endpoints. Provides MCP interface for AI agents.

- src/ contains main server code.
- Uses uv for dependency management.

## Source Code Organization
- server.py - Flask REST API
- mcp_server.py - FastMCP server
- Core patterns: dataclasses, tool execution, workflow generation.

For more: See subfolder docs.
