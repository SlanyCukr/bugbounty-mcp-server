# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Bug Bounty MCP Server focused solely on bug bounty hunting workflows and REST API endpoints. It provides an MCP (Model Context Protocol) interface for AI agents to interact with bug bounty tools and workflows.

## Architecture

The project has files in `src/` for the main server code.

## Dependencies & Environment Management (uv)
- **Project Management**: Uses `uv` exclusively for fast, reliable dependency management
- **Configuration**: Dependencies defined in `pyproject.toml`, locked in `uv.lock`
- **Virtual Environment**: Automatically managed by uv at `.venv/`
- **Installation**: `uv sync` - Install/update dependencies
- **Development Dependencies**: `uv sync --dev` - Include development tools (pre-commit, ruff, etc.)
- **Running Commands**: `uv run <command>` - Execute commands within the project environment

### Package Management Commands
- **Add packages**: `uv add <package>` - Install new dependencies
- **Remove packages**: `uv remove <package>` - Remove dependencies
- **Never use**: pip, pip-tools, poetry, or conda directly for dependency management

### Running Python Code
- **Scripts**: `uv run <script-name>.py` - Run Python scripts
- **Tools**: `uv run pytest`, `uv run ruff` - Run Python tools
- **REPL**: `uv run python` - Launch Python interactive shell

### PEP 723 Inline Metadata Scripts
- **Run scripts**: `uv run script.py` - Execute scripts with inline dependencies
- **Add deps**: `uv add package-name --script script.py` - Add dependencies to script
- **Remove deps**: `uv remove package-name --script script.py` - Remove dependencies from script

## Common Development Commands

### Installing Dependencies

Install all dependencies:
```bash
uv sync
```

Install with development dependencies:
```bash
uv sync --dev
```

### Starting the Servers

**REST API Server:**
```bash
uv run src/server.py
```

**With environment variables:**
```bash
DEBUG=true BUGBOUNTY_MCP_PORT=8888 uv run src/server.py
```

**MCP Server:**
```bash
uv run -m src.mcp_server
```

- Don't proactively commit and push
