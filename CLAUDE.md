# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Bug Bounty MCP Server focused solely on bug bounty hunting workflows and REST API endpoints. It provides an MCP (Model Context Protocol) interface for AI agents to interact with bug bounty tools and workflows.

## Architecture

The project has two main server implementations:

1. **REST API Server** (`src/server.py`) - Flask-based HTTP API server with bug bounty workflow endpoints
2. **MCP Server** (`src/mcp_server.py`) - FastMCP-based server for AI agent communication

### Core Components

- `BugBountyTarget`: Data model for bug bounty targets with domain, scope, and program information
- `BugBountyWorkflowManager`: Generates specialized workflows for different phases of bug bounty hunting
- `FileUploadTestingFramework`: Handles file upload vulnerability testing scenarios


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

## Code Quality & Pre-commit Hooks

This project uses comprehensive pre-commit hooks to ensure code quality, security, and consistency:

### Pre-commit Setup

Install pre-commit hooks:
```bash
uv run pre-commit install
```

### Code Quality Tools

The project includes the following automated checks:

- **Ruff**: Fast Python linter and formatter (replaces black, isort, flake8)
- **Bandit**: Security vulnerability scanner for Python code
- **Pydocstyle**: Documentation quality checker using Google convention
- **Pyright**: Fast static type checker
- **Basic checks**: Trailing whitespace, end-of-file fixes, YAML/JSON validation

### Running Pre-commit Hooks

Run on all files:
```bash
uv run pre-commit run --all-files
```

Run on specific files:
```bash
uv run pre-commit run --files src/server.py
```

### Tool Configuration

All tools are configured in `pyproject.toml`:
- **Line length**: 88 characters (consistent with Ruff/Black standard)
- **Python target**: 3.11+ compatibility
- **Documentation**: Google docstring convention
- **Security**: Bandit with B101 skip for development assertions

### Starting the Servers

**REST API Server:**
```bash
uv run src/server.py --debug --port 8888
```

**MCP Server:**
```bash
uv run -m src.mcp_server
```

Use the provided launcher script:
```bash
./start-server.sh
```

### Testing

Test the servers manually:
```bash
# Test a workflow endpoint
curl -X POST http://127.0.0.1:8888/api/bugbounty/reconnaissance-workflow \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "program_type": "web"}'
```

## Configuration

### Environment Variables
- `BUGBOUNTY_MCP_PORT`: Server port (default: 8888)
- `BUGBOUNTY_MCP_HOST`: Server host (default: 127.0.0.1)
- `DEBUG`: Enable debug mode (default: false)

### Command Line Options for REST Server
- `--debug`: Enable debug mode
- `--port PORT`: Set server port
- `--host HOST`: Set server host

## Key Patterns

### Workflow Generation
All workflow methods follow a similar pattern:
1. Validate required parameters (domain, target info)
2. Build configuration object with tool parameters
3. Generate step-by-step workflow with specific commands
4. Return structured JSON with tools, commands, and expected results

### Error Handling
- All endpoints use try/catch with proper JSON error responses
- Logging is configured to both console and file (`bugbounty-mcp.log`)
- HTTP status codes follow REST conventions

### Data Models
The `BugBountyTarget` dataclass is central to most workflows and includes:
- `domain`: Primary target domain
- `scope`: List of in-scope domains/subdomains
- `out_of_scope`: List of excluded domains
- `program_type`: Type of bug bounty program (web, mobile, api, etc.)

## Dependencies

Core dependencies managed via `uv` in `pyproject.toml`:
- `flask>=3.1.2`: REST API framework
- `fastmcp>=2.12.2`: MCP server framework
- `requests>=2.32.5`: HTTP client
- `aiohttp>=3.12.15`: Async HTTP support

Python version requirement: >=3.11 (supports Python 3.11, 3.12, 3.13)

All dependency management is handled through `uv` - do not use pip, pip-tools, poetry, or other package managers.
- Don't proactively commit and push

## Recent Changes
- 001-let-s-figure: Added memory structure optimization planning (markdown + hierarchy organization)

## Current Feature Development
Working on CLAUDE.md memory structure optimization to organize project instructions into hierarchical, discoverable sections following Claude Code best practices. Key technologies: markdown files, @import syntax, memory hierarchy validation.

Last updated: 2025-09-06
