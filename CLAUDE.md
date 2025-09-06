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

### API Endpoints Structure

All bug bounty endpoints follow the pattern `/api/bugbounty/{workflow-type}`:
- reconnaissance-workflow
- vulnerability-hunting-workflow  
- business-logic-workflow
- osint-workflow
- file-upload-testing
- comprehensive-assessment

Tool execution endpoints follow `/api/tools/{tool-name}`:
- nuclei, nmap, ffuf, amass, etc.

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

Run the example usage script:
```bash
uv run example_usage.py
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
- `flask`: REST API framework
- `fastmcp==2.11.3`: MCP server framework  
- `requests`: HTTP client
- `aiohttp`: Async HTTP support

Python version requirement: >=3.10

All dependency management is handled through `uv` - do not use pip, pip-tools, poetry, or other package managers.