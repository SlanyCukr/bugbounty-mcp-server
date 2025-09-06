# Bug Bounty MCP Server

A clean, focused server containing bug bounty hunting workflows and REST API endpoints.

## Features

- **Clean Architecture**: Removed bloat and unnecessary dependencies while maintaining core functionality
- **Bug Bounty Focused**: Specialized workflows for reconnaissance, vulnerability hunting, business logic testing, OSINT, and file upload testing
- **REST API Endpoints**: Simple HTTP API for workflow generation and management
- **Comprehensive Assessments**: Combine multiple workflows for complete bug bounty assessments

## Architecture

### Core Components
- **REST API Server** (`src/server.py`) - Flask-based HTTP API server with bug bounty workflow endpoints
- **MCP Server** (`src/mcp_server.py`) - FastMCP-based server for AI agent communication
- **Bug Bounty Workflows** - Specialized workflow generation for different phases of testing
- **Tool Integration** - Comprehensive collection of security testing tools

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check endpoint |
| POST | `/api/bugbounty/reconnaissance-workflow` | Generate reconnaissance workflow |
| POST | `/api/bugbounty/vulnerability-hunting-workflow` | Generate vulnerability hunting workflow |
| POST | `/api/bugbounty/business-logic-workflow` | Generate business logic testing workflow |
| POST | `/api/bugbounty/osint-workflow` | Generate OSINT gathering workflow |
| POST | `/api/bugbounty/file-upload-testing` | Generate file upload testing workflow |
| POST | `/api/bugbounty/comprehensive-assessment` | Generate comprehensive assessment combining all workflows |

## Quick Start

### 1. Install Dependencies & Start the Server

```bash
# Install dependencies with uv
uv sync

# Install development dependencies (optional)
uv sync --dev

# Set up pre-commit hooks (recommended for development)
uv run pre-commit install

# Start the server
uv run src/server.py --debug --port 8888

# Or use the launcher script
./start-server.sh --debug
```

### 2. Test the API

```bash
# Health check
curl http://127.0.0.1:8888/health

# Create reconnaissance workflow
curl -X POST http://127.0.0.1:8888/api/bugbounty/reconnaissance-workflow \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "program_type": "web"}'
```


## Configuration

### Environment Variables

- `BUGBOUNTY_MCP_PORT`: Server port (default: 8888)
- `BUGBOUNTY_MCP_HOST`: Server host (default: 127.0.0.1)
- `DEBUG`: Enable debug mode (default: false)

### Command Line Options

```bash
uv run src/server.py --help
```

- `--debug`: Enable debug mode
- `--port PORT`: Set server port
- `--host HOST`: Set server host

## Workflow Examples

### Reconnaissance Workflow

```json
{
  "domain": "example.com",
  "scope": ["*.example.com", "api.example.com"],
  "out_of_scope": ["internal.example.com"],
  "program_type": "web"
}
```

### Vulnerability Hunting Workflow

```json
{
  "domain": "example.com",
  "priority_vulns": ["rce", "sqli", "xss", "idor", "ssrf"],
  "bounty_range": "medium"
}
```

### Comprehensive Assessment

```json
{
  "domain": "example.com",
  "scope": ["*.example.com"],
  "priority_vulns": ["rce", "sqli", "xss"],
  "include_osint": true,
  "include_business_logic": true
}
```

## File Structure

```
bugbounty-mcp-server/
├── src/
│   ├── __init__.py        # Package initialization
│   ├── server.py          # Flask REST API server
│   └── mcp_server.py      # FastMCP server for AI agents
├── .gitignore             # Git ignore patterns
├── CLAUDE.md              # Development guidance for Claude Code
├── README.md              # Project documentation
├── pyproject.toml         # Project configuration and dependencies
├── start-server.sh        # Server launcher script
└── uv.lock                # Dependency lock file
```

## Key Features

1. **Bug Bounty Workflow Management**: Complete workflow generation for different phases of bug bounty hunting
2. **Vulnerability Prioritization**: Intelligence-driven prioritization based on impact and bounty potential
3. **File Upload Testing**: Specialized framework for file upload vulnerability testing
4. **OSINT Integration**: Comprehensive OSINT gathering workflows
5. **Business Logic Testing**: Structured approach to business logic vulnerability discovery

## Dependencies

Project uses `uv` for fast, reliable dependency management:

### Core Dependencies
- **Flask**: Web framework for REST API
- **FastMCP**: MCP server framework
- **Requests**: HTTP client library
- **Python 3.11+**: Core runtime (supports Python 3.11, 3.12, 3.13)

### Development Dependencies
- **Ruff**: Fast Python linter and formatter
- **Bandit**: Security vulnerability scanner
- **Pydocstyle**: Documentation quality checker
- **Pyright**: Static type checker
- **Pre-commit**: Git pre-commit hooks framework

Install dependencies:
```bash
uv sync                # Core dependencies only
uv sync --dev         # Include development tools
```

Add new dependencies:
```bash
uv add package-name
```

## Code Quality

This project enforces code quality through automated pre-commit hooks:

```bash
# Install pre-commit hooks
uv run pre-commit install

# Run checks on all files
uv run pre-commit run --all-files

# Run specific checks
uv run ruff check          # Linting
uv run ruff format         # Formatting
uv run bandit -c pyproject.toml # Security scan
uv run pydocstyle          # Documentation check
```

**Standards:**
- Line length: 88 characters
- Documentation: Google docstring convention
- Type hints: Required for public APIs
- Security: Bandit security scanning enabled

## What Was Removed

To maintain a clean, focused architecture, the following components are not included:

- Complex visual rendering and color formatting
- Tool execution engines and process management
- Advanced caching and error handling systems
- CTF competition frameworks
- CVE intelligence and exploit generation
- AI-powered payload generation
- Complex dependency management
- Selenium browser automation
- Process monitoring and scaling
- Advanced logging and telemetry

The result is a lightweight, focused server that provides core bug bounty workflow generation functionality with a clean, simple architecture.
