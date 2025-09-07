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
uv run src/server.py

# Or with environment variables
DEBUG=true BUGBOUNTY_MCP_PORT=8888 uv run src/server.py

# Or use the launcher script
./start-server.sh --debug --port 8888
```

### 2. Test the API

```bash
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

### Usage Examples

```bash
# Start with default configuration
uv run src/server.py

# Start with custom configuration
DEBUG=true BUGBOUNTY_MCP_PORT=9999 BUGBOUNTY_MCP_HOST=0.0.0.0 uv run src/server.py
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
