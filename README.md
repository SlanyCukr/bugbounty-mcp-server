# Bug Bounty MCP Server

A clean, focused server containing bug bounty hunting workflows and REST API endpoints.

For AI coding assistants, see `AGENTS.md` for repository-specific guidance.

## Features

- **Clean Architecture**: Removed bloat and unnecessary dependencies while maintaining core functionality
- **Bug Bounty Focused**: Specialized workflows for reconnaissance, vulnerability hunting, business logic testing, OSINT, and file upload testing
- **REST API Endpoints**: Simple HTTP API for workflow generation and management
- **Comprehensive Assessments**: Combine multiple workflows for complete bug bounty assessments

## Architecture

### Core Components
- **REST API Server** (`src/rest_api_server/app.py`) - Flask-based HTTP API server with bug bounty workflow endpoints
- **MCP Server** (`src/mcp_server/app.py`) - FastMCP-based server for AI agent communication
- **Bug Bounty Workflows** (`src/rest_api_server/workflows/`) - Specialized workflow generation for different phases of testing
- **Tool Integration** (`src/rest_api_server/tools/`) - Consolidated security tool wrappers
- **Shared Utilities** (`src/rest_api_server/utils/` & `src/rest_api_server/logger.py`) - Registry, logging, and helper utilities shared across endpoints


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
uv run -m src.rest_api_server

# Or with environment variables
DEBUG=true BUGBOUNTY_MCP_PORT=8888 uv run -m src.rest_api_server

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
uv run -m src.rest_api_server

# Start with custom configuration
DEBUG=true BUGBOUNTY_MCP_PORT=9999 BUGBOUNTY_MCP_HOST=0.0.0.0 uv run -m src.rest_api_server
```



## Key Features

1. **Bug Bounty Workflow Management**: Complete workflow generation for different phases of bug bounty hunting
2. **Vulnerability Prioritization**: Intelligence-driven prioritization based on impact and bounty potential
3. **File Upload Testing**: Specialized framework for file upload vulnerability testing
4. **OSINT Integration**: Comprehensive OSINT gathering workflows
5. **Business Logic Testing**: Structured approach to business logic vulnerability discovery

## Spec-Kit Integration & AI-Assisted Development

This repository integrates with [GitHub Spec-Kit](https://github.com/github/spec-kit) for specification-driven development workflow, enhanced with AI assistance for codebase exploration, planning, and verification.

### Gemini CLI Integration

The repository includes integration with Google's Gemini CLI for enhanced AI-powered development assistance:

```bash
# Install Gemini CLI (nightly version for latest features)
npx @google/gemini-cli@nightly
```

#### Key Use Cases

**Codebase Exploration**
- Analyze complex bug bounty tool integrations and workflows
- Understand relationships between MCP server components and REST API endpoints
- Navigate through security tool configurations and vulnerability detection patterns

**Planning & Specification**
- Generate comprehensive implementation plans for new bug bounty workflows
- Create detailed specifications for security tool integrations
- Plan testing strategies for vulnerability detection capabilities

**Code Review & Verification**
- Validate implementation quality against security best practices
- Review bug bounty workflow logic for completeness and accuracy
- Verify API endpoint security and error handling
- Analyze tool output parsing and vulnerability classification

#### Integration with Spec-Kit Workflow

The Gemini CLI complements the existing spec-kit commands:

1. **Specify Phase** (`.claude/commands/specify.md`)
   ```bash
   # Use Gemini CLI to analyze requirements and generate specifications
   npx @google/gemini-cli@nightly analyze-requirements --input "feature_description"
   ```

2. **Planning Phase** (`.claude/commands/plan.md`)
   ```bash
   # Use Gemini CLI to validate and enhance implementation plans
   npx @google/gemini-cli@nightly review-plan --spec-file "path/to/spec.md"
   ```

3. **Implementation Verification**
   ```bash
   # Use Gemini CLI as a code reviewer and security auditor
   npx @google/gemini-cli@nightly audit-security --focus bug-bounty-workflows
   ```

#### Recommended Workflow

```bash
# 1. Explore codebase before making changes
npx @google/gemini-cli@nightly explore --focus "bug bounty tools integration"

# 2. Plan new features with AI assistance
npx @google/gemini-cli@nightly plan --spec-driven --security-focused

# 3. Verify implementations against security standards
npx @google/gemini-cli@nightly verify --check-security --validate-workflows
```

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

## Contributing

We welcome contributions. Please see `CONTRIBUTING.md` for guidelines.

Using an AI coding assistant? Start with `AGENTS.md` for repository-specific guidance.
