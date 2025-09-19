# src/ Code Documentation

Source code organization and implementation patterns for the Bug Bounty MCP Server.

## File Structure

- `server.py` - Flask REST API server (3656 lines)
- `mcp_server.py` - FastMCP server for AI agents (1719 lines)
- `__init__.py` - Package marker

## Core Architecture Patterns

### Data Models
- `BugBountyTarget` dataclass - Central data model with domain, scope, vulnerabilities
- Standard field defaults using `field(default_factory=list)`

### Server Implementations

**Flask REST API (`server.py`)**
- Main classes: `BugBountyWorkflowManager`, `FileUploadTestingFramework`, `IntelligenceEngine`
- Pattern: Tool execution functions (`execute_nuclei()`, `execute_sqlmap()`, etc.)
- Workflow creation methods return structured JSON responses
- Error handling with try/catch and JSON error responses

**MCP Server (`mcp_server.py`)**
- `BugBountyAPIClient` for HTTP communication with retry logic
- FastMCP tool decorators for each security tool
- Individual scan functions (nmap, subfinder, nuclei, etc.)
- Workflow orchestration functions

### Key Implementation Patterns

**Tool Execution Pattern:**
```python
def execute_tool():
    try:
        # Parameter validation
        # Build command/config
        # Return structured response
    except Exception as e:
        return {"error": str(e)}
```

**Workflow Generation Pattern:**
```python
def create_workflow(target: BugBountyTarget) -> dict[str, Any]:
    return {
        "workflow_type": "...",
        "target": target.domain,
        "phases": [...],
        "tools": [...],
        "estimated_time": "..."
    }
```

**MCP Tool Pattern:**
```python
@mcp.tool()
def tool_name(param: str) -> dict[str, Any]:
    return api_client.safe_post("/endpoint", {...})
```

## Configuration & Environment

- Environment variables: `BUGBOUNTY_MCP_PORT`, `BUGBOUNTY_MCP_HOST`, `DEBUG`
- Logging configured for both console and file output
- Default timeouts and retry logic implemented

## Testing Commands

Run servers:
```bash
uv run -m src.rest_api_server
uv run -m src.mcp_server
```

With environment variables:
```bash
DEBUG=true BUGBOUNTY_MCP_PORT=8888 uv run -m src.rest_api_server
```

Manual API testing:
```bash
curl -X POST http://127.0.0.1:8888/api/bugbounty/reconnaissance-workflow \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "program_type": "web"}'
```

## Development Guidelines

- Follow existing dataclass patterns for new models
- Use structured JSON responses with consistent error handling
- Tool functions should validate parameters and handle exceptions
- Maintain the workflow → tools → commands → results pattern
- Log important operations to both console and file
