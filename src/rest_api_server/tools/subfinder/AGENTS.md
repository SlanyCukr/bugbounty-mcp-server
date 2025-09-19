# Subfinder Tool API Documentation

## Overview

The Subfinder tool provides passive subdomain enumeration capabilities through a REST API endpoint. It wraps the `subfinder` command-line tool to discover subdomains for a given domain using various passive reconnaissance techniques.

## API Endpoint

**Path:** `/api/tools/subfinder`
**Method:** `POST`
**Content-Type:** `application/json`

## Parameters

The endpoint accepts the following parameters in the JSON request body:

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | The target domain to enumerate subdomains for |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `silent` | boolean | `true` | Enable silent mode (suppress banner and timestamps) |
| `all_sources` | boolean | `false` | Use all available sources for enumeration |
| `sources` | string | `null` | Comma-separated list of specific sources to use |
| `threads` | integer | `10` | Number of concurrent threads to use |
| `additional_args` | string | `null` | Additional command-line arguments to pass to subfinder |

## Example Request

### Basic Usage

```bash
curl -X POST http://127.0.0.1:8888/api/tools/subfinder \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com"
  }'
```

### Advanced Usage with Custom Parameters

```bash
curl -X POST http://127.0.0.1:8888/api/tools/subfinder \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "silent": true,
    "all_sources": true,
    "threads": 20,
    "sources": "crtsh,virustotal,censys",
    "additional_args": "-v -o /tmp/subdomains.txt"
  }'
```

## Response Format

The endpoint returns a JSON response with the following structure:

```json
{
  "success": true,
  "result": {
    "tool": "subfinder",
    "target": "example.com",
    "command": "subfinder -d example.com -silent -t 10",
    "success": true,
    "stdout": "sub1.example.com\nsub2.example.com\napi.example.com",
    "stderr": "",
    "return_code": 0
  }
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `success` | boolean | Overall API call success status |
| `result.tool` | string | Name of the tool used ("subfinder") |
| `result.target` | string | The target domain that was enumerated |
| `result.command` | string | The actual subfinder command that was executed |
| `result.success` | boolean | Whether the subfinder command executed successfully |
| `result.stdout` | string | Standard output from the subfinder command |
| `result.stderr` | string | Standard error output from the subfinder command |
| `result.return_code` | integer | Exit code from the subfinder command |

## Error Responses

### Missing Required Parameters

```json
{
  "error": "Domain is required"
}
```
HTTP Status: `400 Bad Request`

### Server Errors

```json
{
  "error": "Server error: <error details>"
}
```
HTTP Status: `500 Internal Server Error`

## Logging

Logs from the subfinder endpoint are stored in the following location:

**Log File:** `/home/slanycukr/Documents/MCP_servers/bugbounty-mcp-server/logs/tools.subfinder.subfinder.log`

The logging system uses the module path as the logger name (`tools.subfinder.subfinder`), which is derived from the file location `src/rest_api_server/tools/subfinder/subfinder.py`.

### Log Format

```
2025-09-07 10:30:15,123 - tools.subfinder.subfinder - INFO - Executing Subfinder on example.com
```

**Format Pattern:** `%(asctime)s - %(name)s - %(levelname)s - %(message)s`

### Log Levels

- **INFO**: Normal execution flow (e.g., "Executing Subfinder on example.com")
- **ERROR**: Errors during execution (handled by the registry's exception handling)
- **DEBUG**: Detailed debugging information (when `DEBUG=true` environment variable is set)

## Configuration

### Environment Variables

- `DEBUG=true`: Enable debug logging for more verbose output
- `BUGBOUNTY_MCP_PORT=8888`: Change the server port (default: 8888)
- `BUGBOUNTY_MCP_HOST=127.0.0.1`: Change the server host (default: 127.0.0.1)

### Command Timeout

The subfinder command has a default timeout of **300 seconds** (5 minutes). If the command takes longer than this, it will be terminated.

## Dependencies

- The `subfinder` binary must be installed and available in the system PATH
- The tool uses the `execute_command` utility for command execution with timeout support

## Implementation Notes

1. The tool is registered using the `@tool(required_fields=['domain'])` decorator
2. All parameters are validated and processed through helper functions
3. Error handling is managed by the registry's exception handling decorator
4. Response formatting is standardized through the registry's format_response decorator
5. The command is executed with a 300-second timeout to prevent hanging operations
