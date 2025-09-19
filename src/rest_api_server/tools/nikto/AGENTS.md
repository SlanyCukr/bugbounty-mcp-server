# Nikto Tool API Documentation

This document provides comprehensive documentation for the Nikto web vulnerability scanner tool endpoint in the Bug Bounty MCP Server.

## Overview

The Nikto tool provides a REST API endpoint for executing Nikto web server vulnerability scans. Nikto is an Open Source web server scanner which performs comprehensive tests against web servers for multiple items, including over 6700 potentially dangerous files/programs, checks for outdated versions of over 1250 servers, and version specific problems on over 270 servers.

## API Endpoint

**Path:** `/api/tools/nikto`
**Method:** `POST`
**Content-Type:** `application/json`

## Parameters

The endpoint accepts the following JSON parameters:

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string | **Required.** The target host/URL to scan (e.g., "example.com", "192.168.1.1", "https://example.com") |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `port` | string/integer | "80" | Port number to scan (e.g., "443", "8080") |
| `ssl` | boolean | false | Enable SSL/TLS mode for HTTPS scanning |
| `plugins` | string | "" | Comma-separated list of Nikto plugins to use |
| `output_format` | string | "txt" | Output format (txt, xml, csv, etc.) |
| `evasion` | string | "" | Evasion technique to use (1-9) |
| `timeout` | integer | 600 | Command execution timeout in seconds |
| `additional_args` | string | "" | Additional command-line arguments to pass to Nikto |

## Response Format

The endpoint returns a JSON response with the following structure:

```json
{
  "success": true,
  "result": {
    "tool": "nikto",
    "target": "example.com",
    "parameters": {
      "target": "example.com",
      "port": "80",
      "ssl": false,
      "plugins": "",
      "output_format": "txt",
      "evasion": "",
      "timeout": 600,
      "additional_args": ""
    },
    "command": "nikto -h example.com",
    "status": "completed",
    "raw_output": "...",
    "error_output": "",
    "return_code": 0,
    "execution_time": null
  }
}
```

## Curl Examples

### Basic Scan

```bash
curl -X POST http://127.0.0.1:8888/api/tools/nikto \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com"
  }'
```

### HTTPS Scan with Custom Port

```bash
curl -X POST http://127.0.0.1:8888/api/tools/nikto \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "port": "443",
    "ssl": true
  }'
```

### Comprehensive Scan with Plugins

```bash
curl -X POST http://127.0.0.1:8888/api/tools/nikto \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "port": "8080",
    "plugins": "@@ALL",
    "output_format": "xml",
    "timeout": 1200,
    "additional_args": "-nointeractive -Format txt"
  }'
```

### Scan with Evasion Techniques

```bash
curl -X POST http://127.0.0.1:8888/api/tools/nikto \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.100",
    "port": "80",
    "evasion": "1",
    "timeout": 900
  }'
```

## Logging

### Log File Location

Logs for the Nikto tool endpoint are stored in:
```
logs/tools.nikto.nikto.log
```

### Log Format

Logs follow the standard format:
```
%(asctime)s - %(name)s - %(levelname)s - %(message)s
```

Example log entries:
```
2025-09-07 10:15:30,123 - tools.nikto.nikto - INFO - Executing Nikto scan on example.com
2025-09-07 10:15:30,124 - tools.nikto.nikto - DEBUG - Building command: nikto -h example.com -p 443 -ssl
2025-09-07 10:16:45,567 - tools.nikto.nikto - INFO - Nikto scan completed successfully
```

### Log Levels

- **INFO**: General execution information, scan start/completion
- **DEBUG**: Detailed command building and execution details (only when DEBUG=true)
- **ERROR**: Error conditions and exceptions
- **WARNING**: Non-fatal issues and warnings

## Error Handling

The endpoint implements comprehensive error handling:

### Validation Errors (400)
- Missing required `target` parameter
- Invalid JSON payload

### Server Errors (500)
- Command execution failures
- Nikto tool not installed or not in PATH
- File system permission errors
- Timeout exceeded

### Example Error Response

```json
{
  "error": "Target is required"
}
```

## Environment Variables

The following environment variables affect the endpoint behavior:

- `DEBUG`: Set to "true" to enable debug logging
- `BUGBOUNTY_MCP_HOST`: Server host (default: "127.0.0.1")
- `BUGBOUNTY_MCP_PORT`: Server port (default: 8888)

## Security Considerations

- The endpoint executes system commands based on user input
- Input validation is performed on required fields
- Command injection protection is implemented through parameter extraction
- Timeouts prevent long-running scans from consuming resources indefinitely
- All execution is logged for audit purposes

## Dependencies

- Nikto must be installed and available in the system PATH
- Python packages: flask, logging (standard library)
- System utilities: nikto command-line tool

## Notes

- Nikto scans can be time-consuming; consider adjusting the timeout parameter accordingly
- Some targets may require specific plugins or evasion techniques
- SSL scans require the target to support HTTPS
- Output format affects the structure of the raw_output field in the response
- The tool respects rate limiting and target-specific considerations built into Nikto
