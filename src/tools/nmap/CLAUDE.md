# Nmap Tool API Documentation

## Overview

The Nmap tool provides a REST API endpoint for executing Nmap network scanning commands against target hosts. It's designed for bug bounty hunting workflows and security reconnaissance.

## API Endpoint

**Path**: `/api/tools/nmap`
**Method**: `POST`
**Content-Type**: `application/json`

## Parameters

The endpoint accepts the following JSON parameters:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | Yes | - | The target host, IP address, or network range to scan |
| `scan_type` | string | No | `"-sV"` | Nmap scan type flags (e.g., "-sS", "-sV", "-sU") |
| `ports` | string | No | `""` | Port specification (e.g., "80,443", "1-1000", "80-443") |
| `additional_args` | string | No | `"-T4"` | Additional Nmap arguments (e.g., "-A", "-O", "--script vuln") |

### Parameter Details

- **target**: Can be a single IP (192.168.1.1), hostname (example.com), or network range (192.168.1.0/24)
- **scan_type**: Common values include:
  - `-sS`: SYN stealth scan
  - `-sV`: Version detection scan (default)
  - `-sU`: UDP scan
  - `-sC`: Default script scan
- **ports**: Port specification formats:
  - Single port: `"80"`
  - Multiple ports: `"80,443,8080"`
  - Port range: `"1-1000"`
  - Common ports: `"--top-ports 1000"`
- **additional_args**: Any additional Nmap flags like timing (`-T4`), OS detection (`-O`), aggressive scan (`-A`)

## Example Usage

### Basic Version Scan

```bash
curl -X POST http://127.0.0.1:8888/api/tools/nmap \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.1"
  }'
```

### Custom Port Range Scan

```bash
curl -X POST http://127.0.0.1:8888/api/tools/nmap \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "scan_type": "-sS",
    "ports": "1-1000",
    "additional_args": "-T4 -A"
  }'
```

### UDP Scan on Specific Ports

```bash
curl -X POST http://127.0.0.1:8888/api/tools/nmap \
  -H "Content-Type: application/json" \
  -d '{
    "target": "10.0.0.1",
    "scan_type": "-sU",
    "ports": "53,67,68,123,161",
    "additional_args": "-T4"
  }'
```

### Script Scan for Vulnerabilities

```bash
curl -X POST http://127.0.0.1:8888/api/tools/nmap \
  -H "Content-Type: application/json" \
  -d '{
    "target": "target.example.com",
    "scan_type": "-sV",
    "ports": "80,443",
    "additional_args": "--script vuln -T4"
  }'
```

## Response Format

The API returns a JSON response with the following structure:

```json
{
  "success": true,
  "result": {
    "tool": "nmap",
    "target": "192.168.1.1",
    "parameters": {
      "target": "192.168.1.1",
      "scan_type": "-sV",
      "ports": "",
      "additional_args": "-T4"
    },
    "command": "nmap -sV -T4 192.168.1.1",
    "success": true,
    "return_code": 0,
    "stdout": "Starting Nmap scan results...",
    "stderr": ""
  }
}
```

### Response Fields

- **success**: Overall API call success status
- **result.tool**: Always "nmap" for this endpoint
- **result.target**: The target that was scanned
- **result.parameters**: Echo of input parameters used
- **result.command**: The actual nmap command that was executed
- **result.success**: Whether the nmap command executed successfully
- **result.return_code**: Exit code from the nmap process
- **result.stdout**: Standard output from nmap (scan results)
- **result.stderr**: Standard error output (warnings, errors)

## Logging

### Log Location

Nmap tool execution logs are stored in:
```
logs/tools.nmap.nmap.log
```

### Log Content

The logging system captures:
- Execution start messages with target information
- Command construction and execution details
- Success/failure status
- Error messages and exceptions
- Timestamp and log level for each entry

### Log Format

```
YYYY-MM-DD HH:MM:SS,mmm - tools.nmap.nmap - INFO - Executing Nmap scan on 192.168.1.1
YYYY-MM-DD HH:MM:SS,mmm - tools.nmap.nmap - ERROR - Error message if applicable
```

## Server Configuration

### Default Settings

- **Host**: `127.0.0.1` (can be configured via `BUGBOUNTY_MCP_HOST` environment variable)
- **Port**: `8888` (can be configured via `BUGBOUNTY_MCP_PORT` environment variable)
- **Debug Mode**: Disabled (enable with `DEBUG=true` environment variable)

### Starting the Server

```bash
# Default configuration
uv run src/server.py

# With custom configuration
DEBUG=true BUGBOUNTY_MCP_PORT=8888 uv run src/server.py
```

## Security Considerations

- The tool executes system commands, ensure proper network isolation
- Validate targets to prevent scanning unauthorized networks
- Consider rate limiting for production deployments
- Monitor logs for unusual scan patterns or targets
- Ensure nmap is installed on the system running the server

## Error Handling

The API includes comprehensive error handling:

- **400 Bad Request**: Missing required fields or invalid JSON
- **500 Internal Server Error**: Command execution failures or system errors

Common error scenarios:
- Missing `target` parameter
- Invalid JSON payload
- Nmap command execution failures
- Network connectivity issues
- Permission problems (running nmap may require elevated privileges for some scan types)
