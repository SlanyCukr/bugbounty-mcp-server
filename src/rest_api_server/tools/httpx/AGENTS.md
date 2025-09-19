# HTTPx Tool API Documentation

This document provides comprehensive information about the HTTPx tool endpoint in the Bug Bounty MCP Server.

## Overview

The HTTPx tool provides HTTP probing capabilities for bug bounty hunting. It uses the popular HTTPx tool by ProjectDiscovery to perform fast and reliable HTTP probing of web services.

## REST API Endpoint

**Path**: `/api/tools/httpx`
**Method**: `POST`
**Content-Type**: `application/json`

## Parameters

All parameters are optional unless specified. The tool accepts the following parameters in the JSON request body:

### Required Parameters
- **One of the following must be provided:**
  - `targets` (string or array): Direct targets to probe (URLs, domains, or IP addresses)
  - `target_file` (string): Path to a file containing targets (one per line)

### Core Parameters
- `status_code` / `sc` (boolean, default: false): Include HTTP status code in output
- `content_length` / `cl` (boolean, default: false): Include content length in output
- `title` (boolean, default: true): Include page title in output
- `tech_detect` / `tech` (boolean, default: false): Enable technology detection
- `web_server` / `server` (boolean, default: false): Include web server information
- `location` (boolean, default: false): Include redirect location headers
- `response_time` / `rt` (boolean, default: false): Include response time in output

### HTTP Method Parameters
- `method` (string, default: "GET"): HTTP method to use for requests
- `methods` (string, default: "GET"): Alternative parameter name for HTTP method

### Filtering Parameters
- `match_code` / `mc` (string): Only show responses with matching status codes (e.g., "200,301,302")
- `filter_code` / `fc` (string): Filter out responses with specified status codes (e.g., "404,403")

### Performance Parameters
- `threads` (integer, default: 50): Number of threads to use for concurrent requests
- `timeout` (integer, default: 10): Request timeout in seconds

### Redirect Parameters
- `follow_redirects` (boolean, default: false): Follow all redirects
- `follow_host_redirects` (boolean, default: false): Follow redirects on same host only

### Output Parameters
- `json` (boolean, default: false): Output results in JSON format
- `silent` (boolean, default: true): Suppress unnecessary output
- `ports` (string): Custom ports to probe (e.g., "80,443,8080")

### Advanced Parameters
- `additional_args` (string): Additional command line arguments to pass to HTTPx

## Request Examples

### Basic URL Probing
```json
{
  "targets": "https://example.com",
  "title": true,
  "status_code": true
}
```

### Multiple Targets with Technology Detection
```json
{
  "targets": ["https://example.com", "https://test.com", "https://demo.com"],
  "tech_detect": true,
  "web_server": true,
  "status_code": true,
  "content_length": true
}
```

### File-based Targets with Custom Filtering
```json
{
  "target_file": "/path/to/targets.txt",
  "match_code": "200,301,302",
  "threads": 100,
  "timeout": 15,
  "json": true
}
```

### Advanced Probing Configuration
```json
{
  "targets": "example.com",
  "ports": "80,443,8080,8443",
  "follow_redirects": true,
  "response_time": true,
  "location": true,
  "additional_args": "-random-agent -retries 2"
}
```

## cURL Command Examples

### Basic Request
```bash
curl -X POST http://127.0.0.1:8888/api/tools/httpx \
  -H "Content-Type: application/json" \
  -d '{
    "targets": "https://example.com",
    "title": true,
    "status_code": true
  }'
```

### Advanced Request with Multiple Options
```bash
curl -X POST http://127.0.0.1:8888/api/tools/httpx \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["https://example.com", "https://test.com"],
    "tech_detect": true,
    "web_server": true,
    "status_code": true,
    "content_length": true,
    "threads": 100,
    "timeout": 15,
    "follow_redirects": true,
    "json": true
  }'
```

### Using Target File
```bash
curl -X POST http://127.0.0.1:8888/api/tools/httpx \
  -H "Content-Type: application/json" \
  -d '{
    "target_file": "/home/user/targets.txt",
    "match_code": "200,301,302",
    "title": true,
    "tech_detect": true
  }'
```

## Response Format

The endpoint returns a JSON response with the following structure:

### Successful Response
```json
{
  "success": true,
  "result": {
    "tool": "httpx",
    "target": "https://example.com",
    "command": "httpx -l /tmp/httpx_targets_abc123.txt -sc -title -silent",
    "success": true,
    "stdout": "https://example.com [200] [Example Domain] [Apache/2.4.41]",
    "stderr": "",
    "return_code": 0
  }
}
```

### Error Response
```json
{
  "error": "Targets or target_file is required"
}
```

## Logging Information

### Log File Location
HTTPx tool logs are stored in: `/logs/tools.httpx.httpx.log`

### Log Format
```
YYYY-MM-DD HH:MM:SS,mmm - tools.httpx.httpx - LEVEL - MESSAGE
```

### Example Log Entries
```
2024-01-15 10:30:45,123 - tools.httpx.httpx - INFO - Executing HTTPx on targets
2024-01-15 10:30:47,456 - tools.httpx.httpx - ERROR - Error in execute_httpx: Command failed with return code 1
```

### Debug Logging
To enable debug logging, set the `DEBUG` environment variable to `true`:
```bash
DEBUG=true uv run -m src.rest_api_server
```

## Error Handling

The tool handles various error conditions:

1. **Missing Parameters**: Returns 400 error if neither `targets` nor `target_file` is provided
2. **Command Execution Failures**: Captures stderr and return codes from HTTPx
3. **File Cleanup**: Automatically removes temporary files created during execution
4. **Timeout Handling**: Commands timeout after 600 seconds (10 minutes)

## Implementation Notes

- **Temporary Files**: When using direct targets, the tool creates temporary files that are automatically cleaned up
- **Target Formats**: Supports both string and array formats for targets parameter
- **Parameter Aliases**: Many parameters have short aliases (e.g., `sc` for `status_code`, `cl` for `content_length`)
- **Command Building**: Dynamically builds HTTPx command based on provided parameters
- **Thread Safety**: Uses HTTPx's built-in threading capabilities for concurrent requests

## Security Considerations

- **Input Validation**: All parameters are validated before command execution
- **File Path Handling**: Target files must be accessible by the server process
- **Command Injection**: Additional arguments are split safely to prevent injection attacks
- **Resource Limits**: Default timeout and thread limits prevent resource exhaustion
