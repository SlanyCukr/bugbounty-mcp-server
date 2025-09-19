# Arjun Tool API Documentation

This document provides comprehensive information about the Arjun HTTP parameter discovery tool endpoint in the Bug Bounty MCP Server.

## Overview

The Arjun tool is used for HTTP parameter discovery during bug bounty hunting. It helps identify hidden parameters in web applications that might be vulnerable to various attack vectors.

## REST API Endpoint

**Path:** `/api/tools/arjun`
**Method:** `POST`
**Content-Type:** `application/json`

## Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string | Target URL for parameter discovery |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `method` | string | `"GET"` | HTTP method to use for requests |
| `wordlist` | string | `""` | Custom wordlist file path for parameter names |
| `threads` | integer | `25` | Number of threads to use for concurrent requests |
| `delay` | integer | `0` | Delay between requests in seconds |
| `timeout` | string | `""` | Request timeout value |
| `headers` | string | `""` | Custom HTTP headers (format: "Header1: value1; Header2: value2") |
| `data` | string | `""` | POST data for requests |
| `stable` | boolean | `false` | Enable stable mode for more reliable results |
| `get_method` | boolean | `true` | Include GET method in testing |
| `post_method` | boolean | `false` | Include POST method in testing |
| `json_method` | boolean | `false` | Include JSON method in testing |
| `include_status` | string | `""` | HTTP status codes to include in results |
| `exclude_status` | string | `""` | HTTP status codes to exclude from results |
| `output_file` | string | `""` | Output file path for results |
| `additional_args` | string | `""` | Additional command-line arguments |

## Request Example

```json
{
    "url": "https://example.com/api/endpoint",
    "method": "POST",
    "wordlist": "/path/to/custom/wordlist.txt",
    "threads": 50,
    "delay": 1,
    "timeout": "30",
    "headers": "Authorization: Bearer token123; User-Agent: CustomAgent",
    "data": "existing_param=value",
    "stable": true,
    "get_method": true,
    "post_method": true,
    "json_method": false,
    "include_status": "200,302",
    "exclude_status": "404,403",
    "output_file": "/tmp/arjun_results.txt",
    "additional_args": "--passive"
}
```

## cURL Command Example

```bash
curl -X POST http://127.0.0.1:8888/api/tools/arjun \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/api/endpoint",
    "method": "POST",
    "threads": 30,
    "delay": 1,
    "stable": true,
    "get_method": true,
    "post_method": true
  }'
```

## Response Format

```json
{
    "success": true,
    "result": {
        "tool": "arjun",
        "target": "https://example.com/api/endpoint",
        "command": "arjun -u https://example.com/api/endpoint -t 30 -m GET,POST -d 1 --stable",
        "success": true,
        "return_code": 0,
        "stdout": "Arjun output here...",
        "stderr": "",
        "parameters": {
            "url": "https://example.com/api/endpoint",
            "method": "POST",
            "wordlist": "",
            "threads": 30,
            "delay": 1,
            "timeout": "",
            "stable": true,
            "additional_args": ""
        }
    }
}
```

## Error Responses

### Missing Required Fields
```json
{
    "error": "Url is required"
}
```

### Server Error
```json
{
    "error": "Server error: [error message]"
}
```

## Logging

### Log Location
Logs for the Arjun tool are stored in:
- **File:** `/logs/tools.arjun.arjun.log`
- **Console:** Standard output (when DEBUG=true)

### Log Format
```
YYYY-MM-DD HH:MM:SS,mmm - tools.arjun.arjun - LEVEL - MESSAGE
```

### Log Levels
- **INFO:** General execution information and command details
- **ERROR:** Error conditions and exceptions
- **DEBUG:** Detailed debugging information (when DEBUG=true environment variable is set)

### Sample Log Entries
```
2025-09-07 10:15:30,123 - tools.arjun.arjun - INFO - Executing Arjun on https://example.com/api/endpoint
2025-09-07 10:15:30,124 - tools.arjun.arjun - INFO - Executing arjun command: arjun -u https://example.com/api/endpoint -t 25
```

## Environment Configuration

The endpoint behavior can be modified using environment variables:

- `DEBUG=true`: Enables debug logging and detailed output
- `BUGBOUNTY_MCP_HOST`: Server host (default: 127.0.0.1)
- `BUGBOUNTY_MCP_PORT`: Server port (default: 8888)

## Command Timeout

The Arjun execution has a default timeout of **600 seconds (10 minutes)** to accommodate longer parameter discovery sessions.

## Notes

- The tool requires the `arjun` binary to be installed and accessible in the system PATH
- Multiple HTTP methods can be enabled simultaneously using the method flags
- Custom headers should be formatted as semicolon-separated key-value pairs
- Output files are optional and will be created if specified
- The stable mode provides more reliable results but may take longer to execute
