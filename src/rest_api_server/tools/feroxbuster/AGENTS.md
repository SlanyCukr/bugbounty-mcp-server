# Feroxbuster Tool API Documentation

## Overview

Feroxbuster is a fast recursive directory scanning tool designed for bug bounty hunting and web application security assessment. This tool provides a REST API endpoint for executing feroxbuster scans with comprehensive parameter control and detailed result parsing.

## REST API Endpoint

**Path:** `/api/tools/feroxbuster`
**Method:** `POST`
**Content-Type:** `application/json`

## Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string | Target URL to scan (e.g., "https://example.com") |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `wordlist` | string | `/usr/share/wordlists/dirb/common.txt` | Path to wordlist file for directory/file discovery |
| `threads` | integer | `10` | Number of concurrent threads to use |
| `depth` | integer | `4` | Maximum recursion depth for directory traversal |
| `extensions` | string | `""` | File extensions to append to wordlist entries (e.g., "php,html,js") |
| `filter_codes` | string | `"404"` | HTTP status codes to filter out from results |
| `timeout` | integer | `7` | Request timeout in seconds |
| `additional_args` | string | `""` | Additional command-line arguments to pass to feroxbuster |

## Example Usage

### Curl Command

```bash
curl -X POST http://127.0.0.1:8888/api/tools/feroxbuster \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "wordlist": "/usr/share/wordlists/dirb/common.txt",
    "threads": 20,
    "depth": 3,
    "extensions": "php,html,js,txt",
    "filter_codes": "404,403",
    "timeout": 10,
    "additional_args": "--no-recursion"
  }'
```

### Minimal Request

```bash
curl -X POST http://127.0.0.1:8888/api/tools/feroxbuster \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com"
  }'
```

## Response Format

### Successful Response

```json
{
  "success": true,
  "result": {
    "tool": "feroxbuster",
    "target": "https://example.com",
    "parameters": {
      "url": "https://example.com",
      "wordlist": "/usr/share/wordlists/dirb/common.txt",
      "threads": 10,
      "depth": 4,
      "extensions": "",
      "filter_codes": "404",
      "timeout": 7,
      "additional_args": ""
    },
    "status": "completed",
    "discovered_resources": [
      {
        "url": "https://example.com/admin",
        "status": 200,
        "size": 1024,
        "words": 150,
        "lines": 45,
        "depth": 1
      }
    ],
    "scan_statistics": {
      "total_requests": 150,
      "requests_per_second": 25.5,
      "status_code_distribution": {
        "200": 5,
        "301": 3,
        "403": 8
      },
      "recursion_depth_reached": 2,
      "wildcards_filtered": 0
    },
    "performance_metrics": {
      "avg_response_time": "N/A",
      "max_response_time": "N/A",
      "min_response_time": "N/A",
      "threads_used": 10
    },
    "execution_time": "12.5s",
    "raw_output": "feroxbuster command output..."
  }
}
```

### Error Response

```json
{
  "success": false,
  "error": "Feroxbuster execution failed: Connection timeout"
}
```

## Logging

### Log Location

Feroxbuster tool logs are stored in:
**File Path:** `logs/tools.feroxbuster.feroxbuster.log`

### Log Format

```
2025-09-07 10:15:30,123 - tools.feroxbuster.feroxbuster - INFO - Executing Feroxbuster on https://example.com
2025-09-07 10:15:30,125 - tools.feroxbuster.feroxbuster - ERROR - Feroxbuster command failed: Connection refused
```

### Debug Logging

To enable debug-level logging, set the `DEBUG` environment variable:

```bash
DEBUG=true uv run -m src.rest_api_server
```

## Command Construction

The tool builds feroxbuster commands with the following structure:

```bash
feroxbuster -u <url> -w <wordlist> -t <threads> -d <depth> -T <timeout> [-x <extensions>] [-C <filter_codes>] --json [additional_args]
```

### Example Generated Command

```bash
feroxbuster -u https://example.com -w /usr/share/wordlists/dirb/common.txt -t 10 -d 4 -T 7 -C 404 --json
```

## Error Handling

The tool handles various error scenarios:

1. **Command Execution Failure**: Returns error with command details
2. **JSON Parsing Issues**: Falls back to plain text parsing
3. **Network Timeouts**: 30-minute maximum execution timeout
4. **Invalid Parameters**: Validation handled by the framework

## Output Processing

The tool processes feroxbuster output in two modes:

1. **JSON Mode** (Primary): Parses structured JSON output from feroxbuster
2. **Plain Text Mode** (Fallback): Uses regex parsing if JSON parsing fails

### Discovered Resources Format

Each discovered resource contains:
- `url`: Full URL of the discovered resource
- `status`: HTTP status code
- `size`: Content length in bytes
- `words`: Word count in response
- `lines`: Line count in response
- `depth`: Directory depth from base URL

## Security Considerations

- Command injection protection through parameter validation
- Output truncation for large responses (10KB limit)
- Configurable timeout to prevent indefinite execution
- Input sanitization for all parameters

## Performance Notes

- Default thread count: 10 (configurable)
- Maximum execution timeout: 30 minutes
- Output size limit: 10KB (larger outputs are truncated)
- Supports concurrent scanning with thread control
