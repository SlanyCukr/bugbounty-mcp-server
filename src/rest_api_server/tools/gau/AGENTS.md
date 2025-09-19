# GAU Tool Documentation

## Overview

The GAU (Get All URLs) tool is a URL discovery utility that fetches URLs from multiple sources including Wayback Machine, Common Crawl, AlienVault OTX, and URLScan. It's designed for bug bounty hunters and security researchers to discover historical URLs for a given domain.

## REST API Endpoint

**Endpoint Path:** `/api/tools/gau`
**HTTP Method:** `POST`
**Content-Type:** `application/json`

## Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | Target domain to discover URLs for |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `providers` | string | `"wayback,commoncrawl,otx,urlscan"` | Comma-separated list of data sources |
| `include_subs` | boolean | `true` | Include subdomains in the search |
| `blacklist` | string | `"png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico"` | File extensions to exclude |
| `from` | string | `""` | Start date (YYYY-MM-DD format) |
| `to` | string | `""` | End date (YYYY-MM-DD format) |
| `output_file` | string | `""` | Path to save output file |
| `threads` | integer | `5` | Number of worker threads |
| `timeout` | integer | `60` | Request timeout in seconds |
| `retries` | integer | `5` | Number of retry attempts |
| `proxy` | string | `""` | Proxy URL (http://proxy:port) |
| `random_agent` | boolean | `false` | Use random user agents |
| `verbose` | boolean | `false` | Enable verbose output |
| `additional_args` | string | `""` | Additional command line arguments |

## Request Example

### Basic Request
```json
{
  "domain": "example.com"
}
```

### Advanced Request
```json
{
  "domain": "example.com",
  "providers": "wayback,commoncrawl",
  "include_subs": true,
  "blacklist": "png,jpg,pdf,css,js",
  "from": "2023-01-01",
  "to": "2023-12-31",
  "threads": 10,
  "timeout": 120,
  "random_agent": true,
  "verbose": true
}
```

## Response Format

### Successful Response
```json
{
  "success": true,
  "result": {
    "tool": "gau",
    "target": "example.com",
    "command": "gau example.com --subs",
    "status": "completed",
    "urls": [
      "https://example.com/path1",
      "https://sub.example.com/path2",
      "..."
    ],
    "total_urls": 150,
    "providers_used": ["wayback", "commoncrawl", "otx", "urlscan"],
    "raw_output": "https://example.com/path1\nhttps://sub.example.com/path2\n...",
    "error_output": "",
    "return_code": 0,
    "execution_time": "45.2s",
    "success": true
  }
}
```

### Error Response
```json
{
  "success": true,
  "result": {
    "tool": "gau",
    "target": "example.com",
    "command": "gau example.com --subs",
    "status": "failed",
    "error": "Command execution failed",
    "error_output": "Error message from gau",
    "return_code": 1,
    "success": false
  }
}
```

## cURL Examples

### Basic Usage
```bash
curl -X POST http://127.0.0.1:8888/api/tools/gau \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### Advanced Usage with Custom Parameters
```bash
curl -X POST http://127.0.0.1:8888/api/tools/gau \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "providers": "wayback,commoncrawl",
    "include_subs": true,
    "blacklist": "png,jpg,pdf,css",
    "from": "2023-01-01",
    "to": "2023-12-31",
    "threads": 10,
    "random_agent": true,
    "verbose": true
  }'
```

### With Proxy and Custom Timeout
```bash
curl -X POST http://127.0.0.1:8888/api/tools/gau \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "proxy": "http://proxy.example.com:8080",
    "timeout": 120,
    "retries": 3
  }'
```

## Logging

Based on the logging system configuration:

### Log File Location
- **Primary log file:** `logs/tools.gau.gau.log`
- **Registry log file:** `logs/utils.registry.log` (for endpoint registration)

### Log Levels
- **INFO:** Tool execution start/completion messages
- **DEBUG:** Available when `DEBUG=true` environment variable is set
- **ERROR:** Command execution failures and exceptions

### Log Format
```
YYYY-MM-DD HH:MM:SS,mmm - MODULE_NAME - LEVEL - MESSAGE
```

### Example Log Entries
```
2025-09-07 10:15:32,123 - tools.gau.gau - INFO - Executing Gau on example.com
2025-09-07 10:15:45,456 - tools.gau.gau - ERROR - Error in execute_gau: Command timeout after 300 seconds
```

## Environment Configuration

The server can be configured with these environment variables:
- `BUGBOUNTY_MCP_HOST`: Server host (default: `127.0.0.1`)
- `BUGBOUNTY_MCP_PORT`: Server port (default: `8888`)
- `DEBUG`: Enable debug logging (default: `false`)

## Error Handling

The tool includes comprehensive error handling:
- **400 Bad Request:** Missing required `domain` parameter
- **500 Internal Server Error:** Command execution failures, timeouts, or system errors
- **Command Failures:** Returned in response with `success: false` and error details

## Notes

- The tool requires the `gau` binary to be installed and available in the system PATH
- Default timeout for command execution is 300 seconds (5 minutes)
- URL results are deduplicated and returned as an array
- The tool supports all standard gau command-line options through the `additional_args` parameter
- File output is supported through the `output_file` parameter for large result sets
