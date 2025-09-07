# Waybackurls Tool - REST API Documentation

## Overview

The Waybackurls tool provides a REST API endpoint for discovering historical URLs for a domain using the Wayback Machine. This tool is part of the Bug Bounty MCP Server and helps security researchers gather historical web content for reconnaissance purposes.

## REST API Endpoint

**Path:** `/api/tools/waybackurls`
**Method:** `POST`
**Content-Type:** `application/json`

## Parameters

The endpoint accepts the following JSON parameters in the request body:

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | The target domain to search for historical URLs |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `get_versions` | boolean | `false` | Include different versions of the same URL |
| `no_subs` | boolean | `false` | Don't include subdomains in the search |
| `dates` | string | `""` | Filter results by date range (format depends on waybackurls tool) |
| `output_file` | string | `""` | Save results to a specific file path |
| `additional_args` | string | `""` | Additional command line arguments to pass to waybackurls |

## Request Example

```json
{
    "domain": "example.com",
    "get_versions": true,
    "no_subs": false,
    "dates": "2020-2023",
    "output_file": "/tmp/wayback_results.txt",
    "additional_args": "--verbose"
}
```

## Response Format

### Success Response

```json
{
    "success": true,
    "result": {
        "tool": "waybackurls",
        "target": "example.com",
        "parameters": {
            "domain": "example.com",
            "get_versions": true,
            "no_subs": false,
            "dates": "2020-2023",
            "output_file": "/tmp/wayback_results.txt",
            "additional_args": "--verbose"
        },
        "status": "completed",
        "urls": [
            "https://example.com/",
            "https://example.com/about",
            "https://example.com/contact"
        ],
        "unique_urls": 3,
        "command": "waybackurls example.com --get-versions --dates 2020-2023 -o /tmp/wayback_results.txt --verbose",
        "success": true,
        "stdout": "https://example.com/\nhttps://example.com/about\nhttps://example.com/contact",
        "stderr": null
    }
}
```

### Error Response

```json
{
    "success": true,
    "result": {
        "tool": "waybackurls",
        "target": "example.com",
        "parameters": {
            "domain": "example.com"
        },
        "command": "waybackurls example.com",
        "success": false,
        "status": "failed",
        "error": "Waybackurls execution failed: Command not found"
    }
}
```

## Curl Command Examples

### Basic Usage

```bash
curl -X POST http://127.0.0.1:8888/api/tools/waybackurls \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com"
  }'
```

### Advanced Usage with Options

```bash
curl -X POST http://127.0.0.1:8888/api/tools/waybackurls \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "get_versions": true,
    "no_subs": false,
    "dates": "2020-2023",
    "output_file": "/tmp/wayback_results.txt",
    "additional_args": "--verbose"
  }'
```

### Using Environment Variables

If the server is running on a different host/port:

```bash
# Using custom host and port
curl -X POST http://192.168.1.100:9999/api/tools/waybackurls \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "target.com"
  }'
```

## Logging

### Log File Location

Logs for the waybackurls tool are stored in:
- **File Path:** `/logs/tools.waybackurls.waybackurls.log`
- **Format:** `timestamp - logger_name - level - message`

### Log Levels

The logging system supports different levels based on the `DEBUG` environment variable:
- **Debug Mode Off (default):** INFO level and above
- **Debug Mode On:** DEBUG level and above (set `DEBUG=true`)

### Example Log Entries

```
2025-09-07 10:30:15,123 - tools.waybackurls.waybackurls - INFO - Executing Waybackurls on example.com
2025-09-07 10:30:18,456 - tools.waybackurls.waybackurls - ERROR - Waybackurls command failed: Command not found
```

### Viewing Logs

To monitor logs in real-time:

```bash
# View the specific waybackurls log file
tail -f logs/tools.waybackurls.waybackurls.log

# View all logs in the directory
tail -f logs/*.log
```

## Server Configuration

The server can be configured using environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `BUGBOUNTY_MCP_HOST` | `127.0.0.1` | Server host address |
| `BUGBOUNTY_MCP_PORT` | `8888` | Server port |
| `DEBUG` | `false` | Enable debug logging |

### Starting the Server

```bash
# Default configuration
uv run src/server.py

# With custom configuration
DEBUG=true BUGBOUNTY_MCP_PORT=9999 uv run src/server.py
```

## Dependencies

The waybackurls tool requires:
- The `waybackurls` binary to be installed and available in the system PATH
- Python Flask for the REST API
- Access to the Wayback Machine (internet connection required)

## Error Handling

The endpoint includes comprehensive error handling:
- **400 Bad Request:** Missing required `domain` parameter or invalid JSON
- **500 Internal Server Error:** Tool execution failures, system errors
- **Success with Error Status:** Tool runs but returns error (captured in response)

All errors are logged with appropriate detail levels for debugging and monitoring purposes.
