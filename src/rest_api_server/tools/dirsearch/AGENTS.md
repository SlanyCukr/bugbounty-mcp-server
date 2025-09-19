# Dirsearch Tool Documentation

## Overview

The dirsearch tool is a directory and file discovery utility for web applications. It performs brute-force discovery of hidden files and directories on web servers using customizable wordlists and parameters.

## REST API Endpoint

**Path:** `/api/tools/dirsearch`
**Method:** POST
**Content-Type:** application/json

## Parameters

The endpoint accepts a JSON payload with the following parameters:

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string | **Required.** Target URL to scan for directories and files |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `extensions` | string | `"php,html,js,txt,xml,json"` | Comma-separated list of file extensions to search for |
| `wordlist` | string | `"/usr/share/wordlists/dirb/common.txt"` | Path to wordlist file for brute-forcing |
| `threads` | integer | `30` | Number of concurrent threads to use |
| `recursive` | boolean | `false` | Enable recursive directory scanning |
| `timeout` | integer | `300` | Timeout in seconds for the entire scan |
| `additional_args` | string | `""` | Additional command-line arguments to pass to dirsearch |

## Example Usage

### Basic Request
```bash
curl -X POST http://127.0.0.1:8888/api/tools/dirsearch \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com"
  }'
```

### Advanced Request with Custom Parameters
```bash
curl -X POST http://127.0.0.1:8888/api/tools/dirsearch \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "extensions": "php,html,js,asp,aspx",
    "wordlist": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "threads": 50,
    "recursive": true,
    "timeout": 600,
    "additional_args": "--exclude-status 404,403"
  }'
```

## Response Format

### Success Response
```json
{
  "success": true,
  "result": {
    "tool": "dirsearch",
    "target": "https://example.com",
    "parameters": {
      "url": "https://example.com",
      "extensions": "php,html,js,txt,xml,json",
      "wordlist": "/usr/share/wordlists/dirb/common.txt",
      "threads": 30,
      "recursive": false,
      "timeout": 300,
      "additional_args": ""
    },
    "command": "dirsearch -u https://example.com -e php,html,js,txt,xml,json -w /usr/share/wordlists/dirb/common.txt -t 30",
    "success": true,
    "status": "completed",
    "raw_output": "[20:26:07] 200 -   424B - https://example.com/admin\n[20:26:08] 301 -   169B - https://example.com/backup",
    "error_output": "",
    "return_code": 0,
    "execution_time": null,
    "found_paths": [
      {
        "path": "/admin",
        "status": 200,
        "size": 424
      },
      {
        "path": "/backup",
        "status": 301,
        "size": 169
      }
    ],
    "count": 2
  }
}
```

### Error Response
```json
{
  "success": false,
  "result": {
    "tool": "dirsearch",
    "target": "https://example.com",
    "success": false,
    "status": "failed",
    "error_output": "Error: Unable to connect to target",
    "return_code": 1,
    "found_paths": [],
    "count": 0
  }
}
```

## Found Paths Structure

Each discovered path in the `found_paths` array contains:

- `path`: The discovered directory or file path
- `status`: HTTP status code returned by the server
- `size`: Response size in bytes (converted from KB/MB/GB if necessary)

## Logging

The dirsearch tool uses the centralized logging system defined in `/home/slanycukr/Documents/MCP_servers/bugbounty-mcp-server/src/rest_api_server/logger.py`.

### Log File Location
Logs are stored in: `/home/slanycukr/Documents/MCP_servers/bugbounty-mcp-server/logs/tools.dirsearch.dirsearch.log`

### Log Format
```
YYYY-MM-DD HH:MM:SS,mmm - tools.dirsearch.dirsearch - LEVEL - MESSAGE
```

### Logged Events
- **INFO**: Execution start with target URL
- **ERROR**: Any execution errors or exceptions
- **DEBUG**: Additional debugging information (when DEBUG=true environment variable is set)

### Enable Debug Logging
Set the DEBUG environment variable to enable verbose logging:
```bash
DEBUG=true uv run -m src.rest_api_server
```

## Command Execution Details

The tool constructs and executes dirsearch commands with the following pattern:
```bash
dirsearch -u <url> -e <extensions> -w <wordlist> -t <threads> [-r] [additional_args]
```

Where:
- `-u`: Target URL
- `-e`: File extensions
- `-w`: Wordlist path
- `-t`: Thread count
- `-r`: Recursive flag (if enabled)
- Additional arguments are appended as provided

## Error Handling

The endpoint handles various error scenarios:
- **400 Bad Request**: Missing required `url` parameter
- **500 Internal Server Error**: Command execution failures, parsing errors, or system issues

All errors are logged to the appropriate log file with full stack traces for debugging.
