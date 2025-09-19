# DIRB Tool API Documentation

## Overview
The DIRB tool provides a REST API endpoint for executing DIRB directory and file brute-force scanning. DIRB is a web content scanner that looks for existing (and/or hidden) web objects by launching dictionary-based attacks against web servers.

## API Endpoint

### Path
```
POST /api/tools/dirb
```

### Parameters

The endpoint accepts a JSON payload with the following parameters:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `url` | string | **Yes** | - | Target URL to scan (e.g., "https://example.com") |
| `wordlist` | string | No | "/usr/share/wordlists/dirb/common.txt" | Path to wordlist file for directory/file names |
| `extensions` | string | No | "" | File extensions to append to wordlist entries (e.g., ".php,.html,.txt") |
| `recursive` | boolean | No | false | Enable recursive scanning of found directories |
| `ignore_case` | boolean | No | false | Perform case-insensitive search |
| `user_agent` | string | No | "" | Custom User-Agent string for requests |
| `headers` | string | No | "" | Custom HTTP headers (format: "Header: Value") |
| `cookies` | string | No | "" | HTTP cookies to include in requests |
| `proxy` | string | No | "" | HTTP proxy to use (format: "host:port") |
| `auth` | string | No | "" | HTTP authentication (format: "username:password") |
| `delay` | string | No | "" | Delay between requests in milliseconds |
| `additional_args` | string | No | "" | Additional command-line arguments for dirb |

### Example Request Body
```json
{
  "url": "https://example.com",
  "wordlist": "/usr/share/wordlists/dirb/common.txt",
  "extensions": ".php,.html,.txt",
  "recursive": true,
  "ignore_case": false,
  "user_agent": "Mozilla/5.0 (compatible; DirectoryScanner)",
  "headers": "X-Custom-Header: Testing",
  "delay": "100"
}
```

## cURL Command Example

### Basic Scan
```bash
curl -X POST http://127.0.0.1:8888/api/tools/dirb \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com"
  }'
```

### Advanced Scan with Custom Parameters
```bash
curl -X POST http://127.0.0.1:8888/api/tools/dirb \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "wordlist": "/usr/share/wordlists/dirb/big.txt",
    "extensions": ".php,.html,.txt,.js",
    "recursive": true,
    "user_agent": "Mozilla/5.0 (compatible; DirectoryScanner)",
    "delay": "50"
  }'
```

### Scan with Authentication and Proxy
```bash
curl -X POST http://127.0.0.1:8888/api/tools/dirb \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "auth": "admin:password",
    "proxy": "127.0.0.1:8080",
    "headers": "Authorization: Bearer token123"
  }'
```

## Response Format

### Success Response
```json
{
  "success": true,
  "result": {
    "tool": "dirb",
    "target": "https://example.com",
    "command": "dirb https://example.com /usr/share/wordlists/dirb/common.txt -N",
    "success": true,
    "stdout": "DIRB v2.22 output...",
    "stderr": "",
    "return_code": 0,
    "parameters": {
      "url": "https://example.com",
      "wordlist": "/usr/share/wordlists/dirb/common.txt",
      "extensions": "",
      "recursive": false,
      "ignore_case": false,
      "user_agent": "",
      "headers": "",
      "cookies": "",
      "proxy": "",
      "auth": "",
      "delay": "",
      "additional_args": ""
    }
  }
}
```

### Error Response
```json
{
  "error": "Url is required"
}
```

## Logging

### Log Location
Tool execution logs are stored in:
```
logs/tools.dirb.dirb.log
```

### Log Format
Logs follow the format: `timestamp - module_name - log_level - message`

Example log entries:
```
2025-09-07 10:30:15,123 - tools.dirb.dirb - INFO - Executing DIRB scan on https://example.com
2025-09-07 10:30:15,124 - utils.registry - INFO - Processing request for tool: dirb
```

## Command Line Execution

The tool executes DIRB with the following command structure:
```bash
dirb <URL> <WORDLIST> [OPTIONS]
```

### Common Options Used:
- `-X <extensions>`: File extensions to append
- `-r`: Recursive scanning
- `-z`: Case-insensitive search
- `-N`: Non-interactive mode (always enabled)
- `-a <user-agent>`: Custom User-Agent
- `-H <headers>`: Custom headers
- `-c <cookies>`: HTTP cookies
- `-p <proxy>`: HTTP proxy
- `-u <auth>`: HTTP authentication
- `-l <delay>`: Delay between requests

## Timeout Configuration

The DIRB tool has a default timeout of 600 seconds (10 minutes) for scan execution. Long-running scans may be terminated if they exceed this timeout.

## Security Notes

- The tool runs in non-interactive mode (`-N` flag) to prevent hanging on prompts
- All user inputs are validated and sanitized before execution
- The tool respects standard HTTP authentication and proxy configurations
- Custom wordlists can be specified but must be accessible on the server filesystem
