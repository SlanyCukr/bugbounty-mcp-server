# Gobuster Tool API Documentation

This document provides comprehensive information about the Gobuster tool REST API endpoint in the Bug Bounty MCP Server.

## Overview

Gobuster is a directory/file brute forcer written in Go. This API endpoint provides a unified interface to execute Gobuster in different modes (directory enumeration, DNS subdomain discovery, virtual host discovery, and fuzzing) and returns structured results.

## API Endpoint

**Path:** `/api/tools/gobuster`
**Method:** `POST`
**Content-Type:** `application/json`

## Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string | Target URL or domain to scan |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `mode` | string | `"dir"` | Gobuster mode: `"dir"`, `"dns"`, `"vhost"`, or `"fuzz"` |
| `wordlist` | string | `"/usr/share/wordlists/dirb/common.txt"` | Path to wordlist file |
| `extensions` | string | `""` | File extensions to search for (dir mode only), e.g., `"php,html,txt"` |
| `threads` | integer | `10` | Number of concurrent threads |
| `timeout` | string | `"10s"` | Request timeout (e.g., "10s", "30s", "1m") |
| `user_agent` | string | `""` | Custom User-Agent string |
| `cookies` | string | `""` | Cookies to use in requests |
| `status_codes` | string | `""` | Comma-separated list of status codes to include |
| `additional_args` | string | `""` | Additional command-line arguments |

### Parameter Details

#### Mode-Specific Behavior
- **`dir`**: Directory/file enumeration using `-u` flag
- **`dns`**: DNS subdomain discovery using `-d` flag
- **`vhost`**: Virtual host discovery using `-u` flag
- **`fuzz`**: Fuzzing mode using `-u` flag

#### Extensions Parameter
Only applies to `dir` mode. Specify file extensions without dots, separated by commas:
```json
{
  "extensions": "php,html,txt,js"
}
```

#### Status Codes Parameter
Filter results by HTTP status codes:
```json
{
  "status_codes": "200,301,302,403"
}
```

## Request Examples

### Directory Enumeration
```bash
curl -X POST http://127.0.0.1:8888/api/tools/gobuster \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "mode": "dir",
    "extensions": "php,html,txt",
    "threads": 20,
    "wordlist": "/usr/share/wordlists/dirb/big.txt"
  }'
```

### DNS Subdomain Discovery
```bash
curl -X POST http://127.0.0.1:8888/api/tools/gobuster \
  -H "Content-Type: application/json" \
  -d '{
    "url": "example.com",
    "mode": "dns",
    "wordlist": "/usr/share/wordlists/dnsrecon/subdomains-top1mil-5000.txt",
    "threads": 50
  }'
```

### Virtual Host Discovery
```bash
curl -X POST http://127.0.0.1:8888/api/tools/gobuster \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "mode": "vhost",
    "wordlist": "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
  }'
```

### Fuzzing Mode
```bash
curl -X POST http://127.0.0.1:8888/api/tools/gobuster \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/FUZZ",
    "mode": "fuzz",
    "wordlist": "/usr/share/wordlists/wfuzz/general/common.txt",
    "status_codes": "200,301,302"
  }'
```

## Response Format

### Success Response
```json
{
  "success": true,
  "result": {
    "tool": "gobuster",
    "target": "https://example.com",
    "mode": "dir",
    "parameters": {
      "url": "https://example.com",
      "mode": "dir",
      "wordlist": "/usr/share/wordlists/dirb/common.txt",
      "extensions": "php,html",
      "threads": 10,
      "timeout": "10s",
      "user_agent": "",
      "cookies": "",
      "status_codes": "",
      "additional_args": ""
    },
    "command": "gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -x php,html -t 10 --timeout 10s",
    "raw_output": "...",
    "stderr": "",
    "return_code": 0,
    "success": true,
    "discovered_items": [
      {
        "path": "/admin",
        "status": 301,
        "size": 178,
        "redirect": "https://example.com/admin/"
      },
      {
        "path": "/login.php",
        "status": 200,
        "size": 2456
      }
    ],
    "total_found": 2
  }
}
```

### Discovered Items Structure

#### Directory Mode (`dir`)
```json
{
  "path": "/admin",
  "status": 301,
  "size": 178,
  "redirect": "https://example.com/admin/" // optional
}
```

#### DNS Mode (`dns`)
```json
{
  "subdomain": "mail.example.com",
  "record_type": "A" // or "CNAME", etc.
}
```

#### Virtual Host Mode (`vhost`)
```json
{
  "vhost": "admin.example.com",
  "status": 200,
  "size": 1234
}
```

#### Fuzz Mode (`fuzz`)
```json
{
  "path": "/test=admin",
  "status": 200,
  "size": 1234
}
```

### Error Response
```json
{
  "error": "Invalid mode: invalid. Must be one of: dir, dns, fuzz, vhost"
}
```

## Logging

### Log File Location
Logs for the gobuster tool are stored in:
```
/home/slanycukr/Documents/MCP_servers/bugbounty-mcp-server/logs/tools.gobuster.gobuster.log
```

### Log Format
```
2025-09-07 10:30:15,123 - tools.gobuster.gobuster - INFO - Executing Gobuster dir scan on https://example.com
```

### Debug Mode
To enable debug logging, set the `DEBUG` environment variable to `true`:
```bash
DEBUG=true uv run src/server.py
```

In debug mode, additional detailed logs will be written to both stdout and the log file.

## Command Execution

The tool builds and executes gobuster commands with the following structure:

### Directory Mode
```bash
gobuster dir -u <url> -w <wordlist> [-x <extensions>] -t <threads> --timeout <timeout> [additional options]
```

### DNS Mode
```bash
gobuster dns -d <domain> -w <wordlist> -t <threads> --timeout <timeout> [additional options]
```

### Virtual Host Mode
```bash
gobuster vhost -u <url> -w <wordlist> -t <threads> --timeout <timeout> [additional options]
```

### Fuzz Mode
```bash
gobuster fuzz -u <url> -w <wordlist> -t <threads> --timeout <timeout> [additional options]
```

## Error Handling

The API handles various error conditions:

1. **Missing Required Fields**: Returns 400 with field validation error
2. **Invalid Mode**: Returns 400 with valid mode options
3. **Command Execution Errors**: Returns 500 with error details
4. **Timeout**: Command execution has a default timeout of 600 seconds

## Usage Tips

1. **Wordlist Selection**: Choose appropriate wordlists based on your target
2. **Thread Tuning**: Adjust threads based on target capacity (start with 10-20)
3. **Extensions**: For directory enumeration, include common web file extensions
4. **Status Code Filtering**: Use status codes to filter out noise (e.g., exclude 404s)
5. **DNS Mode**: Use domain name without protocol (e.g., "example.com" not "https://example.com")

## Security Considerations

- Only use this tool against targets you have permission to test
- Be mindful of thread count to avoid overwhelming target servers
- Consider using custom User-Agent strings to identify your testing
- Monitor log files for debugging and audit trails
