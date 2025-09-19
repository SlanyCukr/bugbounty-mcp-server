# Wfuzz Tool API Documentation

## Overview

The Wfuzz tool provides web application fuzzing capabilities through a REST API endpoint. It executes the `wfuzz` command-line tool with configurable parameters for discovering hidden directories, files, and parameters on web applications.

## API Endpoint

**Path:** `/api/tools/wfuzz`
**Method:** POST
**Content-Type:** application/json

## Parameters

The endpoint accepts the following JSON parameters:

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string | **Required.** Target URL to fuzz. If no FUZZ parameter is present, it will be appended to the URL |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `wordlist` | string | `/usr/share/wordlists/dirb/common.txt` | Path to wordlist file for fuzzing |
| `fuzz_parameter` | string | `FUZZ` | Parameter placeholder in URL to be replaced by wordlist entries |
| `hide_codes` | string | `404` | HTTP response codes to hide from results (comma-separated) |
| `show_codes` | string | `""` | HTTP response codes to show in results (comma-separated) |
| `threads` | integer | `10` | Number of concurrent threads to use |
| `follow_redirects` | boolean | `false` | Whether to follow HTTP redirects |
| `additional_args` | string | `""` | Additional wfuzz command-line arguments |
| `timeout` | integer | `300` | Execution timeout in seconds |

## Request Example

### Basic Directory Fuzzing
```bash
curl -X POST http://127.0.0.1:8888/api/tools/wfuzz \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/FUZZ"
  }'
```

### Advanced Fuzzing with Custom Parameters
```bash
curl -X POST http://127.0.0.1:8888/api/tools/wfuzz \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/admin/FUZZ",
    "wordlist": "/usr/share/wordlists/dirb/big.txt",
    "hide_codes": "404,403",
    "show_codes": "200,301,302",
    "threads": 20,
    "follow_redirects": true,
    "additional_args": "--hh 1234",
    "timeout": 600
  }'
```

### Parameter Fuzzing
```bash
curl -X POST http://127.0.0.1:8888/api/tools/wfuzz \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/search.php?q=FUZZ",
    "wordlist": "/usr/share/wordlists/wfuzz/general/common.txt",
    "fuzz_parameter": "FUZZ",
    "hide_codes": "404"
  }'
```

## Response Format

The API returns a JSON response with the following structure:

```json
{
  "success": true,
  "result": {
    "tool": "wfuzz",
    "target": "https://example.com/FUZZ",
    "command": "wfuzz -w /usr/share/wordlists/dirb/common.txt -t 10 --hc 404 'https://example.com/FUZZ'",
    "parameters": {
      "url": "https://example.com/FUZZ",
      "wordlist": "/usr/share/wordlists/dirb/common.txt",
      "fuzz_parameter": "FUZZ",
      "hide_codes": "404",
      "show_codes": "",
      "threads": 10,
      "follow_redirects": false,
      "additional_args": "",
      "timeout": 300
    },
    "execution": {
      "success": true,
      "return_code": 0,
      "stdout": "...",
      "stderr": ""
    },
    "timestamp": "2025-09-07T10:30:45.123456"
  }
}
```

## URL Handling

The tool intelligently handles the FUZZ parameter placement:

1. **If URL contains FUZZ parameter**: Uses the URL as-is
2. **If URL ends with `/`**: Appends the fuzz_parameter (default: "FUZZ")
3. **If URL doesn't end with `/`**: Appends `/{fuzz_parameter}`

Examples:
- `https://example.com/FUZZ` → `https://example.com/FUZZ`
- `https://example.com/admin/` → `https://example.com/admin/FUZZ`
- `https://example.com/admin` → `https://example.com/admin/FUZZ`

## Logging

### Log Location
Wfuzz execution logs are stored in:
```
logs/tools.wfuzz.wfuzz.log
```

### Log Content
The logs include:
- Execution start messages with target URL
- Complete wfuzz command being executed
- Error messages if execution fails
- Timestamps for all operations

### Log Format
```
2025-09-07 10:30:45,123 - tools.wfuzz.wfuzz - INFO - Executing Wfuzz on https://example.com/FUZZ
2025-09-07 10:30:45,124 - tools.wfuzz.wfuzz - INFO - Wfuzz command: wfuzz -w /usr/share/wordlists/dirb/common.txt -t 10 --hc 404 'https://example.com/FUZZ'
```

## Error Handling

The endpoint provides comprehensive error handling:

### 400 Bad Request
- Missing required `url` parameter
- Invalid JSON payload

### 500 Internal Server Error
- Command execution failures
- System errors
- Timeout exceeded

Example error response:
```json
{
  "error": "Url is required"
}
```

## Environment Configuration

The server can be configured using environment variables:

- `BUGBOUNTY_MCP_HOST`: Server host (default: 127.0.0.1)
- `BUGBOUNTY_MCP_PORT`: Server port (default: 8888)
- `DEBUG`: Enable debug mode (default: false)

## Notes

- Ensure the `wfuzz` tool is installed and available in the system PATH
- Default wordlists assume a standard Kali Linux installation
- Large wordlists may require longer timeout values
- Monitor system resources when using high thread counts
- Use appropriate hide/show codes to filter relevant results
