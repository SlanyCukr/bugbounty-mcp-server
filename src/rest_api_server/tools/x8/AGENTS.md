# X8 Tool API Documentation

## Overview
The X8 tool is a hidden parameter discovery tool exposed through a REST API endpoint. It uses the `x8` command-line tool to discover hidden parameters in web applications by fuzzing various HTTP methods and parameter locations.

## API Endpoint

### Path
```
POST /api/tools/x8
```

### Base URL
- **Default**: `http://127.0.0.1:8888/api/tools/x8`
- **Configurable via environment variables**:
  - `BUGBOUNTY_MCP_HOST`: Host address (default: 127.0.0.1)
  - `BUGBOUNTY_MCP_PORT`: Port number (default: 8888)

## Parameters

### Required Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string | Target URL to scan for hidden parameters |

### Optional Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `wordlist` | string | `/usr/share/wordlists/x8/params.txt` | Path to wordlist file for parameter names |
| `method` | string | `GET` | HTTP method to use (GET, POST, PUT, PATCH, DELETE) |
| `body` | string | `""` | Request body data for POST/PUT requests |
| `headers` | string/dict | `""` | HTTP headers (string format: "header:value" or dict format) |
| `output_file` | string | `""` | File path to save results |
| `discover` | boolean | `true` | Enable parameter discovery mode |
| `learn` | boolean | `false` | Enable learning mode |
| `verify` | boolean | `true` | Enable parameter verification |
| `max` | integer | `0` | Maximum parameters per request (0 = no limit) |
| `workers` | integer | `25` | Number of concurrent workers |
| `as_body` | boolean | `false` | Test parameters in request body instead of URL |
| `encode` | boolean | `false` | Enable URL encoding |
| `force` | boolean | `false` | Force scan even if target seems unresponsive |
| `additional_args` | string | `""` | Additional command-line arguments for x8 |

## Request Example

### Basic Usage
```bash
curl -X POST http://127.0.0.1:8888/api/tools/x8 \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/login"
  }'
```

### Advanced Usage with Custom Parameters
```bash
curl -X POST http://127.0.0.1:8888/api/tools/x8 \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/api/endpoint",
    "method": "POST",
    "wordlist": "/custom/wordlist.txt",
    "headers": {
      "Authorization": "Bearer token123",
      "User-Agent": "Custom-Agent/1.0"
    },
    "body": "existing_param=value",
    "workers": 50,
    "verify": true,
    "max": 10,
    "output_file": "/tmp/x8_results.txt"
  }'
```

### Headers as String Format
```bash
curl -X POST http://127.0.0.1:8888/api/tools/x8 \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/search",
    "headers": "Authorization:Bearer token123",
    "method": "GET",
    "workers": 30
  }'
```

## Response Format

### Successful Response
```json
{
  "success": true,
  "result": {
    "tool": "x8",
    "target": "https://example.com/login",
    "parameters": {
      "url": "https://example.com/login",
      "wordlist": "/usr/share/wordlists/x8/params.txt",
      "method": "GET",
      "body": "",
      "headers": "",
      "output_file": "",
      "discover": true,
      "learn": false,
      "verify": true,
      "max": 0,
      "workers": 25,
      "as_body": false,
      "encode": false,
      "force": false,
      "additional_args": ""
    },
    "command_executed": "x8 -u 'https://example.com/login' -X GET -w '/usr/share/wordlists/x8/params.txt' -c 25 --verify",
    "status": "completed",
    "raw_output": "...",
    "stderr": "",
    "return_code": 0,
    "execution_time": "45.2s",
    "discovered_parameters": [
      {
        "raw_line": "GET https://example.com/login?debug=1 [200]",
        "method": "GET",
        "name": "debug",
        "confidence": "unknown"
      }
    ],
    "parameter_count": 1,
    "parameter_lines": ["GET https://example.com/login?debug=1 [200]"]
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
Logs for the X8 tool are stored in:
```
logs/tools.x8.x8.log
```

### Log Content
The logger captures:
- Tool execution start/end events
- Command being executed
- Parameter parsing warnings
- Any errors during execution

### Log Format
```
YYYY-MM-DD HH:MM:SS,mmm - tools.x8.x8 - LEVEL - MESSAGE
```

### Example Log Entries
```
2025-09-07 10:15:32,123 - tools.x8.x8 - INFO - Executing x8 on https://example.com/login
2025-09-07 10:15:32,124 - tools.x8.x8 - INFO - Executing x8 command: x8 -u 'https://example.com/login' -X GET -w '/usr/share/wordlists/x8/params.txt' -c 25 --verify
2025-09-07 10:16:17,456 - tools.x8.x8 - WARNING - Error parsing parameter line 'malformed output': Invalid format
```

## Command Execution Details

### Timeout
- **Default**: 600 seconds (10 minutes)
- The tool will terminate if x8 execution exceeds this timeout

### Security Features
- All user inputs are properly escaped using `shlex.quote()`
- Command injection protection through parameter sanitization
- Structured parameter validation

### Output Processing
The tool attempts to parse x8 output to extract discovered parameters by:
1. Looking for lines containing HTTP methods and parameter patterns
2. Extracting parameter names from lines with `=` characters
3. Identifying HTTP methods (GET, POST, PUT, PATCH, DELETE)
4. Providing both structured data and raw output for manual inspection

## Environment Configuration

### Debug Mode
Enable detailed logging by setting:
```bash
DEBUG=true uv run -m src.rest_api_server
```

### Custom Server Configuration
```bash
BUGBOUNTY_MCP_HOST=0.0.0.0 BUGBOUNTY_MCP_PORT=9999 uv run -m src.rest_api_server
```
