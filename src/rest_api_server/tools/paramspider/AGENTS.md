# ParamSpider Tool Documentation

## Overview

ParamSpider is a parameter mining tool that extracts GET and POST parameters from web archives for a given domain. This tool is exposed as a REST API endpoint in the Bug Bounty MCP Server for automated parameter discovery during reconnaissance phases.

## API Endpoint

**Path:** `/api/tools/paramspider`
**Method:** POST
**Content-Type:** application/json

## Request Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | Target domain to mine parameters from (e.g., "example.com") |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `stream` | boolean | false | Enable stream mode (-s flag) for real-time output |
| `placeholder` | string | "FUZZ" | Placeholder value for parameters in output |
| `proxy` | string | "" | Proxy configuration (e.g., "http://127.0.0.1:8080") |
| `additional_args` | string | "" | Additional command line arguments as space-separated string |
| `exclude` | string | "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico" | File extensions to exclude (ignored by paramspider but kept for compatibility) |
| `output` | string | "" | Output file path (ignored by paramspider but kept for compatibility) |
| `level` | integer | 2 | Crawl depth level (ignored by paramspider but kept for compatibility) |
| `subs` | boolean | true | Include subdomains (ignored by paramspider but kept for compatibility) |
| `silent` | boolean | false | Silent mode (ignored by paramspider but kept for compatibility) |
| `clean` | boolean | false | Clean mode (ignored by paramspider but kept for compatibility) |

**Note:** Some parameters are kept for compatibility with other tools but are ignored by paramspider. Only `domain`, `stream`, `placeholder`, `proxy`, and `additional_args` are actually used in the paramspider command.

## Request Example

```json
{
    "domain": "example.com",
    "stream": true,
    "placeholder": "FUZZ",
    "proxy": "http://127.0.0.1:8080",
    "additional_args": "--level 3"
}
```

## Response Format

```json
{
    "success": true,
    "result": {
        "tool": "paramspider",
        "target": "example.com",
        "command": "paramspider -d example.com -s -p FUZZ --proxy http://127.0.0.1:8080 --level 3",
        "success": true,
        "return_code": 0,
        "stdout": "Parameter mining results...",
        "stderr": "",
        "error": "",
        "parameters": {
            "domain": "example.com",
            "stream": true,
            "placeholder": "FUZZ",
            "proxy": "http://127.0.0.1:8080",
            "additional_args": "--level 3",
            "exclude": "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico",
            "output": "",
            "level": 2,
            "subs": true,
            "silent": false,
            "clean": false
        }
    }
}
```

## Curl Command Examples

### Basic Usage
```bash
curl -X POST http://127.0.0.1:8888/api/tools/paramspider \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com"
  }'
```

### With Stream Mode and Proxy
```bash
curl -X POST http://127.0.0.1:8888/api/tools/paramspider \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "stream": true,
    "proxy": "http://127.0.0.1:8080",
    "placeholder": "PAYLOAD"
  }'
```

### With Additional Arguments
```bash
curl -X POST http://127.0.0.1:8888/api/tools/paramspider \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "additional_args": "--level 5 --timeout 30"
  }'
```

## Logging

### Log File Location
Logs for the paramspider endpoint are stored in:
```
logs/tools.paramspider.paramspider.log
```

### Log Format
```
YYYY-MM-DD HH:MM:SS,mmm - tools.paramspider.paramspider - LEVEL - MESSAGE
```

### Example Log Entries
```
2025-09-07 10:30:45,123 - tools.paramspider.paramspider - INFO - Executing ParamSpider on example.com
2025-09-07 10:30:45,124 - tools.paramspider.paramspider - INFO - Executing command: paramspider -d example.com -s -p FUZZ
```

### Debug Mode
To enable debug logging, set the `DEBUG` environment variable:
```bash
DEBUG=true uv run -m src.rest_api_server
```

## Command Construction

The tool builds paramspider commands using only supported flags:

- `-d`: Domain (required)
- `-s`: Stream mode (optional)
- `-p`: Placeholder value (optional, defaults to "FUZZ")
- `--proxy`: Proxy configuration (optional)

Additional arguments can be passed via the `additional_args` parameter, which will be appended to the command.

## Execution Details

- **Timeout:** 600 seconds (10 minutes)
- **Command Execution:** Uses the shared `execute_command` utility
- **Error Handling:** Comprehensive error handling with detailed response information
- **Return Codes:** Standard Unix return codes (0 = success, non-zero = error)

## Integration Notes

- The tool is registered with the `@tool` decorator with `required_fields=['domain']`
- Automatic endpoint registration via the registry system
- Consistent error handling and response formatting
- Full logging integration with the server's logging system
