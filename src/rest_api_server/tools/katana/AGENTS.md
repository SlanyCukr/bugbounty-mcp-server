# Katana Tool API Documentation

## Overview
The Katana tool provides next-generation crawling and spidering capabilities for bug bounty hunting. It exposes a comprehensive REST API endpoint that allows you to configure and execute katana commands with extensive customization options.

## REST API Endpoint

**Path:** `/api/tools/katana`
**Method:** `POST`
**Content-Type:** `application/json`

## Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string | **Required.** Target URL to crawl and spider |

### Optional Parameters

#### Core Crawling Configuration
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `depth` | integer | `3` | Maximum depth to crawl |
| `concurrency` | integer | `10` | Number of concurrent requests |
| `parallelism` | integer | `10` | Number of parallel operations |
| `max_pages` | integer | `100` | Maximum number of pages to crawl |
| `crawl_duration` | integer | `0` | Maximum crawl duration in seconds (0 = unlimited) |
| `delay` | integer | `0` | Delay between requests in milliseconds |

#### Crawling Behavior
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `js_crawl` | boolean | `true` | Enable JavaScript crawling |
| `form_extraction` | boolean | `true` | Enable form extraction |
| `output_format` | string | `"json"` | Output format (json/text) |

#### Scope Control
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scope` | string | `""` | Crawling scope regex pattern |
| `out_of_scope` | string | `""` | Out-of-scope regex pattern |
| `field_scope` | string | `""` | Field scope pattern |
| `no_scope` | boolean | `false` | Disable scoping |
| `display_out_scope` | boolean | `false` | Display out-of-scope URLs |

#### Authentication & Headers
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `headers` | string | `""` | Custom headers (format: "Header: Value") |
| `cookies` | string | `""` | Custom cookies |
| `user_agent` | string | `""` | Custom user agent |
| `proxy` | string | `""` | Proxy URL |

#### Chrome Browser Options
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `system_chrome` | boolean | `false` | Use system Chrome instead of bundled |
| `headless` | boolean | `true` | Run Chrome in headless mode |
| `no_incognito` | boolean | `false` | Disable incognito mode |
| `chrome_data_dir` | string | `""` | Chrome data directory path |
| `show_source` | boolean | `false` | Show page source |
| `show_browser` | boolean | `false` | Show browser window |

#### Network & Retry Configuration
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `timeout` | integer | `10` | Request timeout in seconds |
| `retry` | integer | `1` | Number of retries |
| `retry_wait` | integer | `1` | Wait time between retries |

#### Filtering Options
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filter_regex` | string | `""` | Filter results by regex |
| `match_regex` | string | `""` | Match results by regex |
| `extension_filter` | string | `""` | Filter by file extensions |
| `mime_filter` | string | `""` | Filter by MIME types |

#### Output Configuration
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `output_file` | string | `""` | Output file path |
| `store_response` | boolean | `false` | Store response bodies |
| `store_response_dir` | string | `""` | Directory to store responses |

#### Advanced Options
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `additional_args` | string | `""` | Additional command line arguments |

## Example Usage

### Basic Crawling
```bash
curl -X POST http://127.0.0.1:8888/api/tools/katana \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com"
  }'
```

### Advanced Crawling Configuration
```bash
curl -X POST http://127.0.0.1:8888/api/tools/katana \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "depth": 5,
    "js_crawl": true,
    "form_extraction": true,
    "max_pages": 200,
    "concurrency": 15,
    "headers": "Authorization: Bearer token123",
    "scope": "https://example.com/*",
    "output_format": "json",
    "timeout": 30
  }'
```

### With Proxy and Custom User Agent
```bash
curl -X POST http://127.0.0.1:8888/api/tools/katana \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://target-site.com",
    "proxy": "http://proxy.example.com:8080",
    "user_agent": "Mozilla/5.0 (Custom Bot)",
    "delay": 1000,
    "retry": 3,
    "output_file": "/tmp/katana_results.json"
  }'
```

## Response Format

### Successful Response
```json
{
  "success": true,
  "result": {
    "tool": "katana",
    "target": "https://example.com",
    "parameters": {
      "url": "https://example.com",
      "depth": 3,
      "js_crawl": true,
      "form_extraction": true,
      "output_format": "json",
      ...
    },
    "command": "katana -u https://example.com -jc -fx -jsonl",
    "status": "completed",
    "stdout": "[katana output...]",
    "stderr": "",
    "return_code": 0,
    "execution_success": true,
    "raw_output": "[raw katana output...]"
  }
}
```

### Error Response
```json
{
  "success": true,
  "result": {
    "tool": "katana",
    "target": "https://example.com",
    "parameters": {...},
    "command": "katana -u https://example.com",
    "status": "failed",
    "stdout": "",
    "stderr": "[error output...]",
    "return_code": 1,
    "execution_success": false,
    "error": "Command execution failed"
  }
}
```

## Logging

### Log File Location
Logs for the katana tool are stored in:
```
logs/tools.katana.katana.log
```

### Log Content
The log file contains:
- Tool execution start/completion messages
- Full katana command being executed
- Execution parameters and results
- Error messages and debugging information

### Log Format
```
YYYY-MM-DD HH:MM:SS,mmm - tools.katana.katana - LEVEL - MESSAGE
```

### Example Log Entries
```
2025-09-07 10:30:15,123 - tools.katana.katana - INFO - Executing Katana on https://example.com
2025-09-07 10:30:15,124 - tools.katana.katana - INFO - Executing Katana command: katana -u https://example.com -jc -fx -jsonl
```

## Command Line Mapping

The tool dynamically builds katana commands based on provided parameters:

| Parameter | Katana Flag | Notes |
|-----------|-------------|-------|
| `url` | `-u` | Always included |
| `depth` | `-d` | Only if different from default (3) |
| `concurrency` | `-c` | Only if different from default (10) |
| `parallelism` | `-p` | Only if different from default (10) |
| `js_crawl` | `-jc` | Only if true |
| `form_extraction` | `-fx` | Only if true |
| `max_pages` | `-kf` | Only if > 0 |
| `crawl_duration` | `-ct` | Only if > 0 |
| `delay` | `-delay` | Only if > 0 |
| `output_format` == "json" | `-jsonl` | For JSON output |
| `scope` | `-cs` | Only if provided |
| `headers` | `-H` | Only if provided |
| `proxy` | `-proxy` | Only if provided |
| `timeout` | `-timeout` | Only if different from default (10) |
| `output_file` | `-o` | Only if provided |

## Error Handling

The endpoint provides comprehensive error handling:
- **400 Bad Request**: Missing required `url` parameter
- **500 Internal Server Error**: Command execution failures, invalid parameters, or system errors
- All errors are logged to the log file with detailed information

## Security Considerations

- The tool executes system commands, so input validation is crucial
- URL parameter should be validated before execution
- Consider rate limiting for production deployments
- Log files may contain sensitive information from crawled sites
