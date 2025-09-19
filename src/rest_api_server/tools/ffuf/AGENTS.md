# FFuf Tool API Documentation

## Overview

FFuf (Fuzz Faster U Fool) is a fast web fuzzer used for directory and file discovery. This tool is exposed as a REST API endpoint that allows comprehensive web fuzzing with extensive filtering and customization options.

## API Endpoint

**Path:** `/api/tools/ffuf`
**Method:** `POST`
**Content-Type:** `application/json`

## Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string | **Required.** Target URL to fuzz. If "FUZZ" keyword is not present, it will be automatically appended to the URL for directory fuzzing |

### Optional Parameters

#### Wordlists
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `wordlist` | string | `/usr/share/wordlists/dirb/common.txt` | Primary wordlist file path |
| `secondary_wordlist` | string | `""` | Secondary wordlist for multi-wordlist fuzzing |

#### Extensions
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `extensions` | string | `""` | Comma-separated list of file extensions to append (e.g., "php,html,txt") |
| `force_extensions` | boolean | `false` | Force extensions (not used in current implementation) |
| `exclude_extensions` | string | `""` | Extensions to exclude (not used in current implementation) |
| `prefixes` | string | `""` | Prefixes to add (not used in current implementation) |
| `suffixes` | string | `""` | Suffixes to add (not used in current implementation) |

#### Status Code Filtering
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `include_status` | string | `"200,204,301,302,307,401,403,500"` | Comma-separated HTTP status codes to include |
| `exclude_status` | string | `""` | Comma-separated HTTP status codes to exclude |

#### Size Filtering
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `include_size` | string | `""` | Response size(s) to include |
| `exclude_size` | string | `""` | Response size(s) to exclude |

#### Word Count Filtering
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `include_words` | string | `""` | Word count(s) to include |
| `exclude_words` | string | `""` | Word count(s) to exclude |

#### Line Count Filtering
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `include_lines` | string | `""` | Line count(s) to include |
| `exclude_lines` | string | `""` | Line count(s) to exclude |

#### Regex Filtering
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `include_regex` | string | `""` | Regex pattern for responses to include |
| `exclude_regex` | string | `""` | Regex pattern for responses to exclude |

#### Performance Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `threads` | integer | `40` | Number of concurrent threads (capped at 200 max) |
| `delay` | string | `""` | Delay between requests (e.g., "0.1s", "100ms") |
| `rate_limit` | string | `""` | Rate limit requests per second |
| `timeout` | integer | `10` | Request timeout in seconds (also used as command timeout multiplied by 60) |

#### HTTP Options
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `method` | string | `"GET"` | HTTP method (GET, POST, PUT, DELETE, etc.) |
| `headers` | string/array | `""` | HTTP headers. Can be string with semicolon-separated headers or array of header strings |
| `cookies` | string | `""` | HTTP cookies string |
| `proxy` | string | `""` | Proxy server (e.g., "http://127.0.0.1:8080") |

#### Recursion Options
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `recursion` | boolean | `false` | Enable recursive directory discovery |
| `recursion_depth` | integer | `1` | Maximum recursion depth |

#### Additional Options
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `additional_args` | string | `""` | Additional ffuf command-line arguments (space-separated) |

## Example cURL Command

### Basic Directory Fuzzing
```bash
curl -X POST http://127.0.0.1:8888/api/tools/ffuf \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "wordlist": "/usr/share/wordlists/dirb/common.txt",
    "threads": 50,
    "timeout": 30
  }'
```

### Advanced Fuzzing with Filters
```bash
curl -X POST http://127.0.0.1:8888/api/tools/ffuf \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/FUZZ",
    "wordlist": "/usr/share/wordlists/dirb/big.txt",
    "extensions": "php,html,txt,js",
    "include_status": "200,301,302,403",
    "exclude_size": "1234,5678",
    "threads": 100,
    "headers": "User-Agent: MyFuzzer/1.0;X-Forwarded-For: 127.0.0.1",
    "method": "GET",
    "timeout": 60,
    "recursion": true,
    "recursion_depth": 2
  }'
```

### POST Request Fuzzing with Cookies
```bash
curl -X POST http://127.0.0.1:8888/api/tools/ffuf \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/api/FUZZ",
    "wordlist": "/usr/share/wordlists/seclists/Discovery/Web-Content/api/objects.txt",
    "method": "POST",
    "headers": ["Content-Type: application/json", "Authorization: Bearer token123"],
    "cookies": "session=abc123; csrf=xyz789",
    "include_status": "200,201,400,401,403,500",
    "threads": 25,
    "delay": "100ms"
  }'
```

## Response Format

The API returns a JSON response with the following structure:

```json
{
  "success": true,
  "result": {
    "tool": "ffuf",
    "target": "https://example.com",
    "parameters": {
      "url": "https://example.com",
      "wordlist": "/usr/share/wordlists/dirb/common.txt",
      "threads": 50,
      ...
    },
    "command": "ffuf -u \"https://example.com/FUZZ\" -w /usr/share/wordlists/dirb/common.txt -mc 200,204,301,302,307,401,403,500 -t 50 -s",
    "success": true,
    "stdout": "ffuf output...",
    "stderr": "",
    "return_code": 0,
    "status": "completed",
    "timestamp": "2025-09-07T10:30:45.123456"
  }
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `success` | boolean | Overall API call success |
| `result.tool` | string | Tool name ("ffuf") |
| `result.target` | string | Target URL that was fuzzed |
| `result.parameters` | object | All parameters used for the ffuf execution |
| `result.command` | string | Complete ffuf command that was executed |
| `result.success` | boolean | Whether the ffuf command executed successfully |
| `result.stdout` | string | Standard output from ffuf command |
| `result.stderr` | string | Standard error output from ffuf command |
| `result.return_code` | integer | Exit code from ffuf command |
| `result.status` | string | Execution status ("completed" or "failed") |
| `result.timestamp` | string | ISO timestamp of execution |
| `result.error` | string | Error message (only present when success is false) |

## Logging

FFuf execution logs are stored in:
**File Path:** `/logs/tools.ffuf.ffuf.log`

The log file contains:
- Info level logs for ffuf execution starts
- Error level logs for any execution failures
- Detailed execution parameters and results
- Timestamps for all operations

Log format:
```
2025-09-07 10:30:45,123 - tools.ffuf.ffuf - INFO - Executing FFuf on https://example.com
```

## Notes

- The tool automatically adds "FUZZ" keyword to URLs if not present
- Thread count is automatically capped at 200 for performance reasons
- Silent mode (-s) is always enabled for cleaner output
- Command timeout is calculated as `timeout parameter * 60` seconds
- Headers can be provided as either a semicolon-separated string or an array
- Extensions are automatically prefixed with "." if not provided
- The tool uses the execute_command utility which handles process execution and timeout management
