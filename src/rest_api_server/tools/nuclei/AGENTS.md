# Nuclei Tool API Documentation

## Overview

The Nuclei tool provides a REST API endpoint for executing Nuclei vulnerability scanner against target URLs. Nuclei is a fast vulnerability scanner based on simple YAML-based templates.

## API Endpoint

**Path:** `/api/tools/nuclei`
**Method:** `POST`
**Content-Type:** `application/json`

## Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string | Target URL or IP address to scan |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `severity` | string | none | Filter templates by severity (info, low, medium, high, critical) |
| `tags` | string | none | Filter templates by tags (e.g., "xss,sqli") |
| `template` | string | none | Path to custom template file or directory |
| `template_id` | string | none | Filter templates by specific template IDs |
| `exclude_id` | string | none | Exclude specific template IDs from scan |
| `exclude_tags` | string | none | Exclude templates with specific tags |
| `concurrency` | integer | 25 | Number of concurrent requests |
| `timeout` | integer | none | Request timeout in seconds |
| `additional_args` | string | none | Additional command line arguments for nuclei |

## Request Body Example

### Basic Scan
```json
{
  "target": "https://example.com"
}
```

### Advanced Scan with Multiple Parameters
```json
{
  "target": "https://example.com",
  "severity": "high,critical",
  "tags": "xss,sqli",
  "concurrency": 50,
  "timeout": 30,
  "exclude_tags": "intrusive",
  "additional_args": "-rate-limit 100"
}
```

## Response Format

The API returns a JSON response with the following structure:

```json
{
  "success": true,
  "result": {
    "tool": "nuclei",
    "target": "https://example.com",
    "command": "nuclei -u https://example.com -severity high,critical -tags xss,sqli -c 50 -timeout 30 -exclude-tags intrusive -rate-limit 100 -jsonl",
    "success": true,
    "stdout": "nuclei scan results in JSON Lines format...",
    "stderr": "",
    "return_code": 0
  }
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `success` | boolean | Overall API call success status |
| `result.tool` | string | Always "nuclei" |
| `result.target` | string | The target that was scanned |
| `result.command` | string | The actual nuclei command that was executed |
| `result.success` | boolean | Whether the nuclei command executed successfully |
| `result.stdout` | string | Nuclei scan output in JSON Lines format |
| `result.stderr` | string | Error output from nuclei command |
| `result.return_code` | integer | Exit code of the nuclei process |

## cURL Command Examples

### Basic Vulnerability Scan
```bash
curl -X POST http://127.0.0.1:8888/api/tools/nuclei \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com"
  }'
```

### High Severity XSS and SQLi Scan
```bash
curl -X POST http://127.0.0.1:8888/api/tools/nuclei \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "severity": "high,critical",
    "tags": "xss,sqli",
    "concurrency": 50
  }'
```

### Custom Template Scan
```bash
curl -X POST http://127.0.0.1:8888/api/tools/nuclei \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "template": "/path/to/custom-templates/",
    "timeout": 60
  }'
```

### Scan with Exclusions
```bash
curl -X POST http://127.0.0.1:8888/api/tools/nuclei \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "severity": "medium,high,critical",
    "exclude_tags": "intrusive,dos",
    "exclude_id": "CVE-2021-12345,generic-detector"
  }'
```

## Logging

### Log File Location
Nuclei tool execution logs are stored in:
```
logs/src.rest_api_server.tools.nuclei.nuclei.log
```

### Log Entry Format
Logs use the standard format:
```
YYYY-MM-DD HH:MM:SS,mmm - src.rest_api_server.tools.nuclei.nuclei - LEVEL - MESSAGE
```

### Sample Log Entries
```
2025-09-07 10:30:15,123 - src.rest_api_server.tools.nuclei.nuclei - INFO - Executing Nuclei scan on https://example.com
2025-09-07 10:30:15,124 - src.rest_api_server.tools.nuclei.nuclei - ERROR - Error in execute_nuclei: Command 'nuclei' not found
```

### Log Levels
- **INFO**: Successful scan initiation messages
- **ERROR**: Command execution failures, missing dependencies, invalid parameters
- **DEBUG**: Detailed command construction and execution information (when DEBUG=true)

## Error Handling

### Common Error Responses

#### Missing Required Field
```json
{
  "error": "Target is required"
}
```
**HTTP Status:** 400 Bad Request

#### Server Error
```json
{
  "error": "Server error: Command 'nuclei' not found"
}
```
**HTTP Status:** 500 Internal Server Error

#### Invalid JSON
```json
{
  "error": "JSON data is required"
}
```
**HTTP Status:** 400 Bad Request

## Command Construction

The tool builds nuclei commands with the following pattern:
```bash
nuclei -u <target> [options] -jsonl
```

### Option Mapping
- `severity` → `-severity`
- `tags` → `-tags`
- `template` → `-t`
- `template_id` → `-template-id`
- `exclude_id` → `-exclude-id`
- `exclude_tags` → `-exclude-tags`
- `concurrency` → `-c` (only if different from default 25)
- `timeout` → `-timeout`
- `additional_args` → parsed and appended as individual arguments

The `-jsonl` flag is always added to ensure structured output format.

## Notes

- Default concurrency is set to 25 to balance speed and resource usage
- Default timeout is 600 seconds for the entire scan execution
- Output is always in JSON Lines format for easier parsing
- The tool requires nuclei to be installed and accessible in the system PATH
- Large scan results may be truncated in the response; check logs for complete output
