# Jaeles Tool - REST API Documentation

## Overview

The Jaeles tool provides a REST API endpoint for advanced vulnerability scanning using custom signatures. Jaeles is a powerful web application security scanner that uses signature-based detection to identify vulnerabilities.

## API Endpoint

**Path:** `/api/tools/jaeles`
**Method:** POST
**Content-Type:** application/json

## Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string | Target URL to scan (required) |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `signatures` | string | "" | Path to signature files or signature patterns |
| `config` | string | "" | Configuration file path |
| `threads` | integer | 20 | Number of concurrent threads |
| `timeout` | integer | 20 | Request timeout in seconds |
| `level` | string | "" | Signature level filter |
| `passive` | boolean | false | Enable passive scanning mode |
| `output_file` | string | "" | Output file path for results |
| `proxy` | string | "" | Proxy server (e.g., http://127.0.0.1:8080) |
| `headers` | string | "" | Custom HTTP headers |
| `verbose` | boolean | false | Enable verbose output |
| `debug` | boolean | false | Enable debug mode |
| `additional_args` | string | "" | Additional command-line arguments |

## Example Usage

### Basic Scan

```bash
curl -X POST http://127.0.0.1:8888/api/tools/jaeles \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com"
  }'
```

### Advanced Scan with Custom Signatures

```bash
curl -X POST http://127.0.0.1:8888/api/tools/jaeles \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "signatures": "/path/to/custom/signatures",
    "threads": 50,
    "timeout": 30,
    "verbose": true,
    "output_file": "/tmp/jaeles_results.json"
  }'
```

### Scan with Proxy and Custom Headers

```bash
curl -X POST http://127.0.0.1:8888/api/tools/jaeles \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://target.com",
    "proxy": "http://127.0.0.1:8080",
    "headers": "Authorization: Bearer token123",
    "level": "critical",
    "debug": true
  }'
```

### Passive Scanning Mode

```bash
curl -X POST http://127.0.0.1:8888/api/tools/jaeles \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "passive": true,
    "threads": 10,
    "signatures": "cve,generic"
  }'
```

## Response Format

### Success Response

```json
{
  "success": true,
  "result": {
    "tool": "jaeles",
    "target": "https://example.com",
    "stdout": "Jaeles scan output...",
    "stderr": "",
    "returncode": 0,
    "command": "jaeles scan -u https://example.com -c 20 --timeout 20",
    "parameters": {
      "url": "https://example.com",
      "threads": 20,
      "timeout": 20,
      // ... other parameters
    },
    "truncated": false
  }
}
```

### Error Response

```json
{
  "error": "Url is required"
}
```

## Generated Command Structure

The tool builds the jaeles command using the following pattern:

```bash
jaeles scan -u <url> -c <threads> --timeout <timeout> [additional options]
```

### Command Building Logic

- Base command: `jaeles scan -u <url>`
- Concurrency: `-c <threads>` (default: 20)
- Timeout: `--timeout <timeout>` (default: 20 seconds)
- Signatures: `-s <signatures>` (if provided)
- Config: `--config <config>` (if provided)
- Level: `--level <level>` (if provided)
- Passive: `--passive` (if enabled)
- Output: `-o <output_file>` (if provided)
- Proxy: `--proxy <proxy>` (if provided)
- Headers: `-H '<headers>'` (if provided)
- Verbose: `-v` (if enabled)
- Debug: `--debug` (if enabled)
- Additional args: appended as-is

## Output Handling

- Output is limited to 20,000 characters to prevent token overflow
- If output exceeds this limit, it will be truncated with a notice
- The `truncated` field in the response indicates if truncation occurred
- Full output is always available in the log files

## Logging

### Log Location

Logs for the Jaeles tool are stored in:
```
logs/tools.jaeles.jaeles.log
```

### Log Content

The log file contains:
- Execution timestamps
- Target URLs being scanned
- Command execution details
- Success/failure status
- Error messages and debugging information
- Performance metrics (if available)

### Log Format

```
2025-09-07 10:30:45,123 - tools.jaeles.jaeles - INFO - Executing Jaeles on https://example.com
2025-09-07 10:30:45,124 - tools.jaeles.jaeles - WARNING - Jaeles output truncated due to size limits
```

## Command Timeout

- Default execution timeout: parameter timeout + 30 seconds
- This allows jaeles to complete within its own timeout before the wrapper times out
- Example: if `timeout` parameter is 20 seconds, total execution timeout is 50 seconds

## Error Handling

The endpoint handles various error scenarios:

1. **Missing required parameters**: Returns 400 with specific field name
2. **Command execution failures**: Returns 500 with error details
3. **Timeout errors**: Returns 500 with timeout information
4. **Invalid JSON**: Returns 400 with JSON parsing error

## Best Practices

1. **Start with lower thread counts** for initial testing
2. **Use appropriate timeouts** based on target complexity
3. **Monitor log files** for detailed execution information
4. **Consider output file parameter** for large scans to avoid response truncation
5. **Use passive mode** for stealthier reconnaissance
6. **Combine with proxy tools** like Burp Suite for comprehensive testing

## Integration Notes

- The tool integrates with the Bug Bounty MCP Server's logging and error handling systems
- All executions are logged for audit and debugging purposes
- Response format is consistent with other tools in the server
- Command execution is handled securely through the centralized command execution utility
