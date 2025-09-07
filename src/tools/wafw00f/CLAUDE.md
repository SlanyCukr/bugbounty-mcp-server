# WAF Detection Tool (wafw00f)

## Overview

This tool provides a REST API endpoint for wafw00f, a Web Application Firewall (WAF) detection tool used in bug bounty hunting and security assessments.

## API Endpoint

### Path
```
POST /api/tools/wafw00f
```

### Parameters

The endpoint accepts a JSON payload with the following parameters:

#### Required Parameters
- **target** (string): The target URL or domain to scan for WAF protection
  - Example: `"https://example.com"` or `"example.com"`

#### Optional Parameters
- **findall** (boolean): Find all WAFs on the target (equivalent to `-a` flag)
  - Default: `false`
  - Example: `true`

- **verbose** (boolean): Enable verbose output (equivalent to `-v` flag)
  - Default: `false`
  - Example: `true`

- **proxy** (string): Proxy server to use for requests
  - Default: `""` (empty string)
  - Example: `"http://127.0.0.1:8080"`

- **headers** (string): Custom headers to send with requests
  - Default: `""` (empty string)
  - Example: `"User-Agent: Custom-Bot/1.0"`

- **output_file** (string): Output file to save results (equivalent to `-o` flag)
  - Default: `""` (empty string)
  - Example: `"/tmp/wafw00f_results.txt"`

- **additional_args** (string): Additional command-line arguments to pass to wafw00f
  - Default: `""` (empty string)
  - Example: `"--timeout 30"`

## Request Example

### Basic WAF Detection

```bash
curl -X POST http://127.0.0.1:8888/api/tools/wafw00f \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com"
  }'
```

### Advanced WAF Detection with All Options

```bash
curl -X POST http://127.0.0.1:8888/api/tools/wafw00f \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "findall": true,
    "verbose": true,
    "proxy": "http://127.0.0.1:8080",
    "headers": "User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1)",
    "output_file": "/tmp/wafw00f_scan.txt",
    "additional_args": "--timeout 30"
  }'
```

### With Custom Headers for Evasion

```bash
curl -X POST http://127.0.0.1:8888/api/tools/wafw00f \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://target-site.com",
    "findall": true,
    "verbose": true,
    "headers": "X-Forwarded-For: 127.0.0.1"
  }'
```

## Response Format

The API returns a JSON response with the following structure:

```json
{
  "success": true,
  "result": {
    "tool": "wafw00f",
    "target": "https://example.com",
    "parameters": {
      "target": "https://example.com",
      "findall": false,
      "verbose": false,
      "proxy": "",
      "headers": "",
      "output_file": "",
      "additional_args": ""
    },
    "command": "wafw00f https://example.com",
    "timestamp": "2025-01-15T10:30:45.123456",
    "exit_code": 0,
    "stdout": "...",
    "stderr": "...",
    "execution_time": 5.23
  }
}
```

## Logging

### Log Location
Logs for wafw00f executions are stored in:
```
logs/tools.wafw00f.wafw00f.log
```

### Log Format
Each log entry includes:
- Timestamp
- Logger name (`tools.wafw00f.wafw00f`)
- Log level (INFO, ERROR, etc.)
- Message content

### Example Log Entries
```
2025-01-15 10:30:45,123 - tools.wafw00f.wafw00f - INFO - Executing wafw00f on https://example.com
2025-01-15 10:30:50,456 - tools.wafw00f.wafw00f - ERROR - Command execution failed: wafw00f command not found
```

## Error Handling

The endpoint handles various error scenarios:

### Missing Required Fields
```json
{
  "error": "Target is required"
}
```

### Command Execution Errors
```json
{
  "error": "Server error: Command 'wafw00f' not found"
}
```

### Timeout Errors
Commands that exceed the 120-second timeout will be terminated and return an error response.

## Security Considerations

- The tool executes system commands with user-provided input
- Input validation is performed on the target parameter
- Command execution is limited to a 120-second timeout
- All parameters are logged for audit purposes

## WAF Detection Capabilities

wafw00f can detect over 100 different WAF solutions including:
- Cloudflare
- AWS WAF
- Akamai
- F5 Big-IP
- Imperva/Incapsula
- ModSecurity
- And many more...

## Usage Tips

1. **Use findall flag**: Set `findall: true` to detect multiple WAFs that might be layered
2. **Enable verbose output**: Set `verbose: true` for detailed detection information
3. **Custom headers**: Use the `headers` parameter to test WAF evasion techniques
4. **Proxy support**: Route requests through a proxy for additional anonymity
5. **Timeout considerations**: Complex targets may require longer timeouts via `additional_args`
