# Fierce DNS Reconnaissance Tool

## Overview

Fierce is a DNS reconnaissance tool used for subdomain discovery and DNS enumeration. This tool helps identify subdomains, DNS records, and potential attack vectors by performing comprehensive DNS reconnaissance against a target domain.

## REST API Endpoint

**Path:** `/api/tools/fierce`
**Method:** `POST`
**Content-Type:** `application/json`

## Parameters

The endpoint accepts the following JSON parameters:

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | Target domain to perform DNS reconnaissance on (e.g., "example.com") |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `dns_servers` | array of strings or string | [] | Custom DNS servers to use for queries (e.g., ["8.8.8.8", "1.1.1.1"]) |
| `wide` | boolean | false | Enable wide scan mode for more comprehensive discovery |
| `connect` | boolean | false | Attempt to connect to discovered hosts |
| `delay` | integer | 0 | Delay between requests in seconds (0 = no delay) |
| `traverse` | string | null | Traverse number of IPs above and below discovered IPs |
| `range` | string | null | Specify IP range for discovery (e.g., "192.168.1.0/24") |
| `subdomain_file` | string | null | Path to custom subdomain wordlist file |
| `subdomains` | array of strings or string | [] | Custom subdomain list to check (e.g., ["www", "api", "admin"]) |
| `tcp` | boolean | false | Use TCP instead of UDP for DNS queries |
| `additional_args` | string | "" | Additional command-line arguments to pass to fierce |

## Example Usage

### Basic Domain Scan

```bash
curl -X POST http://127.0.0.1:8888/api/tools/fierce \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com"
  }'
```

### Advanced Scan with Custom DNS Servers

```bash
curl -X POST http://127.0.0.1:8888/api/tools/fierce \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "target.com",
    "dns_servers": ["8.8.8.8", "1.1.1.1"],
    "wide": true,
    "connect": true,
    "delay": 1,
    "subdomains": ["www", "api", "admin", "dev", "staging"],
    "tcp": true
  }'
```

### Scan with IP Range Traversal

```bash
curl -X POST http://127.0.0.1:8888/api/tools/fierce \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.org",
    "traverse": "5",
    "range": "192.168.1.0/24",
    "additional_args": "--timeout 10"
  }'
```

## Response Format

The API returns a JSON response with the following structure:

```json
{
  "success": true,
  "result": {
    "tool": "fierce",
    "target": "example.com",
    "parameters": {
      "domain": "example.com",
      "dns_servers": ["8.8.8.8"],
      "wide": true,
      "connect": false,
      "delay": 0,
      "traverse": null,
      "range": null,
      "subdomain_file": null,
      "subdomains": [],
      "tcp": false,
      "additional_args": ""
    },
    "command_executed": "fierce --domain example.com --dns-servers 8.8.8.8 --wide",
    "success": true,
    "return_code": 0,
    "raw_output": "...(fierce output)...",
    "error_output": "",
    "timestamp": "2025-09-07T10:30:45.123456"
  }
}
```

### Error Response

If an error occurs, the response will include error information:

```json
{
  "success": true,
  "result": {
    "tool": "fierce",
    "target": "example.com",
    "success": false,
    "return_code": 1,
    "error": "Command execution failed",
    "raw_output": "",
    "error_output": "DNS resolution failed",
    "timestamp": "2025-09-07T10:30:45.123456"
  }
}
```

## Logging

### Log File Location

Logs for the fierce tool are stored in:
```
logs/tools.fierce.fierce.log
```

The log file name is constructed from the module path: `tools.fierce.fierce` (package.module.filename).

### Log Format

```
YYYY-MM-DD HH:MM:SS,mmm - tools.fierce.fierce - LEVEL - MESSAGE
```

### Example Log Entries

```
2025-09-07 10:30:45,123 - tools.fierce.fierce - INFO - Executing Fierce on example.com
2025-09-07 10:30:50,456 - tools.fierce.fierce - ERROR - Error in execute_fierce: DNS resolution failed
```

## Command Execution Details

The tool constructs and executes fierce commands with a 10-minute timeout (600 seconds). The basic command structure is:

```bash
fierce --domain <domain> [additional-options]
```

### Fierce Options Mapping

| API Parameter | Fierce Option | Example |
|---------------|---------------|---------|
| `domain` | `--domain` | `--domain example.com` |
| `dns_servers` | `--dns-servers` | `--dns-servers 8.8.8.8 1.1.1.1` |
| `wide` | `--wide` | `--wide` |
| `connect` | `--connect` | `--connect` |
| `delay` | `--delay` | `--delay 2` |
| `traverse` | `--traverse` | `--traverse 5` |
| `range` | `--range` | `--range 192.168.1.0/24` |
| `subdomain_file` | `--subdomain-file` | `--subdomain-file /path/to/wordlist.txt` |
| `subdomains` | `--subdomains` | `--subdomains www api admin` |
| `tcp` | `--tcp` | `--tcp` |

## Error Handling

The endpoint handles the following error scenarios:

1. **Missing required fields**: Returns 400 Bad Request if `domain` is not provided
2. **Command execution failure**: Returns the error details in the response
3. **Timeout**: Commands are terminated after 600 seconds (10 minutes)
4. **Server errors**: Returns 500 Internal Server Error for unexpected failures

All errors are logged to the respective log file for debugging and monitoring purposes.

## Security Considerations

- The tool executes system commands with user-provided input
- Input validation is performed on required fields
- Commands are executed with a timeout to prevent hanging processes
- All command execution and errors are logged for audit purposes

## Dependencies

- `fierce` command-line tool must be installed on the system
- The tool requires appropriate DNS resolution capabilities
- Custom wordlist files (if specified) must be accessible to the server
