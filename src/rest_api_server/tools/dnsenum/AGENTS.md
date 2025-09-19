# DNS Enumeration Tool (dnsenum)

## Overview

The dnsenum tool provides DNS enumeration and subdomain discovery capabilities through a REST API endpoint. It leverages the dnsenum command-line tool to perform comprehensive DNS reconnaissance on target domains.

## API Endpoint

**Path:** `/api/tools/dnsenum`
**Method:** `POST`
**Content-Type:** `application/json`

## Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | The target domain to enumerate (e.g., "example.com") |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `dns_server` | string | `""` | Custom DNS server to use for queries (e.g., "8.8.8.8") |
| `wordlist` | string | `""` | Path to wordlist file for subdomain brute-forcing |
| `threads` | integer | `5` | Number of threads for concurrent DNS queries |
| `delay` | integer | `0` | Delay between DNS queries in seconds |
| `reverse` | boolean | `false` | Enable/disable reverse DNS lookups (disabled by default for faster execution) |
| `additional_args` | string | `""` | Additional command-line arguments to pass to dnsenum |

## Request Example

### Basic DNS Enumeration

```json
{
  "domain": "example.com"
}
```

### Advanced DNS Enumeration with Custom Settings

```json
{
  "domain": "example.com",
  "dns_server": "8.8.8.8",
  "wordlist": "/usr/share/wordlists/subdomains.txt",
  "threads": 10,
  "delay": 1,
  "reverse": true,
  "additional_args": "--timeout 30"
}
```

## cURL Examples

### Basic Usage

```bash
curl -X POST http://127.0.0.1:8888/api/tools/dnsenum \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### Advanced Usage with Custom DNS Server and Wordlist

```bash
curl -X POST http://127.0.0.1:8888/api/tools/dnsenum \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "dns_server": "8.8.8.8",
    "wordlist": "/usr/share/wordlists/dns/subdomains-top1mil-20000.txt",
    "threads": 15,
    "delay": 0,
    "reverse": false
  }'
```

### Using Custom Port

```bash
curl -X POST http://127.0.0.1:8080/api/tools/dnsenum \
  -H "Content-Type: application/json" \
  -d '{"domain": "target.com"}'
```

## Response Format

### Successful Response

```json
{
  "success": true,
  "result": {
    "tool": "dnsenum",
    "target": "example.com",
    "parameters": {
      "domain": "example.com",
      "dns_server": "",
      "wordlist": "",
      "threads": 5,
      "delay": 0,
      "reverse": false,
      "additional_args": ""
    },
    "command": "dnsenum --nocolor -v example.com --noreverse",
    "success": true,
    "raw_output": "dnsenum VERSION:1.2.6\n\n-----   example.com   -----\n\n\nHost's addresses:\n__________________\n\nexample.com.                             5       IN    A        93.184.216.34\n\n\nName Servers:\n______________\n\na.iana-servers.net.                      172800  IN    A        199.43.135.53\nb.iana-servers.net.                      172800  IN    A        199.43.133.53\n\n...",
    "stderr": "",
    "return_code": 0,
    "timestamp": "2025-09-07T10:30:45.123456"
  }
}
```

### Error Response

```json
{
  "error": "Domain is required"
}
```

## Command Construction

The tool constructs the dnsenum command with the following pattern:

```bash
dnsenum --nocolor -v <domain> [options]
```

### Command Options Added Based on Parameters:

- `--dnsserver <server>` - When `dns_server` is provided
- `-f <wordlist>` - When `wordlist` path is provided
- `--threads <number>` - When `threads` differs from default (5)
- `-d <seconds>` - When `delay` is greater than 0
- `--noreverse` - When `reverse` is false (default behavior for performance)
- Additional arguments are appended as-is

## Logging

### Log File Location

Logs for dnsenum operations are stored in:
```
logs/tools.dnsenum.dnsenum.log
```

### Log Format

```
YYYY-MM-DD HH:MM:SS,mmm - tools.dnsenum.dnsenum - LEVEL - MESSAGE
```

### Example Log Entries

```
2025-09-07 10:30:45,123 - tools.dnsenum.dnsenum - INFO - Executing dnsenum on example.com
2025-09-07 10:30:45,124 - tools.dnsenum.dnsenum - INFO - Executing command: dnsenum --nocolor -v example.com --noreverse
```

### Debug Mode

When `DEBUG=true` environment variable is set, additional debug information will be logged to both console and log file.

## Execution Details

- **Timeout:** 600 seconds (10 minutes) for DNS enumeration operations
- **Command Options:** Always includes `--nocolor` and `-v` for consistent parsing
- **Default Behavior:** Reverse DNS lookups are disabled by default (`--noreverse`) for faster execution
- **Error Handling:** Command failures are captured in the response with error details

## Environment Variables

The following environment variables affect the dnsenum tool endpoint:

| Variable | Default | Description |
|----------|---------|-------------|
| `BUGBOUNTY_MCP_PORT` | `8888` | Port where the API server runs |
| `BUGBOUNTY_MCP_HOST` | `127.0.0.1` | Host address for the API server |
| `DEBUG` | `false` | Enable debug logging |

## Security Considerations

- The tool executes system commands, ensure proper input validation
- Wordlist paths should be validated to prevent directory traversal attacks
- DNS queries may be logged by DNS servers and network infrastructure
- Consider rate limiting for production deployments
