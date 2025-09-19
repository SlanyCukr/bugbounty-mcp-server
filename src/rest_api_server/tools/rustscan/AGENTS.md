# RustScan Tool API Documentation

## Overview

RustScan is an ultra-fast port scanner tool integrated into the Bug Bounty MCP Server. This tool provides a REST API endpoint that executes RustScan with configurable parameters for network reconnaissance and vulnerability assessment.

## REST API Endpoint

**Path:** `/api/tools/rustscan`
**Method:** `POST`
**Content-Type:** `application/json`

## Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string | The target IP address or hostname to scan |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ports` | string | `""` | Specific ports to scan (e.g., "22,80,443" or "1-1000") |
| `ulimit` | integer | `5000` | The number of file descriptors to use for scanning |
| `batch_size` | integer | `4500` | The batch size for port scanning |
| `timeout` | integer | `1500` | Connection timeout in milliseconds |
| `tries` | integer | `1` | Number of tries per port |
| `no_nmap` | boolean | `false` | Disable Nmap integration (when false, adds "-sC -sV" flags) |
| `additional_args` | string | `""` | Additional command-line arguments to pass to RustScan |

## Request Format

```json
{
  "target": "example.com",
  "ports": "22,80,443,8080",
  "ulimit": 5000,
  "batch_size": 4500,
  "timeout": 1500,
  "tries": 1,
  "no_nmap": false,
  "additional_args": "--greppable"
}
```

## Response Format

```json
{
  "success": true,
  "result": {
    "tool": "rustscan",
    "target": "example.com",
    "command": "rustscan -a example.com --ulimit 5000 -b 4500 -t 1500 -p 22,80,443,8080 -- -sC -sV --greppable",
    "parameters": {
      "target": "example.com",
      "ports": "22,80,443,8080",
      "ulimit": 5000,
      "batch_size": 4500,
      "timeout": 1500,
      "tries": 1,
      "no_nmap": false,
      "additional_args": "--greppable"
    },
    "execution": {
      "stdout": "...",
      "stderr": "...",
      "return_code": 0,
      "execution_time": 15.234
    }
  }
}
```

## Example Usage

### Basic Scan

```bash
curl -X POST http://127.0.0.1:8888/api/tools/rustscan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "scanme.nmap.org"
  }'
```

### Advanced Scan with Custom Parameters

```bash
curl -X POST http://127.0.0.1:8888/api/tools/rustscan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.100",
    "ports": "1-65535",
    "ulimit": 10000,
    "batch_size": 9000,
    "timeout": 2000,
    "tries": 2,
    "no_nmap": false,
    "additional_args": "--accessible"
  }'
```

### Quick Scan Without Nmap Integration

```bash
curl -X POST http://127.0.0.1:8888/api/tools/rustscan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "ports": "80,443",
    "no_nmap": true
  }'
```

## Logging

### Log File Location

Logs for the RustScan tool are stored at:
```
logs/tools.rustscan.rustscan.log
```

### Log Format

The logging system uses the following format:
```
%(asctime)s - %(name)s - %(levelname)s - %(message)s
```

### Example Log Entries

```
2024-01-15 10:30:45,123 - tools.rustscan.rustscan - INFO - Executing RustScan on scanme.nmap.org
2024-01-15 10:30:47,456 - tools.rustscan.rustscan - INFO - RustScan completed successfully
```

### Log Levels

- **INFO**: Execution start/completion messages
- **ERROR**: Command execution failures or exceptions
- **DEBUG**: Detailed execution information (when DEBUG=true environment variable is set)

## Environment Configuration

The server can be configured using environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `BUGBOUNTY_MCP_HOST` | `127.0.0.1` | Server host address |
| `BUGBOUNTY_MCP_PORT` | `8888` | Server port |
| `DEBUG` | `false` | Enable debug logging |

## Error Handling

The API provides consistent error responses:

### Validation Errors (400)
```json
{
  "error": "Target is required"
}
```

### Server Errors (500)
```json
{
  "error": "Server error: Command execution failed"
}
```

## Generated Command Examples

Based on different parameter combinations:

### Default Configuration
```bash
rustscan -a example.com --ulimit 5000 -b 4500 -t 1500 -- -sC -sV
```

### Custom Ports and No Nmap
```bash
rustscan -a 192.168.1.1 --ulimit 5000 -b 4500 -t 1500 -p 22,80,443
```

### High Performance Scan
```bash
rustscan -a target.com --ulimit 10000 -b 9000 -t 1000 --tries 2 -- -sC -sV
```

## Notes

- The tool automatically includes Nmap integration (`-sC -sV`) unless `no_nmap` is set to `true`
- Command execution has a default timeout of 300 seconds
- All parameters are validated, and the target field is required
- The generated command and all parameters are included in the response for transparency
