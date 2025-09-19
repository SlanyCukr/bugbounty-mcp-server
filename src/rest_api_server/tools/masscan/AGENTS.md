# Masscan Tool API Documentation

## Overview

The Masscan tool provides high-speed network port scanning capabilities through a REST API endpoint. It wraps the masscan command-line tool and provides structured output parsing for integration with bug bounty workflows.

## API Endpoint

**Path:** `/api/tools/masscan`
**Method:** `POST`
**Content-Type:** `application/json`

## Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string | Target IP address, IP range, or hostname to scan |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ports` | string | `"1-65535"` | Port specification (e.g., "80,443", "1-1000", "80,443,8080-8090") |
| `rate` | integer | `1000` | Packet transmission rate (packets per second) |
| `banners` | boolean | `false` | Enable banner grabbing for open ports |
| `exclude_file` | string | `""` | Path to file containing IPs to exclude from scan |
| `include_file` | string | `""` | Path to file containing IPs to include in scan |
| `output_format` | string | `"list"` | Output format for masscan results |
| `interface` | string | `""` | Network interface to use for scanning |
| `router_mac` | string | `""` | MAC address of the router |
| `source_ip` | string | `""` | Source IP address for packets |
| `additional_args` | string | `""` | Additional command-line arguments for masscan |

## Request Example

### Basic Scan
```json
{
  "target": "192.168.1.0/24"
}
```

### Advanced Scan with Custom Parameters
```json
{
  "target": "scanme.nmap.org",
  "ports": "80,443,8080-8090",
  "rate": 2000,
  "banners": true,
  "interface": "eth0",
  "additional_args": "--wait 5"
}
```

## cURL Commands

### Basic Scan
```bash
curl -X POST http://127.0.0.1:8888/api/tools/masscan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.0/24"
  }'
```

### Advanced Scan with Rate Limiting and Banner Grabbing
```bash
curl -X POST http://127.0.0.1:8888/api/tools/masscan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "scanme.nmap.org",
    "ports": "80,443,8080-8090",
    "rate": 1500,
    "banners": true,
    "interface": "eth0"
  }'
```

### Scan with Custom Port Range and Rate
```bash
curl -X POST http://127.0.0.1:8888/api/tools/masscan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "10.0.0.0/8",
    "ports": "22,80,443,3389,5432",
    "rate": 5000,
    "additional_args": "--wait 10"
  }'
```

## Response Format

### Success Response
```json
{
  "success": true,
  "result": {
    "tool": "masscan",
    "target": "192.168.1.0/24",
    "parameters": {
      "target": "192.168.1.0/24",
      "ports": "80,443",
      "rate": 1000,
      "banners": false,
      "exclude_file": "",
      "include_file": "",
      "output_format": "list",
      "interface": "",
      "router_mac": "",
      "source_ip": "",
      "additional_args": ""
    },
    "status": "completed",
    "scan_results": {
      "open_ports": [
        {
          "port": 80,
          "protocol": "tcp",
          "state": "open",
          "ip_address": "192.168.1.100",
          "timestamp": "2025-09-07 10:15:30"
        },
        {
          "port": 443,
          "protocol": "tcp",
          "state": "open",
          "ip_address": "192.168.1.100",
          "timestamp": "2025-09-07 10:15:31"
        }
      ],
      "banner_grabs": [],
      "total_hosts_scanned": 1,
      "total_ports_scanned": 2,
      "scan_statistics": {
        "packets_sent": 2,
        "packets_received": 2,
        "rate_achieved": 1000
      }
    },
    "execution_time": "2.34s",
    "raw_output": "open tcp 80 192.168.1.100 1725709530\nopen tcp 443 192.168.1.100 1725709531",
    "command": "masscan 192.168.1.0/24 -p80,443 --rate=1000"
  }
}
```

### Error Response
```json
{
  "error": "Target is required"
}
```

## Log Files

Based on the logging configuration in `src/rest_api_server/logger.py`, the masscan tool logs are stored in:

**Log File Path:** `/logs/tools.masscan.masscan.log`

### Log Format
```
YYYY-MM-DD HH:MM:SS,mmm - tools.masscan.masscan - LEVEL - MESSAGE
```

### Example Log Entries
```
2025-09-07 10:15:28,123 - tools.masscan.masscan - INFO - Executing Masscan on 192.168.1.0/24
2025-09-07 10:15:30,456 - tools.masscan.masscan - INFO - Masscan completed successfully
2025-09-07 10:15:31,789 - tools.masscan.masscan - ERROR - Masscan execution failed: Permission denied
```

## Error Handling

The tool handles various error scenarios:

1. **Missing target parameter**: Returns 400 error with message "Target is required"
2. **Command execution failure**: Returns 500 error with masscan error details
3. **Parsing errors**: Malformed output lines are skipped, valid results are still returned
4. **Timeout**: Command execution times out after 600 seconds (10 minutes)

## Security Considerations

- The tool executes system commands, ensure proper input validation
- Rate limiting should be used appropriately to avoid overwhelming target networks
- Banner grabbing may trigger additional security monitoring
- Consider network interface permissions when specifying custom interfaces
- Exclude files should be used to avoid scanning restricted IP ranges

## Performance Notes

- Default rate is 1000 packets/second - adjust based on network capacity
- Higher rates may cause packet loss and incomplete results
- Command timeout is set to 600 seconds for large scans
- Banner grabbing significantly increases scan time
- Large port ranges (1-65535) may take considerable time depending on rate and target size
