# CLAUDE.md - Nmap Advanced Tool

This file documents the `nmap_advanced` tool REST API endpoint within the Bug Bounty MCP Server.

## Overview

The `nmap_advanced` tool provides comprehensive network scanning capabilities using Nmap with advanced configuration options for bug bounty hunting workflows. It supports various scan types, timing options, NSE scripts, and detection methods.

## REST API Endpoint

**Path:** `/api/tools/nmap-advanced`
**Method:** `POST`
**Content-Type:** `application/json`

## Parameters

The endpoint accepts the following JSON parameters in the request body:

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string | **Required.** Target IP address, hostname, or CIDR range to scan |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scan_type` | string | `"-sS"` | Nmap scan type (e.g., `-sS` for SYN scan, `-sT` for TCP connect, `-sU` for UDP) |
| `ports` | string | `""` | Port specification (e.g., `"80,443"`, `"1-1000"`, `"80,443,8080-8090"`) |
| `timing` | string | `"T4"` | Timing template (`T0` to `T5`, where `T0` is slowest and `T5` is fastest) |
| `scripts` | string | `""` | NSE scripts to run (legacy parameter, use `nse_scripts` instead) |
| `nse_scripts` | string | `""` | NSE scripts to run (e.g., `"default"`, `"vuln"`, `"discovery,safe"`) |
| `os_detection` | boolean | `false` | Enable OS detection (`-O` flag) |
| `service_detection` | boolean | `true` | Enable service version detection (`-sV` flag) |
| `version_detection` | boolean | `false` | Explicit version detection flag (enables `-sV` when true) |
| `aggressive` | boolean | `false` | Enable aggressive scan (`-A` flag) - includes OS detection, version detection, script scanning, and traceroute |
| `stealth` | boolean | `false` | Enable stealth mode (uses `-T2 -f --mtu 24` for slower, fragmented packets) |
| `additional_args` | string | `""` | Additional Nmap arguments to append to the command |

### Parameter Priority and Logic

- If `stealth` is `true`, timing is set to `T2` with fragmentation options, overriding the `timing` parameter
- If `nse_scripts` is provided, it takes precedence over the `scripts` parameter
- If neither `nse_scripts` nor `scripts` is provided and `aggressive` is `false`, defaults to `"default,discovery,safe"` scripts
- Both `service_detection` and `version_detection` enable the `-sV` flag
- `aggressive` mode (`-A`) includes multiple detection methods and overrides individual detection flags

## Example Usage

### Basic Scan

```bash
curl -X POST http://127.0.0.1:8888/api/tools/nmap-advanced \
  -H "Content-Type: application/json" \
  -d '{
    "target": "scanme.nmap.org"
  }'
```

### Advanced Vulnerability Scan

```bash
curl -X POST http://127.0.0.1:8888/api/tools/nmap-advanced \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.1",
    "scan_type": "-sS",
    "ports": "80,443,8080,8443",
    "timing": "T3",
    "nse_scripts": "vuln,exploit",
    "os_detection": true,
    "service_detection": true,
    "additional_args": "--script-args=unsafe=1"
  }'
```

### Stealth Scan

```bash
curl -X POST http://127.0.0.1:8888/api/tools/nmap-advanced \
  -H "Content-Type: application/json" \
  -d '{
    "target": "10.0.0.0/24",
    "scan_type": "-sS",
    "ports": "22,80,443",
    "stealth": true,
    "nse_scripts": "banner,ssh-hostkey"
  }'
```

### Aggressive Full Scan

```bash
curl -X POST http://127.0.0.1:8888/api/tools/nmap-advanced \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "aggressive": true,
    "ports": "1-65535",
    "timing": "T4"
  }'
```

## Response Format

The API returns a JSON response with the following structure:

```json
{
  "success": true,
  "result": {
    "tool": "nmap_advanced",
    "target": "scanme.nmap.org",
    "parameters": {
      "target": "scanme.nmap.org",
      "scan_type": "-sS",
      "ports": "",
      "timing": "T4",
      "scripts": "",
      "nse_scripts": "",
      "os_detection": false,
      "service_detection": true,
      "version_detection": false,
      "aggressive": false,
      "stealth": false,
      "additional_args": ""
    },
    "command": "nmap -sS scanme.nmap.org -T4 -sV --script=default,discovery,safe",
    "success": true,
    "return_code": 0,
    "stdout": "Nmap scan results...",
    "stderr": ""
  }
}
```

### Response Fields

| Field | Description |
|-------|-------------|
| `success` | Boolean indicating if the API call was successful |
| `result.tool` | Tool identifier ("nmap_advanced") |
| `result.target` | Target that was scanned |
| `result.parameters` | Echo of all input parameters |
| `result.command` | Full Nmap command that was executed |
| `result.success` | Boolean indicating if the Nmap command executed successfully |
| `result.return_code` | Nmap process return code (0 = success) |
| `result.stdout` | Nmap scan output |
| `result.stderr` | Nmap error output (if any) |

## Logging

### Log Location

Logs for the nmap_advanced tool are stored in:
```
logs/tools.nmap_advanced.nmap_advanced.log
```

This follows the pattern `logs/{module_path}.log` where the module path is `tools.nmap_advanced.nmap_advanced` based on the file location and Python import structure.

### Log Format

Logs use the format:
```
%(asctime)s - %(name)s - %(levelname)s - %(message)s
```

Example log entries:
```
2025-09-07 10:15:23,456 - tools.nmap_advanced.nmap_advanced - INFO - Executing advanced Nmap scan on scanme.nmap.org
```

### Log Levels

- **INFO**: Scan initiation messages
- **ERROR**: Command execution failures, parameter validation errors
- **DEBUG**: Detailed execution information (when DEBUG=true environment variable is set)

### Viewing Logs

To monitor logs in real-time:
```bash
tail -f logs/tools.nmap_advanced.nmap_advanced.log
```

## Security Considerations

- The tool executes system commands directly - ensure proper network isolation
- Stealth mode helps avoid detection but scans will be slower
- Aggressive scans (`-A`) may be detected by intrusion detection systems
- Always ensure you have permission to scan the target systems
- NSE scripts with `unsafe=1` argument can be intrusive

## Common NSE Scripts

| Script Category | Example Scripts | Description |
|----------------|-----------------|-------------|
| `default` | Standard safe scripts | Default scripts that run with `-sC` |
| `discovery` | `dns-brute`, `http-title` | Host and service discovery |
| `safe` | `banner`, `http-headers` | Safe, non-intrusive scripts |
| `vuln` | `http-vuln-*`, `smb-vuln-*` | Vulnerability detection scripts |
| `exploit` | `http-shellshock`, `smb-vuln-ms17-010` | Exploitation attempt scripts |
| `auth` | `http-auth`, `ssh-auth-methods` | Authentication related scripts |

## Troubleshooting

### Common Issues

1. **Permission denied**: Ensure Nmap is installed and executable
2. **Target unreachable**: Verify network connectivity to target
3. **Slow scans**: Consider adjusting timing template or using fewer scripts
4. **No results**: Target may be firewalled or down

### Debug Mode

Enable debug logging by setting the environment variable:
```bash
DEBUG=true uv run -m src.rest_api_server
```
