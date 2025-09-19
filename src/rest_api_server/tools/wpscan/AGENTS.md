# WPScan Tool API Documentation

## Overview

The WPScan tool provides WordPress vulnerability analysis through the Bug Bounty MCP Server. It executes WPScan commands and returns structured results for vulnerability assessment and security testing.

## API Endpoint

**Path**: `/api/tools/wpscan`
**Method**: `POST`
**Content-Type**: `application/json`

## Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string | **Required**. Target WordPress URL to scan |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enumerate` | string | `"ap,at,cb,dbe"` | Enumeration options (ap=All Plugins, at=All Themes, cb=Config Backups, dbe=Db Exports) |
| `update` | boolean | `true` | Whether to update WPScan database before scanning |
| `random_user_agent` | boolean | `true` | Use random user agent for requests |
| `api_token` | string | `""` | WPVulnDB API token for enhanced vulnerability data |
| `threads` | integer | `5` | Maximum number of threads to use |
| `additional_args` | string | `""` | Additional WPScan command line arguments |

## Example Usage

### Basic Scan

```bash
curl -X POST http://127.0.0.1:8888/api/tools/wpscan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example-wordpress-site.com"
  }'
```

### Advanced Scan with Custom Parameters

```bash
curl -X POST http://127.0.0.1:8888/api/tools/wpscan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example-wordpress-site.com",
    "enumerate": "ap,at,u,cb,dbe",
    "update": true,
    "random_user_agent": true,
    "api_token": "your-wpvulndb-api-token",
    "threads": 10,
    "additional_args": "--detection-mode aggressive"
  }'
```

### Scan with API Token (Recommended)

```bash
curl -X POST http://127.0.0.1:8888/api/tools/wpscan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example-wordpress-site.com",
    "api_token": "your-wpvulndb-api-token",
    "enumerate": "ap,at,u",
    "threads": 8
  }'
```

## Response Format

### Success Response

```json
{
  "success": true,
  "result": {
    "tool": "wpscan",
    "target": "https://example-wordpress-site.com",
    "parameters": {
      "url": "https://example-wordpress-site.com",
      "enumerate": "ap,at,cb,dbe",
      "update": true,
      "random_user_agent": true,
      "api_token": "",
      "threads": 5,
      "additional_args": ""
    },
    "command": "wpscan --url https://example-wordpress-site.com --enumerate ap,at,cb,dbe --update --random-user-agent --max-threads 5 --format json",
    "success": true,
    "stdout": "WPScan JSON output...",
    "stderr": "",
    "return_code": 0
  }
}
```

### Error Response

```json
{
  "error": "Url is required"
}
```

## Enumeration Options

The `enumerate` parameter accepts comma-separated values:

- `ap` - All Plugins
- `p` - Popular Plugins
- `vp` - Vulnerable Plugins
- `at` - All Themes
- `t` - Popular Themes
- `vt` - Vulnerable Themes
- `u` - Users
- `cb` - Config Backups
- `dbe` - Database Exports
- `m` - Media IDs

Example combinations:
- `"ap,at,u"` - All plugins, all themes, and users
- `"vp,vt"` - Only vulnerable plugins and themes
- `"p,t,u"` - Popular plugins, themes, and users

## Logging

### Log Location

WPScan execution logs are stored in:
```
logs/tools.wpscan.wpscan.log
```

### Log Format

```
2025-09-07 10:30:15,123 - tools.wpscan.wpscan - INFO - Executing WPScan on https://example-wordpress-site.com
```

The logs include:
- Timestamp
- Module name (`tools.wpscan.wpscan`)
- Log level (INFO, ERROR, etc.)
- Log message with target URL and execution details

### Environment Variables for Logging

- `DEBUG=true` - Enables debug-level logging for more detailed output
- Default log level is INFO

## Server Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BUGBOUNTY_MCP_PORT` | `8888` | Server port |
| `BUGBOUNTY_MCP_HOST` | `127.0.0.1` | Server host |
| `DEBUG` | `false` | Enable debug mode |

### Starting the Server

```bash
# Default configuration
uv run -m src.rest_api_server

# With custom configuration
DEBUG=true BUGBOUNTY_MCP_PORT=9000 uv run -m src.rest_api_server
```

## Security Considerations

1. **API Token**: Use a WPVulnDB API token for comprehensive vulnerability data
2. **Rate Limiting**: Be mindful of scan frequency to avoid being blocked
3. **Target Authorization**: Only scan websites you own or have explicit permission to test
4. **Network Configuration**: Consider using appropriate user agents and request timing

## Command Timeout

WPScan commands have a timeout of 900 seconds (15 minutes). Long-running scans may be terminated if they exceed this limit.
