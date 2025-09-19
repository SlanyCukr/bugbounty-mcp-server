# Hakrawler Tool - REST API Documentation

## Overview

Hakrawler is a fast web crawler tool designed for endpoint discovery during bug bounty reconnaissance. This tool crawls web applications to find hidden endpoints, forms, and other potentially vulnerable areas.

## API Endpoint

**Path:** `/api/tools/hakrawler`
**Method:** `POST`
**Content-Type:** `application/json`

## Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string | Target URL to crawl (required) |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `depth` | integer | `2` | Crawling depth limit |
| `forms` | boolean | `true` | Include forms in crawling |
| `robots` | boolean | `true` | Check robots.txt for crawling rules |
| `sitemap` | boolean | `true` | Check sitemap.xml for additional URLs |
| `wayback` | boolean | `false` | Use Wayback Machine for historical URLs |
| `insecure` | boolean | `false` | Allow insecure SSL connections |
| `additional_args` | string | `""` | Additional command-line arguments for hakrawler |

## Request Example

### Basic Usage

```json
{
    "url": "https://example.com"
}
```

### Advanced Usage

```json
{
    "url": "https://example.com",
    "depth": 3,
    "forms": true,
    "robots": true,
    "sitemap": true,
    "wayback": true,
    "insecure": false,
    "additional_args": "-plain"
}
```

## cURL Examples

### Basic Request

```bash
curl -X POST http://127.0.0.1:8888/api/tools/hakrawler \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com"
  }'
```

### Advanced Request with All Options

```bash
curl -X POST http://127.0.0.1:8888/api/tools/hakrawler \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "depth": 3,
    "forms": true,
    "robots": true,
    "sitemap": true,
    "wayback": true,
    "insecure": false,
    "additional_args": "-plain -timeout 30"
  }'
```

## Response Format

### Success Response

```json
{
    "success": true,
    "result": {
        "tool": "hakrawler",
        "target": "https://example.com",
        "parameters": {
            "url": "https://example.com",
            "depth": 2,
            "forms": true,
            "robots": true,
            "sitemap": true,
            "wayback": false,
            "insecure": false,
            "additional_args": ""
        },
        "command": "hakrawler -url https://example.com -depth 2 -forms -robots -sitemap",
        "success": true,
        "stdout": "https://example.com/page1\nhttps://example.com/page2\nhttps://example.com/api/endpoint",
        "stderr": "",
        "return_code": 0
    }
}
```

### Error Response

```json
{
    "success": false,
    "error": "Server error: Command execution failed"
}
```

## Logging

### Log Location

Logs for the hakrawler tool are stored in:
- **File:** `/logs/tools.hakrawler.hakrawler.log`
- **Console:** Standard output (when DEBUG=true)

### Log Format

```
YYYY-MM-DD HH:MM:SS,mmm - tools.hakrawler.hakrawler - LEVEL - MESSAGE
```

### Example Log Entries

```
2025-09-07 10:15:30,123 - tools.hakrawler.hakrawler - INFO - Executing hakrawler on https://example.com
2025-09-07 10:15:35,456 - tools.hakrawler.hakrawler - ERROR - Command execution failed: hakrawler not found
```

## Command Construction

The tool constructs hakrawler commands based on the provided parameters:

1. **Base command:** `hakrawler -url <URL> -depth <DEPTH>`
2. **Boolean flags:** Added when `true`:
   - `-forms` (include forms)
   - `-robots` (check robots.txt)
   - `-sitemap` (check sitemap.xml)
   - `-wayback` (use Wayback Machine)
   - `-insecure` (allow insecure connections)
3. **Additional arguments:** Appended as-is from `additional_args`

## Prerequisites

- The `hakrawler` binary must be installed and available in the system PATH
- Target URL must be accessible from the server
- Appropriate network permissions for web crawling

## Usage Tips

1. **Start with default parameters** for quick reconnaissance
2. **Increase depth** for thorough crawling (be mindful of performance)
3. **Enable wayback** for historical URL discovery
4. **Use additional_args** for fine-tuning hakrawler behavior
5. **Monitor logs** for execution status and errors

## Environment Variables

The server can be configured with:
- `BUGBOUNTY_MCP_PORT`: Server port (default: 8888)
- `BUGBOUNTY_MCP_HOST`: Server host (default: 127.0.0.1)
- `DEBUG`: Enable debug logging (default: false)
