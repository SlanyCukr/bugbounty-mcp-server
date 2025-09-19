# Reconnaissance Workflow API Documentation

This document describes the reconnaissance workflow REST API endpoint for comprehensive bug bounty target analysis.

## Overview

The reconnaissance workflow creates a comprehensive reconnaissance plan for bug bounty hunting, including subdomain discovery, HTTP service discovery, and content discovery phases. It generates a structured workflow with specific tools, parameters, and estimated execution times.

## API Endpoint

**Path:** `/api/bugbounty/reconnaissance`
**Method:** `POST`
**Content-Type:** `application/json`

## Request Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | The target domain for reconnaissance (e.g., "example.com") |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scope` | array of strings | `[]` | List of in-scope domains/subdomains |
| `out_of_scope` | array of strings | `[]` | List of out-of-scope domains/subdomains |
| `program_type` | string | `"web"` | Program type: "web", "api", "mobile", or "iot" |

## Example Request

### Curl Command

```bash
curl -X POST http://127.0.0.1:8888/api/bugbounty/reconnaissance \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "scope": ["*.example.com", "api.example.com"],
    "out_of_scope": ["admin.example.com", "internal.example.com"],
    "program_type": "web"
  }'
```

### Minimal Request

```bash
curl -X POST http://127.0.0.1:8888/api/bugbounty/reconnaissance \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

## Response Structure

### Success Response (200 OK)

```json
{
  "success": true,
  "workflow": {
    "target": "example.com",
    "phases": [
      {
        "name": "subdomain_discovery",
        "description": "Comprehensive subdomain enumeration",
        "tools": [
          {
            "tool": "amass",
            "params": {
              "domain": "example.com",
              "mode": "enum"
            }
          },
          {
            "tool": "subfinder",
            "params": {
              "domain": "example.com",
              "silent": true
            }
          },
          {
            "tool": "assetfinder",
            "params": {
              "domain": "example.com"
            }
          }
        ],
        "expected_outputs": ["subdomains.txt"],
        "estimated_time": 300
      },
      {
        "name": "http_service_discovery",
        "description": "Identify live HTTP services",
        "tools": [
          {
            "tool": "httpx",
            "params": {
              "probe": true,
              "tech_detect": true,
              "status_code": true
            }
          },
          {
            "tool": "nuclei",
            "params": {
              "tags": "tech",
              "severity": "info"
            }
          }
        ],
        "expected_outputs": ["live_hosts.txt", "technologies.json"],
        "estimated_time": 180
      },
      {
        "name": "content_discovery",
        "description": "Discover hidden content and endpoints",
        "tools": [
          {
            "tool": "katana",
            "params": {
              "depth": 3,
              "js_crawl": true
            }
          },
          {
            "tool": "gau",
            "params": {
              "include_subs": true
            }
          },
          {
            "tool": "waybackurls",
            "params": {}
          },
          {
            "tool": "dirsearch",
            "params": {
              "extensions": "php,html,js,txt,json,xml"
            }
          }
        ],
        "expected_outputs": ["endpoints.txt", "js_files.txt"],
        "estimated_time": 600
      }
    ],
    "estimated_time": 1080,
    "tools_count": 9
  }
}
```

### Error Response (400 Bad Request)

```json
{
  "error": "Domain is required"
}
```

### Error Response (500 Internal Server Error)

```json
{
  "error": "Server error: [specific error message]"
}
```

## Workflow Phases

### 1. Subdomain Discovery
- **Tools:** amass, subfinder, assetfinder
- **Purpose:** Comprehensive subdomain enumeration
- **Expected Output:** subdomains.txt
- **Estimated Time:** 5 minutes (300 seconds)

### 2. HTTP Service Discovery
- **Tools:** httpx, nuclei
- **Purpose:** Identify live HTTP services and technologies
- **Expected Output:** live_hosts.txt, technologies.json
- **Estimated Time:** 3 minutes (180 seconds)

### 3. Content Discovery
- **Tools:** katana, gau, waybackurls, dirsearch
- **Purpose:** Discover hidden content and endpoints
- **Expected Output:** endpoints.txt, js_files.txt
- **Estimated Time:** 10 minutes (600 seconds)

## Logging

### Log Location

Logs for the reconnaissance workflow are stored at:
```
logs/workflows.reconnaissance.log
```

### Log Format

```
YYYY-MM-DD HH:MM:SS,mmm - workflows.reconnaissance - LEVEL - MESSAGE
```

### Example Log Entries

```
2025-09-07 10:30:15,123 - workflows.reconnaissance - INFO - Creating reconnaissance workflow for example.com
2025-09-07 10:30:15,456 - workflows.reconnaissance - INFO - Reconnaissance workflow created for example.com
```

### Log Levels

- **INFO:** Workflow creation start and completion
- **ERROR:** Any errors during workflow creation (logged by registry exception handler)
- **DEBUG:** Additional debug information when DEBUG=true environment variable is set

## Environment Variables

The following environment variables affect the server and logging behavior:

| Variable | Default | Description |
|----------|---------|-------------|
| `BUGBOUNTY_MCP_HOST` | `127.0.0.1` | Server host address |
| `BUGBOUNTY_MCP_PORT` | `8888` | Server port |
| `DEBUG` | `false` | Enable debug logging |

## Testing the Endpoint

### Start the Server

```bash
# Using default settings
uv run -m src.rest_api_server

# With custom environment variables
DEBUG=true BUGBOUNTY_MCP_PORT=8888 uv run -m src.rest_api_server
```

### Verify Endpoint Registration

Check the server startup logs for:
```
Registered workflow: reconnaissance at /api/bugbounty/reconnaissance
```

### Test with Different Program Types

```bash
# Web application testing
curl -X POST http://127.0.0.1:8888/api/bugbounty/reconnaissance \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "program_type": "web"}'

# API testing
curl -X POST http://127.0.0.1:8888/api/bugbounty/reconnaissance \
  -H "Content-Type: application/json" \
  -d '{"domain": "api.example.com", "program_type": "api"}'

# Mobile application backend
curl -X POST http://127.0.0.1:8888/api/bugbounty/reconnaissance \
  -H "Content-Type: application/json" \
  -d '{"domain": "mobile-api.example.com", "program_type": "mobile"}'
```

## Notes

- The workflow generates a plan but does not execute the tools automatically
- All tools and parameters are suggestions based on bug bounty best practices
- Estimated times are approximate and may vary based on target size and complexity
- The response includes a total estimated time and tools count for planning purposes
