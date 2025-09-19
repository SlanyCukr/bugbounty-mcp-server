# Comprehensive Bug Bounty Assessment Workflow API Documentation

This document describes the comprehensive bug bounty assessment workflow REST API endpoint that combines all bug bounty workflows into a single comprehensive assessment.

## Overview

The comprehensive assessment workflow creates a complete bug bounty assessment by combining reconnaissance, vulnerability hunting, OSINT, and business logic testing workflows. It generates a structured assessment with specific tools, parameters, estimated execution times, and comprehensive summaries across all workflow types.

## API Endpoint

**Path:** `/api/bugbounty/comprehensive-bugbounty-assessment`
**Method:** `POST`
**Content-Type:** `application/json`

## Request Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | The target domain for comprehensive assessment (e.g., "example.com") |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scope` | array of strings | `[]` | List of in-scope domains/subdomains |
| `priority_vulns` | array of strings | `["rce", "sqli", "xss", "idor", "ssrf"]` | Priority vulnerability types to focus on |
| `include_osint` | boolean | `true` | Whether to include OSINT workflow in assessment |
| `include_business_logic` | boolean | `true` | Whether to include business logic testing workflow |

## Example Request

### Curl Command

```bash
curl -X POST http://127.0.0.1:8888/api/bugbounty/comprehensive-bugbounty-assessment \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "scope": ["*.example.com", "api.example.com"],
    "priority_vulns": ["rce", "sqli", "xss", "idor", "ssrf"],
    "include_osint": true,
    "include_business_logic": true
  }'
```

### Minimal Request

```bash
curl -X POST http://127.0.0.1:8888/api/bugbounty/comprehensive-bugbounty-assessment \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

## Response Structure

### Success Response (200 OK)

```json
{
  "success": true,
  "workflow": {
    "success": true,
    "assessment": {
      "target": "example.com",
      "reconnaissance": {
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
      },
      "vulnerability_hunting": {
        "target": "example.com",
        "vulnerability_tests": [
          {
            "vulnerability_type": "rce",
            "priority": 10,
            "tools": ["nuclei", "jaeles", "sqlmap"],
            "payload_type": "command_injection",
            "test_scenarios": [
              {
                "name": "Command Injection",
                "payloads": ["$(whoami)", "`id`", ";ls -la"]
              },
              {
                "name": "Code Injection",
                "payloads": ["<?php system($_GET['cmd']); ?>"]
              },
              {
                "name": "Template Injection",
                "payloads": ["{{7*7}}", "${7*7}", "#{7*7}"]
              }
            ],
            "estimated_time": 300
          },
          {
            "vulnerability_type": "sqli",
            "priority": 9,
            "tools": ["sqlmap", "nuclei"],
            "payload_type": "sql_injection",
            "test_scenarios": [
              {
                "name": "Union-based SQLi",
                "payloads": ["' UNION SELECT 1,2,3--", "' OR 1=1--"]
              },
              {
                "name": "Boolean-based SQLi",
                "payloads": ["' AND 1=1--", "' AND 1=2--"]
              },
              {
                "name": "Time-based SQLi",
                "payloads": ["'; WAITFOR DELAY '00:00:05'--", "' AND SLEEP(5)--"]
              }
            ],
            "estimated_time": 270
          }
        ],
        "estimated_time": 1050,
        "priority_score": 42
      },
      "osint": {
        "note": "OSINT workflow implementation referenced but not found in managers"
      },
      "business_logic": {
        "target": "example.com",
        "business_logic_tests": [
          {
            "category": "Authentication Bypass",
            "tests": [
              {
                "name": "Password Reset Token Reuse",
                "method": "manual"
              },
              {
                "name": "JWT Algorithm Confusion",
                "method": "automated",
                "tool": "jwt_tool"
              },
              {
                "name": "Session Fixation",
                "method": "manual"
              },
              {
                "name": "OAuth Flow Manipulation",
                "method": "manual"
              }
            ]
          },
          {
            "category": "Authorization Flaws",
            "tests": [
              {
                "name": "Horizontal Privilege Escalation",
                "method": "automated",
                "tool": "arjun"
              },
              {
                "name": "Vertical Privilege Escalation",
                "method": "manual"
              },
              {
                "name": "Role-based Access Control Bypass",
                "method": "manual"
              }
            ]
          },
          {
            "category": "Business Process Manipulation",
            "tests": [
              {
                "name": "Race Conditions",
                "method": "automated",
                "tool": "race_the_web"
              },
              {
                "name": "Price Manipulation",
                "method": "manual"
              },
              {
                "name": "Quantity Limits Bypass",
                "method": "manual"
              },
              {
                "name": "Workflow State Manipulation",
                "method": "manual"
              }
            ]
          },
          {
            "category": "Input Validation Bypass",
            "tests": [
              {
                "name": "File Upload Restrictions",
                "method": "automated",
                "tool": "upload_scanner"
              },
              {
                "name": "Content-Type Bypass",
                "method": "manual"
              },
              {
                "name": "Size Limit Bypass",
                "method": "manual"
              }
            ]
          }
        ],
        "estimated_time": 480,
        "manual_testing_required": true
      },
      "summary": {
        "total_estimated_time": 2610,
        "total_tools": 21,
        "workflow_count": 4,
        "priority_score": 42
      }
    },
    "timestamp": "2025-09-07T10:30:15.123456"
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

## Assessment Components

### 1. Reconnaissance Workflow
- **Purpose:** Comprehensive target discovery and enumeration
- **Phases:** Subdomain discovery, HTTP service discovery, content discovery
- **Tools:** amass, subfinder, assetfinder, httpx, nuclei, katana, gau, waybackurls, dirsearch
- **Estimated Time:** ~18 minutes (1080 seconds)

### 2. Vulnerability Hunting Workflow
- **Purpose:** Automated vulnerability detection prioritized by impact
- **Focus Areas:** RCE, SQLi, XSS, IDOR, SSRF, and other high-impact vulnerabilities
- **Tools:** nuclei, jaeles, sqlmap, dalfox, ffuf, arjun, paramspider
- **Estimated Time:** ~17.5 minutes (varies by priority vulnerabilities)

### 3. OSINT Workflow (Optional)
- **Purpose:** Open source intelligence gathering
- **Status:** Referenced in code but implementation not found in managers
- **Controlled by:** `include_osint` parameter

### 4. Business Logic Testing Workflow (Optional)
- **Purpose:** Manual and automated business logic flaw detection
- **Categories:** Authentication bypass, authorization flaws, business process manipulation, input validation bypass
- **Methods:** Mix of automated tools and manual testing procedures
- **Estimated Time:** 8 hours (480 minutes) for thorough testing
- **Controlled by:** `include_business_logic` parameter

## Assessment Summary

The workflow provides a comprehensive summary including:
- **total_estimated_time:** Sum of all workflow estimated times
- **total_tools:** Count of all tools across workflows
- **workflow_count:** Number of workflows included in assessment
- **priority_score:** Combined priority score from vulnerability hunting

## Vulnerability Priority System

The vulnerability hunting component uses a priority-based system:

| Vulnerability | Priority | Estimated Time | Tools |
|---------------|----------|----------------|-------|
| RCE | 10 | 300 seconds | nuclei, jaeles, sqlmap |
| SQLi | 9 | 270 seconds | sqlmap, nuclei |
| SSRF | 8 | 240 seconds | nuclei, ffuf |
| IDOR | 8 | 240 seconds | arjun, paramspider, ffuf |
| XSS | 7 | 210 seconds | dalfox, nuclei |
| LFI | 7 | 210 seconds | ffuf, nuclei |
| XXE | 6 | 180 seconds | nuclei |
| CSRF | 5 | 150 seconds | nuclei |

## Logging

### Log Location

Logs for the comprehensive assessment workflow are stored at:
```
logs/workflows.comprehensive_assessment.log
```

### Log Format

```
YYYY-MM-DD HH:MM:SS,mmm - workflows.comprehensive_assessment.comprehensive_assessment - LEVEL - MESSAGE
```

### Example Log Entries

```
2025-09-07 10:30:15,123 - workflows.comprehensive_assessment.comprehensive_assessment - INFO - Creating comprehensive bug bounty assessment for example.com
2025-09-07 10:30:15,456 - workflows.comprehensive_assessment.comprehensive_assessment - INFO - Comprehensive bug bounty assessment created for example.com
```

### Log Levels

- **INFO:** Assessment creation start and completion
- **ERROR:** Any errors during assessment creation (logged by registry exception handler)
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
Registered workflow: comprehensive_bugbounty_assessment at /api/bugbounty/comprehensive-bugbounty-assessment
```

### Test with Different Configurations

```bash
# Full comprehensive assessment
curl -X POST http://127.0.0.1:8888/api/bugbounty/comprehensive-bugbounty-assessment \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "scope": ["*.example.com"],
    "priority_vulns": ["rce", "sqli", "xss"],
    "include_osint": true,
    "include_business_logic": true
  }'

# Basic assessment without OSINT
curl -X POST http://127.0.0.1:8888/api/bugbounty/comprehensive-bugbounty-assessment \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "api.example.com",
    "priority_vulns": ["rce", "sqli"],
    "include_osint": false,
    "include_business_logic": true
  }'

# Minimal assessment (reconnaissance and vulnerability hunting only)
curl -X POST http://127.0.0.1:8888/api/bugbounty/comprehensive-bugbounty-assessment \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "test.example.com",
    "include_osint": false,
    "include_business_logic": false
  }'
```

## Notes

- The comprehensive assessment generates plans but does not execute tools automatically
- All tools and parameters are suggestions based on bug bounty best practices
- Estimated times are approximate and may vary based on target size and complexity
- The OSINT workflow is referenced in code but the implementation may not be complete in the current managers
- Business logic testing includes both automated tools and manual testing procedures
- The assessment provides a unified view across all bug bounty testing phases
- Priority vulnerabilities can be customized based on program requirements and bounty values
- The response includes detailed timing and tool counts for resource planning
