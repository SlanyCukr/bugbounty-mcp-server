# Business Logic Testing Workflow API Documentation

## Overview

This document provides comprehensive documentation for the Business Logic Testing workflow REST API endpoint in the Bug Bounty MCP Server. This workflow creates specialized testing scenarios for identifying business logic vulnerabilities in web applications.

## API Endpoint

### Path
```
POST /api/bugbounty/business-logic
```

### Base URL
The API runs on:
- **Host**: 127.0.0.1 (configurable via `BUGBOUNTY_MCP_HOST` environment variable)
- **Port**: 8888 (configurable via `BUGBOUNTY_MCP_PORT` environment variable)

**Full Endpoint URL**: `http://127.0.0.1:8888/api/bugbounty/business-logic`

## Request Parameters

### Required Parameters

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `domain` | string | Target domain for business logic testing | `"example.com"` |

### Optional Parameters

| Parameter | Type | Default | Description | Example |
|-----------|------|---------|-------------|---------|
| `program_type` | string | `"web"` | Type of bug bounty program | `"web"`, `"api"`, `"mobile"`, `"iot"` |

### Request Body Format

```json
{
  "domain": "example.com",
  "program_type": "web"
}
```

## Response Format

### Success Response (200 OK)

```json
{
  "success": true,
  "workflow": {
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
  }
}
```

### Error Responses

#### Missing Domain (400 Bad Request)
```json
{
  "error": "Domain is required"
}
```

#### Invalid JSON (400 Bad Request)
```json
{
  "error": "JSON data is required"
}
```

#### Server Error (500 Internal Server Error)
```json
{
  "error": "Server error: [specific error message]"
}
```

## cURL Examples

### Basic Request
```bash
curl -X POST http://127.0.0.1:8888/api/bugbounty/business-logic \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com"
  }'
```

### Request with Program Type
```bash
curl -X POST http://127.0.0.1:8888/api/bugbounty/business-logic \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "api.example.com",
    "program_type": "api"
  }'
```

### Request with Custom Server Configuration
```bash
# Assuming custom host/port via environment variables
curl -X POST http://localhost:9999/api/bugbounty/business-logic \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "target.example.com",
    "program_type": "web"
  }'
```

## Testing Categories

The workflow generates comprehensive business logic testing scenarios across four main categories:

### 1. Authentication Bypass
- **Password Reset Token Reuse**: Manual testing for token reuse vulnerabilities
- **JWT Algorithm Confusion**: Automated testing using jwt_tool
- **Session Fixation**: Manual session security testing
- **OAuth Flow Manipulation**: Manual OAuth implementation testing

### 2. Authorization Flaws
- **Horizontal Privilege Escalation**: Automated testing using arjun
- **Vertical Privilege Escalation**: Manual privilege escalation testing
- **Role-based Access Control Bypass**: Manual RBAC testing

### 3. Business Process Manipulation
- **Race Conditions**: Automated testing using race_the_web
- **Price Manipulation**: Manual pricing logic testing
- **Quantity Limits Bypass**: Manual quantity restriction testing
- **Workflow State Manipulation**: Manual state transition testing

### 4. Input Validation Bypass
- **File Upload Restrictions**: Automated testing using upload_scanner
- **Content-Type Bypass**: Manual content type validation testing
- **Size Limit Bypass**: Manual file size restriction testing

## Logging

### Log File Location
Logs for this endpoint are stored at:
```
logs/workflows.business_logic.log
```

### Log Format
```
YYYY-MM-DD HH:MM:SS,mmm - workflows.business_logic - LEVEL - MESSAGE
```

### Sample Log Messages
```
2025-09-07 10:30:15,123 - workflows.business_logic - INFO - Creating business logic testing workflow for example.com
2025-09-07 10:30:15,456 - workflows.business_logic - INFO - Business logic testing workflow created for example.com
```

### Log Levels
- **INFO**: Normal workflow creation and completion events
- **ERROR**: Exceptions and error conditions during workflow creation
- **DEBUG**: Detailed debugging information (when DEBUG=true environment variable is set)

### Console Output
Logs are also written to stdout/stderr with the same format, allowing for real-time monitoring during development.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BUGBOUNTY_MCP_HOST` | `127.0.0.1` | Server host address |
| `BUGBOUNTY_MCP_PORT` | `8888` | Server port |
| `DEBUG` | `false` | Enable debug logging |

## Workflow Integration

This workflow integrates with the broader Bug Bounty MCP Server ecosystem:

- **Target Object**: Creates a `BugBountyTarget` instance with domain and program type
- **Manager Integration**: Uses `BugBountyWorkflowManager.create_business_logic_testing_workflow()`
- **Registry System**: Auto-registered via the `@workflow()` decorator
- **Validation**: Automatic JSON validation and error handling
- **Response Formatting**: Consistent response format across all endpoints

## Development Notes

- The workflow requires manual testing components for comprehensive coverage
- Estimated testing time is 480 minutes (8 hours) for thorough business logic analysis
- Both automated tools and manual testing methods are provided for each category
- The workflow is designed specifically for web application business logic vulnerabilities
- All responses follow the standard Bug Bounty MCP Server format with success/error handling
