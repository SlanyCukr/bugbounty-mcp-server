# OSINT Workflow API Documentation

This document provides comprehensive information about the OSINT (Open Source Intelligence) workflow REST API endpoint.

## Overview

The OSINT workflow generates comprehensive target intelligence for bug bounty hunting activities. It creates structured workflows to gather publicly available information about a target domain.

## API Endpoint

**Path:** `/api/bugbounty/osint`
**Method:** `POST`
**Content-Type:** `application/json`

## Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | The target domain to perform OSINT gathering on (e.g., "example.com") |

### Request Body Structure

```json
{
  "domain": "target-domain.com"
}
```

### Parameter Details

- **domain**: Must be a valid domain name. This will be used to create a `BugBountyTarget` object and generate the OSINT workflow through the `bugbounty_manager.create_osint_workflow()` method.

## Response Format

### Success Response (HTTP 200)

```json
{
  "success": true,
  "workflow": {
    // OSINT workflow object returned by bugbounty_manager.create_osint_workflow()
  }
}
```

### Error Responses

**Missing Domain (HTTP 400)**
```json
{
  "error": "Domain is required"
}
```

**Invalid JSON (HTTP 400)**
```json
{
  "error": "JSON data is required"
}
```

**Server Error (HTTP 500)**
```json
{
  "error": "Server error: [error details]"
}
```

## Usage Examples

### Basic cURL Command

```bash
curl -X POST http://127.0.0.1:8888/api/bugbounty/osint \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com"
  }'
```

### cURL with Custom Server Configuration

```bash
# With custom host/port (using environment variables)
curl -X POST http://localhost:9000/api/bugbounty/osint \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "target.example.com"
  }'
```

### Example with Real Target

```bash
curl -X POST http://127.0.0.1:8888/api/bugbounty/osint \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "hackerone.com"
  }'
```

## Logging

### Log File Location

Logs for this endpoint are stored in:
```
logs/workflows.osint.osint.log
```

### Log Format

Logs follow the standard format:
```
%(asctime)s - %(name)s - %(levelname)s - %(message)s
```

### Example Log Entries

```
2025-01-15 10:30:45,123 - workflows.osint.osint - INFO - Creating OSINT workflow for example.com
2025-01-15 10:30:47,456 - workflows.osint.osint - INFO - OSINT workflow created for example.com
```

### Debug Mode

When the server is running with `DEBUG=true`, additional debug-level logging will be available in both the console output and log files.

**Enable debug logging:**
```bash
DEBUG=true uv run src/server.py
```

## Workflow Processing

1. **Request Validation**: The endpoint validates that the required `domain` parameter is present in the JSON request body
2. **Target Creation**: Creates a `BugBountyTarget` object with the provided domain
3. **Workflow Generation**: Calls `bugbounty_manager.create_osint_workflow(target)` to generate the OSINT workflow
4. **Response**: Returns the generated workflow object wrapped in a standardized success response

## Error Handling

The endpoint includes comprehensive error handling:

- **Validation Errors**: Missing required fields return HTTP 400 with descriptive error messages
- **Server Errors**: Any exceptions during workflow creation are caught and return HTTP 500 with error details
- **Logging**: All errors are logged to both console and log file for debugging purposes

## Integration Notes

- This endpoint is automatically registered through the `@workflow()` decorator system
- The workflow name is derived from the function name by removing `create_` prefix and `_workflow` suffix
- All responses follow the standardized format with `success` and `workflow` fields
- The endpoint supports only POST method as defined in the registry system
