# SQLMap Tool API Documentation

This document provides comprehensive information about the SQLMap tool REST API endpoint for SQL injection testing in the Bug Bounty MCP Server.

## API Endpoint

**Path:** `/api/tools/sqlmap`
**Method:** POST
**Content-Type:** application/json

## Parameters

The endpoint accepts the following JSON parameters:

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string | **Required.** Target URL to test for SQL injection vulnerabilities |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `data` | string | null | POST data to send with the request (for testing POST parameters) |
| `level` | integer | 1 | Level of tests to perform (1-5). Higher levels test more parameters |
| `risk` | integer | 1 | Risk of tests to perform (1-3). Higher risk may cause more intrusive tests |
| `technique` | string | null | SQL injection techniques to use (B,E,U,S,T,Q). See SQLMap documentation for details |
| `dbms` | string | null | Force back-end DBMS (e.g., "mysql", "postgresql", "mssql", "oracle") |
| `additional_args` | string | null | Additional command line arguments to pass to SQLMap |

## Request Example

```json
{
  "url": "https://example.com/search?q=test",
  "level": 3,
  "risk": 2,
  "technique": "BEU",
  "dbms": "mysql",
  "data": "username=admin&password=test",
  "additional_args": "--random-agent --tamper=space2comment"
}
```

## Response Format

The endpoint returns a JSON response with the following structure:

```json
{
  "success": true,
  "result": {
    "tool": "sqlmap",
    "target": "https://example.com/search?q=test",
    "command": "sqlmap -u https://example.com/search?q=test --level 3 --risk 2 --technique BEU --dbms mysql --data username=admin&password=test --random-agent --tamper=space2comment --batch",
    "success": true,
    "stdout": "SQLMap output...",
    "stderr": "",
    "return_code": 0
  }
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `success` | boolean | Overall API request success status |
| `result.tool` | string | Tool identifier (always "sqlmap") |
| `result.target` | string | Target URL that was tested |
| `result.command` | string | Complete SQLMap command that was executed |
| `result.success` | boolean | Whether the SQLMap command executed successfully |
| `result.stdout` | string | Standard output from SQLMap execution |
| `result.stderr` | string | Standard error output from SQLMap execution |
| `result.return_code` | integer | Exit code from SQLMap command |

## cURL Command Examples

### Basic SQL Injection Test

```bash
curl -X POST http://127.0.0.1:8888/api/tools/sqlmap \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/search?q=test"
  }'
```

### Advanced SQL Injection Test with POST Data

```bash
curl -X POST http://127.0.0.1:8888/api/tools/sqlmap \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/login",
    "data": "username=admin&password=test",
    "level": 3,
    "risk": 2,
    "technique": "BEU",
    "dbms": "mysql",
    "additional_args": "--random-agent --tamper=space2comment"
  }'
```

### Testing Specific DBMS with Custom Arguments

```bash
curl -X POST http://127.0.0.1:8888/api/tools/sqlmap \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://api.example.com/users/1",
    "dbms": "postgresql",
    "level": 5,
    "risk": 3,
    "additional_args": "--dump --threads=5"
  }'
```

## Logging

### Log File Location

SQLMap tool execution logs are stored in:
```
logs/tools.sqlmap.sqlmap.log
```

### Log Format

Logs follow the standard format configured in `src/rest_api_server/logger.py`:
```
YYYY-MM-DD HH:MM:SS,mmm - tools.sqlmap.sqlmap - LEVEL - MESSAGE
```

### Log Entries

The tool generates the following log entries:

1. **Execution Start**: When SQLMap execution begins
   ```
   2025-09-07 10:15:30,123 - tools.sqlmap.sqlmap - INFO - Executing SQLMap on https://example.com/search?q=test
   ```

2. **Command Execution**: Details about the command being executed (via `utils.commands`)

3. **Errors**: Any errors encountered during execution
   ```
   2025-09-07 10:15:35,456 - tools.sqlmap.sqlmap - ERROR - Error in execute_sqlmap: Command failed
   ```

### Debug Mode

When `DEBUG=true` environment variable is set:
- Log level is set to DEBUG
- More detailed logging information is available
- All SQLMap output is captured in logs

## Command Execution Details

### Timeout

- Default timeout: 900 seconds (15 minutes)
- SQLMap tests can take significant time to complete
- Long-running tests may timeout and be terminated

### Automatic Arguments

The following arguments are automatically added to all SQLMap commands:
- `--batch`: Run in non-interactive mode (automatic yes to all prompts)

### Security Considerations

- SQLMap is executed with user permissions
- Network access is required for target testing
- Some SQLMap techniques may be detected by WAFs or security systems
- Use appropriate risk levels to avoid potential system damage

## Error Handling

Common error scenarios:

1. **Missing Required Field**: Returns 400 status with error message
2. **Invalid URL**: SQLMap will report invalid target
3. **Network Issues**: Timeout or connection errors
4. **Command Execution Failure**: Returns execution details with error information

Example error response:
```json
{
  "error": "Url is required"
}
```

## Integration Notes

- This tool is part of the Bug Bounty MCP Server architecture
- Registered automatically via the `@tool` decorator
- Uses the common command execution utility (`utils.commands`)
- Follows standard REST API patterns for consistency
