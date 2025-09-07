# Amass Tool API Documentation

## Overview

The Amass tool provides advanced subdomain enumeration capabilities through the Bug Bounty MCP Server's REST API. It wraps the popular OWASP Amass tool with comprehensive configuration options for passive reconnaissance, active scanning, brute force attacks, and DNS intelligence gathering.

## API Endpoint

**Path:** `/api/tools/amass`
**Method:** `POST`
**Content-Type:** `application/json`

## Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | Target domain for subdomain enumeration |

### Optional Parameters

#### Core Enumeration Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `mode` | string | `"enum"` | Operation mode: `enum`, `intel`, `viz`, `track`, `db` |
| `active` | boolean | `false` | Enable active reconnaissance techniques |
| `brute` | boolean | `false` | Enable brute force subdomain discovery |
| `passive` | boolean | `true` | Enable passive reconnaissance (default enabled) |

#### Wordlist and Dictionary Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `wordlist` | string | `null` | Path to custom wordlist file for brute force |
| `wordlist_mask` | string | `null` | Wordlist mask for pattern-based enumeration |
| `alterations` | boolean | `false` | Enable subdomain name alterations |

#### Output and Information Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `show_sources` | boolean | `false` | Display data sources for discovered subdomains |
| `show_ips` | boolean | `false` | Display IP addresses for discovered subdomains |
| `include_unresolved` | boolean | `false` | Include subdomains that don't resolve to IP addresses |

#### Data Source Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `data_sources` | string | `null` | Comma-separated list of data sources to include |
| `exclude_sources` | string | `null` | Comma-separated list of data sources to exclude |

#### Performance and Rate Limiting Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `timeout_minutes` | integer | `30` | Execution timeout in minutes |
| `max_depth` | integer | `0` | Maximum recursion depth for subdomain discovery |
| `dns_qps` | integer | `null` | DNS queries per second rate limit |
| `resolvers_qps` | integer | `null` | Resolver queries per second rate limit |
| `min_recursive` | integer | `0` | Minimum number of recursive DNS queries |
| `max_dns_queries` | integer | `null` | Maximum total DNS queries to perform |

#### Network Configuration Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `resolvers_file` | string | `null` | Path to custom DNS resolvers file |
| `trusted_resolvers` | string | `null` | Comma-separated list of trusted DNS resolvers |
| `blacklist_file` | string | `null` | Path to subdomain blacklist file |
| `no_dns` | boolean | `false` | Disable DNS resolution |

#### Configuration and Output Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config_file` | string | `null` | Path to Amass configuration file |
| `output_file` | string | `null` | Path to output file for results |
| `log_file` | string | `null` | Path to custom log file |

#### Verbosity Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `verbose` | boolean | `false` | Enable verbose output |
| `silent` | boolean | `false` | Enable silent mode (minimal output) |
| `debug` | boolean | `false` | Enable debug output |

#### Intel Mode Specific Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `whois` | boolean | `false` | Perform WHOIS queries (intel mode only) |
| `asn` | boolean | `false` | Discover ASN information (intel mode only) |
| `cidr` | boolean | `false` | Discover CIDR blocks (intel mode only) |
| `org` | boolean | `false` | Discover organization information (intel mode only) |

#### Advanced Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `exclude_disabled` | boolean | `true` | Exclude disabled data sources |
| `scripts_only` | boolean | `false` | Only use script-based enumeration |

#### Visualization Mode Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `viz_input_file` | string | `null` | Input file for visualization mode |
| `viz_output_file` | string | `null` | Output file for visualization mode |

#### Additional Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `additional_args` | string | `null` | Additional command-line arguments as space-separated string |

## Example Usage

### Basic Subdomain Enumeration

```bash
curl -X POST http://127.0.0.1:8888/api/tools/amass \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com"
  }'
```

### Active Reconnaissance with Brute Force

```bash
curl -X POST http://127.0.0.1:8888/api/tools/amass \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "mode": "enum",
    "active": true,
    "brute": true,
    "show_ips": true,
    "show_sources": true,
    "timeout_minutes": 60
  }'
```

### Custom Wordlist and Rate Limiting

```bash
curl -X POST http://127.0.0.1:8888/api/tools/amass \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "target.com",
    "brute": true,
    "wordlist": "/path/to/custom/wordlist.txt",
    "dns_qps": 50,
    "max_dns_queries": 10000,
    "timeout_minutes": 45
  }'
```

### Intelligence Gathering Mode

```bash
curl -X POST http://127.0.0.1:8888/api/tools/amass \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "company.com",
    "mode": "intel",
    "whois": true,
    "asn": true,
    "cidr": true,
    "org": true,
    "timeout_minutes": 30
  }'
```

### Advanced Configuration with Custom Sources

```bash
curl -X POST http://127.0.0.1:8888/api/tools/amass \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.org",
    "active": true,
    "data_sources": "crtsh,hackertarget,virustotal",
    "exclude_sources": "wayback",
    "alterations": true,
    "include_unresolved": true,
    "resolvers_file": "/etc/resolv.conf",
    "verbose": true
  }'
```

## Response Format

### Success Response

```json
{
  "success": true,
  "result": {
    "tool": "amass",
    "target": "example.com",
    "command": "amass enum -d example.com -passive",
    "success": true,
    "stdout": "subdomain1.example.com\nsubdomain2.example.com\n...",
    "stderr": "",
    "return_code": 0
  }
}
```

### Error Response

```json
{
  "error": "Domain is required"
}
```

## Log Storage

Logs for the Amass tool are stored in:

**Log File:** `logs/tools.amass.amass.log`

This log file contains:
- Execution timestamps
- Command details
- Success/failure status
- Error messages and debugging information
- Performance metrics

The log format follows the pattern:
```
YYYY-MM-DD HH:MM:SS - tools.amass.amass - LEVEL - MESSAGE
```

## Common Use Cases

1. **Basic Subdomain Discovery**: Use default passive enumeration for initial reconnaissance
2. **Comprehensive Enumeration**: Combine active, passive, and brute force techniques
3. **Corporate Intelligence**: Use intel mode to gather organizational information
4. **Rate-Limited Scanning**: Configure DNS query limits for stealthy reconnaissance
5. **Custom Wordlist Attacks**: Use specialized wordlists for targeted brute force
6. **Source-Specific Enumeration**: Include/exclude specific data sources based on requirements

## Error Handling

The API handles various error conditions:
- Missing required `domain` parameter
- Invalid parameter types or values
- Command execution timeouts
- File access permissions issues
- Network connectivity problems

All errors are logged to the designated log file with appropriate detail levels for debugging.
