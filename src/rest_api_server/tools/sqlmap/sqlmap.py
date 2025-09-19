"""sqlmap tool implementation."""

import ipaddress
import logging
import re
from datetime import datetime
from typing import Any, cast
from urllib.parse import urlparse

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import (
    ConfidenceLevel,
    SeverityLevel,
    create_finding,
    create_stats,
    tool,
)

logger = logging.getLogger(__name__)

# Aggressive preset for sqlmap
AGGRESSIVE_PRESET = {
    "level": 5,
    "risk": 3,
    "technique": "BEUSTQ",  # All techniques
    "additional_args": (
        "--batch --crawl=2 --forms --dbs --tables --dump-all "
        "--tamper=space2comment,charencode,randomcase"
    ),
}


def _apply_aggressive_preset(user_params: dict, aggressive: bool = False) -> dict:
    """Apply aggressive preset to user parameters if aggressive=True."""
    if not aggressive:
        return user_params

    # Start with user params and apply aggressive preset
    merged_params = user_params.copy()

    # Apply aggressive preset for parameters not explicitly set by user
    for key, aggressive_value in AGGRESSIVE_PRESET.items():
        if key not in user_params:
            merged_params[key] = aggressive_value
        else:
            # For certain key parameters, use aggressive values if user set defaults
            if key in ["level", "risk", "technique"] and user_params.get(key) in [
                1,
                None,
                "",
            ]:
                merged_params[key] = aggressive_value

    return merged_params


def _extract_sqlmap_params(data):
    """Extract and validate sqlmap parameters from request data."""
    if not data:
        raise ValueError("Request data is required")

    # Validate required URL parameter
    if "url" not in data or not data["url"]:
        raise ValueError("URL parameter is required")

    url = str(data["url"]).strip()

    # Enhanced URL validation
    if not url:
        raise ValueError("URL cannot be empty")

    parsed = urlparse(url)
    if not parsed.scheme:
        raise ValueError("URL must include a scheme (http/https)")

    if parsed.scheme not in ["http", "https"]:
        raise ValueError("URL scheme must be http or https")

    if not parsed.netloc:
        raise ValueError("URL must include a valid hostname")

    # Check for aggressive mode
    aggressive = data.get("aggressive", False)
    if not isinstance(aggressive, bool):
        raise ValueError("Aggressive parameter must be a boolean")

    # Validate and sanitize parameters
    base_params = {
        "url": url,
        "data": _validate_string_param(data.get("data", ""), "data"),
        "method": _validate_http_method(data.get("method", "GET")),
        "headers": _validate_string_param(data.get("headers", ""), "headers"),
        "cookies": _validate_string_param(data.get("cookies", ""), "cookies"),
        "level": _validate_int_param(data.get("level", 1), "level", 1, 5),
        "risk": _validate_int_param(data.get("risk", 1), "risk", 1, 3),
        "technique": _validate_technique_param(data.get("technique")),
        "dbms": _validate_dbms_param(data.get("dbms")),
        "threads": _validate_int_param(data.get("threads", 1), "threads", 1, 10),
        "delay": _validate_float_param(data.get("delay", 0), "delay", 0, 60),
        "timeout": _validate_int_param(data.get("timeout", 30), "timeout", 1, 3600),
        "retries": _validate_int_param(data.get("retries", 3), "retries", 0, 10),
        "random_agent": _validate_bool_param(
            data.get("random_agent", True), "random_agent"
        ),
        "proxy": _validate_proxy_param(data.get("proxy", "")),
        "tor": _validate_bool_param(data.get("tor", False), "tor"),
        "tamper": _validate_string_param(data.get("tamper", ""), "tamper"),
        "additional_args": _validate_additional_args(data.get("additional_args", "")),
    }

    # Apply aggressive preset if requested
    return _apply_aggressive_preset(base_params, aggressive)


def _validate_string_param(value, param_name, max_length=5000):
    """Validate string parameters with length limits."""
    if value is None:
        return ""

    if not isinstance(value, str):
        try:
            value = str(value)
        except Exception as exc:
            raise ValueError(f"{param_name} must be a string") from exc

    if len(value) > max_length:
        raise ValueError(f"{param_name} exceeds maximum length of {max_length}")

    return value.strip()


def _validate_int_param(value, param_name, min_val, max_val):
    """Validate integer parameters with range checks."""
    if value is None:
        return min_val

    try:
        value = int(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{param_name} must be an integer") from exc

    if not (min_val <= value <= max_val):
        raise ValueError(f"{param_name} must be between {min_val} and {max_val}")

    return value


def _validate_float_param(value, param_name, min_val, max_val):
    """Validate float parameters with range checks."""
    if value is None:
        return min_val

    try:
        value = float(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{param_name} must be a number") from exc

    if not (min_val <= value <= max_val):
        raise ValueError(f"{param_name} must be between {min_val} and {max_val}")

    return value


def _validate_bool_param(value, param_name):
    """Validate boolean parameters."""
    if value is None:
        return False

    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        value_lower = value.lower()
        if value_lower in ["true", "1", "yes", "on"]:
            return True
        elif value_lower in ["false", "0", "no", "off"]:
            return False

    raise ValueError(f"{param_name} must be a boolean value")


def _validate_http_method(method):
    """Validate HTTP method parameter."""
    if not method:
        return "GET"

    method = str(method).upper().strip()
    valid_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]

    if method not in valid_methods:
        raise ValueError(f"HTTP method must be one of: {', '.join(valid_methods)}")

    return method


def _validate_technique_param(technique):
    """Validate SQL injection technique parameter."""
    if not technique:
        return None

    technique = str(technique).upper().strip()
    valid_techniques = ["B", "E", "U", "S", "T", "Q"]

    # Allow combinations like "BEUSTQ"
    for char in technique:
        if char not in valid_techniques:
            valid_list = ", ".join(valid_techniques)
            raise ValueError(
                f"Invalid technique character '{char}'. Valid: {valid_list}"
            )

    return technique


def _validate_dbms_param(dbms):
    """Validate database management system parameter."""
    if not dbms:
        return None

    dbms = str(dbms).lower().strip()
    valid_dbms = [
        "mysql",
        "oracle",
        "postgresql",
        "mssql",
        "sqlite",
        "access",
        "firebird",
        "maxdb",
        "sybase",
        "db2",
        "hsqldb",
        "informix",
        "monetdb",
        "derby",
        "vertica",
        "mckoi",
        "presto",
        "altibase",
        "mimersql",
        "cratedb",
        "cubrid",
        "frontbase",
        "h2",
        "cache",
        "phoenix",
        "voltdb",
        "iris",
        "raima",
        "virtuoso",
        "xsql",
        "clickhouse",
        "cockroachdb",
        "drizzle",
    ]

    if dbms not in valid_dbms:
        raise ValueError(
            f"Invalid DBMS. Valid options: {', '.join(valid_dbms[:10])}..."
        )

    return dbms


def _validate_proxy_param(proxy):
    """Validate proxy parameter."""
    if not proxy:
        return ""

    proxy = str(proxy).strip()

    # Basic proxy format validation (host:port or protocol://host:port)
    if ":" not in proxy:
        raise ValueError(
            "Proxy must include port (format: host:port or protocol://host:port)"
        )

    # Allow HTTP, HTTPS, SOCKS4, SOCKS5 proxies
    if proxy.startswith(("http://", "https://", "socks4://", "socks5://")):
        parsed = urlparse(proxy)
        if not parsed.netloc:
            raise ValueError("Invalid proxy URL format")
    else:
        # Simple host:port format
        parts = proxy.split(":")
        if len(parts) != 2:
            raise ValueError("Proxy format should be host:port")

        try:
            port = int(parts[1])
            if not (1 <= port <= 65535):
                raise ValueError("Proxy port must be between 1 and 65535")
        except ValueError as exc:
            raise ValueError("Proxy port must be a valid integer") from exc

    return proxy


def _validate_additional_args(args):
    """Validate additional arguments parameter."""
    if not args:
        return ""

    args = str(args).strip()

    # Basic safety check for dangerous arguments
    dangerous_patterns = [
        "--os-shell",
        "--os-pwn",
        "--priv-esc",
        "--file-write",
        "--file-dest",
        "--file-read",
        "--sql-shell",
        "--sql-query",
        "--common-tables",
        "--common-columns",
        "--udf-inject",
        "--shared-lib",
    ]

    args_lower = args.lower()
    for pattern in dangerous_patterns:
        if pattern in args_lower:
            raise ValueError(f"Dangerous argument '{pattern}' is not allowed")

    # Prevent command injection attempts
    if any(char in args for char in [";", "&", "|", "`", "$("]):
        raise ValueError(
            "Additional arguments contain potentially dangerous characters"
        )

    return args


def _build_sqlmap_command(params):
    """Build sqlmap command from parameters."""
    cmd_parts = ["sqlmap", "-u", params["url"]]

    # HTTP method and data
    if params["data"]:
        cmd_parts.extend(["--data", params["data"]])
    if params["method"] and params["method"] != "GET":
        cmd_parts.extend(["--method", params["method"]])

    # Headers and cookies
    if params["headers"]:
        cmd_parts.extend(["--headers", params["headers"]])
    if params["cookies"]:
        cmd_parts.extend(["--cookie", params["cookies"]])

    # Detection options
    if params["level"] != 1:
        cmd_parts.extend(["--level", str(params["level"])])
    if params["risk"] != 1:
        cmd_parts.extend(["--risk", str(params["risk"])])
    if params["technique"]:
        cmd_parts.extend(["--technique", params["technique"]])
    if params["dbms"]:
        cmd_parts.extend(["--dbms", params["dbms"]])

    # Performance options
    if params["threads"] > 1:
        cmd_parts.extend(["--threads", str(params["threads"])])
    if params["delay"] > 0:
        cmd_parts.extend(["--delay", str(params["delay"])])
    if params["timeout"] != 30:
        cmd_parts.extend(["--timeout", str(params["timeout"])])
    if params["retries"] != 3:
        cmd_parts.extend(["--retries", str(params["retries"])])

    # Stealth options
    if params["random_agent"]:
        cmd_parts.append("--random-agent")
    if params["proxy"]:
        cmd_parts.extend(["--proxy", params["proxy"]])
    if params["tor"]:
        cmd_parts.append("--tor")
    if params["tamper"]:
        cmd_parts.extend(["--tamper", params["tamper"]])

    # Always use batch mode (non-interactive)
    cmd_parts.append("--batch")

    # Additional arguments
    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return " ".join(cmd_parts)


def _determine_sqli_severity(injectable: bool, dbms: str, technique: str) -> str:
    """Determine severity based on SQL injection findings."""
    if not injectable:
        return "info"

    # SQL injection is generally high severity
    if technique in ["UNION", "ERROR", "BOOLEAN", "TIME", "STACKED"]:
        return "high"
    else:
        return "medium"


def _parse_sqlmap_text_output(raw_output: str, target_url: str) -> list[dict[str, Any]]:
    """Parse sqlmap text output format with enhanced technique detection."""
    findings = []

    if not raw_output:
        return findings

    lines = raw_output.split("\n")
    current_parameter = None
    current_dbms = None
    current_version = None
    injectable_found = False

    # Enhanced technique patterns for better detection
    technique_patterns = {
        "BOOLEAN": [
            r"boolean-based blind",
            r"boolean.*blind",
            r"AND\s+\d+\s*=\s*\d+",
            r"OR\s+\d+\s*=\s*\d+",
            r"conditional\s+error",
            r"blind\s+inference",
        ],
        "ERROR": [
            r"error-based",
            r"error.*injection",
            r"syntax\s+error",
            r"division\s+by\s+zero",
            r"mysql.*error",
            r"postgresql.*error",
            r"oracle.*error",
            r"mssql.*error",
        ],
        "UNION": [
            r"union.*based",
            r"UNION\s+SELECT",
            r"union.*query",
            r"column.*number",
            r"number\s+of\s+columns",
            r"union.*injection",
        ],
        "TIME": [
            r"time-based blind",
            r"time.*blind",
            r"delay.*injection",
            r"SLEEP\s*\(",
            r"WAITFOR\s+DELAY",
            r"BENCHMARK\s*\(",
            r"pg_sleep",
            r"DBMS_LOCK.SLEEP",
        ],
        "STACKED": [
            r"stacked queries",
            r"multiple\s+statements",
            r";\s*SELECT",
            r";\s*INSERT",
            r";\s*UPDATE",
            r";\s*DELETE",
            r"stacked.*injection",
        ],
        "INLINE": [r"inline\s+queries", r"inline.*injection", r"query.*stacking"],
        "OUT_OF_BAND": [
            r"out-of-band",
            r"DNS.*exfiltration",
            r"external.*resolution",
            r"OOB",
            r"network.*interaction",
        ],
    }

    for line in lines:
        line = line.strip()
        if not line:
            continue

        line_lower = line.lower()

        # Extract parameter being tested with improved patterns
        param_patterns = [
            r"testing parameter\s+'([^']+)'",
            r"parameter[:=]\s*'?([^'\s]+)'?",
            r"injectable parameter[:=]\s*'?([^'\s]+)'?",
            r"vulnerable parameter[:=]\s*'?([^'\s]+)'?",
            r"parameter\s+'([^']+)'\s+appears",
            r"parameter\s+'([^']+)'\s+is\s+vulnerable",
        ]

        for pattern in param_patterns:
            param_match = re.search(pattern, line, re.IGNORECASE)
            if param_match:
                current_parameter = param_match.group(1)
                break

        # Enhanced DBMS detection
        if "back-end DBMS:" in line_lower or "dbms:" in line_lower:
            dbms_match = re.search(
                r"(?:back-end\s+)?dbms:\s*([^\n\r]+)", line, re.IGNORECASE
            )
            if dbms_match:
                current_dbms = dbms_match.group(1).strip()

                # Also try to extract version
                version_match = re.search(
                    r"version\s*([0-9]+(?:\.[0-9]+)*)", current_dbms, re.IGNORECASE
                )
                if version_match:
                    current_version = version_match.group(1)

        # Detect injection points with enhanced technique recognition
        injection_indicators = [
            "is vulnerable",
            "injection point",
            "injectable",
            "vulnerable to sql injection",
            "sqli vulnerability",
            "appears to be injectable",
            "injection found",
            "successfully exploited",
            "payload was successful",
        ]

        if any(indicator in line_lower for indicator in injection_indicators):
            injectable_found = True

            # Detect technique using enhanced patterns
            detected_techniques = []
            for technique, patterns in technique_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        detected_techniques.append(technique)
                        break

            # If no specific technique detected, try to infer from context
            if not detected_techniques:
                if "blind" in line_lower:
                    if "time" in line_lower:
                        detected_techniques.append("TIME")
                    else:
                        detected_techniques.append("BOOLEAN")
                elif "union" in line_lower:
                    detected_techniques.append("UNION")
                elif "error" in line_lower:
                    detected_techniques.append("ERROR")
                elif "stack" in line_lower:
                    detected_techniques.append("STACKED")
                else:
                    detected_techniques.append("UNKNOWN")

            # Create findings for each detected technique
            for technique in detected_techniques or ["UNKNOWN"]:
                if target_url:
                    parsed_url = urlparse(target_url)
                    host = parsed_url.netloc

                    # Determine confidence based on technique and evidence
                    confidence = _determine_confidence(
                        technique, current_dbms, current_parameter
                    )
                    severity = _determine_sqli_severity(
                        True, current_dbms or "", technique
                    )

                    tags = ["vulnerability", "sql-injection", technique.lower()]
                    if current_dbms:
                        # Normalize DBMS name for tagging
                        dbms_tag = current_dbms.lower().replace(" ", "-").split()[0]
                        tags.append(dbms_tag)
                    if parsed_url.scheme == "https":
                        tags.append("https")
                    else:
                        tags.append("http")

                    # Enhanced evidence collection
                    evidence = {
                        "parameter": current_parameter or "unknown",
                        "dbms": current_dbms or "unknown",
                        "dbms_version": current_version,
                        "technique": technique,
                        "url": target_url,
                        "path": parsed_url.path,
                        "scheme": parsed_url.scheme,
                        "port": parsed_url.port,
                        "discovered_by": "sqlmap",
                        "vulnerability_type": "sql_injection",
                        "payload_info": _extract_payload_info(line),
                        "risk_level": _assess_risk_level(technique, current_dbms),
                        "exploitation_complexity": _assess_exploitation_complexity(
                            technique
                        ),
                    }

                    finding = create_finding(
                        finding_type="vuln",
                        target=host,
                        evidence=evidence,
                        severity=cast(SeverityLevel, severity),
                        confidence=cast(ConfidenceLevel, confidence),
                        tags=tags,
                        raw_ref=line,
                    )
                    findings.append(finding)

    # Enhanced no-injection-found reporting
    if (
        not injectable_found
        and target_url
        and (
            "scan finished" in raw_output.lower()
            or "all tested parameters" in raw_output.lower()
            or "no injectable parameters" in raw_output.lower()
        )
    ):
        parsed_url = urlparse(target_url)
        host = parsed_url.netloc

        tags = ["scan-result", "sql-injection-test", "clean"]
        if parsed_url.scheme == "https":
            tags.append("https")
        else:
            tags.append("http")

        # Check if WAF was detected
        waf_detected = _detect_waf_presence(raw_output)
        if waf_detected:
            tags.append("waf-detected")

        evidence = {
            "url": target_url,
            "path": parsed_url.path,
            "scheme": parsed_url.scheme,
            "port": parsed_url.port,
            "discovered_by": "sqlmap",
            "vulnerability_type": "sql_injection",
            "result": "not_vulnerable",
            "scan_coverage": _analyze_scan_coverage(raw_output),
            "waf_detected": waf_detected,
            "test_parameters": _extract_tested_parameters(raw_output),
        }

        finding = create_finding(
            finding_type="vuln",  # Still vulnerability type but with info severity
            target=host,
            evidence=evidence,
            severity=cast(SeverityLevel, "info"),
            confidence=cast(ConfidenceLevel, "high"),
            tags=tags,
            raw_ref="scan_completed_no_injection",
        )
        findings.append(finding)

    return findings


def _determine_confidence(technique, dbms, parameter):
    """Determine confidence level based on detection factors."""
    confidence = "medium"

    if technique in ["UNION", "ERROR"]:
        confidence = "high"
    elif technique in ["BOOLEAN", "TIME"] and dbms:
        confidence = "high"
    elif technique == "STACKED" and dbms:
        confidence = "high"
    elif technique == "UNKNOWN":
        confidence = "low"

    return confidence


def _extract_payload_info(line):
    """Extract payload information from sqlmap output line."""
    payload_info = {}

    # Look for payload patterns
    payload_match = re.search(r"payload:\s*(.+?)(?:\s|$)", line, re.IGNORECASE)
    if payload_match:
        payload_info["payload"] = payload_match.group(1).strip()

    # Look for vector information
    vector_match = re.search(r"vector:\s*(.+?)(?:\s|$)", line, re.IGNORECASE)
    if vector_match:
        payload_info["vector"] = vector_match.group(1).strip()

    return payload_info


def _assess_risk_level(technique, dbms):
    """Assess risk level based on technique and DBMS."""
    high_risk_techniques = ["UNION", "STACKED", "OUT_OF_BAND"]
    medium_risk_techniques = ["ERROR", "BOOLEAN", "TIME"]

    if technique in high_risk_techniques:
        return "high"
    elif technique in medium_risk_techniques:
        return "medium"
    else:
        return "low"


def _assess_exploitation_complexity(technique):
    """Assess exploitation complexity based on technique."""
    simple_techniques = {"UNION", "ERROR"}
    moderate_techniques = {"BOOLEAN", "TIME"}
    complex_techniques = {"STACKED", "OUT_OF_BAND"}

    if technique in simple_techniques:
        return "low"
    if technique in moderate_techniques:
        return "medium"
    if technique in complex_techniques:
        return "high"
    return "medium"


def _detect_waf_presence(output):
    """Detect WAF presence from sqlmap output."""
    waf_indicators = [
        "WAF/IPS/IDS",
        "protection system",
        "filtering",
        "blocked",
        "forbidden",
        "suspicious",
        "rate limit",
        "cloudflare",
        "akamai",
        "sucuri",
        "barracuda",
    ]

    output_lower = output.lower()
    return any(indicator in output_lower for indicator in waf_indicators)


def _analyze_scan_coverage(output):
    """Analyze what was covered in the scan."""
    coverage = {"parameters_tested": 0, "payloads_used": 0, "techniques_attempted": []}

    # Count tested parameters
    param_matches = re.findall(r"testing parameter", output, re.IGNORECASE)
    coverage["parameters_tested"] = len(param_matches)

    # Count payloads (approximate)
    payload_matches = re.findall(r"payload", output, re.IGNORECASE)
    coverage["payloads_used"] = len(payload_matches)

    # Detect attempted techniques
    technique_indicators = {
        "boolean": "BOOLEAN",
        "union": "UNION",
        "error": "ERROR",
        "time": "TIME",
        "stack": "STACKED",
    }

    for indicator, technique in technique_indicators.items():
        if indicator in output.lower():
            coverage["techniques_attempted"].append(technique)

    return coverage


def _extract_tested_parameters(output):
    """Extract list of parameters that were tested."""
    parameters = []

    # Find parameter names in various formats
    param_patterns = [
        r"testing parameter\s+'([^']+)'",
        r"parameter\s+'([^']+)'",
        r"testing\s+([a-zA-Z0-9_]+)\s+parameter",
    ]

    for pattern in param_patterns:
        matches = re.findall(pattern, output, re.IGNORECASE)
        parameters.extend(matches)

    return list(set(parameters))  # Remove duplicates


def _parse_sqlmap_result(
    execution_result, params, command, started_at: datetime, ended_at: datetime
) -> dict[str, Any]:
    """Parse sqlmap execution result and format response with findings."""
    if not execution_result["success"]:
        return {"findings": [], "stats": create_stats(0, 0, 0)}

    # Parse output into structured findings
    stdout = execution_result.get("stdout", "")
    findings = _parse_sqlmap_text_output(stdout, params["url"])

    # Remove duplicates based on parameter and technique
    seen_vulns = set()
    unique_findings = []
    dupes_count = 0

    for finding in findings:
        param = finding["evidence"].get("parameter", "unknown")
        technique = finding["evidence"].get("technique", "unknown")
        target = finding["target"]
        unique_key = f"{target}:{param}:{technique}"

        if unique_key not in seen_vulns:
            seen_vulns.add(unique_key)
            unique_findings.append(finding)
        else:
            dupes_count += 1

    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "findings": unique_findings,
        "stats": create_stats(len(unique_findings), dupes_count, payload_bytes),
    }


@tool(required_fields=["url"])
def execute_sqlmap():
    """Execute SQLMap for SQL injection testing."""
    try:
        # Get request data with validation
        data = request.get_json()
        if not data:
            return {
                "findings": [],
                "stats": create_stats(0, 0, 0),
                "error": "No request data provided",
            }

        # Extract and validate parameters (this now includes comprehensive validation)
        try:
            params = _extract_sqlmap_params(data)
        except ValueError as e:
            logger.error(f"Parameter validation failed: {e}")
            return {
                "findings": [],
                "stats": create_stats(0, 0, 0),
                "error": f"Invalid parameters: {str(e)}",
            }

        logger.info(f"Executing SQLMap on {params['url']}")

        # Additional safety checks before execution
        if not _is_safe_target(params["url"]):
            logger.warning(f"Target URL appears unsafe: {params['url']}")
            return {
                "findings": [],
                "stats": create_stats(0, 0, 0),
                "error": "Target URL appears to be unsafe for testing",
            }

        started_at = datetime.now()

        try:
            command = _build_sqlmap_command(params)
            logger.debug(f"Executing command: {command}")

            # Execute with timeout and proper error handling
            execution_result = execute_command(
                command, timeout=900
            )  # 15 minute timeout for sqlmap

        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return {
                "findings": [],
                "stats": create_stats(0, 0, 0),
                "error": f"Command execution failed: {str(e)}",
            }

        ended_at = datetime.now()

        # Parse results with error handling
        try:
            result = _parse_sqlmap_result(
                execution_result, params, command, started_at, ended_at
            )

            # Add execution metadata
            result["execution_metadata"] = {
                "started_at": started_at.isoformat(),
                "ended_at": ended_at.isoformat(),
                "duration_seconds": (ended_at - started_at).total_seconds(),
                "command_executed": command,
                "target_url": params["url"],
                "sqlmap_version": _get_sqlmap_version(),
                "execution_success": execution_result.get("success", False),
            }

            return result

        except Exception as e:
            logger.error(f"Result parsing failed: {e}")
            return {
                "findings": [],
                "stats": create_stats(0, 0, 0),
                "error": f"Result parsing failed: {str(e)}",
                "execution_metadata": {
                    "started_at": started_at.isoformat(),
                    "ended_at": ended_at.isoformat(),
                    "duration_seconds": (ended_at - started_at).total_seconds(),
                    "command_executed": command if "command" in locals() else "unknown",
                    "target_url": params["url"],
                    "execution_success": False,
                },
            }

    except Exception as e:
        logger.error(f"Unexpected error in SQLMap execution: {e}")
        return {
            "findings": [],
            "stats": create_stats(0, 0, 0),
            "error": f"Unexpected error: {str(e)}",
        }


def _is_safe_target(url):
    """Check if target URL is safe for SQLMap testing."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return False

        # Block localhost and internal networks for safety
        try:
            ip = ipaddress.ip_address(hostname)
            # Block localhost, private networks, and multicast
            if ip.is_loopback or ip.is_private or ip.is_multicast:
                return False
        except ValueError:
            # Hostname is not an IP address, check for localhost names
            if hostname.lower() in ["localhost", "127.0.0.1", "::1"]:
                return False

        # Additional hostname checks
        if hostname.startswith(".") or hostname.endswith("."):
            return False

        return True

    except Exception:
        return False


def _get_sqlmap_version():
    """Get SQLMap version for metadata."""
    try:
        result = execute_command("sqlmap --version", timeout=10)
        if result.get("success") and result.get("stdout"):
            return result["stdout"].strip()
    except Exception:
        pass
    return "unknown"
