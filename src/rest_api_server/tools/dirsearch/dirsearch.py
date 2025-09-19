"""dirsearch tool implementation."""

import json
import logging
import re
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import (
    SeverityLevel,
    create_finding,
    create_stats,
    tool,
)

logger = logging.getLogger(__name__)

# Aggressive preset for dirsearch
AGGRESSIVE_PRESET = {
    "wordlist": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "extensions": (
        "php,asp,aspx,jsp,jspx,html,htm,txt,bak,old,"
        "zip,tar,tar.gz,sql,xml,json,config,conf,ini,log"
    ),
    "threads": 100,
    "timeout": 10,
    "recursive": True,
    "max_recursion_depth": 3,
    "exclude_status": "404",
    "rate_limit": 500,
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
            if key in [
                "threads",
                "rate_limit",
                "recursive",
                "max_recursion_depth",
            ] and user_params.get(key) in [10, "", False, 1]:
                merged_params[key] = aggressive_value

    return merged_params


def _extract_dirsearch_params(data):
    """Extract and validate dirsearch parameters from request data."""
    # Check for aggressive mode
    aggressive = data.get("aggressive", False)

    # Base parameters with security validation
    base_params = {
        "url": _validate_url(data["url"]),
        "wordlist": _validate_wordlist_path(
            data.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        ),
        "extensions": _validate_extensions(data.get("extensions", "")),
        "threads": _validate_integer_param(
            data.get("threads", 10), "threads", min_val=1, max_val=200
        ),
        "timeout": _validate_integer_param(
            data.get("timeout", 10), "timeout", min_val=1, max_val=300
        ),
        "recursive": _validate_boolean_param(data.get("recursive", False), "recursive"),
        "max_recursion_depth": _validate_integer_param(
            data.get("max_recursion_depth", 1),
            "max_recursion_depth",
            min_val=1,
            max_val=10,
        ),
        "exclude_status": _validate_status_codes(data.get("exclude_status", "404")),
        "rate_limit": _validate_rate_limit(data.get("rate_limit", "")),
        "additional_args": _validate_additional_args(data.get("additional_args", "")),
    }

    # Apply aggressive preset if requested
    return _apply_aggressive_preset(base_params, aggressive)


def _validate_url(url: str) -> str:
    """Validate and sanitize URL parameter."""
    if not url:
        raise ValueError("URL parameter is required")

    # Remove any whitespace
    url = url.strip()

    # Ensure URL has a scheme
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # Basic URL format validation
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError("Invalid URL format")

        # Only allow http and https schemes
        if parsed.scheme not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS URLs are allowed")

        # Reconstruct URL to normalize it
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    except Exception as e:
        raise ValueError(f"Invalid URL: {e}") from None


def _validate_wordlist_path(wordlist_path: str) -> str:
    """Validate wordlist file path."""
    if not wordlist_path:
        return "/usr/share/wordlists/dirb/common.txt"  # Default

    # Only allow absolute paths in safe directories
    allowed_dirs = [
        "/usr/share/wordlists/",
        "/opt/wordlists/",
        "/home/*/wordlists/",
        "/tmp/wordlists/",
    ]

    # Normalize the path
    import os

    normalized_path = os.path.normpath(wordlist_path)

    # Check for path traversal attempts
    if ".." in normalized_path or normalized_path.startswith("../"):
        logger.warning("Path traversal attempt detected in wordlist path")
        return "/usr/share/wordlists/dirb/common.txt"

    # Check if path is in allowed directories (basic check)
    is_allowed = any(
        normalized_path.startswith(allowed_dir.replace("*", ""))
        for allowed_dir in allowed_dirs
    )

    if not is_allowed:
        logger.warning(f"Wordlist path not in allowed directories: {normalized_path}")
        return "/usr/share/wordlists/dirb/common.txt"

    return normalized_path


def _validate_extensions(extensions: str) -> str:
    """Validate file extensions parameter."""
    if not extensions:
        return ""

    # Split and validate individual extensions
    ext_list = [ext.strip() for ext in extensions.split(",") if ext.strip()]
    validated_exts = []

    for ext in ext_list:
        # Remove leading dots and validate
        ext = ext.lstrip(".")

        # Only allow alphanumeric characters and common extension chars
        if ext.replace("_", "").replace("-", "").isalnum() and len(ext) <= 10:
            validated_exts.append(ext)
        else:
            logger.warning(f"Invalid extension filtered out: {ext}")

    return ",".join(validated_exts)


def _validate_integer_param(
    value: int | str, param_name: str, min_val: int = 1, max_val: int = 1000
) -> int:
    """Validate integer parameters with bounds checking."""
    try:
        if isinstance(value, str):
            int_value = int(value)
        elif isinstance(value, int | float):
            int_value = int(value)
        else:
            raise ValueError(f"Invalid type for {param_name}")

        if int_value < min_val:
            logger.warning(
                f"{param_name} value {int_value} too low, using minimum {min_val}"
            )
            return min_val
        elif int_value > max_val:
            logger.warning(
                f"{param_name} value {int_value} too high, using maximum {max_val}"
            )
            return max_val

        return int_value
    except (ValueError, TypeError):
        logger.warning(f"Invalid {param_name} value: {value}, using default")
        return min_val


def _validate_boolean_param(value: bool | str, param_name: str) -> bool:
    """Validate boolean parameters."""
    if isinstance(value, bool):
        return value
    elif isinstance(value, str):
        return value.lower() in ("true", "1", "yes", "on")
    elif isinstance(value, int | float):
        return bool(value)
    else:
        logger.warning(f"Invalid {param_name} value: {value}, using False")
        return False


def _validate_status_codes(status_codes: str) -> str:
    """Validate status codes parameter."""
    if not status_codes:
        return "404"

    # Split and validate individual status codes
    code_list = [code.strip() for code in status_codes.split(",") if code.strip()]
    validated_codes = []

    for code in code_list:
        try:
            code_int = int(code)
            # Valid HTTP status codes are 100-599
            if 100 <= code_int <= 599:
                validated_codes.append(str(code_int))
            else:
                logger.warning(f"Invalid status code filtered out: {code}")
        except ValueError:
            logger.warning(f"Non-numeric status code filtered out: {code}")

    return ",".join(validated_codes) if validated_codes else "404"


def _validate_rate_limit(rate_limit: int | str) -> int | str:
    """Validate rate limiting parameter."""
    if not rate_limit:
        return ""

    try:
        if isinstance(rate_limit, str) and rate_limit.isdigit():
            return int(rate_limit)
        elif isinstance(rate_limit, int | float):
            # Ensure reasonable bounds for rate limiting
            rate_value = float(rate_limit)
            if rate_value <= 0:
                logger.warning("Rate limit must be positive")
                return ""
            elif rate_value > 10000:  # Very high rate limit
                logger.warning("Rate limit too high, capping at 10000")
                return 10000
            return int(rate_value)
        else:
            logger.warning(f"Invalid rate limit value: {rate_limit}")
            return ""
    except (ValueError, TypeError):
        logger.warning(f"Could not parse rate limit: {rate_limit}")
        return ""


def _validate_additional_args(additional_args: str) -> str:
    """Validate and sanitize additional arguments for security."""
    if not additional_args or not additional_args.strip():
        return ""

    # Remove dangerous characters that could be used for command injection
    dangerous_chars = [
        ";",
        "&",
        "|",
        "`",
        "$",
        "(",
        ")",
        ">",
        "<",
        "*",
        "?",
        "[",
        "]",
        "{",
        "}",
        "~",
    ]
    sanitized = additional_args

    for char in dangerous_chars:
        if char in sanitized:
            logger.warning(
                f"Removing dangerous character '{char}' from additional arguments"
            )
            sanitized = sanitized.replace(char, "")

    # Limit length to prevent buffer overflow attempts
    if len(sanitized) > 500:
        logger.warning("Additional arguments too long, truncating")
        sanitized = sanitized[:500]

    # Only allow printable ASCII characters
    sanitized = "".join(c for c in sanitized if c.isprintable() and ord(c) < 128)

    return sanitized.strip()


def _build_dirsearch_command(params):
    """Build dirsearch command from parameters."""
    import shlex

    cmd_parts = ["dirsearch", "-u", params["url"]]

    # Add extensions
    if params["extensions"]:
        cmd_parts.extend(["-e", params["extensions"]])

    # Add wordlist
    cmd_parts.extend(["-w", params["wordlist"]])

    # Add threads
    cmd_parts.extend(["-t", str(params["threads"])])

    # Add timeout
    cmd_parts.extend(["--timeout", str(params["timeout"])])

    # Add recursive option
    if params["recursive"]:
        cmd_parts.append("-r")
        if params["max_recursion_depth"] > 1:
            cmd_parts.extend(
                ["--max-recursion-depth", str(params["max_recursion_depth"])]
            )

    # Add exclude status codes
    if params["exclude_status"]:
        cmd_parts.extend(["--exclude-status", params["exclude_status"]])

    # Add rate limiting - convert rate_limit (requests per second) to delay
    # (milliseconds)
    if params["rate_limit"]:
        rate_limit_value = params["rate_limit"]
        if isinstance(rate_limit_value, int | float) and rate_limit_value > 0:
            # Convert requests per second to delay in milliseconds
            delay_ms = int(1000 / rate_limit_value)
            cmd_parts.extend(["--delay", str(delay_ms)])
        elif isinstance(rate_limit_value, str) and rate_limit_value.isdigit():
            # If it's already a delay value in string format
            delay_ms = int(rate_limit_value)
            if delay_ms > 0:
                cmd_parts.extend(["--delay", str(delay_ms)])

    # Force JSON output for structured parsing
    cmd_parts.extend(["--format", "json"])

    # Handle additional arguments with proper escaping and validation
    if params["additional_args"]:
        # Validate and sanitize additional arguments
        additional_args = _validate_additional_args(params["additional_args"])
        if additional_args:
            # Use shlex to safely split the arguments
            try:
                safe_args = shlex.split(additional_args)
                # Only allow known safe dirsearch arguments
                allowed_args = {
                    "--follow-redirects",
                    "--random-agents",
                    "--exclude-response",
                    "--exclude-sizes",
                    "--exclude-texts",
                    "--exclude-regexps",
                    "--include-status",
                    "--minimal",
                    "--suppress-empty",
                    "--full-url",
                    "--crawl",
                    "--deep-recursive",
                    "--force-recursive",
                    "--uppercase",
                    "--lowercase",
                    "--capitalization",
                }

                filtered_args = []
                for arg in safe_args:
                    if arg.startswith("-") and arg in allowed_args:
                        filtered_args.append(arg)
                    elif (
                        not arg.startswith("-")
                        and filtered_args
                        and filtered_args[-1] in allowed_args
                    ):
                        # Allow argument values for the previous option
                        filtered_args.append(arg)

                cmd_parts.extend(filtered_args)
            except ValueError as e:
                logger.warning(f"Invalid additional arguments format: {e}")

    return " ".join(shlex.quote(part) for part in cmd_parts)


def _parse_size_string(size_str: str) -> int:
    """Convert size string to bytes."""
    if not size_str or size_str == "-":
        return 0

    # Remove commas and convert to lowercase
    size_str = size_str.replace(",", "").lower()

    try:
        if size_str.endswith("kb"):
            return int(float(size_str[:-2]) * 1024)
        elif size_str.endswith("mb"):
            return int(float(size_str[:-2]) * 1024 * 1024)
        elif size_str.endswith("gb"):
            return int(float(size_str[:-2]) * 1024 * 1024 * 1024)
        elif size_str.endswith("b"):
            return int(size_str[:-1])
        else:
            return int(size_str)
    except (ValueError, TypeError):
        return 0


def _determine_endpoint_severity(
    status_code: int, path: str, size: int
) -> SeverityLevel:
    """Determine severity based on status code and path characteristics."""
    if status_code in [403, 401]:
        return "low"  # Authentication/authorization endpoints
    elif status_code >= 500:
        return "low"  # Server errors
    elif any(
        keyword in path.lower()
        for keyword in ["admin", "debug", "test", "config", "backup"]
    ):
        return "medium"  # Potentially sensitive paths
    elif status_code == 200 and size > 0:
        return "info"  # Successfully accessible content
    else:
        return "info"


def _parse_dirsearch_json_output(stdout: str) -> list[dict[str, Any]]:
    """Parse dirsearch JSON output into structured findings."""
    findings = []

    if not stdout.strip():
        return findings

    # Try to parse as JSON first
    try:
        # Dirsearch JSON format is one JSON object per line
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            try:
                result = json.loads(line)

                url = result.get("url", "")
                status_code = result.get("status", 0)
                content_length = result.get("content-length", 0)
                redirect_url = result.get("redirect", "")

                if url:
                    parsed_url = urlparse(url)
                    host = parsed_url.netloc
                    path = parsed_url.path or "/"

                    # Determine confidence based on response characteristics
                    confidence = "high"
                    if status_code == 0:
                        confidence = "low"
                    elif status_code >= 400:
                        confidence = "medium"

                    # Determine severity
                    severity = _determine_endpoint_severity(
                        status_code, path, content_length
                    )

                    # Build tags
                    tags = ["endpoint", "directory-enum"]
                    if status_code:
                        tags.append(f"status-{status_code}")
                    if redirect_url:
                        tags.append("redirect")
                    if parsed_url.scheme == "https":
                        tags.append("https")
                    else:
                        tags.append("http")

                    finding = create_finding(
                        finding_type="endpoint",
                        target=host,
                        evidence={
                            "url": url,
                            "path": path,
                            "status_code": status_code,
                            "content_length": content_length,
                            "redirect_url": redirect_url,
                            "scheme": parsed_url.scheme,
                            "port": parsed_url.port,
                            "discovered_by": "dirsearch",
                        },
                        severity=severity,
                        confidence=confidence,
                        tags=tags,
                        raw_ref=line,
                    )
                    findings.append(finding)

            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse dirsearch JSON line: {line} - {e}")
                continue

    except Exception as e:
        logger.warning(
            f"Failed to parse dirsearch JSON output, falling back to regex parsing: {e}"
        )
        # Fall back to regex parsing for non-JSON output
        return _parse_dirsearch_legacy_output(stdout)

    return findings


def _parse_dirsearch_legacy_output(raw_output: str) -> list[dict[str, Any]]:
    """Parse legacy dirsearch text output format."""
    findings = []

    if not raw_output:
        return findings

    lines = raw_output.split("\n")

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Match dirsearch output format: [timestamp] STATUS - SIZE - URL
        status_match = re.search(
            r"\[\d{2}:\d{2}:\d{2}\]\s+(\d{3})\s+-\s+(\d+[KMGT]?B?|\-)\s+-\s+(\S+)", line
        )

        if status_match:
            status_code, size, full_url = status_match.groups()

            try:
                parsed_url = urlparse(full_url)
                host = parsed_url.netloc
                path = parsed_url.path if parsed_url.path else "/"

                # Convert size to bytes
                content_length = _parse_size_string(size)

                # Determine confidence and severity
                confidence = "high" if int(status_code) < 400 else "medium"
                severity = _determine_endpoint_severity(
                    int(status_code), path, content_length
                )

                # Build tags
                tags = ["endpoint", "directory-enum", f"status-{status_code}"]
                if parsed_url.scheme == "https":
                    tags.append("https")
                else:
                    tags.append("http")

                finding = create_finding(
                    finding_type="endpoint",
                    target=host,
                    evidence={
                        "url": full_url,
                        "path": path,
                        "status_code": int(status_code),
                        "content_length": content_length,
                        "scheme": parsed_url.scheme,
                        "port": parsed_url.port,
                        "discovered_by": "dirsearch",
                    },
                    severity=severity,
                    confidence=confidence,
                    tags=tags,
                    raw_ref=line,
                )
                findings.append(finding)

            except Exception as e:
                logger.warning(f"Failed to parse dirsearch line: {line} - {e}")
                continue

    return findings


def _parse_dirsearch_result(
    execution_result, params, command, started_at: datetime, ended_at: datetime
) -> dict[str, Any]:
    """Parse dirsearch execution result and format response with findings."""
    if not execution_result["success"]:
        return {"findings": [], "stats": create_stats(0, 0, 0), "version": None}

    # Parse JSON output into structured findings
    stdout = execution_result.get("stdout", "")
    findings = _parse_dirsearch_json_output(stdout)

    # Remove duplicates based on URL
    seen_urls = set()
    unique_findings = []
    dupes_count = 0

    for finding in findings:
        url = finding["evidence"]["url"]
        if url not in seen_urls:
            seen_urls.add(url)
            unique_findings.append(finding)
        else:
            dupes_count += 1

    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "findings": unique_findings,
        "stats": create_stats(len(unique_findings), dupes_count, payload_bytes),
    }


@tool(required_fields=["url"])
def execute_dirsearch():
    """Execute Dirsearch for directory and file discovery."""
    data = request.get_json()
    params = _extract_dirsearch_params(data)

    logger.info(f"Executing Dirsearch on {params['url']}")

    started_at = datetime.now()
    command = _build_dirsearch_command(params)
    execution_result = execute_command(command, timeout=600)
    ended_at = datetime.now()

    return _parse_dirsearch_result(
        execution_result, params, command, started_at, ended_at
    )
