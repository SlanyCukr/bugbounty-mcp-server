"""arjun tool implementation."""

import json
import logging
import re
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import create_finding, create_stats, tool

logger = logging.getLogger(__name__)

# Aggressive preset for arjun
AGGRESSIVE_PRESET = {
    "threads": 50,
    "delay": 0,
    "timeout": 30,
    "get": True,
    "post": True,
    "json": True,
    "stable": True,
    "passive": False,  # Use active scanning
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
            if key in ["threads", "delay", "timeout", "stable"] and user_params.get(
                key
            ) in [10, 0, False]:
                merged_params[key] = aggressive_value

    return merged_params


def _extract_arjun_params(data):
    """Extract and validate arjun parameters from request data."""
    # Check for aggressive mode
    aggressive = data.get("aggressive", False)

    base_params = {
        "url": data["url"],
        "threads": data.get("threads", 10),
        "methods": data.get("methods", "GET,POST"),
        "wordlist": data.get("wordlist", ""),
        "headers": data.get("headers", ""),
        "post_data": data.get("post_data", ""),
        "delay": data.get("delay", 0),
        "timeout": data.get("timeout", 10),
        "stable": data.get("stable", False),
        "include_status": data.get("include_status", ""),
        "exclude_status": data.get("exclude_status", ""),
        "output_file": data.get("output_file", ""),
        "additional_args": data.get("additional_args", ""),
    }

    # Apply aggressive preset if requested
    return _apply_aggressive_preset(base_params, aggressive)


def _build_arjun_command(params):
    """Build arjun command from parameters with proper input validation."""
    import shlex
    from pathlib import Path

    # Validate and sanitize URL
    url = params["url"]
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")

    # Basic URL validation
    if not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError("URL must start with http:// or https://")

    # Use shlex.quote to prevent command injection
    cmd_parts = ["arjun", "-u", shlex.quote(url)]

    # Validate and add threads (integer validation)
    threads = params.get("threads", 10)
    if not isinstance(threads, int) or threads <= 0 or threads > 100:
        threads = 10  # Safe default
    cmd_parts.extend(["-t", str(threads)])

    # Add HTTP methods with validation
    methods = params.get("methods", "")
    if methods and isinstance(methods, str):
        # Validate allowed HTTP methods
        allowed_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
        method_list = [m.strip().upper() for m in methods.split(",")]
        valid_methods = [m for m in method_list if m in allowed_methods]
        if valid_methods:
            cmd_parts.extend(["-m", ",".join(valid_methods)])

    # Add wordlist with path validation
    wordlist = params.get("wordlist", "")
    if wordlist and isinstance(wordlist, str):
        # Validate wordlist path to prevent path traversal
        wordlist_path = Path(wordlist).resolve()
        # Only allow wordlists in specific directories or absolute paths that exist
        if wordlist_path.exists() and wordlist_path.is_file():
            cmd_parts.extend(["-w", shlex.quote(str(wordlist_path))])

    # Add headers with validation
    headers = params.get("headers", "")
    if headers and isinstance(headers, str):
        # Basic header validation - no dangerous characters
        if not any(char in headers for char in [";", "&", "|", "`", "$", "(", ")"]):
            cmd_parts.extend(["--headers", shlex.quote(headers)])

    # Add POST data with validation
    post_data = params.get("post_data", "")
    if post_data and isinstance(post_data, str):
        cmd_parts.extend(["--data", shlex.quote(post_data)])

    # Add delay with validation
    delay = params.get("delay", 0)
    if isinstance(delay, int | float) and 0 <= delay <= 60:
        if delay > 0:
            cmd_parts.extend(["-d", str(delay)])

    # Add timeout with validation
    timeout = params.get("timeout", 10)
    if isinstance(timeout, int) and timeout > 0 and timeout <= 3600:  # Max 1 hour
        cmd_parts.extend(["--timeout", str(timeout)])

    # Add stable mode
    stable = params.get("stable", False)
    if stable is True:
        cmd_parts.append("--stable")

    # Add status code filters with validation
    include_status = params.get("include_status", "")
    if include_status and isinstance(include_status, str):
        # Validate status codes (3-digit numbers, comma-separated)
        import re

        if re.match(r"^(\d{3})(,\d{3})*$", include_status):
            cmd_parts.extend(["--include-status", include_status])

    exclude_status = params.get("exclude_status", "")
    if exclude_status and isinstance(exclude_status, str):
        # Validate status codes (3-digit numbers, comma-separated)
        import re

        if re.match(r"^(\d{3})(,\d{3})*$", exclude_status):
            cmd_parts.extend(["--exclude-status", exclude_status])

    # Force JSON output for structured parsing
    cmd_parts.append("--json")

    # Add output file with path validation
    output_file = params.get("output_file", "")
    if output_file and isinstance(output_file, str):
        # Validate output file path to prevent path traversal
        output_path = Path(output_file).resolve()

        # Ensure output directory exists and is writable
        output_dir = output_path.parent
        if not output_dir.exists():
            try:
                output_dir.mkdir(parents=True, exist_ok=True)
            except (OSError, PermissionError):
                # Skip output file if we can't create directory
                pass

        # Only add if path is safe (no traversal attempts)
        if not any(part in str(output_path) for part in ["../", "..\\", "~/"]):
            cmd_parts.extend(["-o", shlex.quote(str(output_path))])

    # Handle additional arguments with strict validation
    additional_args = params.get("additional_args", "")
    if additional_args and isinstance(additional_args, str):
        # Parse and validate each additional argument
        try:
            parsed_args = shlex.split(additional_args)
            # Only allow safe arguments (no shell operators)
            safe_args = []
            for arg in parsed_args:
                if not any(
                    char in arg for char in [";", "&", "|", "`", "$", "(", ")", ">"]
                ):
                    safe_args.append(shlex.quote(arg))
            if safe_args:
                cmd_parts.extend(safe_args)
        except ValueError:
            # Skip malformed additional arguments
            pass

    return cmd_parts  # Return as list for secure execution


def _parse_arjun_json_output(stdout: str) -> list[dict[str, Any]]:
    """Parse arjun JSON output into structured findings."""
    findings = []

    if not stdout.strip():
        return findings

    try:
        # Arjun outputs JSON data
        data = json.loads(stdout)

        # Handle different arjun output formats
        if isinstance(data, dict):
            url = data.get("url", "")
            parameters = data.get("parameters", [])

            if url and parameters:
                parsed_url = urlparse(url)
                host = parsed_url.netloc

                for param_data in parameters:
                    if isinstance(param_data, dict):
                        param_name = param_data.get("name", "")
                        method = param_data.get("method", "GET")

                        if param_name:
                            tags = ["parameter", "discovery", method.lower()]
                            if parsed_url.scheme == "https":
                                tags.append("https")
                            else:
                                tags.append("http")

                            finding = create_finding(
                                finding_type="param",
                                target=host,
                                evidence={
                                    "parameter_name": param_name,
                                    "method": method,
                                    "url": url,
                                    "path": parsed_url.path,
                                    "scheme": parsed_url.scheme,
                                    "port": parsed_url.port,
                                    "discovered_by": "arjun",
                                },
                                severity="info",
                                confidence="medium",
                                tags=tags,
                                raw_ref=json.dumps(param_data),
                            )
                            findings.append(finding)
                    elif isinstance(param_data, str):
                        # Simple parameter name
                        tags = ["parameter", "discovery"]
                        if parsed_url.scheme == "https":
                            tags.append("https")
                        else:
                            tags.append("http")

                        finding = create_finding(
                            finding_type="param",
                            target=host,
                            evidence={
                                "parameter_name": param_data,
                                "url": url,
                                "path": parsed_url.path,
                                "scheme": parsed_url.scheme,
                                "port": parsed_url.port,
                                "discovered_by": "arjun",
                            },
                            severity="info",
                            confidence="medium",
                            tags=tags,
                            raw_ref=param_data,
                        )
                        findings.append(finding)

        elif isinstance(data, list):
            # Handle list format
            for item in data:
                if isinstance(item, str):
                    # Simple parameter name without URL context
                    finding = create_finding(
                        finding_type="param",
                        target="unknown",
                        evidence={"parameter_name": item, "discovered_by": "arjun"},
                        severity="info",
                        confidence="low",
                        tags=["parameter", "discovery"],
                        raw_ref=item,
                    )
                    findings.append(finding)

    except json.JSONDecodeError:
        logger.warning(
            "Failed to parse arjun JSON output, falling back to text parsing"
        )
        return _parse_arjun_text_output(stdout)

    return findings


def _parse_arjun_text_output(raw_output: str) -> list[dict[str, Any]]:
    """Parse arjun text output format as fallback."""
    findings = []

    if not raw_output:
        return findings

    lines = raw_output.split("\n")
    current_url = None

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Look for URL context
        if line.startswith("http") and "://" in line:
            current_url = line
            continue

        # Look for parameter findings
        # Common arjun output patterns
        if "Parameter" in line or "Found" in line:
            # Extract parameter name
            param_match = re.search(r"Parameter:\s*(\w+)", line, re.IGNORECASE)
            if not param_match:
                param_match = re.search(r"Found:\s*(\w+)", line, re.IGNORECASE)

            if param_match:
                param_name = param_match.group(1)

                if current_url:
                    parsed_url = urlparse(current_url)
                    host = parsed_url.netloc

                    tags = ["parameter", "discovery"]
                    if parsed_url.scheme == "https":
                        tags.append("https")
                    else:
                        tags.append("http")

                    finding = create_finding(
                        finding_type="param",
                        target=host,
                        evidence={
                            "parameter_name": param_name,
                            "url": current_url,
                            "path": parsed_url.path,
                            "scheme": parsed_url.scheme,
                            "port": parsed_url.port,
                            "discovered_by": "arjun",
                        },
                        severity="info",
                        confidence="medium",
                        tags=tags,
                        raw_ref=line,
                    )
                else:
                    finding = create_finding(
                        finding_type="param",
                        target="unknown",
                        evidence={
                            "parameter_name": param_name,
                            "discovered_by": "arjun",
                        },
                        severity="info",
                        confidence="low",
                        tags=["parameter", "discovery"],
                        raw_ref=line,
                    )

                findings.append(finding)

    return findings


def _parse_arjun_result(
    execution_result, params, command, started_at: datetime, ended_at: datetime
) -> dict[str, Any]:
    """Parse arjun execution result and format response with findings."""
    if not execution_result["success"]:
        return {"findings": [], "stats": create_stats(0, 0, 0)}

    # Parse JSON output into structured findings
    stdout = execution_result.get("stdout", "")
    findings = _parse_arjun_json_output(stdout)

    # Remove duplicates based on parameter name and target
    seen_params = set()
    unique_findings = []
    dupes_count = 0

    for finding in findings:
        param_name = finding["evidence"]["parameter_name"]
        target = finding["target"]
        unique_key = f"{target}:{param_name}"

        if unique_key not in seen_params:
            seen_params.add(unique_key)
            unique_findings.append(finding)
        else:
            dupes_count += 1

    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "findings": unique_findings,
        "stats": create_stats(len(unique_findings), dupes_count, payload_bytes),
    }


@tool(required_fields=["url"])
def execute_arjun():
    """Execute Arjun for HTTP parameter discovery."""
    data = request.get_json()
    params = _extract_arjun_params(data)

    logger.info(f"Executing Arjun on {params['url']}")

    started_at = datetime.now()
    command_parts = _build_arjun_command(params)
    # Pass command as array for secure execution
    execution_result = execute_command(
        command_parts, timeout=600
    )  # 10 minute timeout for arjun
    ended_at = datetime.now()

    return _parse_arjun_result(
        execution_result, params, command_parts, started_at, ended_at
    )
