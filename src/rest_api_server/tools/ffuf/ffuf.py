"""ffuf tool implementation."""

import json
import logging
import time
from datetime import UTC, datetime

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.confidence_mapping import map_finding_confidence
from src.rest_api_server.utils.deduplication import deduplicate_findings
from src.rest_api_server.utils.registry import (
    create_finding,
    tool,
)
from src.rest_api_server.utils.severity_mapping import map_finding_severity

logger = logging.getLogger(__name__)

# Aggressive preset for ffuf
AGGRESSIVE_PRESET = {
    "wordlist": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "extensions": (
        "php,asp,aspx,jsp,jspx,html,htm,txt,bak,old,zip,tar,tar.gz,"
        "sql,xml,json,config,conf,ini,log"
    ),
    "threads": 100,
    "timeout": 30,
    "recursion": True,
    "recursion_depth": 3,
    "include_status": "200,204,301,302,307,401,403,500,503",
    "rate_limit": 500,
}


def _build_ffuf_command(url: str, params: dict) -> str:
    """Build comprehensive ffuf command with all parameters."""
    command_parts = ["ffuf"]

    # Ensure URL has FUZZ placeholder for directory fuzzing
    if "FUZZ" not in url:
        if url.endswith("/"):
            target_url = f"{url}FUZZ"
        else:
            target_url = f"{url}/FUZZ"
    else:
        target_url = url

    # Basic parameters
    command_parts.extend(["-u", target_url])
    command_parts.extend(["-w", params["wordlist"]])

    # Secondary wordlist
    if params.get("secondary_wordlist"):
        command_parts.extend(["-w", params["secondary_wordlist"]])

    # Status code filtering
    if params.get("include_status"):
        command_parts.extend(["-mc", params["include_status"]])

    if params.get("exclude_status"):
        command_parts.extend(["-fc", params["exclude_status"]])

    # Size filtering
    if params.get("include_size"):
        command_parts.extend(["-ms", params["include_size"]])

    if params.get("exclude_size"):
        command_parts.extend(["-fs", params["exclude_size"]])

    # Word count filtering
    if params.get("include_words"):
        command_parts.extend(["-mw", params["include_words"]])

    if params.get("exclude_words"):
        command_parts.extend(["-fw", params["exclude_words"]])

    # Line count filtering
    if params.get("include_lines"):
        command_parts.extend(["-ml", params["include_lines"]])

    if params.get("exclude_lines"):
        command_parts.extend(["-fl", params["exclude_lines"]])

    # Regex filtering
    if params.get("include_regex"):
        command_parts.extend(["-mr", params["include_regex"]])

    if params.get("exclude_regex"):
        command_parts.extend(["-fr", params["exclude_regex"]])

    # Extensions
    if params.get("extensions"):
        extensions = params["extensions"].split(",")
        for ext in extensions:
            ext = ext.strip()
            if not ext.startswith("."):
                ext = f".{ext}"
            command_parts.extend(["-e", ext])

    # Performance parameters
    threads = min(int(params.get("threads", 40)), 200)  # Cap at 200 threads
    command_parts.extend(["-t", str(threads)])

    if params.get("delay"):
        command_parts.extend(["-p", params["delay"]])

    if params.get("rate_limit"):
        command_parts.extend(["-rate", str(params["rate_limit"])])

    # HTTP method
    if params.get("method", "GET") != "GET":
        command_parts.extend(["-X", params["method"]])

    # Headers
    if params.get("headers"):
        headers = params["headers"]
        if isinstance(headers, str):
            # Split multiple headers if provided as string
            for header in headers.split(";"):
                if header.strip():
                    command_parts.extend(["-H", header.strip()])
        elif isinstance(headers, list):
            for header in headers:
                command_parts.extend(["-H", header])

    # Cookies
    if params.get("cookies"):
        command_parts.extend(["-b", params["cookies"]])

    # Proxy
    if params.get("proxy"):
        command_parts.extend(["-x", params["proxy"]])

    # Timeout
    if params.get("timeout"):
        command_parts.extend(["-timeout", str(params["timeout"])])

    # Recursion
    if params.get("recursion"):
        command_parts.append("-recursion")
        if params.get("recursion_depth"):
            command_parts.extend(["-recursion-depth", str(params["recursion_depth"])])

    # JSON output format for structured parsing
    command_parts.extend(["-of", "json"])

    # Silent mode for cleaner output
    command_parts.append("-s")

    # Handle additional arguments
    if params.get("additional_args"):
        command_parts.extend(params["additional_args"].split())

    return " ".join(command_parts)


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
                "recursion",
                "recursion_depth",
            ] and user_params.get(key) in [40, "", False, 1]:
                merged_params[key] = aggressive_value

    return merged_params


def _extract_ffuf_params(data):
    """Extract and validate ffuf parameters from request data."""
    # Check for aggressive mode
    aggressive = data.get("aggressive", False)

    url = data["url"]
    wordlist = data.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    extensions = data.get("extensions", "")
    threads = data.get("threads", 40)
    timeout = data.get("timeout", 10)
    method = data.get("method", "GET")
    additional_args = data.get("additional_args", "")

    include_status = data.get("include_status", "200,204,301,302,307,401,403,500")
    exclude_status = data.get("exclude_status", "")

    base_params = {
        "url": url,
        "wordlist": wordlist,
        "secondary_wordlist": data.get("secondary_wordlist", ""),
        "extensions": extensions,
        "force_extensions": data.get("force_extensions", False),
        "exclude_extensions": data.get("exclude_extensions", ""),
        "prefixes": data.get("prefixes", ""),
        "suffixes": data.get("suffixes", ""),
        "include_status": include_status,
        "exclude_status": exclude_status,
        "include_size": data.get("include_size", ""),
        "exclude_size": data.get("exclude_size", ""),
        "include_words": data.get("include_words", ""),
        "exclude_words": data.get("exclude_words", ""),
        "include_lines": data.get("include_lines", ""),
        "exclude_lines": data.get("exclude_lines", ""),
        "include_regex": data.get("include_regex", ""),
        "exclude_regex": data.get("exclude_regex", ""),
        "threads": threads,
        "delay": data.get("delay", ""),
        "timeout": timeout,
        "method": method,
        "headers": data.get("headers", ""),
        "cookies": data.get("cookies", ""),
        "proxy": data.get("proxy", ""),
        "rate_limit": data.get("rate_limit", ""),
        "recursion": data.get("recursion", False),
        "recursion_depth": data.get("recursion_depth", 1),
        "additional_args": additional_args,
    }

    # Apply aggressive preset if requested
    return _apply_aggressive_preset(base_params, aggressive)


def _parse_ffuf_findings(stdout: str) -> list[dict]:
    """Parse ffuf JSON output and extract findings."""
    findings = []

    if not stdout.strip():
        return findings

    try:
        # Parse JSON output
        data = json.loads(stdout)

        # Handle ffuf JSON structure
        results = data.get("results", [])
        if not isinstance(results, list):
            return findings

        for result in results:
            if not isinstance(result, dict):
                continue

            # Extract key information
            url = result.get("url", "")
            status = result.get("status", 0)
            length = result.get("length", 0)
            words = result.get("words", 0)
            lines = result.get("lines", 0)
            input_data = result.get("input", {})

            if not url:
                continue

            # Build evidence from ffuf result
            evidence = {
                "url": url,
                "status_code": status,
                "response_size": length,
                "word_count": words,
                "line_count": lines,
                "discovered_by": "ffuf",
            }

            # Add input information if available
            if input_data:
                evidence["fuzzed_input"] = input_data

            # Add redirectlocation if available
            if "redirectlocation" in result:
                evidence["redirect_location"] = result["redirectlocation"]

            # Determine target (extract base domain from URL)
            from urllib.parse import urlparse

            parsed_url = urlparse(url)
            target = parsed_url.netloc

            # Map severity using utility
            severity_info = {
                "tool": "ffuf",
                "status_code": status,
                "response_size": length,
                "url_path": parsed_url.path,
            }
            severity = map_finding_severity(severity_info)

            # Map confidence using utility
            confidence_info = {
                "tool": "ffuf",
                "status_code": status,
                "has_response": status > 0,
                "response_size": length,
                "word_count": words,
            }
            confidence = map_finding_confidence(confidence_info)

            # Build tags based on status code and characteristics
            tags = ["directory-enum", f"status-{status}"]

            # Add specific tags based on status code
            if status == 200:
                tags.append("found")
            elif status in [301, 302, 307]:
                tags.append("redirect")
            elif status in [401, 403]:
                tags.append("restricted")
            elif status >= 500:
                tags.append("server-error")

            # Add size-based tags
            if length > 10000:
                tags.append("large-response")
            elif length == 0:
                tags.append("empty-response")

            finding = create_finding(
                finding_type="endpoint",
                target=target,
                evidence=evidence,
                severity=severity,
                confidence=confidence,
                tags=tags,
                raw_ref=f"ffuf_{len(findings)}",
            )

            findings.append(finding)

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse ffuf JSON output: {e}")
        logger.debug(f"Raw output (first 500 chars): {stdout[:500]}")
    except Exception as e:
        logger.error(f"Error processing ffuf results: {e}")
        raise

    return findings


def _parse_ffuf_result(execution_result, params, command, start_time, end_time):
    """Parse ffuf execution result and format unified response."""
    duration_ms = int((end_time - start_time) * 1000)

    if not execution_result["success"]:
        return {
            "success": False,
            "tool": "ffuf",
            "params": params,
            "started_at": datetime.fromtimestamp(start_time, UTC).isoformat(),
            "ended_at": datetime.fromtimestamp(end_time, UTC).isoformat(),
            "duration_ms": duration_ms,
            "error": execution_result.get("stderr", "Command execution failed"),
            "findings": [],
            "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
        }

    # Parse findings if execution was successful
    stdout = execution_result.get("stdout", "")
    findings = _parse_ffuf_findings(stdout)

    # Use standardized deduplication
    unique_findings = deduplicate_findings(findings)
    dupes_count = len(findings) - len(unique_findings)

    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "success": True,
        "tool": "ffuf",
        "params": params,
        "started_at": datetime.fromtimestamp(start_time, UTC).isoformat(),
        "ended_at": datetime.fromtimestamp(end_time, UTC).isoformat(),
        "duration_ms": duration_ms,
        "findings": unique_findings,
        "stats": {
            "findings": len(unique_findings),
            "dupes": dupes_count,
            "payload_bytes": payload_bytes,
        },
    }


@tool(required_fields=["url"])
def execute_ffuf():
    """Execute FFuf web fuzzer."""
    data = request.get_json()
    params = _extract_ffuf_params(data)

    logger.info(f"Executing FFuf on {params['url']}")

    start_time = time.time()
    command = _build_ffuf_command(params["url"], params)
    execution_result = execute_command(command, timeout=params["timeout"] * 60)
    end_time = time.time()

    return _parse_ffuf_result(execution_result, params, command, start_time, end_time)
