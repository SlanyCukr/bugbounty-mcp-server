"""feroxbuster tool implementation."""

import json
import logging
import os
import re
import shlex
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import (
    create_finding,
    create_stats,
    tool,
)
from src.rest_api_server.utils.severity_mapping import map_finding_severity

logger = logging.getLogger(__name__)

# Aggressive preset for feroxbuster
AGGRESSIVE_PRESET = {
    "wordlist": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "extensions": (
        "php,asp,aspx,jsp,jspx,html,htm,txt,bak,old,"
        "zip,tar,tar.gz,sql,xml,json,config,conf,ini,log"
    ),
    "threads": 100,
    "depth": 3,
    "timeout": 10,
    "rate_limit": 500,
    "status_codes": "200,204,301,302,307,401,403,500,503",
    "filter_status": "404",
    "auto_tune": True,
    "filter_size": "",
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
            if key in ["threads", "rate_limit", "depth"] and user_params.get(key) in [
                50,
                "",
                1,
            ]:
                merged_params[key] = aggressive_value

    return merged_params


def _extract_feroxbuster_params(data):
    """Extract and validate feroxbuster parameters from request data."""
    # Check for aggressive mode
    aggressive = data.get("aggressive", False)

    # Base parameters
    base_params = {
        "url": data["url"],
        "wordlist": data.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
        "extensions": data.get("extensions", ""),
        "threads": data.get("threads", 50),
        "depth": data.get("depth", 1),
        "timeout": data.get("timeout", 7),
        "rate_limit": data.get("rate_limit", ""),
        "status_codes": data.get("status_codes", ""),
        "filter_status": data.get("filter_status", ""),
        "auto_tune": data.get("auto_tune", False),
        "filter_size": data.get("filter_size", ""),
        "additional_args": data.get("additional_args", ""),
    }

    # Apply aggressive preset if requested
    return _apply_aggressive_preset(base_params, aggressive)


def _validate_wordlist(wordlist_path):
    """Validate wordlist file exists."""
    if not os.path.exists(wordlist_path):
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")
    return True


def _build_feroxbuster_command(params):
    """Build feroxbuster command from parameters with secure argument handling."""
    # Validate wordlist first
    _validate_wordlist(params["wordlist"])

    # Build feroxbuster command with proper security escaping
    cmd_parts = [
        "feroxbuster",
        "-u",
        shlex.quote(params["url"]),
        "-w",
        shlex.quote(params["wordlist"]),
    ]

    cmd_parts.extend(["-t", str(params["threads"])])
    cmd_parts.extend(["-d", str(params["depth"])])
    cmd_parts.extend(["-T", str(params["timeout"])])

    # Add rate limiting support
    if params.get("rate_limit"):
        cmd_parts.extend(["-L", str(params["rate_limit"])])

    if params["extensions"]:
        cmd_parts.extend(["-x", shlex.quote(params["extensions"])])

    # Add status code inclusion support
    if params.get("status_codes"):
        cmd_parts.extend(["-s", shlex.quote(params["status_codes"])])

    # Filter status codes (exclusion)
    if params.get("filter_status"):
        cmd_parts.extend(["-C", shlex.quote(params["filter_status"])])

    # Add auto-filtering support
    if params.get("auto_tune", False):
        cmd_parts.append("--auto-tune")

    if params.get("filter_size"):
        cmd_parts.extend(["-S", str(params["filter_size"])])

    cmd_parts.append("--json")

    # Handle additional arguments securely
    if params["additional_args"]:
        try:
            # Split and quote each argument properly
            additional_parts = shlex.split(params["additional_args"])
            for part in additional_parts:
                cmd_parts.append(shlex.quote(part))
        except ValueError:
            # Invalid shell syntax - reject
            raise ValueError("Invalid additional arguments format") from None

    # CRITICAL SECURITY FIX: Return properly escaped string, not array
    return " ".join(cmd_parts)


def _determine_ferox_severity(status_code: int, url: str, content_length: int) -> str:
    """Determine severity based on status code and URL characteristics."""
    parsed_url = urlparse(url)
    path = parsed_url.path.lower()

    if status_code in [403, 401]:
        return "low"  # Authentication/authorization endpoints
    elif status_code >= 500:
        return "low"  # Server errors
    elif any(
        keyword in path
        for keyword in ["admin", "debug", "test", "config", "backup", "login"]
    ):
        return "medium"  # Potentially sensitive paths
    elif status_code == 200 and content_length > 0:
        return "info"  # Successfully accessible content
    else:
        return "info"


def _parse_feroxbuster_result(
    execution_result, params, command, started_at: datetime, ended_at: datetime
) -> dict[str, Any]:
    """Parse feroxbuster execution result and format response with findings."""
    if not execution_result["success"]:
        return {"findings": [], "stats": create_stats(0, 0, 0)}

    findings = []
    stdout = execution_result.get("stdout", "")

    # Parse JSON output
    for line in stdout.split("\n"):
        if line.strip():
            try:
                result_data = json.loads(line)
                if result_data.get("type") == "response":
                    url = result_data.get("url", "")
                    status_code = result_data.get("status", 0)
                    content_length = result_data.get("content_length", 0)
                    word_count = result_data.get("word_count", 0)
                    line_count = result_data.get("line_count", 0)

                    if url:
                        parsed_url = urlparse(url)
                        host = parsed_url.netloc
                        path = parsed_url.path or "/"

                        # Calculate depth
                        depth = len(url.rstrip("/").split("/")) - 3 if url else 0

                        # Determine confidence based on response characteristics
                        confidence = "high"
                        if status_code == 0:
                            confidence = "low"
                        elif status_code >= 400:
                            confidence = "medium"

                        # Determine severity using mapping utility
                        severity_info = {
                            "tool": "feroxbuster",
                            "status_code": status_code,
                            "response_size": content_length,
                            "url_path": path,
                            "url": url,
                        }
                        severity = map_finding_severity(severity_info)

                        # Build tags
                        tags = ["endpoint", "directory-enum", "recursive"]
                        if status_code:
                            tags.append(f"status-{status_code}")
                        if depth > 1:
                            tags.append("deep-path")
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
                                "word_count": word_count,
                                "line_count": line_count,
                                "depth": depth,
                                "scheme": parsed_url.scheme,
                                "port": parsed_url.port,
                                "discovered_by": "feroxbuster",
                            },
                            severity=severity,
                            confidence=confidence,
                            tags=tags,
                            raw_ref=line,
                        )
                        findings.append(finding)

            except json.JSONDecodeError:
                continue

    # Fallback to plain text parsing if no JSON results
    if not findings and stdout:
        logger.info("JSON parsing yielded no results, attempting plain text parsing")
        for line in stdout.split("\n"):
            if line.strip():
                match = re.search(
                    r"(\d{3})\s+\d+l\s+\d+w\s+(\d+)c\s+(https?://[^\s]+)", line
                )
                if match:
                    status_code, size, url = match.groups()

                    parsed_url = urlparse(url)
                    host = parsed_url.netloc
                    path = parsed_url.path or "/"

                    depth = len(url.rstrip("/").split("/")) - 3 if url else 0
                    confidence = "high" if int(status_code) < 400 else "medium"

                    # Determine severity using mapping utility
                    severity_info = {
                        "tool": "feroxbuster",
                        "status_code": int(status_code),
                        "response_size": int(size),
                        "url_path": path,
                        "url": url,
                    }
                    severity = map_finding_severity(severity_info)

                    tags = [
                        "endpoint",
                        "directory-enum",
                        "recursive",
                        f"status-{status_code}",
                    ]
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
                            "status_code": int(status_code),
                            "content_length": int(size),
                            "depth": depth,
                            "scheme": parsed_url.scheme,
                            "port": parsed_url.port,
                            "discovered_by": "feroxbuster",
                        },
                        severity=severity,
                        confidence=confidence,
                        tags=tags,
                        raw_ref=line,
                    )
                    findings.append(finding)

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
def execute_feroxbuster():
    """Execute Feroxbuster for fast recursive directory scanning."""
    data = request.get_json()
    params = _extract_feroxbuster_params(data)

    logger.info(f"Executing Feroxbuster on {params['url']}")

    started_at = datetime.now()
    command = _build_feroxbuster_command(params)
    execution_result = execute_command(command, timeout=1800)  # 30 minute timeout
    ended_at = datetime.now()

    return _parse_feroxbuster_result(
        execution_result, params, command, started_at, ended_at
    )
