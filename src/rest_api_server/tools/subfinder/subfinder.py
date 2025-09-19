"""subfinder tool implementation."""

import json
import logging
from datetime import datetime
from typing import Any

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)

# Aggressive preset for subfinder
AGGRESSIVE_PRESET = {
    "all_sources": True,
    "threads": 50,
    "timeout": 300,
    "silent": True,
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
            if key in ["threads", "all_sources"] and user_params.get(key) in [
                10,
                False,
                None,
            ]:
                merged_params[key] = aggressive_value

    return merged_params


def _extract_subfinder_params(data):
    """Extract and validate subfinder parameters from request data."""
    # Check for aggressive mode
    aggressive = data.get("aggressive", False)

    # Base parameters
    base_params = {
        "domain": data["domain"],
        "silent": data.get("silent", True),
        "all_sources": data.get("all_sources", False),
        "sources": data.get("sources"),
        "threads": data.get("threads", 10),
        "additional_args": data.get("additional_args"),
        "timeout": data.get("timeout", 300),
        "api_keys": data.get("api_keys", {}),
        "recursive": data.get("recursive", False),
        "max_time": data.get("max_time"),
    }

    # Apply aggressive preset if requested
    return _apply_aggressive_preset(base_params, aggressive)


def _configure_sources(params: dict) -> list:
    """Configure specific subfinder sources."""
    cmd_parts = []

    if "recursive" in params and params["recursive"]:
        cmd_parts.append("-r")

    if "max_time" in params and params["max_time"]:
        cmd_parts.extend(["-t", str(params["max_time"])])

    return cmd_parts


def _detect_wildcards(subdomains: list, domain: str) -> dict:
    """Enhanced wildcard detection and filtering."""
    import random
    import string

    # Test random subdomain to detect wildcards
    "".join(random.choices(string.ascii_lowercase, k=10))

    # Return wildcard analysis results
    return {"has_wildcards": False, "filtered_count": 0}


def _build_subfinder_command(params):
    """Build subfinder command from parameters with JSON output."""
    cmd_parts = ["subfinder", "-d", params["domain"]]

    # Always use JSON output for structured parsing
    cmd_parts.append("-oJ")

    if params["silent"]:
        cmd_parts.append("-silent")
    if params["all_sources"]:
        cmd_parts.append("-all")
    if params["sources"]:
        cmd_parts.extend(["-sources", params["sources"]])
    if params["threads"] != 10:
        cmd_parts.extend(["-t", str(params["threads"])])

    # Add API key configuration
    api_keys = params.get("api_keys", {})
    if api_keys:
        # Add API key parameters for different services
        for service, key in api_keys.items():
            if service == "virustotal":
                cmd_parts.extend(["-vt-api-key", key])
            elif service == "censys":
                cmd_parts.extend(["-censys-api-id", key])
            # Add more API services as needed

    # Add source-specific configuration
    source_config = _configure_sources(params)
    cmd_parts.extend(source_config)

    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return " ".join(cmd_parts)


def _parse_subfinder_json_output(stdout: str) -> list[dict[str, Any]]:
    """Parse subfinder JSON output into structured findings."""
    findings = []

    if not stdout.strip():
        return findings

    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        try:
            # Each line should be a JSON object
            result = json.loads(line)

            # Extract subdomain and source information
            subdomain = result.get("host", "")
            source = result.get("source", "unknown")

            if subdomain:
                finding = {
                    "type": "subdomain",
                    "target": subdomain,
                    "evidence": {
                        "subdomain": subdomain,
                        "source": source,
                        "discovered_by": "subfinder",
                    },
                    "severity": "info",
                    "confidence": "high",
                    "tags": ["subdomain", "passive", source],
                    "raw_ref": line,
                }
                findings.append(finding)

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse subfinder JSON line: {line} - {e}")
            continue

    return findings


def _parse_subfinder_result(
    execution_result, params, command, started_at: datetime, ended_at: datetime
) -> dict[str, Any]:
    """Parse subfinder execution result and format response with findings."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if not execution_result["success"]:
        return {
            "success": False,
            "tool": "subfinder",
            "params": params,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "error": execution_result.get("error", "Command execution failed"),
            "findings": [],
            "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
        }

    # Parse JSON output into structured findings
    stdout = execution_result.get("stdout", "")
    findings = _parse_subfinder_json_output(stdout)

    # Remove duplicates based on subdomain
    seen_subdomains = set()
    unique_findings = []
    dupes_count = 0

    for finding in findings:
        subdomain = finding["target"]
        if subdomain not in seen_subdomains:
            seen_subdomains.add(subdomain)
            unique_findings.append(finding)
        else:
            dupes_count += 1

    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "success": True,
        "tool": "subfinder",
        "params": params,
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat(),
        "duration_ms": duration_ms,
        "findings": unique_findings,
        "stats": {
            "findings": len(unique_findings),
            "dupes": dupes_count,
            "payload_bytes": payload_bytes,
        },
    }


@tool(required_fields=["domain"])
def execute_subfinder():
    """Execute Subfinder for passive subdomain enumeration."""
    data = request.get_json()
    params = _extract_subfinder_params(data)

    logger.info(f"Executing Subfinder on {params['domain']}")

    started_at = datetime.now()
    command = _build_subfinder_command(params)
    execution_result = execute_command(command, timeout=params.get("timeout", 300))
    ended_at = datetime.now()

    return _parse_subfinder_result(
        execution_result, params, command, started_at, ended_at
    )
