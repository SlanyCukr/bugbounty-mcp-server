"""waybackurls tool implementation."""

import logging
import shlex
from datetime import datetime
from typing import Any

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)

# Aggressive preset for waybackurls
AGGRESSIVE_PRESET = {
    "no_subs": False,  # Include subdomains
    "get_versions": True,
    "timeout": 120,
}


def extract_waybackurls_params(data: dict) -> dict[str, Any]:
    """Extract waybackurls parameters from request data."""
    # Check for aggressive mode
    aggressive = data.get("aggressive", False)

    # Extract parameters with basic defaults
    domain = data.get("url", data.get("domain", ""))

    # Base parameters without validation
    base_params = {
        "domain": domain,
        "no_subs": data.get("no_subs", False),
        "get_versions": data.get("get_versions", False),
        "dates": data.get("dates", ""),
        "output_file": data.get("output_file", ""),
        "timeout": data.get("timeout", 30),
        "additional_args": data.get("additional_args", ""),
    }

    # Apply aggressive preset if requested
    if aggressive:
        merged_params = base_params.copy()
        for key, aggressive_value in AGGRESSIVE_PRESET.items():
            if key not in base_params or base_params.get(key) in [
                True,
                False,
                30,
                None,
                "",
            ]:
                merged_params[key] = aggressive_value
        return merged_params

    return base_params


def build_waybackurls_command(params: dict) -> list[str]:
    """Build waybackurls command from parameters."""
    command_args = ["waybackurls", params["domain"]]

    if params["get_versions"]:
        command_args.append("--get-versions")

    if params["no_subs"]:
        command_args.append("--no-subs")

    if params["dates"]:
        command_args.extend(["--dates", params["dates"]])

    if params["output_file"]:
        command_args.extend(["-o", params["output_file"]])

    # Parse additional args safely
    if params["additional_args"]:
        try:
            additional_parsed = shlex.split(params["additional_args"])
            command_args.extend(additional_parsed)
        except ValueError as e:
            logger.warning(
                f"Invalid additional args: {params['additional_args']}, error: {e}"
            )
            # Skip invalid additional args rather than failing

    return command_args


def parse_waybackurls_output(
    execution_result: dict[str, Any],
    params: dict,
    command: list[str],
    started_at: datetime,
    ended_at: datetime,
) -> dict[str, Any]:
    """Parse waybackurls execution result and format response."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)
    command_str = " ".join(command)

    if execution_result["success"]:
        urls = [
            url.strip() for url in execution_result["stdout"].split("\n") if url.strip()
        ]

        # Convert URLs to findings format
        findings = []
        for url in urls:
            finding = {
                "type": "url",
                "target": url,
                "evidence": {
                    "raw_output": url,
                    "tool": "waybackurls",
                    "domain": params["domain"],
                },
                "severity": "info",
                "confidence": "high",
                "tags": ["waybackurls", "historical"],
                "raw_ref": url,
            }
            findings.append(finding)

        payload_bytes = len(execution_result["stdout"].encode("utf-8"))

        return {
            "tool": "waybackurls",
            "target": params["domain"],
            "parameters": params,
            "command": command_str,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "status": "completed",
            "urls": urls,
            "unique_urls": len(urls),
            "success": True,
            "stdout": execution_result["stdout"],
            "stderr": execution_result["stderr"]
            if execution_result["stderr"]
            else None,
            "findings": findings,
            "stats": {
                "findings": len(findings),
                "dupes": 0,
                "payload_bytes": payload_bytes,
            },
        }
    else:
        default_error = "Unknown error"
        error_msg = execution_result.get(
            "error", execution_result.get("stderr", default_error)
        )
        logger.error(
            "Waybackurls command failed: "
            f"{execution_result.get('error', 'Unknown error')}"
        )
        return {
            "tool": "waybackurls",
            "target": params["domain"],
            "parameters": params,
            "command": command_str,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "success": False,
            "status": "failed",
            "error": f"Waybackurls execution failed: {error_msg}",
            "findings": [],
            "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
        }


@tool(required_fields=["domain"])
def execute_waybackurls():
    """Execute Waybackurls for historical URL discovery."""
    data = request.get_json()
    params = extract_waybackurls_params(data)

    logger.info(f"Executing Waybackurls on {params['domain']}")

    started_at = datetime.now()
    command = build_waybackurls_command(params)
    execution_result = execute_command(command, timeout=params["timeout"])
    ended_at = datetime.now()

    return parse_waybackurls_output(
        execution_result, params, command, started_at, ended_at
    )
