"""wafw00f tool implementation."""

import re
from datetime import datetime
from typing import Any

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool


def extract_wafw00f_params(data: dict) -> dict:
    """Extract and organize wafw00f parameters from request data."""
    return {
        "target": data["target"],
        "findall": data.get("findall", False),
        "verbose": data.get("verbose", False),
        "proxy": data.get("proxy", ""),
        "headers": data.get("headers", ""),
        "output_file": data.get("output_file", ""),
        "additional_args": data.get("additional_args", ""),
        "timeout": data.get("timeout", 120),
    }


def build_wafw00f_command(params: dict) -> list[str]:
    """Build the wafw00f command from parameters."""
    args = ["wafw00f", params["target"]]

    # Add optional parameters
    if params["findall"]:
        args.append("-a")

    if params["verbose"]:
        args.append("-v")

    if params["proxy"]:
        args.extend(["--proxy", params["proxy"]])

    if params["headers"]:
        args.extend(["--headers", params["headers"]])

    if params["output_file"]:
        args.extend(["-o", params["output_file"]])

    if params["additional_args"]:
        args.extend(params["additional_args"].split())

    return args


def parse_wafw00f_output(
    execution_result: dict[str, Any],
    params: dict,
    command: list[str],
    started_at: datetime,
    ended_at: datetime,
) -> dict[str, Any]:
    """Parse wafw00f execution results into structured findings."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if not execution_result["success"]:
        return {
            "success": False,
            "tool": "wafw00f",
            "params": params,
            "command": command,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "error": execution_result.get("error", "Command execution failed"),
            "findings": [],
            "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
        }

    # Parse successful output
    stdout = execution_result.get("stdout", "")
    findings = []

    # Extract WAF information from output
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        # Parse WAF findings
        waf_info = _extract_waf_from_line(line)
        if waf_info:
            finding = {
                "type": "waf",
                "target": waf_info.get("waf_name", params["target"]),
                "evidence": {
                    "raw_output": line,
                    "detection_method": waf_info.get("detection_method", "signature"),
                },
                "severity": "info",
                "confidence": waf_info.get("confidence", "medium"),
                "tags": ["wafw00f", "waf-detection"],
                "raw_ref": line,
            }
            findings.append(finding)

    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "success": True,
        "tool": "wafw00f",
        "params": params,
        "command": command,
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat(),
        "duration_ms": duration_ms,
        "findings": findings,
        "stats": {
            "findings": len(findings),
            "dupes": 0,
            "payload_bytes": payload_bytes,
        },
    }


def _extract_waf_from_line(line: str) -> dict[str, Any] | None:
    """Extract WAF information from a single output line."""
    # Pattern for WAF detection output
    patterns = [
        r"([A-Za-z0-9\s]+WAF|[A-Za-z0-9\s]+Firewall)",
        r"Detected:\s*([A-Za-z0-9\s]+)",
        r"WAF identified:\s*([A-Za-z0-9\s]+)",
        r"([A-Za-z]+)\s+(Firewall|WAF|Protection)",
    ]

    for pattern in patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            waf_name = match.group(1).strip()
            return {
                "waf_name": waf_name,
                "confidence": "medium",
                "detection_method": "signature",
                "raw_line": line,
            }

    # If no WAF found but line contains relevant content
    if any(
        keyword in line.lower()
        for keyword in ["waf", "firewall", "protection", "detected"]
    ):
        return {"raw_line": line, "detection_method": "unknown"}

    return None


@tool(required_fields=["target"])
def execute_wafw00f():
    """Execute wafw00f to identify Web Application Firewall (WAF) protection."""
    data = request.get_json()
    params = extract_wafw00f_params(data)

    started_at = datetime.now()
    command = build_wafw00f_command(params)
    execution_result = execute_command(
        " ".join(command), timeout=params.get("timeout", 120)
    )
    ended_at = datetime.now()

    return parse_wafw00f_output(execution_result, params, command, started_at, ended_at)
