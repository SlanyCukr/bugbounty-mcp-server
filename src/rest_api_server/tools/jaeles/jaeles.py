"""jaeles tool implementation."""

import re
from datetime import datetime
from typing import Any

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool


def extract_jaeles_params(data: dict) -> dict:
    """Extract and organize jaeles parameters from request data."""
    url = data["url"]
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return {
        "url": url,
        "signatures": data.get("signatures", ""),
        "config": data.get("config", ""),
        "threads": data.get("threads", 20),
        "timeout": data.get("timeout", 20),
        "level": data.get("level", ""),
        "passive": data.get("passive", False),
        "output_file": data.get("output_file", ""),
        "proxy": data.get("proxy", ""),
        "headers": data.get("headers", ""),
        "verbose": data.get("verbose", False),
        "debug": data.get("debug", False),
        "additional_args": data.get("additional_args", ""),
    }


def build_jaeles_command(params: dict) -> list[str]:
    """Build the jaeles command from parameters."""
    args = ["jaeles", "scan", "-u", params["url"]]

    # Add concurrency/threads parameter
    args.extend(["-c", str(params["threads"])])

    # Add timeout parameter
    args.extend(["--timeout", str(params["timeout"])])

    # Add signatures parameter if provided
    if params["signatures"]:
        args.extend(["-s", params["signatures"]])

    # Add config parameter if provided
    if params["config"]:
        args.extend(["--config", params["config"]])

    # Add level parameter if provided
    if params["level"]:
        args.extend(["--level", params["level"]])

    # Add passive scanning option
    if params["passive"]:
        args.append("--passive")

    # Add output file if provided
    if params["output_file"]:
        args.extend(["-o", params["output_file"]])

    # Add proxy if provided
    if params["proxy"]:
        args.extend(["--proxy", params["proxy"]])

    # Add headers if provided
    if params["headers"]:
        args.extend(["-H", params["headers"]])

    # Add verbose flag
    if params["verbose"]:
        args.append("-v")

    # Add debug flag
    if params["debug"]:
        args.append("--debug")

    # Add any additional arguments
    if params["additional_args"]:
        args.extend(params["additional_args"].split())

    return args


def parse_jaeles_output(
    execution_result: dict[str, Any],
    params: dict,
    command: list[str],
    started_at: datetime,
    ended_at: datetime,
) -> dict[str, Any]:
    """Parse jaeles execution results into structured findings."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if not execution_result["success"]:
        return {
            "success": False,
            "tool": "jaeles",
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

    # Extract vulnerabilities from jaeles output
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        # Parse vulnerability findings
        vuln_info = _extract_vulnerability_from_line(line, params)
        if vuln_info:
            finding = {
                "type": "vulnerability",
                "target": vuln_info.get("target", params["url"]),
                "evidence": {
                    "raw_output": line,
                    "signature": vuln_info.get("signature"),
                    "severity": vuln_info.get("severity", "medium"),
                },
                "severity": vuln_info.get("severity", "medium"),
                "confidence": vuln_info.get("confidence", "medium"),
                "tags": ["jaeles", "vulnerability-scan"],
                "raw_ref": line,
            }
            findings.append(finding)

    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "success": True,
        "tool": "jaeles",
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


def _extract_vulnerability_from_line(line: str, params: dict) -> dict[str, Any] | None:
    """Extract vulnerability information from a single output line."""
    # Pattern for jaeles vulnerability output
    patterns = [
        r"\[([^\]]+)\]\s*\[([^\]]+)\]\s*(.+)",
        r"([A-Za-z]+)\s*:\s*(.+)",
        r"Found\s+([A-Za-z\s]+)\s+at\s+(.+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            groups = match.groups()
            if len(groups) >= 2:
                return {
                    "signature": groups[0],
                    "target": groups[1] if len(groups) > 1 else params.get("url"),
                    "severity": "medium",
                    "confidence": "medium",
                    "raw_line": line,
                }

    return None


@tool(required_fields=["url"])
def execute_jaeles():
    """Execute Jaeles for advanced vulnerability scanning with custom signatures."""
    data = request.get_json()
    params = extract_jaeles_params(data)

    started_at = datetime.now()
    command = build_jaeles_command(params)
    execution_result = execute_command(command, timeout=params["timeout"] + 30)
    ended_at = datetime.now()

    return parse_jaeles_output(execution_result, params, command, started_at, ended_at)
