"""Base Tool Pattern Template.

This file serves as a reference template for implementing security tools
following a consistent pattern without enforcing inheritance or complexity.

Tools should follow this pattern organically, not through inheritance.
The goal is consistency and separation of concerns, not enforcement.

Pattern Structure:
1. extract_params() - Extract and organize parameters from request data
2. build_command() - Build the command string/list from parameters
3. parse_output() - Parse execution results into structured findings
4. execute_*() - Main execution function (decorated with @tool)

Key Principles:
- NO base classes or inheritance
- NO validation logic in the pattern
- NO security enhancements - just structure
- Direct parameter usage
- Clear separation of concerns
- Simple and minimal
- Truncate findings to 100 max to prevent overload
"""

from datetime import datetime
from typing import Any

# Example template for a hypothetical security tool


def extract_params(data: dict) -> dict:
    """Extract and organize parameters from request data."""
    params = {
        "target": data.get("target"),
        "mode": data.get("mode", "default"),
        "timeout": data.get("timeout", 300),
    }

    return params


def build_command(params: dict) -> str | list[str]:
    """Build the command string/list from parameters."""
    cmd_parts = ["tool-name"]

    if params["mode"] != "default":
        cmd_parts.extend(["--mode", params["mode"]])

    if params["timeout"]:
        cmd_parts.extend(["--timeout", str(params["timeout"])])

    if params["target"]:
        cmd_parts.append(params["target"])

    return cmd_parts


def parse_output(
    execution_result: dict[str, Any],
    params: dict,
    command: str | list[str],
    started_at: datetime,
    ended_at: datetime,
) -> dict[str, Any]:
    """Parse execution results into structured findings."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if not execution_result["success"]:
        return {
            "success": False,
            "tool": "tool-name",
            "params": params,
            "command": command,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "error": execution_result.get("error", "Command execution failed"),
            "findings": [],
            "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
        }

    stdout = execution_result.get("stdout", "")
    findings = []

    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        finding = {
            "type": "finding_type",
            "target": line,
            "evidence": {
                "raw_output": line,
                "discovered_by": "tool-name",
            },
            "severity": "info",
            "confidence": "medium",
            "tags": ["tool-name"],
            "raw_ref": line,
        }
        findings.append(finding)

    if len(findings) > 100:
        findings = findings[:100]
        stats = {
            "findings": 100,
            "dupes": 0,
            "payload_bytes": len(stdout.encode("utf-8")),
            "truncated": True,
        }
    else:
        stats = {
            "findings": len(findings),
            "dupes": 0,
            "payload_bytes": len(stdout.encode("utf-8")),
            "truncated": False,
        }

    return {
        "success": True,
        "tool": "tool-name",
        "params": params,
        "command": command,
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat(),
        "duration_ms": duration_ms,
        "findings": findings,
        "stats": stats,
    }


# Example main execution function (actual implementation in tool files)
"""
from flask import request
from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool

@tool(required_fields=["target"])
def execute_tool_name():
    data = request.get_json()
    params = extract_params(data)

    started_at = datetime.now()
    command = build_command(params)
    execution_result = execute_command(command, timeout=params.get("timeout", 300))
    ended_at = datetime.now()

    return parse_output(execution_result, params, command, started_at, ended_at)
"""
