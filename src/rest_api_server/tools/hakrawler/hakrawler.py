"""hakrawler tool implementation."""

import re
import shlex
from datetime import datetime
from typing import Any

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool


def extract_hakrawler_params(data: dict) -> dict:
    """Extract and organize hakrawler parameters from request data."""
    return {
        "url": data["url"],
        "depth": data.get("depth", 2),
        "forms": data.get("forms", True),
        "robots": data.get("robots", True),
        "sitemap": data.get("sitemap", True),
        "wayback": data.get("wayback", False),
        "insecure": data.get("insecure", False),
        "additional_args": data.get("additional_args", ""),
        "timeout": data.get("timeout", 120),
    }


def build_hakrawler_command(params: dict) -> list[str]:
    """Build the hakrawler command from parameters."""
    args = ["hakrawler"]

    # Add URL
    args.extend(["-url", params["url"]])

    # Add depth parameter
    args.extend(["-depth", str(params["depth"])])

    # Add boolean flags only if enabled
    if params["forms"]:
        args.append("-forms")
    if params["robots"]:
        args.append("-robots")
    if params["sitemap"]:
        args.append("-sitemap")
    if params["wayback"]:
        args.append("-wayback")
    if params["insecure"]:
        args.append("-insecure")

    # Add additional arguments
    if params["additional_args"]:
        args.extend(shlex.split(params["additional_args"]))

    return args


def parse_hakrawler_output(
    execution_result: dict[str, Any],
    params: dict,
    command: list[str],
    started_at: datetime,
    ended_at: datetime,
) -> dict[str, Any]:
    """Parse hakrawler execution results into structured findings."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if not execution_result["success"]:
        return {
            "success": False,
            "tool": "hakrawler",
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

    # Extract URLs from hakrawler output
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        # Parse URL findings
        url_info = _extract_url_from_line(line)
        if url_info:
            finding = {
                "type": "url",
                "target": url_info.get("url", line),
                "evidence": {
                    "raw_output": line,
                    "source": url_info.get("source", "crawl"),
                },
                "severity": "info",
                "confidence": "medium",
                "tags": ["hakrawler", "url-discovery"],
                "raw_ref": line,
            }
            findings.append(finding)

    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "success": True,
        "tool": "hakrawler",
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


def _extract_url_from_line(line: str) -> dict[str, Any] | None:
    """Extract URL information from a single output line."""
    # Simple URL pattern matching
    url_pattern = r"https?://[^\s]+"
    match = re.search(url_pattern, line)
    if match:
        url = match.group(0)
        return {
            "url": url,
            "source": "crawl",
            "raw_line": line,
        }

    # If no URL found but line contains relevant content
    if any(keyword in line.lower() for keyword in ["found", "discovered", "url"]):
        return {"raw_line": line, "source": "unknown"}

    return None


@tool(required_fields=["url"])
def execute_hakrawler():
    """Execute hakrawler for fast web crawling and endpoint discovery."""
    data = request.get_json()
    params = extract_hakrawler_params(data)

    started_at = datetime.now()
    command = build_hakrawler_command(params)
    execution_result = execute_command(
        " ".join(command), timeout=params.get("timeout", 120)
    )
    ended_at = datetime.now()

    return parse_hakrawler_output(
        execution_result, params, command, started_at, ended_at
    )
