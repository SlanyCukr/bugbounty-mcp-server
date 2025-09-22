"""sqlmap tool implementation."""

import logging
from datetime import datetime

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)


def extract_sqlmap_params(data):
    """Extract sqlmap parameters from request data."""
    params = {
        "url": data["url"],
        "data": data.get("data", ""),
        "method": data.get("method", "GET"),
        "headers": data.get("headers", ""),
        "cookies": data.get("cookies", ""),
        "level": data.get("level", 1),
        "risk": data.get("risk", 1),
        "technique": data.get("technique"),
        "dbms": data.get("dbms"),
        "threads": data.get("threads", 1),
        "delay": data.get("delay", 0),
        "timeout": data.get("timeout", 30),
        "retries": data.get("retries", 3),
        "random_agent": data.get("random_agent", True),
        "proxy": data.get("proxy", ""),
        "tor": data.get("tor", False),
        "tamper": data.get("tamper", ""),
        "additional_args": data.get("additional_args", ""),
    }

    return params


def build_sqlmap_command(params):
    """Build sqlmap command from parameters."""
    cmd_parts = ["sqlmap", "-u", params["url"]]

    if params["data"]:
        cmd_parts.extend(["--data", params["data"]])
    if params["method"] and params["method"] != "GET":
        cmd_parts.extend(["--method", params["method"]])

    if params["headers"]:
        cmd_parts.extend(["--headers", params["headers"]])
    if params["cookies"]:
        cmd_parts.extend(["--cookie", params["cookies"]])

    if params["level"] != 1:
        cmd_parts.extend(["--level", str(params["level"])])
    if params["risk"] != 1:
        cmd_parts.extend(["--risk", str(params["risk"])])
    if params["technique"]:
        cmd_parts.extend(["--technique", params["technique"]])
    if params["dbms"]:
        cmd_parts.extend(["--dbms", params["dbms"]])

    if params["threads"] > 1:
        cmd_parts.extend(["--threads", str(params["threads"])])
    if params["delay"] > 0:
        cmd_parts.extend(["--delay", str(params["delay"])])
    if params["timeout"] != 30:
        cmd_parts.extend(["--timeout", str(params["timeout"])])
    if params["retries"] != 3:
        cmd_parts.extend(["--retries", str(params["retries"])])

    if params["random_agent"]:
        cmd_parts.append("--random-agent")
    if params["proxy"]:
        cmd_parts.extend(["--proxy", params["proxy"]])
    if params["tor"]:
        cmd_parts.append("--tor")
    if params["tamper"]:
        cmd_parts.extend(["--tamper", params["tamper"]])

    cmd_parts.append("--batch")

    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return " ".join(cmd_parts)


def parse_sqlmap_output(raw_output: str, target_url: str) -> list[dict]:
    """Parse sqlmap text output format for basic vulnerability detection."""
    findings = []

    if not raw_output:
        return findings

    lines = raw_output.split("\n")
    injectable_found = False

    injection_indicators = [
        "is vulnerable",
        "injection point",
        "injectable",
        "vulnerable to sql injection",
        "sqli vulnerability",
        "appears to be injectable",
        "injection found",
        "successfully exploited",
        "payload was successful",
    ]

    for line in lines:
        line = line.strip()
        if not line:
            continue

        line_lower = line.lower()

        if any(indicator in line_lower for indicator in injection_indicators):
            injectable_found = True

            finding = {
                "type": "vulnerability",
                "target": target_url,
                "evidence": {
                    "raw_output": line,
                    "url": target_url,
                    "discovered_by": "sqlmap",
                    "vulnerability_type": "sql_injection",
                },
                "severity": "high",
                "confidence": "medium",
                "tags": ["sql-injection", "vulnerability", "sqlmap"],
                "raw_ref": line,
            }
            findings.append(finding)

    if (
        not injectable_found
        and target_url
        and (
            "scan finished" in raw_output.lower()
            or "all tested parameters" in raw_output.lower()
            or "no injectable parameters" in raw_output.lower()
        )
    ):
        finding = {
            "type": "scan_result",
            "target": target_url,
            "evidence": {
                "raw_output": "Scan completed - no SQL injection vulnerabilities found",
                "url": target_url,
                "discovered_by": "sqlmap",
                "result": "not_vulnerable",
            },
            "severity": "info",
            "confidence": "high",
            "tags": ["sql-injection-test", "scan-result", "sqlmap"],
            "raw_ref": "scan_completed_no_injection",
        }
        findings.append(finding)

    if len(findings) > 100:
        findings = findings[:100]

    return findings


def parse_sqlmap_result(
    execution_result, params, command, started_at: datetime, ended_at: datetime
):
    """Parse sqlmap execution result and format response."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if not execution_result["success"]:
        return {
            "tool": "sqlmap",
            "params": params,
            "command": command,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "success": False,
            "error": execution_result.get("stderr", "Command execution failed"),
            "findings": [],
            "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
        }

    stdout = execution_result.get("stdout", "")
    findings = parse_sqlmap_output(stdout, params["url"])

    payload_bytes = len(stdout.encode("utf-8"))
    truncated = len(findings) > 100

    stats = {
        "findings": len(findings),
        "dupes": 0,
        "payload_bytes": payload_bytes,
        "truncated": truncated,
    }

    return {
        "tool": "sqlmap",
        "params": params,
        "command": command,
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat(),
        "duration_ms": duration_ms,
        "success": True,
        "findings": findings,
        "stats": stats,
    }


@tool(required_fields=["url"])
def execute_sqlmap():
    """Execute SQLMap for SQL injection testing."""
    data = request.get_json()
    params = extract_sqlmap_params(data)

    logger.info(f"Executing SQLMap on {params['url']}")

    started_at = datetime.now()
    command = build_sqlmap_command(params)
    execution_result = execute_command(command, timeout=900)
    ended_at = datetime.now()

    return parse_sqlmap_result(execution_result, params, command, started_at, ended_at)
