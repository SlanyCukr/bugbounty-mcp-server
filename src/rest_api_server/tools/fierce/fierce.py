"""fierce tool implementation."""

from datetime import datetime
from typing import Any

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool


def extract_fierce_params(data: dict) -> dict:
    """Extract and organize fierce parameters from request data."""
    return {
        "domain": data.get("target", ""),
        "dns_servers": data.get("dns_servers", []),
        "wide": data.get("wide", False),
        "connect": data.get("connect", False),
        "delay": data.get("delay", 0),
        "traverse": data.get("traverse"),
        "range": data.get("range"),
        "subdomain_file": data.get("subdomain_file"),
        "subdomains": data.get("subdomains", []),
        "tcp": data.get("tcp", False),
        "additional_args": data.get("additional_args", ""),
        "timeout": data.get("timeout", 600),
    }


def build_fierce_command(params: dict) -> list[str]:
    """Build the fierce command from parameters."""
    args = ["fierce", "--domain", params["domain"]]

    # Add optional parameters
    if params["dns_servers"]:
        if isinstance(params["dns_servers"], list):
            dns_servers_str = " ".join(params["dns_servers"])
        else:
            dns_servers_str = str(params["dns_servers"])
        args.extend(["--dns-servers", dns_servers_str])

    if params["wide"]:
        args.append("--wide")

    if params["connect"]:
        args.append("--connect")

    if params["delay"] > 0:
        args.extend(["--delay", str(params["delay"])])

    if params["traverse"]:
        args.extend(["--traverse", params["traverse"]])

    if params["range"]:
        args.extend(["--range", params["range"]])

    if params["subdomain_file"]:
        args.extend(["--subdomain-file", params["subdomain_file"]])

    if params["subdomains"]:
        if isinstance(params["subdomains"], list):
            subdomains_str = " ".join(params["subdomains"])
        else:
            subdomains_str = str(params["subdomains"])
        args.extend(["--subdomains", subdomains_str])

    if params["tcp"]:
        args.append("--tcp")

    # Add any additional arguments
    if params["additional_args"]:
        args.extend(params["additional_args"].split())

    return args


def parse_fierce_output(
    execution_result: dict[str, Any],
    params: dict,
    command: list[str],
    started_at: datetime,
    ended_at: datetime,
) -> dict[str, Any]:
    """Parse fierce execution results into structured findings."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if not execution_result["success"]:
        return {
            "success": False,
            "tool": "fierce",
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
    with open("/tmp/fierce_raw_output.log", "a") as f:
        f.write(stdout + "\n")
    findings = []

    # Extract subdomains from fierce output
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        # Parse subdomain findings
        subdomain_info = _extract_subdomain_from_line(line, params["domain"])
        if subdomain_info:
            finding = {
                "type": "subdomain",
                "target": subdomain_info.get("subdomain", line),
                "evidence": {
                    "raw_output": line,
                    "domain": params["domain"],
                    "discovered_by": "fierce",
                },
                "severity": "info",
                "confidence": "medium",
                "tags": ["fierce", "subdomain-discovery"],
                "raw_ref": line,
            }
            findings.append(finding)

    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "success": True,
        "tool": "fierce",
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


def _extract_subdomain_from_line(line: str, domain: str) -> dict[str, Any] | None:
    """Extract subdomain information from a single output line."""
    # Look for subdomain discoveries in fierce output
    # Fierce typically outputs found subdomains with IP addresses
    if "." in line and domain in line:
        # Basic pattern matching for subdomains
        parts = line.split()
        for part in parts:
            if part.endswith(f".{domain}"):
                subdomain = part.rstrip(".")
                if subdomain != domain:
                    return {
                        "subdomain": subdomain,
                        "domain": domain,
                        "raw_line": line,
                    }

    # If no subdomain found but line contains relevant content
    if any(
        keyword in line.lower()
        for keyword in ["found", "discovered", "subdomain", domain]
    ):
        return {"raw_line": line, "domain": domain}

    return None


@tool(required_fields=["target"])
def execute_fierce():
    """Execute Fierce for DNS reconnaissance and subdomain discovery."""
    data = request.get_json()
    params = extract_fierce_params(data)

    started_at = datetime.now()
    command = build_fierce_command(params)
    execution_result = execute_command(
        " ".join(command), timeout=params.get("timeout", 600)
    )
    ended_at = datetime.now()

    return parse_fierce_output(execution_result, params, command, started_at, ended_at)
