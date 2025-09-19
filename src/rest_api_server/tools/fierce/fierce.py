"""fierce tool implementation."""

import logging
from datetime import datetime

from flask import jsonify, request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_fierce_params(data):
    """Extract fierce parameters from request data."""
    domain = data.get("domain")
    if not domain:
        return None, "Domain is required"

    dns_servers = data.get("dns_servers", [])
    delay = data.get("delay", 0)
    traverse = data.get("traverse")
    ip_range = data.get("range")
    subdomain_file = data.get("subdomain_file")
    subdomains = data.get("subdomains", [])
    additional_args = data.get("additional_args", "")

    params = {
        "domain": domain,
        "dns_servers": dns_servers,
        "wide": data.get("wide", False),
        "connect": data.get("connect", False),
        "delay": int(delay),
        "traverse": traverse,
        "range": ip_range,
        "subdomain_file": subdomain_file,
        "subdomains": subdomains,
        "tcp": data.get("tcp", False),
        "additional_args": additional_args,
    }

    return params, None


def _build_fierce_command(params):
    """Build fierce command from parameters using secure approach."""
    cmd_parts = ["fierce", "--domain", params["domain"]]

    # Add optional parameters
    if params["dns_servers"]:
        if isinstance(params["dns_servers"], list):
            dns_servers_str = " ".join(params["dns_servers"])
        else:
            dns_servers_str = str(params["dns_servers"])
        cmd_parts.extend(["--dns-servers", dns_servers_str])

    if params["wide"]:
        cmd_parts.append("--wide")

    if params["connect"]:
        cmd_parts.append("--connect")

    if params["delay"] > 0:
        cmd_parts.extend(["--delay", str(params["delay"])])  # Already validated as int

    if params["traverse"]:
        cmd_parts.extend(["--traverse", params["traverse"]])

    if params["range"]:
        cmd_parts.extend(["--range", params["range"]])

    if params["subdomain_file"]:
        cmd_parts.extend(["--subdomain-file", params["subdomain_file"]])

    if params["subdomains"]:
        if isinstance(params["subdomains"], list):
            subdomains_str = " ".join(params["subdomains"])
        else:
            subdomains_str = str(params["subdomains"])
        cmd_parts.extend(["--subdomains", subdomains_str])

    if params["tcp"]:
        cmd_parts.append("--tcp")

    # Add any additional arguments (already validated)
    if params["additional_args"]:
        for arg in params["additional_args"].split():
            cmd_parts.append(arg)

    return " ".join(cmd_parts)


def _parse_fierce_subdomains(stdout: str, domain: str) -> list[dict]:
    """Extract structured findings from fierce output."""
    findings = []
    seen_subdomains = set()

    if not stdout.strip():
        return findings

    lines = stdout.strip().split("\n")

    for line in lines:
        line = line.strip()

        # Skip empty lines
        if not line:
            continue

        # Look for subdomain discoveries in fierce output
        # Fierce typically outputs found subdomains with IP addresses
        if "." in line and domain in line:
            # Basic pattern matching for subdomains
            parts = line.split()
            for part in parts:
                if part.endswith(f".{domain}"):
                    subdomain = part.rstrip(".")

                    if subdomain not in seen_subdomains and subdomain != domain:
                        seen_subdomains.add(subdomain)

                        finding = {
                            "type": "subdomain",
                            "target": subdomain,
                            "evidence": {
                                "subdomain": subdomain,
                                "domain": domain,
                                "discovered_by": "fierce",
                            },
                            "severity": "info",
                            "confidence": "medium",
                            "tags": ["subdomain", "dns_reconnaissance"],
                            "raw_ref": line,
                        }
                        findings.append(finding)

    return findings


def _parse_fierce_result(
    execution_result, params, command, started_at: datetime, ended_at: datetime
):
    """Parse fierce execution result and format response with structured findings."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if not execution_result.get("success", False):
        return {
            "success": False,
            "tool": "fierce",
            "params": params,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "error": execution_result.get("error", "Command execution failed"),
            "findings": [],
            "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
        }

    # Parse output to extract structured findings
    stdout = execution_result.get("stdout", "")
    findings = _parse_fierce_subdomains(stdout, params["domain"])

    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "success": True,
        "tool": "fierce",
        "params": params,
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


@tool(required_fields=["domain"])
def execute_fierce():
    """Execute Fierce for DNS reconnaissance and subdomain discovery."""
    data = request.get_json()

    params, error = _extract_fierce_params(data)
    if error:
        return jsonify({"error": error}), 400

    assert params is not None  # Should never be None after error check
    logger.info(f"Executing Fierce on {params['domain']}")

    command = _build_fierce_command(params)
    started_at = datetime.now()
    execution_result = execute_command(command, timeout=600)  # 10-minute timeout
    ended_at = datetime.now()

    return _parse_fierce_result(execution_result, params, command, started_at, ended_at)
