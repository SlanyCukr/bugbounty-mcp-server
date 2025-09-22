"""wpscan tool implementation."""

import logging
from datetime import datetime
from typing import Any

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import (
    create_finding,
    create_stats,
    tool,
)

logger = logging.getLogger(__name__)


def extract_wpscan_params(data):
    """Extract wpscan parameters from request data."""
    params = {
        "url": data["url"],
        "enumerate": data.get("enumerate", "ap,at,cb,dbe,u,m"),
        "stealthy": data.get("stealthy", False),
        "random_user_agent": data.get("random_user_agent", True),
        "user_agent": data.get("user_agent", ""),
        "detection_mode": data.get("detection_mode", "mixed"),
        "plugin_detection": data.get("plugin_detection", "mixed"),
        "update": data.get("update", True),
        "api_token": data.get("api_token", ""),
        "threads": data.get("threads", 5),
        "request_timeout": data.get("request_timeout", 60),
        "connect_timeout": data.get("connect_timeout", 30),
        "follow_redirects": data.get("follow_redirects", True),
        "wp_content_dir": data.get("wp_content_dir", ""),
        "wp_plugins_dir": data.get("wp_plugins_dir", ""),
        "disable_ssl_check": data.get("disable_ssl_check", False),
        "proxy": data.get("proxy", ""),
        "http_auth": data.get("http_auth", ""),
        "headers": data.get("headers", {}),
        "format": data.get("format", "json"),
        "verbose": data.get("verbose", False),
        "no_banner": data.get("no_banner", True),
        "passwords_file": data.get("passwords_file", ""),
        "usernames_file": data.get("usernames_file", ""),
        "password_attack": data.get("password_attack", False),
        "multicall": data.get("multicall", 20),
        "output_file": data.get("output_file", ""),
        "cookie": data.get("cookie", ""),
        "scope": data.get("scope", ""),
        "additional_args": data.get("additional_args", ""),
    }
    return params


def build_wpscan_command(params):
    """Build wpscan command from parameters."""
    cmd_parts = ["wpscan", "--url", params["url"]]

    # Enhanced enumeration options
    if params["enumerate"]:
        cmd_parts.extend(["--enumerate", params["enumerate"]])

    # Add detection evasion and stealth options
    if params["stealthy"]:
        cmd_parts.extend(["--stealthy"])

    # Add user agent randomization
    if params["random_user_agent"]:
        cmd_parts.append("--random-user-agent")

    # Add custom user agent
    if params["user_agent"]:
        cmd_parts.extend(["--ua", params["user_agent"]])

    # Enhanced detection options
    if params["detection_mode"] != "mixed":
        cmd_parts.extend(["--detection-mode", params["detection_mode"]])

    # Add plugin detection
    if params["plugin_detection"] != "mixed":
        cmd_parts.extend(["--plugins-detection", params["plugin_detection"]])

    # Add update option
    if params["update"]:
        cmd_parts.append("--update")

    # Add API token
    if params["api_token"]:
        cmd_parts.extend(["--api-token", params["api_token"]])

    # Enhanced threading
    cmd_parts.extend(["--max-threads", str(params["threads"])])

    # Add timeouts
    cmd_parts.extend(["--request-timeout", str(params["request_timeout"])])
    cmd_parts.extend(["--connect-timeout", str(params["connect_timeout"])])

    # Add follow redirects
    if params["follow_redirects"]:
        cmd_parts.append("--follow-redirects")

    # Add WordPress directory detection
    if params["wp_content_dir"]:
        cmd_parts.extend(["--wp-content-dir", params["wp_content_dir"]])
    if params["wp_plugins_dir"]:
        cmd_parts.extend(["--wp-plugins-dir", params["wp_plugins_dir"]])

    # Add SSL check control
    if params["disable_ssl_check"]:
        cmd_parts.append("--disable-tls-checks")

    # Add proxy support
    if params["proxy"]:
        cmd_parts.extend(["--proxy", params["proxy"]])

    # Add HTTP authentication
    if params["http_auth"]:
        cmd_parts.extend(["--http-auth", params["http_auth"]])

    # Add custom headers
    if params["headers"]:
        for header_name, header_value in params["headers"].items():
            cmd_parts.extend(["--headers", f"{header_name}: {header_value}"])

    # Add output format
    if params["format"] in ["json", "cli"]:
        cmd_parts.extend(["--format", params["format"]])

    # Add verbose output
    if params["verbose"]:
        cmd_parts.append("--verbose")

    # Add no banner
    if params["no_banner"]:
        cmd_parts.append("--no-banner")

    # Add password attack options
    if params["passwords_file"]:
        cmd_parts.extend(["--passwords", params["passwords_file"]])
    if params["usernames_file"]:
        cmd_parts.extend(["--usernames", params["usernames_file"]])
    if params["password_attack"]:
        cmd_parts.extend(["--multicall-max-passwords", str(params["multicall"])])

    # Add output file
    if params["output_file"]:
        cmd_parts.extend(["--output", params["output_file"]])

    # Add custom cookie
    if params["cookie"]:
        cmd_parts.extend(["--cookie-string", params["cookie"]])

    # Add scope limitation
    if params["scope"]:
        cmd_parts.extend(["--scope", params["scope"]])

    # Add additional arguments
    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return " ".join(cmd_parts)


def parse_wpscan_output(
    execution_result: dict[str, Any],
    params: dict,
    command: str,
    started_at: datetime,
    ended_at: datetime,
) -> dict[str, Any]:
    """Parse wpscan execution result and format response with findings."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if not execution_result["success"]:
        return {
            "success": False,
            "tool": "wpscan",
            "params": params,
            "command": command,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "error": execution_result.get("error", "Command execution failed"),
            "findings": [],
            "stats": create_stats(0, 0, 0),
        }

    stdout = execution_result.get("stdout", "")
    stderr = execution_result.get("stderr", "")

    # Parse findings from output
    findings = _parse_wpscan_findings(stdout, stderr, params["url"])

    # Remove duplicates based on finding type and target
    seen_findings = set()
    unique_findings = []
    dupes_count = 0

    for finding in findings:
        unique_key = (
            f"{finding['type']}:{finding['target']}:{finding.get('raw_ref', '')}"
        )
        if unique_key not in seen_findings:
            seen_findings.add(unique_key)
            unique_findings.append(finding)
        else:
            dupes_count += 1

    payload_bytes = len((stdout + stderr).encode("utf-8"))

    return {
        "success": True,
        "tool": "wpscan",
        "params": params,
        "command": command,
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat(),
        "duration_ms": duration_ms,
        "findings": unique_findings,
        "stats": create_stats(len(unique_findings), dupes_count, payload_bytes),
    }


def _parse_wpscan_findings(stdout: str, stderr: str, url: str) -> list[dict[str, Any]]:
    """Parse wpscan output for basic findings."""
    findings = []

    # Look for vulnerability indicators in output
    output = stdout + stderr
    lines = output.split("\n")

    vulnerability_indicators = [
        "vulnerability",
        "vulnerable",
        "cve",
        "security",
        "exploit",
        "weak",
        "outdated",
        "insecure",
    ]

    for line in lines:
        line = line.strip()
        if not line:
            continue

        line_lower = line.lower()

        # Check for vulnerability indicators
        if any(indicator in line_lower for indicator in vulnerability_indicators):
            finding = create_finding(
                finding_type="vuln",
                target=url,
                evidence={
                    "raw_output": line,
                    "url": url,
                    "discovered_by": "wpscan",
                },
                severity="medium",  # Default severity for WordPress vulns
                confidence="medium",
                tags=["wordpress", "vulnerability", "wpscan"],
                raw_ref=line,
            )
            findings.append(finding)

    # Add basic scan completion info
    if findings:
        # Add scan summary finding
        finding = create_finding(
            finding_type="vuln",
            target=url,
            evidence={
                "raw_output": f"WPScan completed on {url}",
                "url": url,
                "discovered_by": "wpscan",
                "vulnerabilities_found": len(findings),
            },
            severity="info",
            confidence="high",
            tags=["wordpress", "scan-result", "wpscan"],
            raw_ref="scan_completed",
        )
        findings.append(finding)

    return findings


@tool(required_fields=["url"])
def execute_wpscan():
    """Execute WPScan for comprehensive WordPress vulnerability analysis."""
    data = request.get_json()
    params = extract_wpscan_params(data)

    logger.info(f"Executing WPScan on {params['url']}")

    started_at = datetime.now()
    command = build_wpscan_command(params)
    execution_result = execute_command(command, timeout=1800)
    ended_at = datetime.now()

    return parse_wpscan_output(execution_result, params, command, started_at, ended_at)
