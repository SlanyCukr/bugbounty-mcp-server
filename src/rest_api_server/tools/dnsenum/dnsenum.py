"""dnsenum tool implementation."""

import logging
import shlex
from datetime import datetime

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)


def extract_dnsenum_params(data):
    """Extract dnsenum parameters from request data."""
    return {
        "domain": data.get("target", "").strip(),
        "dns_server": data.get("dns_server", "").strip(),
        "wordlist": data.get("wordlist", "").strip(),
        "threads": data.get("threads", 5),
        "delay": data.get("delay", 0),
        "reverse": data.get("reverse", False),
        "additional_args": data.get("additional_args", "").strip(),
    }


def build_dnsenum_command(params):
    """Build dnsenum command from parameters."""
    cmd_parts = ["dnsenum", "--nocolor", "-v", "-t", "60"]

    # Add domain
    cmd_parts.append(params["domain"])

    # Add DNS server if specified
    if params["dns_server"]:
        cmd_parts.extend(["--dnsserver", params["dns_server"]])

    # Add wordlist file if specified
    if params["wordlist"]:
        cmd_parts.extend(["-f", params["wordlist"]])

    # Add threads if specified
    if params["threads"] != 5:
        cmd_parts.extend(["--threads", str(params["threads"])])

    # Add delay if specified
    if params["delay"] > 0:
        cmd_parts.extend(["-d", str(params["delay"])])

    # Add reverse lookup option
    if not params["reverse"]:
        cmd_parts.append("--noreverse")

    # Handle additional arguments
    if params["additional_args"]:
        try:
            additional_parts = shlex.split(params["additional_args"])
            cmd_parts.extend(additional_parts)
        except ValueError as e:
            logger.warning(f"Failed to parse additional_args: {e}")

    return cmd_parts


def parse_dnsenum_subdomains(stdout, domain):
    """Extract subdomains from dnsenum output."""
    findings = []
    seen_subdomains = set()

    if not stdout.strip():
        return findings

    lines = stdout.strip().split("\n")

    for line in lines:
        line = line.strip()

        # Skip empty lines and noise
        if not line:
            continue

        # Look for successful DNS resolutions (lines with IP addresses)
        if "IN    A" in line and "query failed" not in line.lower():
            parts = line.split()
            if len(parts) >= 5:
                subdomain_candidate = parts[0].rstrip(".")
                ip_address = parts[-1]

                # Check if this is a subdomain of our target domain
                if (
                    subdomain_candidate.endswith(f".{domain}")
                    or subdomain_candidate == domain
                ):
                    if subdomain_candidate not in seen_subdomains:
                        seen_subdomains.add(subdomain_candidate)

                        finding = {
                            "type": "subdomain",
                            "target": subdomain_candidate,
                            "evidence": {
                                "subdomain": subdomain_candidate,
                                "domain": domain,
                                "ip_address": ip_address,
                                "discovered_by": "dnsenum",
                            },
                            "tags": ["subdomain", "dns_enumeration"],
                            "raw_ref": line,
                        }
                        findings.append(finding)

    return findings


def parse_dnsenum_output(execution_result, params, command, started_at, ended_at):
    """Parse dnsenum execution result and format response."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if not execution_result.get("success", False):
        return {
            "success": False,
            "tool": "dnsenum",
            "params": params,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "error": execution_result.get("error", "Command execution failed"),
            "findings": [],
            "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
        }

    # Parse output to extract subdomains
    stdout = execution_result.get("stdout", "")
    findings = parse_dnsenum_subdomains(stdout, params["domain"])

    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "success": True,
        "tool": "dnsenum",
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


@tool(required_fields=["target"])
def execute_dnsenum():
    """Execute dnsenum for DNS enumeration and subdomain discovery."""
    try:
        data = request.get_json()
        if not data:
            return {"error": "No JSON data provided", "success": False}

        # Extract parameters
        params = extract_dnsenum_params(data)

        logger.info(f"Executing dnsenum on {params['domain']}")

        # Build command
        command = build_dnsenum_command(params)
        logger.info(f"Executing command: {' '.join(command)}")

        # Execute command with timing
        started_at = datetime.now()
        execution_result = execute_command(
            " ".join(command), timeout=600
        )  # 10 minute timeout for DNS enumeration
        ended_at = datetime.now()

        return parse_dnsenum_output(
            execution_result, params, " ".join(command), started_at, ended_at
        )

    except ValueError as e:
        logger.error(f"Invalid parameters for dnsenum: {e}")
        return {
            "error": f"Invalid parameters: {str(e)}",
            "success": False,
            "tool": "dnsenum",
        }
    except Exception as e:
        logger.error(f"Unexpected error in dnsenum execution: {e}")
        return {
            "error": f"Execution failed: {str(e)}",
            "success": False,
            "tool": "dnsenum",
        }
