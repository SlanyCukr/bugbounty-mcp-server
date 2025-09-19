"""dnsenum tool implementation."""

import logging
import re
import shlex
from datetime import datetime

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)


def _is_valid_domain(domain):
    """Validate domain format to prevent injection attacks."""
    if not domain or len(domain) > 253:
        return False

    # Basic domain regex - allows letters, numbers, dots, hyphens
    domain_pattern = re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    )

    # Check for dangerous characters
    dangerous_chars = [
        ";",
        "&",
        "|",
        "`",
        "$",
        "(",
        ")",
        "{",
        "}",
        "[",
        "]",
        '"',
        "'",
        "\\",
        "\n",
        "\r",
    ]
    if any(char in domain for char in dangerous_chars):
        return False

    return bool(domain_pattern.match(domain))


def _is_valid_dns_server(dns_server):
    """Validate DNS server format (IP address or domain name)."""
    if not dns_server:
        return True  # Optional parameter

    # Check for IPv4 address
    ipv4_pattern = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    if ipv4_pattern.match(dns_server):
        return True

    # Check for IPv6 address (simplified)
    if ":" in dns_server:
        ipv6_pattern = re.compile(r"^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$")
        if ipv6_pattern.match(dns_server):
            return True

    # Check for domain name format
    return _is_valid_domain(dns_server)


def _is_valid_file_path(file_path):
    """Validate file path to prevent path traversal attacks."""
    if not file_path:
        return True  # Optional parameter

    # Check for dangerous path traversal sequences
    dangerous_sequences = ["../", "..\\", "/../", "\\..\\"]
    if any(seq in file_path for seq in dangerous_sequences):
        return False

    # Check for dangerous characters
    dangerous_chars = [
        ";",
        "&",
        "|",
        "`",
        "$",
        "(",
        ")",
        "{",
        "}",
        '"',
        "'",
        "\n",
        "\r",
    ]
    if any(char in file_path for char in dangerous_chars):
        return False

    # Only allow absolute paths or relative paths in safe directories
    if file_path.startswith("/"):
        # Absolute path - ensure it's in allowed directories
        allowed_dirs = ["/usr/share/wordlists", "/opt/wordlists", "/tmp/wordlists"]
        if not any(file_path.startswith(allowed_dir) for allowed_dir in allowed_dirs):
            return False
    else:
        # Relative path - ensure it doesn't start with dangerous patterns
        if file_path.startswith("../") or file_path.startswith("..\\"):
            return False

    return True


def _validate_additional_args(additional_args):
    """Validate additional arguments to prevent command injection."""
    if not additional_args:
        return

    # Check for dangerous characters and command injection patterns
    dangerous_chars = [
        ";",
        "&",
        "|",
        "`",
        "$",
        "(",
        ")",
        "{",
        "}",
        "\n",
        "\r",
        ">",
        "<",
    ]
    if any(char in additional_args for char in dangerous_chars):
        raise ValueError(f"Invalid characters in additional_args: {additional_args}")

    # Split args safely using shlex
    try:
        args = shlex.split(additional_args)
    except ValueError as e:
        raise ValueError(f"Invalid additional_args format: {e}") from None

    # Validate each argument
    allowed_args = [
        "--enum",
        "--timeout",
        "--scrap",
        "--nocolor",
        "-v",
        "--verbose",
        "--threads",
        "-t",
        "--delay",
        "-d",
        "--dnsserver",
        "-s",
        "--file",
        "-f",
        "--noreverse",
        "--nocolor",
        "--update",
    ]

    for arg in args:
        if arg.startswith("-"):
            # This is a flag - check if it's allowed
            arg_name = arg.split("=")[0]  # Handle --flag=value format
            if arg_name not in allowed_args:
                raise ValueError(f"Disallowed argument: {arg_name}")
        else:
            # This is a value - basic validation
            if len(arg) > 100:  # Reasonable length limit
                raise ValueError(f"Argument value too long: {arg}")


def _extract_dnsenum_params(data):
    """Extract and validate dnsenum parameters from request data."""
    domain = data.get("domain", "").strip()
    if not domain:
        raise ValueError("Domain is required")

    # Validate domain format
    if not _is_valid_domain(domain):
        raise ValueError(f"Invalid domain format: {domain}")

    dns_server = data.get("dns_server", "").strip()
    if dns_server and not _is_valid_dns_server(dns_server):
        raise ValueError(f"Invalid DNS server format: {dns_server}")

    wordlist = data.get("wordlist", "").strip()
    if wordlist and not _is_valid_file_path(wordlist):
        raise ValueError(f"Invalid wordlist path: {wordlist}")

    threads = data.get("threads", 5)
    if not isinstance(threads, int) or not (1 <= threads <= 50):
        raise ValueError(f"Threads must be an integer between 1-50, got: {threads}")

    delay = data.get("delay", 0)
    if not isinstance(delay, int | float) or not (0 <= delay <= 10):
        raise ValueError(f"Delay must be a number between 0-10, got: {delay}")

    reverse = data.get("reverse", False)
    if not isinstance(reverse, bool):
        raise ValueError(f"Reverse must be a boolean, got: {reverse}")

    additional_args = data.get("additional_args", "").strip()
    if additional_args:
        # Validate additional arguments for security
        _validate_additional_args(additional_args)

    return {
        "domain": domain,
        "dns_server": dns_server,
        "wordlist": wordlist,
        "threads": threads,
        "delay": delay,
        "reverse": reverse,
        "additional_args": additional_args,
    }


def _build_dnsenum_command(params):
    """Build dnsenum command from parameters using secure argument handling."""
    # Use list-based command building for security - avoid shell injection
    cmd_parts = ["dnsenum", "--nocolor", "-v"]

    # Add domain (already validated)
    cmd_parts.append(params["domain"])

    # Add DNS server if specified (already validated)
    if params["dns_server"]:
        cmd_parts.extend(["--dnsserver", params["dns_server"]])

    # Add wordlist file if specified (already validated)
    if params["wordlist"]:
        cmd_parts.extend(["-f", params["wordlist"]])

    # Add threads if specified (already validated)
    if params["threads"] != 5:
        cmd_parts.extend(["--threads", str(params["threads"])])

    # Add delay if specified (already validated)
    if params["delay"] > 0:
        cmd_parts.extend(["-d", str(params["delay"])])

    # Add reverse lookup option (dnsenum does reverse by default)
    if not params["reverse"]:
        cmd_parts.append("--noreverse")

    # Handle additional arguments securely (already validated)
    if params["additional_args"]:
        # Use shlex.split to safely parse additional arguments
        try:
            additional_parts = shlex.split(params["additional_args"])
            cmd_parts.extend(additional_parts)
        except ValueError as e:
            logger.warning(f"Failed to parse additional_args: {e}")
            # Additional args already validated, so this shouldn't happen

    # Return as list for secure execution - execute_command should handle this
    return cmd_parts


def _parse_dnsenum_subdomains(stdout: str, domain: str) -> list[dict]:
    """Extract clean subdomains from dnsenum output."""
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
        # Format: "subdomain.domain.com.    TTL    IN    A    IP_ADDRESS"
        if "IN    A" in line and "query failed" not in line.lower():
            parts = line.split()
            if len(parts) >= 5:
                subdomain_candidate = parts[0].rstrip(".")
                ip_address = parts[-1]

                # Check if this is a valid subdomain of our target domain
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
                            "severity": "info",
                            "confidence": "high",
                            "tags": ["subdomain", "dns_enumeration"],
                            "raw_ref": line,
                        }
                        findings.append(finding)

    return findings


def _parse_dnsenum_result(
    execution_result, params, command, started_at: datetime, ended_at: datetime
):
    """Parse dnsenum execution result and format response with clean findings."""
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

    # Parse output to extract clean subdomains
    stdout = execution_result.get("stdout", "")
    findings = _parse_dnsenum_subdomains(stdout, params["domain"])

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


@tool(required_fields=["domain"])
def execute_dnsenum():
    """Execute dnsenum for DNS enumeration and subdomain discovery."""
    try:
        data = request.get_json()
        if not data:
            return {"error": "No JSON data provided", "success": False}

        # Extract and validate parameters - this will raise ValueError
        # for invalid inputs
        params = _extract_dnsenum_params(data)

        logger.info(f"Executing dnsenum on {params['domain']}")

        # Build secure command as list
        command = _build_dnsenum_command(params)
        logger.info(f"Executing command: {' '.join(command)}")

        # Execute command with timing
        started_at = datetime.now()
        execution_result = execute_command(
            " ".join(command), timeout=600
        )  # 10 minute timeout for DNS enumeration
        ended_at = datetime.now()

        return _parse_dnsenum_result(
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
