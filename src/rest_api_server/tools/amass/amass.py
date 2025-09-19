"""Amass tool implementation for subdomain enumeration."""

import logging
import os
from datetime import datetime
from typing import Any

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)

# Aggressive preset for amass
AGGRESSIVE_PRESET = {
    "active": True,
    "brute": True,
    "passive": True,
    "alterations": True,
    "show_sources": True,
    "show_ips": True,
    "timeout_minutes": 60,
    "max_depth": 3,
    "dns_qps": 100,
    "resolvers_qps": 50,
    "min_recursive": 2,
}


def _apply_aggressive_preset(user_params: dict, aggressive: bool = False) -> dict:
    """Apply aggressive preset to user parameters if aggressive=True."""
    if not aggressive:
        return user_params

    # Start with user params and apply aggressive preset
    merged_params = user_params.copy()

    # Apply aggressive preset for parameters not explicitly set by user
    for key, aggressive_value in AGGRESSIVE_PRESET.items():
        if key not in user_params:
            merged_params[key] = aggressive_value
        else:
            should_override = key in {
                "dns_qps",
                "resolvers_qps",
                "active",
                "brute",
                "alterations",
                "show_sources",
                "show_ips",
                "timeout_minutes",
                "max_depth",
                "min_recursive",
            }
            default_like_values = (None, False, 0)
            if should_override and user_params.get(key) in default_like_values:
                merged_params[key] = aggressive_value

    return merged_params


def _extract_amass_params(data):
    """Extract amass parameters from request data."""
    # Check for aggressive mode
    aggressive = data.get("aggressive", False)

    domain = data["domain"]
    mode = data.get("mode", "enum")

    # Get string parameters
    wordlist = data.get("wordlist")
    wordlist_mask = data.get("wordlist_mask")
    data_sources = data.get("data_sources")
    exclude_sources = data.get("exclude_sources")
    resolvers_file = data.get("resolvers_file")
    trusted_resolvers = data.get("trusted_resolvers")
    blacklist_file = data.get("blacklist_file")
    config_file = data.get("config_file")
    output_file = data.get("output_file")
    log_file = data.get("log_file")
    viz_input_file = data.get("viz_input_file")
    viz_output_file = data.get("viz_output_file")
    additional_args = data.get("additional_args")

    # Get numeric parameters
    timeout_minutes = data.get("timeout_minutes")
    max_depth = data.get("max_depth", 0)
    dns_qps = data.get("dns_qps")
    resolvers_qps = data.get("resolvers_qps")
    min_recursive = data.get("min_recursive", 0)
    max_dns_queries = data.get("max_dns_queries")
    ct_timeout = data.get("ct_timeout")

    # Get certificate transparency parameters
    ct_sources = data.get("ct_sources", ["crt.sh", "google"])

    base_params = {
        "domain": domain,
        "mode": mode,
        "active": data.get("active", False),
        "brute": data.get("brute", False),
        "passive": data.get("passive", True),
        "wordlist": wordlist,
        "wordlist_mask": wordlist_mask,
        "alterations": data.get("alterations", False),
        "show_sources": data.get("show_sources", False),
        "show_ips": data.get("show_ips", False),
        "include_unresolved": data.get("include_unresolved", False),
        "data_sources": data_sources,
        "exclude_sources": exclude_sources,
        "timeout_minutes": timeout_minutes,
        "max_depth": max_depth,
        "dns_qps": dns_qps,
        "resolvers_qps": resolvers_qps,
        "min_recursive": min_recursive,
        "max_dns_queries": max_dns_queries,
        "resolvers_file": resolvers_file,
        "trusted_resolvers": trusted_resolvers,
        "blacklist_file": blacklist_file,
        "no_dns": data.get("no_dns", False),
        "config_file": config_file,
        "output_file": output_file,
        "log_file": log_file,
        "verbose": data.get("verbose", False),
        "silent": data.get("silent", False),
        "debug": data.get("debug", False),
        "whois": data.get("whois", False),
        "asn": data.get("asn", False),
        "cidr": data.get("cidr", False),
        "org": data.get("org", False),
        "exclude_disabled": data.get("exclude_disabled", True),
        "scripts_only": data.get("scripts_only", False),
        "viz_input_file": viz_input_file,
        "viz_output_file": viz_output_file,
        "additional_args": additional_args,
        "ct_sources": ct_sources,
        "ct_timeout": ct_timeout,
    }

    # Apply aggressive preset if requested
    return _apply_aggressive_preset(base_params, aggressive)


def _validate_amass_config(config_file: str) -> dict:
    """Validate amass configuration file."""
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Config file not found: {config_file}")

    # Basic validation logic
    return {"valid": True, "warnings": []}


def _configure_certificate_transparency(params: dict) -> list:
    """Configure certificate transparency log sources."""
    cmd_parts = []

    ct_sources = params.get("ct_sources", ["crt.sh", "google"])
    for source in ct_sources:
        cmd_parts.extend(["-src", source])

    if params.get("ct_timeout"):
        cmd_parts.extend(["-timeout", str(params["ct_timeout"])])

    return cmd_parts


def _build_amass_command(params):
    """Build amass command from parameters using secure argument handling."""
    cmd_parts = ["amass"]

    cmd_parts.append(params["mode"])
    cmd_parts.extend(["-d", params["domain"]])

    # Core enumeration parameters
    if params["active"]:
        cmd_parts.append("-active")
    if params["brute"]:
        cmd_parts.append("-brute")
    if params["passive"]:
        cmd_parts.append("-passive")

    # Wordlist and dictionary parameters
    if params["wordlist"]:
        cmd_parts.extend(["-w", params["wordlist"]])
    if params["wordlist_mask"]:
        cmd_parts.extend(["-wm", params["wordlist_mask"]])
    if params["alterations"]:
        cmd_parts.append("-alts")

    # Note: Amass doesn't have native JSON output, using text output
    # Remove the invalid -json flag

    # Output and information parameters
    if params["show_sources"]:
        cmd_parts.append("-src")
    if params["show_ips"]:
        cmd_parts.append("-ip")
    if params["include_unresolved"]:
        cmd_parts.append("-include-unresolvable")

    # Data source parameters
    if params["data_sources"]:
        cmd_parts.extend(["-include", params["data_sources"]])
    if params["exclude_sources"]:
        cmd_parts.extend(["-exclude", params["exclude_sources"]])

    # Certificate transparency configuration
    ct_parts = _configure_certificate_transparency(params)
    cmd_parts.extend(ct_parts)

    # Performance and rate limiting parameters
    if params["timeout_minutes"]:
        timeout_seconds = params["timeout_minutes"] * 60
        cmd_parts.extend(["-timeout", str(timeout_seconds)])
    if params["max_depth"]:
        cmd_parts.extend(["-max-depth", str(params["max_depth"])])
    if params["dns_qps"]:
        cmd_parts.extend(["-dns-qps", str(params["dns_qps"])])
    if params["resolvers_qps"]:
        cmd_parts.extend(["-resolvers-qps", str(params["resolvers_qps"])])
    if params["min_recursive"]:
        cmd_parts.extend(["-min-recursive", str(params["min_recursive"])])
    if params["max_dns_queries"]:
        cmd_parts.extend(["-max-dns-queries", str(params["max_dns_queries"])])

    # Network configuration parameters
    if params["resolvers_file"]:
        cmd_parts.extend(["-r", params["resolvers_file"]])
    if params["trusted_resolvers"]:
        cmd_parts.extend(["-tr", params["trusted_resolvers"]])
    if params["blacklist_file"]:
        cmd_parts.extend(["-bl", params["blacklist_file"]])
    if params["no_dns"]:
        cmd_parts.append("-no-dns")

    # Configuration and output parameters
    if params["config_file"]:
        try:
            _validate_amass_config(params["config_file"])
            cmd_parts.extend(["-config", params["config_file"]])
        except FileNotFoundError as e:
            logger.warning(f"Config file validation failed: {e}")
    if params["output_file"]:
        cmd_parts.extend(["-o", params["output_file"]])
    if params["log_file"]:
        cmd_parts.extend(["-log", params["log_file"]])

    # Verbosity parameters
    if params["verbose"]:
        cmd_parts.append("-v")
    if params["silent"]:
        cmd_parts.append("-silent")
    if params["debug"]:
        cmd_parts.append("-debug")

    # Intel mode specific parameters
    if params["mode"] == "intel":
        if params["whois"]:
            cmd_parts.append("-whois")
        if params["asn"]:
            cmd_parts.append("-asn")
        if params["cidr"]:
            cmd_parts.append("-cidr")
        if params["org"]:
            cmd_parts.append("-org")

    # Advanced parameters
    if params["exclude_disabled"]:
        cmd_parts.append("-exclude-disabled")
    if params["scripts_only"]:
        cmd_parts.append("-scripts-only")

    # Visualization mode parameters
    if params["mode"] == "viz":
        if params["viz_input_file"]:
            cmd_parts.extend(["-i", params["viz_input_file"]])
        if params["viz_output_file"]:
            cmd_parts.extend(["-o", params["viz_output_file"]])

    # Handle additional arguments
    if params["additional_args"]:
        additional_parts = params["additional_args"].split()
        cmd_parts.extend(additional_parts)

    return " ".join(cmd_parts)


# JSON parsing removed - amass doesn't support JSON output natively


def _parse_amass_text_output(
    execution_result, params, command, started_at: datetime, ended_at: datetime
) -> dict[str, Any]:
    """Parse plain text amass output into structured findings."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if not execution_result["success"]:
        return {
            "success": False,
            "tool": "amass",
            "params": params,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "error": execution_result.get("error", "Command execution failed"),
            "findings": [],
            "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
        }

    stdout = execution_result.get("stdout", "")
    findings = []
    seen_subdomains = set()

    # Parse text output - each line is a subdomain
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        # Basic subdomain validation
        if "." in line and not line.startswith("."):
            subdomain = line
            if subdomain not in seen_subdomains:
                seen_subdomains.add(subdomain)

                finding = {
                    "type": "subdomain",
                    "target": subdomain,
                    "evidence": {
                        "subdomain": subdomain,
                        "domain": params.get("domain", ""),
                        "discovered_by": "amass",
                    },
                    "severity": "info",
                    "confidence": "medium",
                    "tags": ["subdomain", "text_output"],
                    "raw_ref": line,
                }
                findings.append(finding)

    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "success": True,
        "tool": "amass",
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


def _create_response(
    findings: list,
    execution_result,
    params,
    command,
    started_at: datetime,
    ended_at: datetime,
) -> dict[str, Any]:
    """Create standardized response with deduplication."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    # Remove duplicates based on subdomain
    seen_subdomains = set()
    unique_findings = []
    dupes_count = 0

    for finding in findings:
        subdomain = finding["target"]
        if subdomain not in seen_subdomains:
            seen_subdomains.add(subdomain)
            unique_findings.append(finding)
        else:
            dupes_count += 1

    stdout = execution_result.get("stdout", "")
    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "success": True,
        "tool": "amass",
        "params": params,
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat(),
        "duration_ms": duration_ms,
        "findings": unique_findings,
        "stats": {
            "findings": len(unique_findings),
            "dupes": dupes_count,
            "payload_bytes": payload_bytes,
        },
    }


def _parse_amass_output(
    execution_result, params, command, started_at: datetime, ended_at: datetime
) -> dict[str, Any]:
    """Parse amass text output into structured findings."""
    # Amass only supports text output, so use text parsing directly
    return _parse_amass_text_output(
        execution_result, params, command, started_at, ended_at
    )


@tool(required_fields=["domain"])
def execute_amass():
    """Execute Amass for advanced subdomain enumeration."""
    data = request.get_json()
    params = _extract_amass_params(data)

    logger.info(f"Executing Amass on {params['domain']}")

    started_at = datetime.now()
    command = _build_amass_command(params)
    execution_result = execute_command(
        command, timeout=params.get("timeout_minutes", 30) * 60
    )
    ended_at = datetime.now()

    return _parse_amass_output(execution_result, params, command, started_at, ended_at)
