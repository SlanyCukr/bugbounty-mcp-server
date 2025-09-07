import logging

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_amass_params(data):
    """Extract and validate amass parameters from request data."""
    return {
        "domain": data["domain"],
        "mode": data.get("mode", "enum"),
        "active": data.get("active", False),
        "brute": data.get("brute", False),
        "passive": data.get("passive", True),
        "wordlist": data.get("wordlist"),
        "wordlist_mask": data.get("wordlist_mask"),
        "alterations": data.get("alterations", False),
        "show_sources": data.get("show_sources", False),
        "show_ips": data.get("show_ips", False),
        "include_unresolved": data.get("include_unresolved", False),
        "data_sources": data.get("data_sources"),
        "exclude_sources": data.get("exclude_sources"),
        "timeout_minutes": data.get("timeout_minutes"),
        "max_depth": data.get("max_depth", 0),
        "dns_qps": data.get("dns_qps"),
        "resolvers_qps": data.get("resolvers_qps"),
        "min_recursive": data.get("min_recursive", 0),
        "max_dns_queries": data.get("max_dns_queries"),
        "resolvers_file": data.get("resolvers_file"),
        "trusted_resolvers": data.get("trusted_resolvers"),
        "blacklist_file": data.get("blacklist_file"),
        "no_dns": data.get("no_dns", False),
        "config_file": data.get("config_file"),
        "output_file": data.get("output_file"),
        "log_file": data.get("log_file"),
        "verbose": data.get("verbose", False),
        "silent": data.get("silent", False),
        "debug": data.get("debug", False),
        "whois": data.get("whois", False),
        "asn": data.get("asn", False),
        "cidr": data.get("cidr", False),
        "org": data.get("org", False),
        "exclude_disabled": data.get("exclude_disabled", True),
        "scripts_only": data.get("scripts_only", False),
        "viz_input_file": data.get("viz_input_file"),
        "viz_output_file": data.get("viz_output_file"),
        "additional_args": data.get("additional_args"),
    }


def _build_amass_command(params):
    """Build amass command from parameters."""
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

    # Performance and rate limiting parameters
    if params["timeout_minutes"]:
        timeout_seconds = int(params["timeout_minutes"]) * 60
        cmd_parts.extend(["-timeout", str(timeout_seconds)])
    if params["max_depth"] > 0:
        cmd_parts.extend(["-max-depth", str(params["max_depth"])])
    if params["dns_qps"]:
        cmd_parts.extend(["-dns-qps", str(params["dns_qps"])])
    if params["resolvers_qps"]:
        cmd_parts.extend(["-resolvers-qps", str(params["resolvers_qps"])])
    if params["min_recursive"] > 0:
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
        cmd_parts.extend(["-config", params["config_file"]])
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

    # Additional arguments
    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return " ".join(cmd_parts)


def _parse_amass_result(execution_result, params, command):
    """Parse amass execution result and format response."""
    return {
        "tool": "amass",
        "target": params["domain"],
        "command": command,
        "success": execution_result["success"],
        "stdout": execution_result.get("stdout", ""),
        "stderr": execution_result.get("stderr", ""),
        "return_code": execution_result.get("return_code", 0),
    }


@tool(required_fields=["domain"])
def execute_amass():
    """Execute Amass for advanced subdomain enumeration."""
    data = request.get_json()
    params = _extract_amass_params(data)

    logger.info(f"Executing Amass on {params['domain']}")

    command = _build_amass_command(params)
    execution_result = execute_command(
        command, timeout=params.get("timeout_minutes", 30) * 60
    )

    return _parse_amass_result(execution_result, params, command)
