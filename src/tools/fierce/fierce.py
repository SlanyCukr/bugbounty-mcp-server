import logging
from datetime import datetime

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_fierce_params(data):
    """Extract and validate fierce parameters from request data."""
    domain = data["domain"]
    dns_servers = data.get("dns_servers", [])
    wide = data.get("wide", False)
    connect = data.get("connect", False)
    delay = data.get("delay", 0)
    traverse = data.get("traverse")
    ip_range = data.get("range")
    subdomain_file = data.get("subdomain_file")
    subdomains = data.get("subdomains", [])
    tcp = data.get("tcp", False)
    additional_args = data.get("additional_args", "")

    return {
        "domain": domain,
        "dns_servers": dns_servers,
        "wide": wide,
        "connect": connect,
        "delay": delay,
        "traverse": traverse,
        "range": ip_range,
        "subdomain_file": subdomain_file,
        "subdomains": subdomains,
        "tcp": tcp,
        "additional_args": additional_args,
    }


def _build_fierce_command(params):
    """Build fierce command from parameters."""
    # Build fierce command
    command = f"fierce --domain {params['domain']}"

    # Add optional parameters
    if params["dns_servers"]:
        if isinstance(params["dns_servers"], list):
            dns_servers_str = " ".join(params["dns_servers"])
        else:
            dns_servers_str = str(params["dns_servers"])
        command += f" --dns-servers {dns_servers_str}"

    if params["wide"]:
        command += " --wide"

    if params["connect"]:
        command += " --connect"

    if params["delay"] > 0:
        command += f" --delay {params['delay']}"

    if params["traverse"]:
        command += f" --traverse {params['traverse']}"

    if params["range"]:
        command += f" --range {params['range']}"

    if params["subdomain_file"]:
        command += f" --subdomain-file {params['subdomain_file']}"

    if params["subdomains"]:
        if isinstance(params["subdomains"], list):
            subdomains_str = " ".join(params["subdomains"])
        else:
            subdomains_str = str(params["subdomains"])
        command += f" --subdomains {subdomains_str}"

    if params["tcp"]:
        command += " --tcp"

    # Add any additional arguments
    if params["additional_args"]:
        command += f" {params['additional_args']}"

    return command


def _parse_fierce_result(execution_result, params, command):
    """Parse fierce execution result and format response."""
    response_data = {
        "tool": "fierce",
        "target": params["domain"],
        "parameters": {
            "domain": params["domain"],
            "dns_servers": params["dns_servers"],
            "wide": params["wide"],
            "connect": params["connect"],
            "delay": params["delay"],
            "traverse": params["traverse"],
            "range": params["range"],
            "subdomain_file": params["subdomain_file"],
            "subdomains": params["subdomains"],
            "tcp": params["tcp"],
            "additional_args": params["additional_args"],
        },
        "command_executed": command,
        "success": execution_result.get("success", False),
        "return_code": execution_result.get("return_code"),
        "raw_output": execution_result.get("stdout", ""),
        "error_output": execution_result.get("stderr", ""),
        "timestamp": datetime.now().isoformat(),
    }

    # Add error information if command failed
    if not execution_result.get("success", False):
        response_data["error"] = execution_result.get(
            "error", "Command execution failed"
        )

    return response_data


@tool(required_fields=["domain"])
def execute_fierce():
    """Execute Fierce for DNS reconnaissance and subdomain discovery."""
    data = request.get_json()
    params = _extract_fierce_params(data)

    logger.info(f"Executing Fierce on {params['domain']}")

    command = _build_fierce_command(params)
    execution_result = execute_command(command, timeout=600)  # 10-minute timeout

    return _parse_fierce_result(execution_result, params, command)
