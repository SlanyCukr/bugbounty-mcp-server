import logging
from datetime import datetime

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_dnsenum_params(data):
    """Extract and validate dnsenum parameters from request data."""
    domain = data["domain"]
    dns_server = data.get("dns_server", "")
    wordlist = data.get("wordlist", "")
    threads = data.get("threads", 5)
    delay = data.get("delay", 0)
    reverse = data.get("reverse", False)
    additional_args = data.get("additional_args", "")

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
    """Build dnsenum command from parameters."""
    # Build the dnsenum command with verbose output and no color
    command = f"dnsenum --nocolor -v {params['domain']}"

    # Add DNS server if specified
    if params["dns_server"]:
        command += f" --dnsserver {params['dns_server']}"

    # Add wordlist file if specified
    if params["wordlist"]:
        command += f" -f {params['wordlist']}"

    # Add threads if specified (default is usually fine)
    if params["threads"] != 5:
        command += f" --threads {params['threads']}"

    # Add delay if specified
    if params["delay"] > 0:
        command += f" -d {params['delay']}"

    # Add reverse lookup option (dnsenum does reverse by default, --noreverse disables it)
    if not params["reverse"]:
        command += (
            " --noreverse"  # Disable reverse lookups by default for faster execution
        )

    # Add any additional arguments
    if params["additional_args"]:
        command += f" {params['additional_args']}"

    return command


def _parse_dnsenum_result(execution_result, params, command):
    """Parse dnsenum execution result and format response."""
    response_data = {
        "tool": "dnsenum",
        "target": params["domain"],
        "parameters": {
            "domain": params["domain"],
            "dns_server": params["dns_server"],
            "wordlist": params["wordlist"],
            "threads": params["threads"],
            "delay": params["delay"],
            "reverse": params["reverse"],
            "additional_args": params["additional_args"],
        },
        "command": command,
        "success": execution_result.get("success", False),
        "raw_output": execution_result.get("stdout", ""),
        "stderr": execution_result.get("stderr", ""),
        "return_code": execution_result.get("return_code", -1),
        "timestamp": datetime.now().isoformat(),
    }

    # Add error information if command failed
    if not execution_result.get("success", False):
        response_data["error"] = execution_result.get("error", "Command failed")

    return response_data


@tool(required_fields=["domain"])
def execute_dnsenum():
    """Execute dnsenum for DNS enumeration and subdomain discovery."""
    data = request.get_json()
    params = _extract_dnsenum_params(data)

    logger.info(f"Executing dnsenum on {params['domain']}")

    command = _build_dnsenum_command(params)
    logger.info(f"Executing command: {command}")
    execution_result = execute_command(
        command, timeout=600
    )  # 10 minute timeout for DNS enumeration

    return _parse_dnsenum_result(execution_result, params, command)
