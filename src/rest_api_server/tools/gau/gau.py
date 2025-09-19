"""gau tool implementation."""

import logging

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)

# Aggressive preset for gau
AGGRESSIVE_PRESET = {
    "providers": "wayback,commoncrawl,otx,urlscan",
    "blacklist": "",  # Include all extensions
    "include_subdomains": True,
    "from_date": "",  # Get all historical data
    "to_date": "",
    "threads": 10,
}


def _extract_gau_params(data):
    """Extract and validate gau parameters from request data."""
    return {
        "domain": data.get("url", data.get("domain", "")),
        "providers": data.get("providers", "wayback,commoncrawl,otx,urlscan"),
        "include_subs": data.get("include_subs", data.get("include_subdomains", False)),
        "blacklist": data.get("blacklist", ""),
        "from_date": data.get("from_date", ""),
        "to_date": data.get("to_date", ""),
        "output_file": data.get("output_file", ""),
        "threads": data.get("threads", 5),
        "timeout": data.get("timeout", 60),
        "retries": data.get("retries", 5),
        "proxy": data.get("proxy", ""),
        "random_agent": data.get("random_agent", False),
        "verbose": data.get("verbose", False),
        "additional_args": data.get("additional_args", ""),
        "gau_timeout": data.get("gau_timeout", 300),
        "api_keys": data.get("api_keys", {}),
    }


def _validate_gau_params(params):
    """Validate GAU parameters."""
    if not params.get("domain"):
        raise ValueError("Domain parameter is required")

    # Validate domain format
    import re

    domain_pattern = r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]$"
    if not re.match(domain_pattern, params["domain"]):
        raise ValueError("Invalid domain format")

    return True


def _configure_api_keys(params):
    """Configure API keys for providers."""
    api_keys = params.get("api_keys", {})
    env_vars = []

    if "urlscan" in api_keys:
        env_vars.append(f"URLSCAN_API_KEY={api_keys['urlscan']}")
    if "otx" in api_keys:
        env_vars.append(f"OTX_API_KEY={api_keys['otx']}")

    return env_vars


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
            # For certain key parameters, use aggressive values if user set defaults
            if key in [
                "providers",
                "blacklist",
                "include_subdomains",
                "threads",
            ] and user_params.get(key) in ["wayback", "png,jpg,css,js", False, 3, None]:
                merged_params[key] = aggressive_value

    return merged_params


def _build_gau_command(params):
    """Build gau command from parameters."""
    command = f"gau {params['domain']}"

    if params["providers"] != "wayback,commoncrawl,otx,urlscan":
        command += f" --providers {params['providers']}"

    if params["include_subs"]:
        command += " --subs"

    if params["blacklist"]:
        command += f" --blacklist {params['blacklist']}"

    if params["from_date"]:
        command += f" --from {params['from_date']}"

    if params["to_date"]:
        command += f" --to {params['to_date']}"

    if params["output_file"]:
        command += f" --output {params['output_file']}"

    if params["threads"] != 5:
        command += f" --threads {int(params['threads'])}"

    if params["timeout"] != 60:
        command += f" --timeout {int(params['timeout'])}"

    if params["retries"] != 5:
        command += f" --retries {int(params['retries'])}"

    if params["proxy"]:
        command += f" --proxy {params['proxy']}"

    if params["random_agent"]:
        command += " --random-agent"

    if params["verbose"]:
        command += " --verbose"

    # Handle additional arguments
    if params["additional_args"]:
        command += " " + params["additional_args"]

    return command


def _parse_gau_result(execution_result, params, command):
    """Parse gau execution result and format response."""
    if execution_result.get("success"):
        urls = []
        if execution_result.get("stdout"):
            urls = [
                line.strip()
                for line in execution_result["stdout"].split("\n")
                if line.strip()
            ]

        return {
            "tool": "gau",
            "target": params["domain"],
            "command": command,
            "status": "completed",
            "urls": urls,
            "total_urls": len(urls),
            "providers_used": params["providers"].split(",")
            if params["providers"]
            else [],
            "raw_output": execution_result.get("stdout", ""),
            "error_output": execution_result.get("stderr", ""),
            "return_code": execution_result.get("return_code", 0),
            "execution_time": execution_result.get("execution_time", "unknown"),
            "success": True,
        }
    else:
        return {
            "tool": "gau",
            "target": params["domain"],
            "command": command,
            "status": "failed",
            "error": execution_result.get("error", "Command execution failed"),
            "error_output": execution_result.get("stderr", ""),
            "return_code": execution_result.get("return_code", 1),
            "success": False,
        }


@tool(required_fields=["domain"])
def execute_gau():
    """Execute Gau (Get All URLs) for URL discovery from multiple sources."""
    data = request.get_json()
    params = _extract_gau_params(data)

    # Validate parameters
    _validate_gau_params(params)

    # Configure API keys environment
    env_vars = _configure_api_keys(params)

    logger.info(f"Executing Gau on {params['domain']}")

    # Build base command
    command = _build_gau_command(params)

    # Prefix environment variables to the command if any
    if env_vars:
        env_prefix = " ".join(env_vars)
        command = f"{env_prefix} {command}"

    execution_result = execute_command(command, timeout=params["gau_timeout"])

    return _parse_gau_result(execution_result, params, command)
