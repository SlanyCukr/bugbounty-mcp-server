"""nikto tool implementation."""

import logging

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_nikto_params(data):
    """Extract and validate nikto parameters from request data."""
    # Check for aggressive mode
    aggressive = data.get("aggressive", False)

    # Base parameters
    base_params = {
        "target": data["target"],
        "port": data.get("port", "80"),
        "ssl": data.get("ssl", False),
        "plugins": data.get("plugins", ""),
        "output_format": data.get("output_format", "txt"),
        "evasion": data.get("evasion", ""),
        "timeout": data.get("timeout", 600),
        "max_time": data.get("max_time", ""),
        "mutate": data.get("mutate", ""),
        "additional_args": data.get("additional_args", ""),
        # Authentication parameters
        "auth_type": data.get("auth_type", ""),  # basic, digest, ntlm
        "username": data.get("username", ""),
        "password": data.get("password", ""),
        # Custom headers
        "headers": data.get("headers", {}),  # Dict of header_name: header_value
        "user_agent": data.get("user_agent", ""),
        "cookies": data.get("cookies", ""),
        # Proxy settings
        "proxy": data.get("proxy", ""),
        # Other advanced options
        "virtual_host": data.get("virtual_host", ""),
        "config_file": data.get("config_file", ""),
    }

    # Apply aggressive preset if requested
    if aggressive:
        # Nikto aggressive preset
        base_params.update(
            {
                "plugins": "@@ALL",
                "timeout": 30,
                "max_time": 3600,
                "evasion": "1,2,3,4,5,6,7,8,9,A,B",
                "mutate": "1,2,3,4,5,6",
                "output_format": "json",
            }
        )
    return base_params


def _build_nikto_command(params):
    """Build nikto command from parameters."""
    cmd_parts = ["nikto", "-h", params["target"]]

    if params["port"] and params["port"] != "80":
        cmd_parts.extend(["-p", str(params["port"])])

    if params["ssl"]:
        cmd_parts.append("-ssl")

    if params["plugins"]:
        cmd_parts.extend(["-Plugins", params["plugins"]])

    if params["output_format"] != "txt":
        cmd_parts.extend(["-Format", params["output_format"]])

    if params["evasion"]:
        cmd_parts.extend(["-evasion", params["evasion"]])

    if params["max_time"]:
        cmd_parts.extend(["-maxtime", str(params["max_time"])])

    if params["mutate"]:
        cmd_parts.extend(["-mutate", params["mutate"]])

    # Authentication support
    if params["auth_type"] and params["username"] and params["password"]:
        auth_string = f"{params['username']}:{params['password']}"
        if params["auth_type"].lower() == "basic":
            cmd_parts.extend(["-id", auth_string])
        elif params["auth_type"].lower() == "digest":
            # Nikto handles digest automatically when credentials are provided
            cmd_parts.extend(["-id", auth_string])

    # Custom headers support
    if params["headers"]:
        for header_name, header_value in params["headers"].items():
            cmd_parts.extend(["-header", f"{header_name}: {header_value}"])

    # User Agent
    if params["user_agent"]:
        cmd_parts.extend(["-useragent", params["user_agent"]])

    # Cookies
    if params["cookies"]:
        cmd_parts.extend(["-cookie", params["cookies"]])

    # Proxy support
    if params["proxy"]:
        cmd_parts.extend(["-useproxy", params["proxy"]])

    # Virtual host
    if params["virtual_host"]:
        cmd_parts.extend(["-vhost", params["virtual_host"]])

    # Config file
    if params["config_file"]:
        cmd_parts.extend(["-config", params["config_file"]])

    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return " ".join(cmd_parts)


def _parse_nikto_result(execution_result, params, command):
    """Parse nikto execution result and format response."""
    result = {
        "tool": "nikto",
        "target": params["target"],
        "parameters": {
            "port": params["port"],
            "ssl": params["ssl"],
            "plugins": params["plugins"],
            "auth_type": params.get("auth_type", ""),
            "has_custom_headers": bool(params.get("headers")),
            "user_agent": params.get("user_agent", ""),
            "proxy": params.get("proxy", ""),
            "virtual_host": params.get("virtual_host", ""),
        },
        "command": command,
        "status": "completed" if execution_result["success"] else "failed",
        "raw_output": execution_result.get("stdout", ""),
        "error_output": execution_result.get("stderr", ""),
        "return_code": execution_result.get("return_code", -1),
        "execution_time": None,
    }

    # Parse basic findings from output if successful
    if execution_result["success"] and result["raw_output"]:
        try:
            findings = []
            lines = result["raw_output"].strip().split("\n")

            for line in lines:
                line = line.strip()
                # Look for Nikto findings (lines that contain vulnerability indicators)
                if any(
                    indicator in line.lower()
                    for indicator in [
                        "osvdb",
                        "cve",
                        "potential",
                        "vulnerability",
                        "misconfiguration",
                        "directory",
                        "file found",
                        "server version",
                    ]
                ):
                    findings.append({"message": line, "raw_output": line})

            result["findings"] = findings
        except Exception as e:
            logger.warning(f"Failed to parse Nikto findings: {e}")

    return result


@tool()
def execute_nikto():
    """Execute Nikto web server vulnerability scanner."""
    data = request.get_json()
    params = _extract_nikto_params(data)

    logger.info(f"Executing Nikto scan on {params['target']}")

    command = _build_nikto_command(params)
    execution_result = execute_command(command, params["timeout"])

    return _parse_nikto_result(execution_result, params, command)
