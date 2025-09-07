import logging

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


@tool(required_fields=["url"])
def execute_wpscan():
    """Execute WPScan for WordPress vulnerability analysis."""
    data = request.get_json()
    url = data["url"]
    logger.info(f"Executing WPScan on {url}")

    # Build wpscan command
    cmd_parts = ["wpscan", "--url", url]

    # Add enumeration options
    enumerate = data.get("enumerate", "ap,at,cb,dbe")
    if enumerate:
        cmd_parts.extend(["--enumerate", enumerate])

    # Add update option
    if data.get("update", True):
        cmd_parts.append("--update")

    # Add random user agent
    if data.get("random_user_agent", True):
        cmd_parts.append("--random-user-agent")

    # Add API token if provided
    api_token = data.get("api_token", "")
    if api_token:
        cmd_parts.extend(["--api-token", api_token])

    # Add threads
    threads = data.get("threads", 5)
    cmd_parts.extend(["--max-threads", str(threads)])

    # Add output format for better parsing
    cmd_parts.extend(["--format", "json"])

    # Add additional arguments
    additional_args = data.get("additional_args", "")
    if additional_args:
        cmd_parts.extend(additional_args.split())

    command = " ".join(cmd_parts)

    # Execute wpscan command
    execution_result = execute_command(command, timeout=900)

    wpscan_params = {
        "url": url,
        "enumerate": enumerate,
        "update": data.get("update", True),
        "random_user_agent": data.get("random_user_agent", True),
        "api_token": api_token,
        "threads": threads,
        "additional_args": additional_args,
    }

    result = {
        "tool": "wpscan",
        "target": url,
        "parameters": wpscan_params,
        "command": command,
        "success": execution_result["success"],
        "stdout": execution_result.get("stdout", ""),
        "stderr": execution_result.get("stderr", ""),
        "return_code": execution_result.get("return_code", 0),
    }

    return result
