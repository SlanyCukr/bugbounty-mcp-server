import logging

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_dirb_params(data):
    """Extract and validate dirb parameters from request data."""
    url = data["url"]
    wordlist = data.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    extensions = data.get("extensions", "")
    recursive = data.get("recursive", False)
    ignore_case = data.get("ignore_case", False)
    user_agent = data.get("user_agent", "")
    headers = data.get("headers", "")
    cookies = data.get("cookies", "")
    proxy = data.get("proxy", "")
    auth = data.get("auth", "")
    delay = data.get("delay", "")
    additional_args = data.get("additional_args", "")

    return {
        "url": url,
        "wordlist": wordlist,
        "extensions": extensions,
        "recursive": recursive,
        "ignore_case": ignore_case,
        "user_agent": user_agent,
        "headers": headers,
        "cookies": cookies,
        "proxy": proxy,
        "auth": auth,
        "delay": delay,
        "additional_args": additional_args,
    }


def _build_dirb_command(params):
    """Build dirb command from parameters."""
    # Build dirb command
    cmd_parts = ["dirb", params["url"]]

    # Add wordlist parameter
    cmd_parts.append(params["wordlist"])

    # Add extensions if specified
    if params["extensions"]:
        cmd_parts.extend(["-X", params["extensions"]])

    # Add recursive scanning option
    if params["recursive"]:
        cmd_parts.append("-r")

    # Add case insensitive option
    if params["ignore_case"]:
        cmd_parts.append("-z")

    # Add non-interactive mode (always use this for automated execution)
    cmd_parts.append("-N")

    # Add user agent if specified
    if params["user_agent"]:
        cmd_parts.extend(["-a", params["user_agent"]])

    # Add custom headers if specified
    if params["headers"]:
        cmd_parts.extend(["-H", params["headers"]])

    # Add cookies if specified
    if params["cookies"]:
        cmd_parts.extend(["-c", params["cookies"]])

    # Add proxy if specified
    if params["proxy"]:
        cmd_parts.extend(["-p", params["proxy"]])

    # Add authentication if specified
    if params["auth"]:
        cmd_parts.extend(["-u", params["auth"]])

    # Add delay between requests if specified
    if params["delay"]:
        cmd_parts.extend(["-l", str(params["delay"])])

    # Add additional arguments if specified
    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return " ".join(cmd_parts)


def _parse_dirb_result(execution_result, params, command):
    """Parse dirb execution result and format response."""
    return {
        "tool": "dirb",
        "target": params["url"],
        "command": command,
        "success": execution_result["success"],
        "stdout": execution_result["stdout"],
        "stderr": execution_result["stderr"],
        "return_code": execution_result["return_code"],
        "parameters": {
            "url": params["url"],
            "wordlist": params["wordlist"],
            "extensions": params["extensions"],
            "recursive": params["recursive"],
            "ignore_case": params["ignore_case"],
            "user_agent": params["user_agent"],
            "headers": params["headers"],
            "cookies": params["cookies"],
            "proxy": params["proxy"],
            "auth": params["auth"],
            "delay": params["delay"],
            "additional_args": params["additional_args"],
        },
    }


@tool(required_fields=["url"])
def execute_dirb():
    """Execute DIRB directory scanner."""
    data = request.get_json()
    params = _extract_dirb_params(data)

    logger.info(f"Executing DIRB scan on {params['url']}")

    command = _build_dirb_command(params)
    execution_result = execute_command(
        command, timeout=600
    )  # 10 minute timeout for dirb scans

    return _parse_dirb_result(execution_result, params, command)
