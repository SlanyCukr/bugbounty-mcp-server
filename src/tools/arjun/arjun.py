import logging

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_arjun_params(data):
    """Extract and validate arjun parameters from request data."""
    url = data["url"]
    method = data.get("method", "GET")
    wordlist = data.get("wordlist", "")
    threads = data.get("threads", 25)
    delay = data.get("delay", 0)
    timeout = data.get("timeout", "")
    headers = data.get("headers", "")
    post_data = data.get("data", "")
    stable = data.get("stable", False)
    get_method = data.get("get_method", True)
    post_method = data.get("post_method", False)
    json_method = data.get("json_method", False)
    include_status = data.get("include_status", "")
    exclude_status = data.get("exclude_status", "")
    output_file = data.get("output_file", "")
    additional_args = data.get("additional_args", "")

    return {
        "url": url,
        "method": method,
        "wordlist": wordlist,
        "threads": threads,
        "delay": delay,
        "timeout": timeout,
        "headers": headers,
        "post_data": post_data,
        "stable": stable,
        "get_method": get_method,
        "post_method": post_method,
        "json_method": json_method,
        "include_status": include_status,
        "exclude_status": exclude_status,
        "output_file": output_file,
        "additional_args": additional_args,
    }


def _build_arjun_command(params):
    """Build arjun command from parameters."""
    command = f"arjun -u {params['url']} -t {params['threads']}"

    # HTTP methods
    methods_list = []
    if params["get_method"]:
        methods_list.append("GET")
    if params["post_method"]:
        methods_list.append("POST")
    if params["json_method"]:
        methods_list.append("JSON")

    if methods_list:
        command += f" -m {','.join(methods_list)}"
    elif params["method"] != "GET":
        command += f" -m {params['method']}"

    # Add optional parameters
    if params["wordlist"]:
        command += f" -w {params['wordlist']}"

    if params["headers"]:
        command += f" --headers '{params['headers']}'"

    if params["post_data"]:
        command += f" --data '{params['post_data']}'"

    if params["delay"] > 0:
        command += f" -d {params['delay']}"

    if params["timeout"]:
        command += f" --timeout {params['timeout']}"

    if params["stable"]:
        command += " --stable"

    if params["include_status"]:
        command += f" --include-status {params['include_status']}"

    if params["exclude_status"]:
        command += f" --exclude-status {params['exclude_status']}"

    if params["output_file"]:
        command += f" -o {params['output_file']}"

    if params["additional_args"]:
        command += f" {params['additional_args']}"

    return command


def _parse_arjun_result(execution_result, params, command):
    """Parse arjun execution result and format response."""
    return {
        "tool": "arjun",
        "target": params["url"],
        "command": command,
        "success": execution_result["success"],
        "return_code": execution_result["return_code"],
        "stdout": execution_result["stdout"],
        "stderr": execution_result["stderr"],
        "parameters": {
            "url": params["url"],
            "method": params["method"],
            "wordlist": params["wordlist"],
            "threads": params["threads"],
            "delay": params["delay"],
            "timeout": params["timeout"],
            "stable": params["stable"],
            "additional_args": params["additional_args"],
        },
    }


@tool(required_fields=["url"])
def execute_arjun():
    """Execute Arjun for HTTP parameter discovery."""
    data = request.get_json()
    params = _extract_arjun_params(data)

    logger.info(f"Executing Arjun on {params['url']}")

    command = _build_arjun_command(params)
    logger.info(f"Executing arjun command: {command}")

    execution_result = execute_command(
        command, timeout=600
    )  # 10 minute timeout for arjun

    return _parse_arjun_result(execution_result, params, command)
