import logging
from datetime import datetime

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _build_ffuf_command(url: str, params: dict) -> str:
    """Build comprehensive ffuf command with all parameters."""
    command_parts = ["ffuf"]

    # Ensure URL has FUZZ placeholder for directory fuzzing
    if "FUZZ" not in url:
        if url.endswith("/"):
            target_url = f"{url}FUZZ"
        else:
            target_url = f"{url}/FUZZ"
    else:
        target_url = url

    # Basic parameters
    command_parts.extend(["-u", f'"{target_url}"'])
    command_parts.extend(["-w", params["wordlist"]])

    # Secondary wordlist
    if params.get("secondary_wordlist"):
        command_parts.extend(["-w", params["secondary_wordlist"]])

    # Status code filtering
    if params.get("include_status"):
        command_parts.extend(["-mc", params["include_status"]])

    if params.get("exclude_status"):
        command_parts.extend(["-fc", params["exclude_status"]])

    # Size filtering
    if params.get("include_size"):
        command_parts.extend(["-ms", params["include_size"]])

    if params.get("exclude_size"):
        command_parts.extend(["-fs", params["exclude_size"]])

    # Word count filtering
    if params.get("include_words"):
        command_parts.extend(["-mw", params["include_words"]])

    if params.get("exclude_words"):
        command_parts.extend(["-fw", params["exclude_words"]])

    # Line count filtering
    if params.get("include_lines"):
        command_parts.extend(["-ml", params["include_lines"]])

    if params.get("exclude_lines"):
        command_parts.extend(["-fl", params["exclude_lines"]])

    # Regex filtering
    if params.get("include_regex"):
        command_parts.extend(["-mr", f'"{params["include_regex"]}"'])

    if params.get("exclude_regex"):
        command_parts.extend(["-fr", f'"{params["exclude_regex"]}"'])

    # Extensions
    if params.get("extensions"):
        extensions = params["extensions"].split(",")
        for ext in extensions:
            ext = ext.strip()
            if not ext.startswith("."):
                ext = f".{ext}"
            command_parts.extend(["-e", ext])

    # Performance parameters
    threads = min(int(params.get("threads", 40)), 200)  # Cap at 200 threads
    command_parts.extend(["-t", str(threads)])

    if params.get("delay"):
        command_parts.extend(["-p", params["delay"]])

    if params.get("rate_limit"):
        command_parts.extend(["-rate", str(params["rate_limit"])])

    # HTTP method
    if params.get("method", "GET") != "GET":
        command_parts.extend(["-X", params["method"]])

    # Headers
    if params.get("headers"):
        headers = params["headers"]
        if isinstance(headers, str):
            # Split multiple headers if provided as string
            for header in headers.split(";"):
                if header.strip():
                    command_parts.extend(["-H", f'"{header.strip()}"'])
        elif isinstance(headers, list):
            for header in headers:
                command_parts.extend(["-H", f'"{header}"'])

    # Cookies
    if params.get("cookies"):
        command_parts.extend(["-b", f'"{params["cookies"]}"'])

    # Proxy
    if params.get("proxy"):
        command_parts.extend(["-x", params["proxy"]])

    # Timeout
    if params.get("timeout"):
        command_parts.extend(["-timeout", str(params["timeout"])])

    # Recursion
    if params.get("recursion"):
        command_parts.append("-recursion")
        if params.get("recursion_depth"):
            command_parts.extend(["-recursion-depth", str(params["recursion_depth"])])

    # Silent mode for cleaner output
    command_parts.append("-s")

    # Additional arguments
    if params.get("additional_args"):
        command_parts.extend(params["additional_args"].split())

    return " ".join(command_parts)


def _extract_ffuf_params(data):
    """Extract and validate ffuf parameters from request data."""
    return {
        "url": data["url"],
        "wordlist": data.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
        "secondary_wordlist": data.get("secondary_wordlist", ""),
        "extensions": data.get("extensions", ""),
        "force_extensions": data.get("force_extensions", False),
        "exclude_extensions": data.get("exclude_extensions", ""),
        "prefixes": data.get("prefixes", ""),
        "suffixes": data.get("suffixes", ""),
        "include_status": data.get("include_status", "200,204,301,302,307,401,403,500"),
        "exclude_status": data.get("exclude_status", ""),
        "include_size": data.get("include_size", ""),
        "exclude_size": data.get("exclude_size", ""),
        "include_words": data.get("include_words", ""),
        "exclude_words": data.get("exclude_words", ""),
        "include_lines": data.get("include_lines", ""),
        "exclude_lines": data.get("exclude_lines", ""),
        "include_regex": data.get("include_regex", ""),
        "exclude_regex": data.get("exclude_regex", ""),
        "threads": data.get("threads", 40),
        "delay": data.get("delay", ""),
        "timeout": data.get("timeout", 10),
        "method": data.get("method", "GET"),
        "headers": data.get("headers", ""),
        "cookies": data.get("cookies", ""),
        "proxy": data.get("proxy", ""),
        "rate_limit": data.get("rate_limit", ""),
        "recursion": data.get("recursion", False),
        "recursion_depth": data.get("recursion_depth", 1),
        "additional_args": data.get("additional_args", ""),
    }


def _parse_ffuf_result(execution_result, params, command):
    """Parse ffuf execution result and format response."""
    result = {
        "tool": "ffuf",
        "target": params["url"],
        "parameters": params,
        "command": command,
        "success": execution_result["success"],
        "stdout": execution_result.get("stdout", ""),
        "stderr": execution_result.get("stderr", ""),
        "return_code": execution_result.get("return_code", -1),
        "timestamp": datetime.now().isoformat(),
    }

    if execution_result["success"]:
        result["status"] = "completed"
    else:
        result["status"] = "failed"
        result["error"] = execution_result.get("error", "Command execution failed")

    return result


@tool(required_fields=["url"])
def execute_ffuf():
    """Execute FFuf web fuzzer."""
    data = request.get_json()
    params = _extract_ffuf_params(data)

    logger.info(f"Executing FFuf on {params['url']}")

    command = _build_ffuf_command(params["url"], params)
    execution_result = execute_command(command, timeout=params["timeout"] * 60)

    return _parse_ffuf_result(execution_result, params, command)
