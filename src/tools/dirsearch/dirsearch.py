import logging
import re
from typing import Any
from urllib.parse import urlparse

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_dirsearch_params(data):
    """Extract and validate dirsearch parameters from request data."""
    url = data["url"]
    extensions = data.get("extensions", "php,html,js,txt,xml,json")
    wordlist = data.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    threads = data.get("threads", 30)
    recursive = data.get("recursive", False)
    timeout = data.get("timeout", 300)
    additional_args = data.get("additional_args", "")

    return {
        "url": url,
        "extensions": extensions,
        "wordlist": wordlist,
        "threads": threads,
        "recursive": recursive,
        "timeout": timeout,
        "additional_args": additional_args,
    }


def _build_dirsearch_command(params):
    """Build dirsearch command from parameters."""
    # Build dirsearch command
    cmd_parts = ["dirsearch", "-u", params["url"]]

    # Add extensions
    cmd_parts.extend(["-e", params["extensions"]])

    # Add wordlist
    cmd_parts.extend(["-w", params["wordlist"]])

    # Add threads
    cmd_parts.extend(["-t", str(params["threads"])])

    # Add recursive option
    if params["recursive"]:
        cmd_parts.append("-r")

    # Add any additional arguments
    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return " ".join(cmd_parts)


def _parse_dirsearch_results(raw_output: str) -> list[dict[str, Any]]:
    """
    Parse dirsearch output and extract found paths with status codes and sizes.

    Args:
        raw_output: Raw stdout from dirsearch command

    Returns:
        List of dictionaries containing path information
    """
    found_paths = []

    if not raw_output:
        return found_paths

    lines = raw_output.split("\n")

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Match dirsearch output format: [timestamp] STATUS - SIZE - URL
        # Example: "[20:26:07] 200 -   424B - https://httpbin.org/cache"
        # Example: "[20:26:15] 502 -   524B - https://httpbin.org/csproj"
        status_match = re.search(
            r"\[\d{2}:\d{2}:\d{2}\]\s+(\d{3})\s+-\s+(\d+[KMGT]?B?|\-)\s+-\s+(\S+)", line
        )

        if status_match:
            status_code, size, full_url = status_match.groups()

            # Extract path from full URL
            try:
                parsed_url = urlparse(full_url)
                path = parsed_url.path if parsed_url.path else "/"
            except Exception:
                # Fallback: use the full URL if parsing fails
                path = full_url

            # Clean up size field
            if size == "-":
                size = 0
            else:
                # Convert size to bytes if needed
                if size.endswith("KB"):
                    size = int(float(size[:-2]) * 1024)
                elif size.endswith("MB"):
                    size = int(float(size[:-2]) * 1024 * 1024)
                elif size.endswith("GB"):
                    size = int(float(size[:-2]) * 1024 * 1024 * 1024)
                elif size.endswith("B"):
                    size = int(size[:-1])
                else:
                    try:
                        size = int(size)
                    except ValueError:
                        size = 0

            found_paths.append({"path": path, "status": int(status_code), "size": size})

    return found_paths


def _parse_dirsearch_result(execution_result, params, command):
    """Parse dirsearch execution result and format response."""
    # Parse structured output from dirsearch results
    found_paths = _parse_dirsearch_results(execution_result.get("stdout", ""))

    return {
        "tool": "dirsearch",
        "target": params["url"],
        "parameters": {
            "url": params["url"],
            "extensions": params["extensions"],
            "wordlist": params["wordlist"],
            "threads": params["threads"],
            "recursive": params["recursive"],
            "timeout": params["timeout"],
            "additional_args": params["additional_args"],
        },
        "command": command,
        "success": execution_result["success"],
        "status": "completed" if execution_result["success"] else "failed",
        "raw_output": execution_result.get("stdout", ""),
        "error_output": execution_result.get("stderr", ""),
        "return_code": execution_result.get("return_code", -1),
        "execution_time": None,  # Could be parsed from output if needed
        "found_paths": found_paths,
        "count": len(found_paths),
    }


@tool()
def execute_dirsearch():
    """Execute Dirsearch for directory and file discovery."""
    data = request.get_json()
    params = _extract_dirsearch_params(data)

    logger.info(f"Executing Dirsearch on {params['url']}")

    command = _build_dirsearch_command(params)
    execution_result = execute_command(command, params["timeout"])

    return _parse_dirsearch_result(execution_result, params, command)
