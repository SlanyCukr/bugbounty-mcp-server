import logging
import re
from typing import Any

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _parse_gobuster_output(raw_output: str, mode: str) -> list[dict[str, Any]]:
    """
    Parse gobuster output and extract discovered items.

    Args:
        raw_output: Raw stdout from gobuster command
        mode: Gobuster mode (dir, dns, vhost, fuzz)

    Returns:
        List of dictionaries containing discovered item information
    """
    discovered_items = []

    if not raw_output:
        return discovered_items

    lines = raw_output.split("\n")

    for line in lines:
        line = line.strip()
        if (
            not line
            or line.startswith("=")
            or line.startswith("Gobuster")
            or line.startswith("[+]")
        ):
            continue

        if mode == "dir":
            # Directory/file enumeration output format:
            # /admin                (Status: 301) [Size: 178] [--> http://example.com/admin/]
            # /login.php            (Status: 200) [Size: 2456]
            dir_match = re.search(
                r"(/[^\s]*)\s+\(Status:\s+(\d{3})\)\s+\[Size:\s+(\d+)\](?:\s+\[--> ([^\]]+)\])?",
                line,
            )
            if dir_match:
                path, status_code, size, redirect = dir_match.groups()
                item = {"path": path, "status": int(status_code), "size": int(size)}
                if redirect:
                    item["redirect"] = redirect
                discovered_items.append(item)

        elif mode == "dns":
            # DNS subdomain enumeration output format:
            # Found: mail.example.com
            # Found: www.example.com (CNAME)
            dns_match = re.search(r"Found:\s+([^\s]+)(?:\s+\(([^)]+)\))?", line)
            if dns_match:
                subdomain, record_type = dns_match.groups()
                item = {
                    "subdomain": subdomain,
                    "record_type": record_type if record_type else "A",
                }
                discovered_items.append(item)

        elif mode == "vhost":
            # Virtual host enumeration output format:
            # Found: admin.example.com (Status: 200) [Size: 1234]
            vhost_match = re.search(
                r"Found:\s+([^\s]+)\s+\(Status:\s+(\d{3})\)\s+\[Size:\s+(\d+)\]", line
            )
            if vhost_match:
                vhost, status_code, size = vhost_match.groups()
                item = {"vhost": vhost, "status": int(status_code), "size": int(size)}
                discovered_items.append(item)

        elif mode == "fuzz":
            # Fuzzing mode output format (similar to dir mode):
            # /test=admin           (Status: 200) [Size: 1234]
            fuzz_match = re.search(
                r"(/[^\s]*)\s+\(Status:\s+(\d{3})\)\s+\[Size:\s+(\d+)\]", line
            )
            if fuzz_match:
                fuzzed_path, status_code, size = fuzz_match.groups()
                item = {
                    "path": fuzzed_path,
                    "status": int(status_code),
                    "size": int(size),
                }
                discovered_items.append(item)

    return discovered_items


def _extract_gobuster_params(data):
    """Extract and validate gobuster parameters from request data."""
    url = data["url"]
    mode = data.get("mode", "dir")
    wordlist = data.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    extensions = data.get("extensions", "")
    threads = data.get("threads", 10)
    timeout = data.get("timeout", "10s")
    user_agent = data.get("user_agent", "")
    cookies = data.get("cookies", "")
    additional_args = data.get("additional_args", "")
    status_codes = data.get("status_codes", "")

    # Validate mode
    if mode not in ["dir", "dns", "fuzz", "vhost"]:
        from flask import jsonify

        return jsonify(
            {"error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"}
        ), 400

    return {
        "url": url,
        "mode": mode,
        "wordlist": wordlist,
        "extensions": extensions,
        "threads": threads,
        "timeout": timeout,
        "user_agent": user_agent,
        "cookies": cookies,
        "additional_args": additional_args,
        "status_codes": status_codes,
    }


def _build_gobuster_command(params):
    """Build gobuster command from parameters."""
    # Build gobuster command
    cmd_parts = ["gobuster", params["mode"]]

    # Add target URL
    if params["mode"] == "dns":
        cmd_parts.extend(["-d", params["url"]])
    else:
        cmd_parts.extend(["-u", params["url"]])

    # Add wordlist
    cmd_parts.extend(["-w", params["wordlist"]])

    # Add extensions for dir mode
    if params["mode"] == "dir" and params["extensions"]:
        cmd_parts.extend(["-x", params["extensions"]])

    # Add threads
    cmd_parts.extend(["-t", str(params["threads"])])

    # Add timeout
    cmd_parts.extend(["--timeout", params["timeout"]])

    # Add user agent
    if params["user_agent"]:
        cmd_parts.extend(["-a", params["user_agent"]])

    # Add cookies
    if params["cookies"]:
        cmd_parts.extend(["-c", params["cookies"]])

    # Add status codes
    if params["status_codes"]:
        cmd_parts.extend(["-s", params["status_codes"]])

    # Add additional arguments
    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return " ".join(cmd_parts)


def _parse_gobuster_result(execution_result, params, command):
    """Parse gobuster execution result and format response."""
    # Parse gobuster output
    discovered_items = _parse_gobuster_output(
        execution_result.get("stdout", ""), params["mode"]
    )

    return {
        "tool": "gobuster",
        "target": params["url"],
        "mode": params["mode"],
        "parameters": {
            "url": params["url"],
            "mode": params["mode"],
            "wordlist": params["wordlist"],
            "extensions": params["extensions"],
            "threads": params["threads"],
            "timeout": params["timeout"],
            "user_agent": params["user_agent"],
            "cookies": params["cookies"],
            "status_codes": params["status_codes"],
            "additional_args": params["additional_args"],
        },
        "command": command,
        "raw_output": execution_result.get("stdout", ""),
        "stderr": execution_result.get("stderr", ""),
        "return_code": execution_result.get("return_code", 0),
        "success": execution_result.get("success", False),
        "discovered_items": discovered_items,
        "total_found": len(discovered_items),
    }


@tool(required_fields=["url"])
def execute_gobuster():
    """Execute Gobuster for directory, DNS, or vhost discovery."""
    data = request.get_json()
    params = _extract_gobuster_params(data)

    # Handle validation error
    if isinstance(params, tuple):
        return params

    logger.info(f"Executing Gobuster {params['mode']} scan on {params['url']}")

    command = _build_gobuster_command(params)
    execution_result = execute_command(command, timeout=600)

    return _parse_gobuster_result(execution_result, params, command)
