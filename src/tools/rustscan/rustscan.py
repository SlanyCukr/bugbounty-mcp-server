import logging

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


@tool()
def execute_rustscan():
    """Execute RustScan for ultra-fast port scanning."""
    data = request.get_json()
    target = data["target"]

    logger.info(f"Executing RustScan on {target}")

    # Extract parameters with defaults
    ports = data.get("ports", "")
    ulimit = data.get("ulimit", 5000)
    batch_size = data.get("batch_size", 4500)
    timeout = data.get("timeout", 1500)
    tries = data.get("tries", 1)
    no_nmap = data.get("no_nmap", False)
    additional_args = data.get("additional_args", "")

    # Build rustscan command
    command = f"rustscan -a {target} --ulimit {ulimit} -b {batch_size} -t {timeout}"

    # Add port specification if provided
    if ports:
        command += f" -p {ports}"

    # Add tries parameter
    if tries > 1:
        command += f" --tries {tries}"

    # Add Nmap integration unless disabled
    if not no_nmap:
        command += " -- -sC -sV"

    # Add any additional arguments
    if additional_args:
        command += f" {additional_args}"

    # Execute the command
    result = execute_command(command, timeout=300)

    # Prepare the response in the expected format
    response_result = {
        "tool": "rustscan",
        "target": target,
        "command": command,
        "parameters": {
            "target": target,
            "ports": ports,
            "ulimit": ulimit,
            "batch_size": batch_size,
            "timeout": timeout,
            "tries": tries,
            "no_nmap": no_nmap,
            "additional_args": additional_args,
        },
        "execution": result,
    }

    return response_result
