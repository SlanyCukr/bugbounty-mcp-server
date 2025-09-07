import logging

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


@tool(name="nmap-advanced")
def execute_nmap_advanced():
    """Execute advanced Nmap scan with comprehensive options."""
    data = request.get_json()
    target = data["target"]
    scan_type = data.get("scan_type", "-sS")
    ports = data.get("ports", "")
    timing = data.get("timing", "T4")
    scripts = data.get("scripts", "")
    nse_scripts = data.get(
        "nse_scripts", ""
    )  # Support both 'scripts' and 'nse_scripts'
    os_detection = data.get("os_detection", False)
    service_detection = data.get("service_detection", True)
    version_detection = data.get(
        "version_detection", False
    )  # Explicit version detection
    aggressive = data.get("aggressive", False)
    stealth = data.get("stealth", False)
    additional_args = data.get("additional_args", "")

    logger.info(f"Executing advanced Nmap scan on {target}")

    # Build advanced nmap command
    command = f"nmap {scan_type} {target}"

    if ports:
        command += f" -p {ports}"

    if stealth:
        command += " -T2 -f --mtu 24"
    else:
        command += f" -{timing}"

    if os_detection:
        command += " -O"

    if service_detection or version_detection:
        command += " -sV"

    if aggressive:
        command += " -A"

    # Handle NSE scripts
    script_param = (
        nse_scripts or scripts
    )  # Use nse_scripts if provided, fallback to scripts
    if script_param:
        command += f" --script={script_param}"
    elif (
        not aggressive
    ):  # Default useful scripts if not aggressive and no specific scripts
        command += " --script=default,discovery,safe"

    if additional_args:
        command += f" {additional_args}"

    # Execute the actual nmap command
    result = execute_command(command)

    # Format response with actual execution results
    nmap_result = {
        "tool": "nmap_advanced",
        "target": target,
        "parameters": {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "timing": timing,
            "scripts": scripts,
            "nse_scripts": nse_scripts,
            "os_detection": os_detection,
            "service_detection": service_detection,
            "version_detection": version_detection,
            "aggressive": aggressive,
            "stealth": stealth,
            "additional_args": additional_args,
        },
        "command": command,
        "success": result["success"],
        "return_code": result["return_code"],
        "stdout": result["stdout"],
        "stderr": result["stderr"],
    }

    return nmap_result
