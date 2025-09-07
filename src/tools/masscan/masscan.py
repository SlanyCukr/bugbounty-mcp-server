import logging
from typing import Any

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _parse_masscan_output(raw_output: str, masscan_params: dict) -> dict[str, Any]:
    """
    Parse masscan output and extract port information.

    Args:
        raw_output: Raw stdout from masscan command
        masscan_params: Parameters used for the scan

    Returns:
        Dictionary containing parsed scan results
    """
    open_ports = []
    banner_grabs = []

    if not raw_output.strip():
        return {
            "open_ports": open_ports,
            "banner_grabs": banner_grabs,
            "total_hosts_scanned": 0,
            "total_ports_scanned": 0,
            "scan_statistics": {
                "packets_sent": 0,
                "packets_received": 0,
                "rate_achieved": masscan_params.get("rate", 0),
            },
        }

    lines = raw_output.strip().split("\n")

    for line in lines:
        line = line.strip()

        # Parse standard port results in various formats
        if line.startswith("open tcp") or line.startswith("open udp"):
            # Format: "open tcp 80 ip.address timestamp"
            parts = line.split()
            if len(parts) >= 4:
                protocol = parts[1]  # tcp or udp
                port = int(parts[2])
                ip_address = parts[3]
                timestamp = " ".join(parts[4:]) if len(parts) > 4 else ""

                port_info = {
                    "port": port,
                    "protocol": protocol,
                    "state": "open",
                    "ip_address": ip_address,
                    "timestamp": timestamp,
                }
                open_ports.append(port_info)

        elif line.startswith("Discovered open port"):
            # Format: "Discovered open port 80/tcp on 192.168.1.1"
            try:
                parts = line.split()
                if len(parts) >= 6 and "/" in parts[3] and "on" in parts:
                    port_proto = parts[3].split("/")
                    port = int(port_proto[0])
                    protocol = port_proto[1]
                    ip_address = parts[5]  # IP after "on"

                    port_info = {
                        "port": port,
                        "protocol": protocol,
                        "state": "open",
                        "ip_address": ip_address,
                        "timestamp": "",
                    }
                    open_ports.append(port_info)
            except (ValueError, IndexError):
                # Skip malformed lines
                pass

        # Parse banner information if available
        elif "banner" in line.lower() and masscan_params.get("banners", False):
            # Banner format can vary, attempt to extract what we can
            if ":" in line:
                banner_parts = line.split(":", 1)
                if len(banner_parts) == 2:
                    banner_info = {
                        "source": banner_parts[0].strip(),
                        "banner": banner_parts[1].strip(),
                    }
                    banner_grabs.append(banner_info)

    # Calculate statistics
    total_hosts = len(
        set(port["ip_address"] for port in open_ports if "ip_address" in port)
    )
    total_ports_scanned = _calculate_port_count(masscan_params.get("ports", "1-65535"))

    return {
        "open_ports": open_ports,
        "banner_grabs": banner_grabs,
        "total_hosts_scanned": max(total_hosts, 1) if open_ports else 0,
        "total_ports_scanned": total_ports_scanned,
        "scan_statistics": {
            "packets_sent": total_ports_scanned,
            "packets_received": len(open_ports),
            "rate_achieved": masscan_params.get("rate", 0),
        },
    }


def _calculate_port_count(port_spec: str) -> int:
    """Calculate the total number of ports from a port specification."""
    if not port_spec or port_spec == "1-65535":
        return 65535

    total = 0
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = map(int, part.split("-"))
                total += end - start + 1
            except ValueError:
                total += 1  # fallback for invalid range
        else:
            try:
                int(part)  # validate single port
                total += 1
            except ValueError:
                pass  # ignore invalid port specifications

    return total


@tool()
def execute_masscan():
    """Execute Masscan for high-speed port scanning."""
    data = request.get_json()
    target = data["target"]

    logger.info(f"Executing Masscan on {target}")

    masscan_params = {
        "target": target,
        "ports": data.get("ports", "1-65535"),
        "rate": data.get("rate", 1000),
        "banners": data.get("banners", False),
        "exclude_file": data.get("exclude_file", ""),
        "include_file": data.get("include_file", ""),
        "output_format": data.get("output_format", "list"),
        "interface": data.get("interface", ""),
        "router_mac": data.get("router_mac", ""),
        "source_ip": data.get("source_ip", ""),
        "additional_args": data.get("additional_args", ""),
    }

    # Build masscan command
    command = (
        f"masscan {target} -p{masscan_params['ports']} --rate={masscan_params['rate']}"
    )

    # Add network interface if provided
    if masscan_params["interface"]:
        command += f" -e {masscan_params['interface']}"

    # Add router MAC if provided
    if masscan_params["router_mac"]:
        command += f" --router-mac {masscan_params['router_mac']}"

    # Add source IP if provided
    if masscan_params["source_ip"]:
        command += f" --source-ip {masscan_params['source_ip']}"

    # Add banners option if requested
    if masscan_params["banners"]:
        command += " --banners"

    # Add exclude file if provided
    if masscan_params["exclude_file"]:
        command += f" --excludefile {masscan_params['exclude_file']}"

    # Add include file if provided
    if masscan_params["include_file"]:
        command += f" --includefile {masscan_params['include_file']}"

    # Add additional arguments if provided
    if masscan_params["additional_args"]:
        command += f" {masscan_params['additional_args']}"

    # Execute the command
    execution_result = execute_command(command, timeout=600)

    if not execution_result["success"]:
        raise Exception(
            f"Masscan execution failed: {execution_result.get('error', execution_result.get('stderr', 'Unknown error'))}"
        )

    # Parse masscan output
    scan_results = _parse_masscan_output(execution_result["stdout"], masscan_params)

    result = {
        "tool": "masscan",
        "target": target,
        "parameters": masscan_params,
        "status": "completed" if execution_result["success"] else "failed",
        "scan_results": scan_results,
        "execution_time": execution_result.get("execution_time", "N/A"),
        "raw_output": execution_result["stdout"],
        "command": command,
    }

    return result
