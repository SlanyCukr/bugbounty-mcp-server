"""Nmap tool implementation for network scanning."""

import logging
import shlex
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import (
    create_finding,
    create_stats,
    tool,
)

logger = logging.getLogger(__name__)


def extract_nmap_params(data: dict) -> dict:
    """Extract and organize nmap parameters from request data."""
    return {
        "target": data["target"],
        "scan_type": data.get("scan_type", "-sS"),
        "ports": data.get("ports", ""),
        "timing": data.get("timing", "-T3"),
        "host_timeout": data.get("host_timeout", ""),
        "max_retries": data.get("max_retries", 1),
        "additional_args": data.get("additional_args", ""),
    }


def build_nmap_command(params: dict) -> str:
    """Build nmap command from parameters with proper security escaping."""
    cmd_parts = ["nmap"]

    # Add scan type
    if params["scan_type"]:
        for scan_arg in params["scan_type"].split():
            cmd_parts.append(shlex.quote(scan_arg))

    # Add timing
    if params["timing"]:
        cmd_parts.append(shlex.quote(params["timing"]))

    # Add ports if specified
    if params["ports"]:
        cmd_parts.extend(["-p", shlex.quote(params["ports"])])

    # Add host timeout
    if params["host_timeout"]:
        cmd_parts.extend(["--host-timeout", shlex.quote(params["host_timeout"])])

    # Add max retries
    if params["max_retries"]:
        cmd_parts.extend(["--max-retries", str(params["max_retries"])])

    # Force XML output for structured parsing
    cmd_parts.extend(["-oX", "-"])

    # Add additional arguments if provided
    if params["additional_args"]:
        try:
            # Split and quote each argument properly
            additional_parts = shlex.split(params["additional_args"])
            for part in additional_parts:
                cmd_parts.append(shlex.quote(part))
        except ValueError as e:
            # Invalid shell syntax - reject
            raise ValueError("Invalid additional arguments format") from e

    # Add target
    cmd_parts.append(shlex.quote(params["target"]))

    return " ".join(cmd_parts)


def parse_nmap_output(xml_output: str) -> list[dict[str, Any]]:
    """Parse nmap XML output into basic findings."""
    findings = []

    if not xml_output.strip():
        return findings

    try:
        # Parse XML
        root = ET.fromstring(xml_output)

        # Iterate through hosts
        for host in root.findall("host"):
            # Get host information
            address_elem = host.find("address")
            if address_elem is None:
                continue

            host_ip = address_elem.get("addr", "")
            if not host_ip:
                continue

            # Get hostname if available
            hostname = host_ip
            hostnames_elem = host.find("hostnames")
            if hostnames_elem is not None:
                hostname_elem = hostnames_elem.find("hostname")
                if hostname_elem is not None:
                    hostname = hostname_elem.get("name", host_ip)

            # Get host state
            status_elem = host.find("status")
            host_state = (
                status_elem.get("state", "unknown")
                if status_elem is not None
                else "unknown"
            )

            # Parse ports
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    port_id = int(port_elem.get("portid", 0))
                    protocol = port_elem.get("protocol", "tcp")

                    # Get port state
                    state_elem = port_elem.find("state")
                    port_state = (
                        state_elem.get("state", "unknown")
                        if state_elem is not None
                        else "unknown"
                    )

                    # Get service information
                    service_elem = port_elem.find("service")
                    service_name = ""
                    service_product = ""
                    service_version = ""
                    service_extra = ""

                    if service_elem is not None:
                        service_name = service_elem.get("name", "")
                        service_product = service_elem.get("product", "")
                        service_version = service_elem.get("version", "")
                        service_extra = service_elem.get("extrainfo", "")

                    # Get scripts output if available
                    scripts = []
                    for script_elem in port_elem.findall("script"):
                        script_id = script_elem.get("id", "")
                        script_output = script_elem.get("output", "")
                        if script_id and script_output:
                            scripts.append({"id": script_id, "output": script_output})

                    # Basic confidence mapping
                    confidence = "high" if port_state == "open" else "medium"

                    # Build basic tags
                    tags = ["port", "scan", protocol, port_state]
                    if service_name:
                        tags.append(service_name)
                    if scripts:
                        tags.append("scripted")

                    # Create basic finding without severity calculation
                    finding = create_finding(
                        finding_type="port",
                        target=hostname,
                        evidence={
                            "host_ip": host_ip,
                            "hostname": hostname,
                            "port": port_id,
                            "protocol": protocol,
                            "state": port_state,
                            "service_name": service_name,
                            "service_product": service_product,
                            "service_version": service_version,
                            "service_extra": service_extra,
                            "scripts": scripts,
                            "discovered_by": "nmap",
                            "host_state": host_state,
                        },
                        severity="info",  # Default to info for all findings
                        confidence=confidence,
                        tags=tags,
                        raw_ref=ET.tostring(port_elem, encoding="unicode"),
                    )
                    findings.append(finding)

            # If no ports found but host is up, create a host discovery finding
            if host_state == "up" and ports_elem is None:
                finding = create_finding(
                    finding_type="port",
                    target=hostname,
                    evidence={
                        "host_ip": host_ip,
                        "hostname": hostname,
                        "state": host_state,
                        "discovered_by": "nmap",
                        "scan_type": "host_discovery",
                    },
                    severity="info",
                    confidence="high",
                    tags=["host", "discovery", host_state],
                    raw_ref=ET.tostring(host, encoding="unicode"),
                )
                findings.append(finding)

    except ET.ParseError as e:
        logger.error(f"Failed to parse nmap XML output: {e}")
        # No text fallback - return empty list
        return []

    return findings


def parse_nmap_result(
    execution_result: dict[str, Any],
    params: dict,
    command: str,
    started_at: datetime,
    ended_at: datetime,
) -> dict[str, Any]:
    """Parse nmap execution result and format response with findings."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if not execution_result["success"]:
        return {
            "success": False,
            "tool": "nmap",
            "params": params,
            "command": command,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "error": execution_result.get("error", "Command execution failed"),
            "findings": [],
            "stats": create_stats(0, 0, 0),
        }

    # Parse XML output into structured findings
    stdout = execution_result.get("stdout", "")
    findings = parse_nmap_output(stdout)

    # Remove duplicates based on host and port combination
    seen_ports = set()
    unique_findings = []
    dupes_count = 0

    for finding in findings:
        if finding["type"] == "port":
            host = finding["target"]
            port = finding["evidence"]["port"]
            protocol = finding["evidence"]["protocol"]
            unique_key = f"{host}:{port}:{protocol}"
        else:
            # For host discoveries
            unique_key = finding["target"]

        if unique_key not in seen_ports:
            seen_ports.add(unique_key)
            unique_findings.append(finding)
        else:
            dupes_count += 1

    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "success": True,
        "tool": "nmap",
        "params": params,
        "command": command,
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat(),
        "duration_ms": duration_ms,
        "findings": unique_findings,
        "stats": create_stats(len(unique_findings), dupes_count, payload_bytes),
    }


@tool(required_fields=["target"])
def execute_nmap():
    """Execute Nmap scan against a target."""
    data = request.get_json()

    params = extract_nmap_params(data)

    logger.info(f"Executing Nmap scan on {params['target']}")

    started_at = datetime.now()
    command = build_nmap_command(params)
    execution_result = execute_command(
        command, timeout=1800
    )  # 30 minute timeout for nmap
    ended_at = datetime.now()

    return parse_nmap_result(execution_result, params, command, started_at, ended_at)
