"""Nmap tool implementation for network scanning."""

import ipaddress
import logging
import re
import shlex
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import (
    SeverityLevel,
    create_finding,
    create_stats,
    tool,
)

logger = logging.getLogger(__name__)

# Aggressive preset for nmap
AGGRESSIVE_PRESET = {
    "scan_type": "-sS",  # SYN stealth scan
    "port_range": "1-65535",
    "timing": "-T4",
    "additional_args": (
        "-sV -sC --script vuln,exploit,brute --version-all --traceroute --reason"
    ),
    "host_timeout": "30m",
    "max_retries": 3,
}


def _extract_nmap_params(data):
    """Extract and validate nmap parameters from request data."""
    # Check for aggressive mode
    aggressive = data.get("aggressive", False)

    # Base parameters
    base_params = {
        "target": data["target"],
        "scan_type": data.get("scan_type", "-sS"),
        "ports": data.get("ports", ""),
        "timing": data.get("timing", "-T3"),
        "host_timeout": data.get("host_timeout", ""),
        "max_retries": data.get("max_retries", 1),
        "additional_args": data.get("additional_args", ""),
    }

    # Apply aggressive preset if requested
    return _apply_aggressive_preset(base_params, aggressive)


def _apply_aggressive_preset(user_params: dict, aggressive: bool = False) -> dict:
    """Apply aggressive preset to user parameters if aggressive=True."""
    if not aggressive:
        return user_params

    # Start with user params and apply aggressive preset
    merged_params = user_params.copy()

    # Apply aggressive preset for parameters not explicitly set by user
    for key, aggressive_value in AGGRESSIVE_PRESET.items():
        if key not in user_params:
            merged_params[key] = aggressive_value
        else:
            # For certain key parameters, use aggressive values if user set defaults
            if key in ["port_range", "timing", "max_retries"] and user_params.get(
                key
            ) in ["1-1000", "-T3", 1, None]:
                merged_params[key] = aggressive_value

    return merged_params


def _validate_target(target: str) -> bool:
    """Validate nmap target format."""
    if not target or len(target) > 253:  # Max hostname length
        return False

    # Check for dangerous characters
    if re.search(r"[;&|`$(){}]", target):
        return False

    # Try to validate as IP, CIDR, or hostname
    try:
        # Check if it's an IP address or CIDR
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        # Check if it's a valid hostname/domain
        hostname_pattern = re.compile(
            r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
        )
        return bool(hostname_pattern.match(target))


def _build_nmap_command(params):
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

    # Add target (already validated)
    cmd_parts.append(shlex.quote(params["target"]))

    return " ".join(cmd_parts)


def _determine_port_severity(port: int, service: str, state: str) -> SeverityLevel:
    """Determine severity based on port number, service, and state."""
    if state != "open":
        return "info"

    # Critical services that are often targeted
    critical_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
    # High-risk services
    high_risk_ports = [135, 139, 445, 1433, 1521, 3389, 5432, 5900, 6379]
    # Medium-risk services
    medium_risk_ports = [111, 512, 513, 514, 2049, 6000]

    if port in critical_ports:
        return "low"  # Open ports are informational unless they have vulns
    elif port in high_risk_ports:
        return "low"
    elif port in medium_risk_ports:
        return "info"
    elif service and any(
        keyword in service.lower()
        for keyword in ["ssh", "http", "ftp", "smtp", "mysql", "postgres"]
    ):
        return "low"
    else:
        return "info"


def _parse_nmap_xml_output(xml_output: str) -> list[dict[str, Any]]:
    """Parse nmap XML output into structured findings."""
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

                    # Determine confidence and severity
                    confidence = "high" if port_state == "open" else "medium"
                    severity = _determine_port_severity(
                        port_id, service_name, port_state
                    )

                    # Build tags
                    tags = ["port", "scan", protocol, port_state]
                    if service_name:
                        tags.append(service_name)
                    if scripts:
                        tags.append("scripted")

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
                        severity=severity,
                        confidence=confidence,
                        tags=tags,
                        raw_ref=ET.tostring(port_elem, encoding="unicode"),
                    )
                    findings.append(finding)

            # If no ports found but host is up, create a host discovery finding
            if host_state == "up" and ports_elem is None:
                finding = create_finding(
                    finding_type="subdomain",  # Host discovery
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
        # Fall back to text parsing
        return _parse_nmap_text_output(xml_output)

    return findings


def parse_nmap_xml_output(xml_output: str) -> list[dict[str, Any]]:
    """Public wrapper for Nmap XML parsing used by other modules."""
    return _parse_nmap_xml_output(xml_output)


def parse_nmap_text_output(raw_output: str) -> list[dict[str, Any]]:
    """Public wrapper for Nmap text parsing used by other modules."""
    return _parse_nmap_text_output(raw_output)


def determine_nmap_port_severity(port: int, service: str, state: str) -> SeverityLevel:
    """Expose the port severity helper for other network scanning tools."""
    return _determine_port_severity(port, service, state)


def _parse_nmap_text_output(raw_output: str) -> list[dict[str, Any]]:
    """Parse nmap text output as fallback."""
    findings = []

    if not raw_output:
        return findings

    lines = raw_output.split("\n")
    current_host = None

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Look for host information
        host_match = re.search(
            r"Nmap scan report for ([^\s]+)(?:\s+\(([^)]+)\))?", line
        )
        if host_match:
            hostname = host_match.group(1)
            ip_addr = host_match.group(2) if host_match.group(2) else hostname
            current_host = {"hostname": hostname, "ip": ip_addr}
            continue

        # Look for port information
        port_match = re.search(
            r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+([^\s]+)(?:\s+(.+))?", line
        )
        if port_match and current_host:
            port_id = int(port_match.group(1))
            protocol = port_match.group(2)
            state = port_match.group(3)
            service = port_match.group(4)
            extra = port_match.group(5) if port_match.group(5) else ""

            confidence = "high" if state == "open" else "medium"
            severity = _determine_port_severity(port_id, service, state)

            tags = ["port", "scan", protocol, state]
            if service:
                tags.append(service)

            finding = create_finding(
                finding_type="port",
                target=current_host["hostname"],
                evidence={
                    "host_ip": current_host["ip"],
                    "hostname": current_host["hostname"],
                    "port": port_id,
                    "protocol": protocol,
                    "state": state,
                    "service_name": service,
                    "service_extra": extra,
                    "discovered_by": "nmap",
                },
                severity=severity,
                confidence=confidence,
                tags=tags,
                raw_ref=line,
            )
            findings.append(finding)

    return findings


def _parse_nmap_result(
    execution_result, params, command, started_at: datetime, ended_at: datetime
) -> dict[str, Any]:
    """Parse nmap execution result and format response with findings."""
    if not execution_result["success"]:
        return {"findings": [], "stats": create_stats(0, 0, 0)}

    # Parse XML output into structured findings
    stdout = execution_result.get("stdout", "")
    findings = _parse_nmap_xml_output(stdout)

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
        "findings": unique_findings,
        "stats": create_stats(len(unique_findings), dupes_count, payload_bytes),
    }


@tool(required_fields=["target"])
def execute_nmap():
    """Execute Nmap scan against a target."""
    data = request.get_json()

    params = _extract_nmap_params(data)

    # Validate target before executing
    if not _validate_target(params["target"]):
        raise ValueError(f"Invalid target format: {params['target']}")

    logger.info(f"Executing Nmap scan on {params['target']}")

    started_at = datetime.now()
    command = _build_nmap_command(params)
    execution_result = execute_command(
        command, timeout=1800
    )  # 30 minute timeout for nmap
    ended_at = datetime.now()

    return _parse_nmap_result(execution_result, params, command, started_at, ended_at)
