"""Masscan tool implementation that returns actionable port findings."""

import json
import logging
import shlex
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from typing import Any

from flask import jsonify, request

from src.rest_api_server.tools.nmap import determine_nmap_port_severity
from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import (
    create_error_response,
    create_finding,
    create_stats,
    tool,
)


class MasscanParseError(RuntimeError):
    """Raised when masscan output cannot be parsed."""


logger = logging.getLogger(__name__)


def _extract_masscan_params(data: dict[str, Any]) -> dict[str, Any]:
    """Extract parameters for masscan execution."""
    output_format = data.get("output_format", "json").lower()
    if output_format not in {"json", "xml"}:
        output_format = "json"

    return {
        "target": data["target"],
        "ports": data.get("ports", "1-65535"),
        "rate": int(data.get("rate", 1000)),
        "banners": bool(data.get("banners", False)),
        "interface": data.get("interface"),
        "router_mac": data.get("router_mac"),
        "source_ip": data.get("source_ip"),
        "exclude_file": data.get("exclude_file"),
        "include_file": data.get("include_file"),
        "additional_args": data.get("additional_args", ""),
        "output_format": output_format,
    }


def _build_masscan_command(params: dict[str, Any]) -> str:
    """Build a masscan command string with safe shell escaping."""
    cmd_parts: list[str] = ["masscan"]

    if params.get("ports"):
        cmd_parts.extend(["-p", params["ports"]])

    cmd_parts.extend(["--rate", str(params["rate"])])

    if params.get("banners"):
        cmd_parts.append("--banners")

    if params.get("interface"):
        cmd_parts.extend(["-e", params["interface"]])

    if params.get("router_mac"):
        cmd_parts.extend(["--router-mac", params["router_mac"]])

    if params.get("source_ip"):
        cmd_parts.extend(["--source-ip", params["source_ip"]])

    if params.get("exclude_file"):
        cmd_parts.extend(["--excludefile", params["exclude_file"]])

    if params.get("include_file"):
        cmd_parts.extend(["--includefile", params["include_file"]])

    additional_parts = (
        shlex.split(params["additional_args"]) if params.get("additional_args") else []
    )

    has_output_directive = any(
        part.startswith("-o") or part.startswith("--output")
        for part in additional_parts
    )

    if not has_output_directive:
        if params["output_format"] == "xml":
            cmd_parts.extend(["-oX", "-"])
        else:
            cmd_parts.extend(["-oJ", "-"])

    cmd_parts.extend(additional_parts)

    target = params.get("target")
    if target:
        # Allow specifying multiple targets separated by whitespace
        for item in target.split():
            cmd_parts.append(item)

    return " ".join(shlex.quote(part) for part in cmd_parts)


def _iter_masscan_records(
    stdout: str, expected_format: str
) -> Iterable[dict[str, Any]]:
    """Yield structured port records from masscan output."""
    stripped = stdout.strip()
    if not stripped:
        return []

    if expected_format == "xml":
        return list(_iter_masscan_records_from_xml(stripped))

    if expected_format == "json":
        return list(_iter_masscan_records_from_json(stripped))

    raise MasscanParseError(f"Unsupported output format: {expected_format}")


def _iter_masscan_records_from_xml(xml_output: str) -> Iterable[dict[str, Any]]:
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise MasscanParseError("Failed to parse XML output") from exc

    for host_elem in root.findall("host"):
        address_elem = host_elem.find("address")
        if address_elem is None:
            continue

        host_ip = address_elem.get("addr", "").strip()
        if not host_ip:
            continue

        ports_elem = host_elem.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            try:
                port_id = int(port_elem.get("portid", ""))
            except (TypeError, ValueError):
                continue

            protocol = port_elem.get("protocol", "tcp")
            state_elem = port_elem.find("state")
            state = (
                state_elem.get("state", "unknown")
                if state_elem is not None
                else "unknown"
            )

            service_elem = port_elem.find("service")
            service_name = (
                service_elem.get("name", "") if service_elem is not None else ""
            )
            service_product = (
                service_elem.get("product", "") if service_elem is not None else ""
            )
            service_version = (
                service_elem.get("version", "") if service_elem is not None else ""
            )

            yield {
                "host": host_ip,
                "hostname": host_ip,
                "port": port_id,
                "protocol": protocol,
                "state": state,
                "service_name": service_name,
                "service_product": service_product,
                "service_version": service_version,
                "raw": ET.tostring(port_elem, encoding="unicode"),
            }


def _iter_masscan_records_from_json(json_output: str) -> Iterable[dict[str, Any]]:
    try:
        parsed = json.loads(json_output)
    except json.JSONDecodeError as exc:
        raise MasscanParseError("Failed to parse JSON output") from exc

    if isinstance(parsed, dict):
        hosts = parsed.get("hosts")
        if isinstance(hosts, list):
            for host in hosts:
                yield from _records_from_json_host(host)
        else:
            yield from _records_from_json_host(parsed)
        return

    if isinstance(parsed, list):
        for entry in parsed:
            yield from _records_from_json_host(entry)

    return []


def _records_from_json_host(host_entry: dict[str, Any]) -> Iterable[dict[str, Any]]:
    host_ip = host_entry.get("ip") or host_entry.get("host") or ""
    if not host_ip:
        return

    timestamp = host_entry.get("timestamp")
    ports = host_entry.get("ports")

    if isinstance(ports, list):
        for port_entry in ports:
            record = _record_from_json_port(host_ip, port_entry, timestamp)
            if record:
                yield record
        return

    # Some outputs flatten ports at top level
    record = _record_from_json_port(host_ip, host_entry, timestamp)
    if record:
        yield record


def _record_from_json_port(
    host_ip: str, port_entry: dict[str, Any], timestamp: Any
) -> dict[str, Any] | None:
    try:
        port_value = port_entry.get("port")
        if port_value is None:
            return None
        port_id = int(port_value)
    except (TypeError, ValueError):
        return None

    protocol = port_entry.get("proto") or port_entry.get("protocol", "tcp")
    state = port_entry.get("status") or port_entry.get("state", "open")

    service_info = port_entry.get("service") or {}
    banner = port_entry.get("banner") or service_info.get("banner")

    record = {
        "host": host_ip,
        "hostname": host_ip,
        "port": port_id,
        "protocol": protocol,
        "state": state,
        "service_name": service_info.get("name", ""),
        "service_product": service_info.get("product", ""),
        "service_version": service_info.get("version", ""),
        "banner": banner,
        "timestamp": timestamp,
        "raw": json.dumps(port_entry, ensure_ascii=False),
    }
    return record


def _collect_findings(
    stdout: str, output_format: str
) -> tuple[list[dict[str, Any]], int]:
    """Convert raw masscan output into unique findings."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    duplicates = 0

    records = _iter_masscan_records(stdout, output_format)

    for record in records:
        if record is None:
            continue

        host = record["host"]
        port = record["port"]
        protocol = record.get("protocol", "tcp")

        if not host:
            continue

        dedupe_key = (host, port, protocol)
        if dedupe_key in seen:
            duplicates += 1
            continue
        seen.add(dedupe_key)

        state = record.get("state", "open")
        service_name = record.get("service_name", "")
        severity = determine_nmap_port_severity(port, service_name, state)
        confidence = "high" if state == "open" else "medium"

        tags = ["port", "scan", protocol, state]
        if service_name:
            tags.append(service_name)

        evidence = {
            "host_ip": host,
            "hostname": record.get("hostname", host),
            "port": port,
            "protocol": protocol,
            "state": state,
            "discovered_by": "masscan",
        }

        for field in (
            "service_name",
            "service_product",
            "service_version",
            "banner",
            "timestamp",
        ):
            value = record.get(field)
            if value:
                evidence[field] = value

        findings.append(
            create_finding(
                finding_type="port",
                target=host,
                evidence=evidence,
                severity=severity,
                confidence=confidence,
                tags=tags,
                raw_ref=record.get("raw", ""),
            )
        )

    return findings, duplicates


@tool(required_fields=["target"])
def execute_masscan():
    """Execute Masscan and return structured port findings."""
    data = request.get_json()
    params = _extract_masscan_params(data)

    logger.info("Executing Masscan on %s", params["target"])

    command = _build_masscan_command(params)
    execution_result = execute_command(command, timeout=600)

    if not execution_result["success"]:
        error_message = (
            execution_result.get("stderr")
            or execution_result.get("error")
            or "Masscan execution failed"
        )
        error_response, status_code = create_error_response(
            error_message,
            stage="exec",
            details={
                "return_code": execution_result.get("return_code"),
                "command": execution_result.get("command", command),
            },
            status_code=500,
        )
        return jsonify(error_response), status_code

    stdout = execution_result.get("stdout", "")
    try:
        findings, duplicates = _collect_findings(stdout, params["output_format"])
    except MasscanParseError as exc:
        error_response, status_code = create_error_response(
            str(exc),
            stage="parse",
            details={
                "command": execution_result.get("command", command),
                "output_sample": stdout[:500],
            },
            status_code=500,
        )
        return jsonify(error_response), status_code

    stats = create_stats(
        len(findings),
        duplicates,
        len(stdout.encode("utf-8")),
    )

    return {
        "findings": findings,
        "stats": stats,
    }
