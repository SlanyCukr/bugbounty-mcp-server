"""Masscan tool implementation that returns actionable port findings."""

import json
import logging
import shlex
from datetime import datetime
from typing import Any

from flask import request

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


def extract_masscan_params(data: dict[str, Any]) -> dict[str, Any]:
    """Extract parameters for masscan execution."""
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
    }


def build_masscan_command(params: dict[str, Any]) -> str:
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
        cmd_parts.extend(["-oJ", "-"])

    cmd_parts.extend(additional_parts)

    target = params.get("target")
    if target:
        for item in target.split():
            cmd_parts.append(item)

    return " ".join(shlex.quote(part) for part in cmd_parts)


def parse_masscan_output(
    execution_result: dict[str, Any],
    params: dict[str, Any],
    command: str,
    started_at: datetime,
    ended_at: datetime,
) -> dict[str, Any]:
    """Parse masscan JSON output into structured findings."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

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
        return {
            "success": False,
            "tool": "masscan",
            "params": params,
            "command": command,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "error": error_response,
            "findings": [],
            "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
        }

    stdout = execution_result.get("stdout", "")
    try:
        findings, duplicates = _parse_masscan_findings(stdout)
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
        return {
            "success": False,
            "tool": "masscan",
            "params": params,
            "command": command,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "error": error_response,
            "findings": [],
            "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
        }

    payload_bytes = len(stdout.encode("utf-8"))
    stats = create_stats(len(findings), duplicates, payload_bytes)

    return {
        "success": True,
        "tool": "masscan",
        "params": params,
        "command": command,
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat(),
        "duration_ms": duration_ms,
        "findings": findings,
        "stats": stats,
    }


def _parse_masscan_findings(stdout: str) -> tuple[list[dict[str, Any]], int]:
    """Convert raw masscan JSON output into unique findings."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    duplicates = 0

    stripped = stdout.strip()
    if not stripped:
        return findings, duplicates

    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise MasscanParseError("Failed to parse JSON output") from exc

    records = _parse_masscan_json_structure(parsed)

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
                severity="info",
                confidence="high" if state == "open" else "medium",
                tags=tags,
                raw_ref=record.get("raw", ""),
            )
        )

    return findings, duplicates


def _parse_masscan_json_structure(parsed: Any) -> list[dict[str, Any]]:
    """Parse masscan JSON output into structured records."""
    records = []

    if isinstance(parsed, dict):
        hosts = parsed.get("hosts")
        if isinstance(hosts, list):
            for host in hosts:
                records.extend(_parse_json_host_entry(host))
        else:
            records.extend(_parse_json_host_entry(parsed))
    elif isinstance(parsed, list):
        for entry in parsed:
            records.extend(_parse_json_host_entry(entry))

    return records


def _parse_json_host_entry(host_entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse a single host entry from JSON."""
    host_ip = host_entry.get("ip") or host_entry.get("host") or ""
    if not host_ip:
        return []

    timestamp = host_entry.get("timestamp")
    ports = host_entry.get("ports")
    records = []

    if isinstance(ports, list):
        for port_entry in ports:
            record = _parse_json_port_entry(host_ip, port_entry, timestamp)
            if record:
                records.append(record)
    else:
        record = _parse_json_port_entry(host_ip, host_entry, timestamp)
        if record:
            records.append(record)

    return records


def _parse_json_port_entry(
    host_ip: str, port_entry: dict[str, Any], timestamp: Any
) -> dict[str, Any] | None:
    """Parse a single port entry from JSON."""
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

    return {
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


@tool(required_fields=["target"])
def execute_masscan():
    """Execute Masscan and return structured port findings."""
    data = request.get_json()
    params = extract_masscan_params(data)

    logger.info("Executing Masscan on %s", params["target"])

    started_at = datetime.now()
    command = build_masscan_command(params)
    execution_result = execute_command(command, timeout=600)
    ended_at = datetime.now()

    return parse_masscan_output(execution_result, params, command, started_at, ended_at)
