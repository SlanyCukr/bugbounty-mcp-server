"""RustScan tool implementation focused on actionable port findings."""

import json
import logging
import shlex
from datetime import datetime
from typing import Any

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import (
    create_finding,
    tool,
)


class RustscanParseError(RuntimeError):
    """Raised when rustscan JSON output cannot be parsed."""


logger = logging.getLogger(__name__)

# Aggressive preset for rustscan tuned for fast comprehensive sweeps.
AGGRESSIVE_PRESET = {
    "ulimit": 5000,
    "timeout": 3000,
    "tries": 3,
    "batch_size": 4500,
    "ports": "1-65535",
}


def _apply_aggressive_preset(
    user_params: dict[str, Any], aggressive: bool
) -> dict[str, Any]:
    if not aggressive:
        return user_params

    merged = user_params.copy()
    for key, value in AGGRESSIVE_PRESET.items():
        if not merged.get(key):
            merged[key] = value
    return merged


def extract_rustscan_params(data: dict[str, Any]) -> dict[str, Any]:
    """Extract and validate RustScan parameters from request data.

    Args:
        data: The incoming request JSON data.

    Returns:
        Dict containing extracted and processed parameters for RustScan.
    """
    params = {
        "target": data["target"],
        "ports": data.get("ports", ""),
        "ulimit": data.get("ulimit", 5000),
        "batch_size": data.get("batch_size", 4500),
        "timeout": data.get("timeout", 1500),
        "tries": data.get("tries", 1),
        "no_nmap": data.get("no_nmap", False),
        "scripts": data.get("scripts", True),
        "greppable": data.get("greppable", True),
        "accessible": data.get("accessible", False),
        "additional_args": data.get("additional_args", ""),
        "aggressive": data.get("aggressive", False),
    }

    return _apply_aggressive_preset(params, params["aggressive"])


def build_rustscan_command(params: dict[str, Any]) -> str:
    """Build the RustScan command line from the provided parameters.

    Args:
        params: Dict of parameters extracted from request.

    Returns:
        Str representing the complete command to execute.
    """
    cmd_parts: list[str] = [
        "rustscan",
        "-a",
        params["target"],
        "--ulimit",
        str(params["ulimit"]),
        "-b",
        str(params["batch_size"]),
        "-t",
        str(params["timeout"]),
    ]

    if params["tries"] and int(params["tries"]) > 1:
        cmd_parts.extend(["--tries", str(params["tries"])])

    ports_spec = params.get("ports")
    if ports_spec:
        cleaned = ports_spec.replace(" ", "")
        if "," in cleaned:
            cmd_parts.extend(["--ports", cleaned])
        elif "-" in cleaned:
            cmd_parts.extend(["--range", cleaned])
        else:
            cmd_parts.extend(["--ports", cleaned])
    else:
        cmd_parts.append("--top")

    if params["greppable"]:
        cmd_parts.append("-g")

    if params["accessible"]:
        cmd_parts.append("--accessible")

    additional_parts = (
        shlex.split(params["additional_args"]) if params.get("additional_args") else []
    )

    cmd_parts.extend(additional_parts)

    nmap_args: list[str] = []
    if not params["no_nmap"]:
        nmap_args.append("-sV")
        if params["scripts"]:
            nmap_args.insert(0, "-sC")

    if nmap_args:
        cmd_parts.append("--")
        cmd_parts.extend(nmap_args)

    return " ".join(shlex.quote(part) for part in cmd_parts)


def _parse_rustscan_json_output(stdout: str) -> list[dict[str, Any]]:
    """Parse RustScan JSON output into raw records."""
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RustscanParseError("Failed to parse JSON output") from exc

    records: list[dict[str, Any]] = []

    def _handle_port(host: str, port_data: dict[str, Any]) -> None:
        port_value = port_data.get("port")
        if port_value is None:
            return

        try:
            port = int(port_value)
        except (TypeError, ValueError):
            return

        protocol = port_data.get("protocol") or port_data.get("proto", "tcp")
        state = port_data.get("state") or port_data.get("status", "open")
        service = port_data.get("service") or ""

        record = {
            "host": host,
            "port": port,
            "protocol": protocol,
            "state": state,
            "service": service,
            "raw": json.dumps(port_data, ensure_ascii=False),
        }
        records.append(record)

    if isinstance(parsed, dict):
        hosts = parsed.get("hosts") or parsed.get("results")
        if isinstance(hosts, list):
            for host_entry in hosts:
                host = host_entry.get("host") or host_entry.get("ip")
                if not host:
                    continue
                for port_data in host_entry.get("ports", []):
                    _handle_port(host, port_data)
        elif "port" in parsed:
            host = parsed.get("host") or parsed.get("ip")
            if host:
                _handle_port(host, parsed)
        return records

    if isinstance(parsed, list):
        for entry in parsed:
            host = entry.get("host") or entry.get("ip")
            if not host:
                continue
            ports = entry.get("ports")
            if isinstance(ports, list):
                for port_data in ports:
                    _handle_port(host, port_data)
            else:
                _handle_port(host, entry)

    return records


def parse_rustscan_output(
    execution_result: dict[str, Any],
    params: dict[str, Any],
    command: str,
    started_at: datetime,
    ended_at: datetime,
) -> dict[str, Any]:
    """Parse RustScan execution result and return structured response."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if not execution_result["success"]:
        return {
            "success": False,
            "tool": "rustscan",
            "params": params,
            "command": command,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "error": execution_result.get("error", "Command execution failed"),
            "findings": [],
            "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
        }

    stdout = execution_result.get("stdout", "")
    findings = []
    seen: set[tuple[str, int, str]] = set()
    duplicates = 0

    try:
        records = _parse_rustscan_json_output(stdout)
    except RustscanParseError:
        return {
            "success": False,
            "tool": "rustscan",
            "params": params,
            "command": command,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "error": "Failed to parse RustScan JSON output",
            "findings": [],
            "stats": {
                "findings": 0,
                "dupes": 0,
                "payload_bytes": len(stdout.encode("utf-8")),
            },
        }

    for record in records:
        host = record.get("host")
        port = record.get("port")
        protocol = record.get("protocol", "tcp")
        if not host or port is None:
            continue

        dedupe_key = (host, port, protocol)
        if dedupe_key in seen:
            duplicates += 1
            continue
        seen.add(dedupe_key)

        state = record.get("state", "open")
        service = record.get("service", "")
        severity = "medium"
        confidence = "high" if state == "open" else "medium"

        tags = ["port", "scan", protocol, state]
        if service:
            tags.append(service)

        evidence = {
            "host_ip": host,
            "hostname": host,
            "port": port,
            "protocol": protocol,
            "state": state,
            "service_name": service,
            "discovered_by": "rustscan",
        }

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

    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "success": True,
        "tool": "rustscan",
        "params": params,
        "command": command,
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat(),
        "duration_ms": duration_ms,
        "findings": findings,
        "stats": {
            "findings": len(findings),
            "dupes": duplicates,
            "payload_bytes": payload_bytes,
        },
    }


@tool(required_fields=["target"])
def execute_rustscan():
    """Execute RustScan and return structured findings only."""
    data = request.get_json()
    params = extract_rustscan_params(data)

    logger.info("Executing RustScan on %s", params["target"])

    started_at = datetime.now()
    command = build_rustscan_command(params)
    execution_result = execute_command(command, timeout=600)
    ended_at = datetime.now()

    return parse_rustscan_output(
        execution_result, params, command, started_at, ended_at
    )
