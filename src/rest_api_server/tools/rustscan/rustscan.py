"""RustScan tool implementation focused on actionable port findings."""

import json
import logging
import re
import shlex
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
    "greppable": True,
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


def _extract_rustscan_params(data: dict[str, Any]) -> dict[str, Any]:
    params = {
        "target": data["target"],
        "ports": data.get("ports", ""),
        "ulimit": int(data.get("ulimit", 5000)),
        "batch_size": int(data.get("batch_size", 4500)),
        "timeout": int(data.get("timeout", 1500)),
        "tries": int(data.get("tries", 1)),
        "no_nmap": bool(data.get("no_nmap", False)),
        "scripts": bool(data.get("scripts", True)),
        "greppable": bool(data.get("greppable", True)),
        "accessible": bool(data.get("accessible", False)),
        "additional_args": data.get("additional_args", ""),
        "aggressive": bool(data.get("aggressive", False)),
    }

    return _apply_aggressive_preset(params, params["aggressive"])


def _build_rustscan_command(params: dict[str, Any]) -> str:
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

    if params["tries"] > 1:
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


def _records_from_json(stdout: str) -> list[dict[str, Any]]:
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


GREPPABLE_PATTERN = re.compile(r"^(?P<host>[^\s]+)\s*->\s*\[(?P<ports>[^]]+)\]")


def _records_from_greppable(stdout: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        match = GREPPABLE_PATTERN.match(line)
        if not match:
            continue

        host = match.group("host")
        ports_text = match.group("ports")
        for port_entry in ports_text.split(","):
            port_entry = port_entry.strip().strip("[]")
            if not port_entry:
                continue
            try:
                port = int(port_entry)
            except ValueError:
                continue

            records.append(
                {
                    "host": host,
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "",
                    "raw": line,
                }
            )

    return records


def _collect_findings(stdout: str) -> tuple[list[dict[str, Any]], int]:
    if not stdout.strip():
        return [], 0

    records: list[dict[str, Any]] = []

    try:
        records = _records_from_json(stdout)
    except RustscanParseError:
        records = _records_from_greppable(stdout)

    if not records:
        raise RustscanParseError("Unsupported RustScan output format")

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    duplicates = 0

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
        severity = determine_nmap_port_severity(port, service, state)
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
            "service_info": service,
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

    return findings, duplicates


@tool(required_fields=["target"])
def execute_rustscan():
    """Execute RustScan and return structured findings only."""
    data = request.get_json()
    params = _extract_rustscan_params(data)

    logger.info("Executing RustScan on %s", params["target"])

    command = _build_rustscan_command(params)
    execution_result = execute_command(command, timeout=600)

    if not execution_result["success"]:
        error_message = (
            execution_result.get("stderr")
            or execution_result.get("error")
            or "RustScan execution failed"
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
        findings, duplicates = _collect_findings(stdout)
    except RustscanParseError as exc:
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
