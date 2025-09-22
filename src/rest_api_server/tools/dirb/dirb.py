"""dirb tool implementation."""

import logging
import subprocess
from datetime import datetime
from typing import Any

from flask import request

from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)


def extract_dirb_params(data: dict) -> dict:
    """Extract dirb parameters from request data."""
    target = data.get("target", "")
    if not target.startswith(("http://", "https://")):
        url = f"https://{target}"
    else:
        url = target
    return {
        "url": url,
        "wordlist": data.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
        "extensions": data.get("extensions", ""),
        "recursive": bool(data.get("recursive", False)),
        "ignore_case": bool(data.get("ignore_case", False)),
        "user_agent": data.get("user_agent", ""),
        "headers": data.get("headers", ""),
        "cookies": data.get("cookies", ""),
        "proxy": data.get("proxy", ""),
        "auth": data.get("auth", ""),
        "delay": data.get("delay", 0),
        "timeout": data.get("timeout", 600),
    }


def build_dirb_command(params: dict) -> list[str]:
    """Build dirb command from parameters."""
    cmd_parts = ["dirb", params["url"]]

    cmd_parts.append(params["wordlist"])

    if params["extensions"]:
        cmd_parts.extend(["-X", params["extensions"]])

    if params["recursive"]:
        cmd_parts.append("-r")

    if params["ignore_case"]:
        cmd_parts.append("-z")

    cmd_parts.append("-N")

    if params["user_agent"]:
        cmd_parts.extend(["-a", params["user_agent"]])

    if params["headers"]:
        cmd_parts.extend(["-H", params["headers"]])

    if params["cookies"]:
        cmd_parts.extend(["-c", params["cookies"]])

    if params["proxy"]:
        cmd_parts.extend(["-p", params["proxy"]])

    if params["auth"]:
        cmd_parts.extend(["-u", params["auth"]])

    if params["delay"]:
        cmd_parts.extend(["-l", str(params["delay"])])

    return cmd_parts


def execute_dirb_command_secure(cmd_parts: list[str], timeout: int = 600) -> dict:
    """Execute dirb command securely using subprocess.run with argument list."""
    try:
        logger.info(f"Executing secure DIRB command: {' '.join(cmd_parts)}")

        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )

        return {
            "success": result.returncode == 0,
            "return_code": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "command": cmd_parts,
            "duration_ms": 0,
        }

    except subprocess.TimeoutExpired:
        logger.error(f"DIRB command timed out: {' '.join(cmd_parts)}")
        return {
            "success": False,
            "error": "Command timed out",
            "command": cmd_parts,
            "timeout": timeout,
            "timeout_occurred": True,
        }
    except FileNotFoundError:
        logger.error("DIRB command not found - ensure dirb is installed")
        return {
            "success": False,
            "error": "DIRB not found - please install dirb",
            "command": cmd_parts,
        }
    except Exception as e:
        logger.error(f"Error executing DIRB command: {str(e)}")
        return {"success": False, "error": str(e), "command": cmd_parts}


def parse_dirb_output(stdout: str) -> list[dict[str, Any]]:
    """Parse dirb output into findings."""
    findings = []

    if not stdout.strip():
        return findings

    lines = stdout.splitlines()

    for line in lines:
        line = line.strip()
        if not line or line.startswith("----") or "Scanning URL" in line:
            continue

        if line.startswith("+"):
            original_line = line
            target_line = line.strip("+").strip()
            if target_line.startswith("http"):
                # Extract clean target URL
                if " (" in target_line:
                    target = target_line.split(" (")[0].strip()
                else:
                    target = target_line
                finding = {
                    "type": "endpoint",
                    "target": target,
                    "evidence": {
                        "raw_output": original_line,
                        "discovered_by": "dirb",
                    },
                    "severity": "info",
                    "confidence": "medium",
                    "tags": ["dirb", "directory-enum"],
                    "raw_ref": target_line,
                }
                findings.append(finding)
        elif line.startswith(("-", "*")):
            continue

    return findings


def parse_dirb_result(
    execution_result: dict,
    params: dict,
    command: list[str],
    started_at: datetime,
    ended_at: datetime,
) -> dict[str, Any]:
    """Parse dirb execution result and format response."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if not execution_result["success"]:
        return {
            "success": False,
            "tool": "dirb",
            "params": params,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "error": execution_result.get("stderr", "Command execution failed"),
            "findings": [],
            "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
        }

    stdout = execution_result.get("stdout", "")
    with open("/tmp/dirb_raw_output.log", "w") as f:
        f.write(stdout)
    logger.info("Dirb raw stdout logged")
    findings = parse_dirb_output(stdout)
    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "success": True,
        "tool": "dirb",
        "target": params["url"],
        "command": " ".join(command),
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat(),
        "duration_ms": duration_ms,
        "findings": findings,
        "stats": {
            "findings": len(findings),
            "dupes": 0,
            "payload_bytes": payload_bytes,
        },
        "stdout": execution_result["stdout"],
        "stderr": execution_result["stderr"],
        "return_code": execution_result["return_code"],
        "parameters": {
            "url": params["url"],
            "wordlist": params["wordlist"],
            "extensions": params["extensions"],
            "recursive": params["recursive"],
            "ignore_case": params["ignore_case"],
            "user_agent": params["user_agent"],
            "headers": params["headers"],
            "cookies": params["cookies"],
            "proxy": params["proxy"],
            "auth": params["auth"],
            "delay": params["delay"],
        },
    }


@tool(required_fields=["target"])
def execute_dirb():
    """Execute DIRB directory scanner."""
    data = request.get_json()
    params = extract_dirb_params(data)

    logger.info(f"Executing DIRB scan on {params['url']}")

    started_at = datetime.now()
    command_parts = build_dirb_command(params)
    execution_result = execute_dirb_command_secure(
        command_parts, timeout=params["timeout"]
    )
    ended_at = datetime.now()

    return parse_dirb_result(
        execution_result, params, command_parts, started_at, ended_at
    )
