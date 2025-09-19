"""nuclei tool implementation."""

import json
import logging
import time
from datetime import UTC, datetime

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)

# Aggressive preset for nuclei
AGGRESSIVE_PRESET = {
    "severity": "info,low,medium,high,critical",
    "tags": "",  # Use all templates
    "concurrency": 100,
    "timeout": 30,
    "additional_args": "-es info -etags intrusive",  # Include intrusive templates
}


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
            if key in ["concurrency", "severity"] and user_params.get(key) in [
                25,
                None,
                "",
            ]:
                merged_params[key] = aggressive_value

    return merged_params


def _validate_template_path(template_path):
    """Validate that template path exists and is accessible."""
    import os

    if not template_path:
        return True  # Empty template path is valid (uses default)

    if os.path.isfile(template_path) or os.path.isdir(template_path):
        return True

    # Check if it's a valid template ID or tag
    if os.path.sep not in template_path and not template_path.startswith("."):
        return True

    return False


def _prepare_custom_templates(params):
    """Prepare and validate custom templates."""
    template_issues = []

    # Validate template directory
    if params.get("template_dir") and not _validate_template_path(
        params["template_dir"]
    ):
        template_issues.append(
            f"Template directory not found: {params['template_dir']}"
        )

    # Validate custom templates
    if params.get("custom_templates"):
        templates = params["custom_templates"]
        if isinstance(templates, list):
            for template in templates:
                if not _validate_template_path(template):
                    template_issues.append(f"Template not found: {template}")
        elif not _validate_template_path(templates):
            template_issues.append(f"Template not found: {templates}")

    # Validate main template parameter
    if params.get("template") and not _validate_template_path(params["template"]):
        template_issues.append(f"Template not found: {params['template']}")

    return template_issues


def _extract_nuclei_params(data):
    """Extract and validate nuclei parameters from request data."""
    # Check for aggressive mode
    aggressive = data.get("aggressive", False)

    base_params = {
        "target": data["target"],
        "severity": data.get("severity"),
        "tags": data.get("tags"),
        "template": data.get("template"),
        "template_id": data.get("template_id"),
        "exclude_id": data.get("exclude_id"),
        "exclude_tags": data.get("exclude_tags"),
        "concurrency": data.get("concurrency", 25),
        "timeout": data.get("timeout"),
        "additional_args": data.get("additional_args"),
        # Add support for custom template directories
        "template_dir": data.get("template_dir"),
        "custom_templates": data.get("custom_templates"),
        # Add support for multiple targets
        "targets_file": data.get("targets_file"),
        "target_list": data.get("target_list"),
    }

    # Apply aggressive preset if requested
    return _apply_aggressive_preset(base_params, aggressive)


def _build_nuclei_command(params):
    """Build nuclei command from parameters."""
    cmd_parts = ["nuclei"]

    # Handle target(s)
    if params.get("targets_file"):
        cmd_parts.extend(["-l", params["targets_file"]])
    elif params.get("target_list") and isinstance(params["target_list"], list):
        # Create a temporary file for multiple targets
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            for target in params["target_list"]:
                f.write(f"{target}\n")
            cmd_parts.extend(["-l", f.name])
    else:
        cmd_parts.extend(["-u", params["target"]])

    # Template configuration
    if params.get("template_dir"):
        cmd_parts.extend(["-t", params["template_dir"]])
    elif params.get("custom_templates"):
        if isinstance(params["custom_templates"], list):
            for template in params["custom_templates"]:
                cmd_parts.extend(["-t", template])
        else:
            cmd_parts.extend(["-t", params["custom_templates"]])
    elif params["template"]:
        cmd_parts.extend(["-t", params["template"]])

    # Other parameters
    if params["severity"]:
        cmd_parts.extend(["-severity", params["severity"]])
    if params["tags"]:
        cmd_parts.extend(["-tags", params["tags"]])
    if params["template_id"]:
        cmd_parts.extend(["-template-id", params["template_id"]])
    if params["exclude_id"]:
        cmd_parts.extend(["-exclude-id", params["exclude_id"]])
    if params["exclude_tags"]:
        cmd_parts.extend(["-exclude-tags", params["exclude_tags"]])
    if params["concurrency"] != 25:
        cmd_parts.extend(["-c", str(params["concurrency"])])
    if params["timeout"]:
        cmd_parts.extend(["-timeout", str(params["timeout"])])
    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    cmd_parts.extend(["-json"])

    return " ".join(cmd_parts)


def _map_nuclei_severity_to_unified(nuclei_severity: str) -> str:
    """Map nuclei severity levels to unified scale."""
    severity_mapping = {
        "info": "info",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
        "unknown": "info",
    }
    return severity_mapping.get(nuclei_severity.lower(), "info")


def _parse_nuclei_findings(stdout: str) -> tuple[list[dict], dict]:
    """Parse nuclei JSON output and extract findings with statistics."""
    findings = []
    stats = {"findings": 0, "dupes": 0, "payload_bytes": len(stdout.encode("utf-8"))}
    seen_findings = set()  # For deduplication

    if not stdout.strip():
        return findings, stats

    try:
        # Parse JSON line-by-line for findings
        lines = stdout.strip().split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue

            try:
                result = json.loads(line)
                if not isinstance(result, dict):
                    continue

                # Extract finding information
                template_id = result.get("template-id", "")
                template_name = result.get("info", {}).get("name", "")
                severity = result.get("info", {}).get("severity", "info")
                matched_at = result.get("matched-at", "")

                # Skip if no meaningful data
                if not template_id and not matched_at:
                    continue

                # Create deduplication key
                dedup_key = f"{template_id}:{matched_at}"
                if dedup_key in seen_findings:
                    stats["dupes"] += 1
                    continue
                seen_findings.add(dedup_key)

                # Build evidence from nuclei result
                evidence = {
                    "template_id": template_id,
                    "template_name": template_name,
                    "matched_at": matched_at,
                }

                # Add extracted data if available
                if "extracted-results" in result:
                    evidence["extracted_results"] = result["extracted-results"]
                if "matcher-name" in result:
                    evidence["matcher_name"] = result["matcher-name"]
                if "curl-command" in result:
                    evidence["curl_command"] = result["curl-command"]

                # Add request/response info if available
                if "request" in result:
                    evidence["request"] = result["request"]
                if "response" in result:
                    evidence["response"] = result["response"]

                # Determine target from matched URL
                target = matched_at if matched_at else result.get("host", "")

                # Build tags from template info
                tags = []
                template_info = result.get("info", {})
                if "tags" in template_info:
                    if isinstance(template_info["tags"], list):
                        tags = template_info["tags"]
                    else:
                        tags = [template_info["tags"]]

                # Add template ID as tag if not already included
                if template_id and template_id not in tags:
                    tags.append(template_id)

                finding = {
                    "type": "vuln",
                    "target": target,
                    "evidence": evidence,
                    "severity": _map_nuclei_severity_to_unified(severity),
                    "confidence": "high",  # High confidence for template matches
                    "tags": tags,
                    "raw_ref": f"nuclei_{len(findings)}",
                }

                findings.append(finding)
                stats["findings"] += 1

            except json.JSONDecodeError as e:
                logger.debug(
                    f"Failed to parse nuclei JSON line: {line[:100]}... Error: {e}"
                )
                continue
            except Exception as e:
                logger.warning(f"Error processing nuclei result line: {e}")
                continue

    except Exception as e:
        logger.error(f"Failed to parse nuclei output: {e}")

    return findings, stats


def _parse_nuclei_result(execution_result, params, command, start_time, end_time):
    """Parse nuclei execution result and format unified response."""
    duration_ms = int((end_time - start_time) * 1000)

    # Base response structure
    response = {
        "tool": "nuclei",
        "params": params,
        "started_at": datetime.fromtimestamp(start_time, UTC).isoformat(),
        "ended_at": datetime.fromtimestamp(end_time, UTC).isoformat(),
        "duration_ms": duration_ms,
        "findings": [],
        "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
    }

    # Parse findings if execution was successful
    if execution_result["success"] and execution_result.get("stdout"):
        findings, stats = _parse_nuclei_findings(execution_result["stdout"])
        response["findings"] = findings
        response["stats"] = stats

    # Include error information if execution failed
    if not execution_result["success"]:
        response["error"] = {
            "message": execution_result.get("stderr", "Command execution failed"),
            "return_code": execution_result.get("return_code", -1),
        }

    return response


@tool()
def execute_nuclei():
    """Execute Nuclei vulnerability scanner."""
    data = request.get_json()
    params = _extract_nuclei_params(data)

    logger.info(f"Executing Nuclei scan on {params['target']}")

    # Validate templates before execution
    template_issues = _prepare_custom_templates(params)
    if template_issues:
        logger.warning(f"Template validation issues: {template_issues}")
        return {
            "tool": "nuclei",
            "params": params,
            "error": {
                "message": f"Template validation failed: {'; '.join(template_issues)}",
                "return_code": -1,
            },
            "success": False,
            "findings": [],
            "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
        }

    start_time = time.time()
    command = _build_nuclei_command(params)
    execution_result = execute_command(command, timeout=600)
    end_time = time.time()

    return _parse_nuclei_result(execution_result, params, command, start_time, end_time)
