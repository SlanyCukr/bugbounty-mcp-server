import logging
import shlex

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


@tool(required_fields=["url"])
def execute_x8():
    """Execute x8 for hidden parameter discovery."""
    data = request.get_json()
    url = data["url"]

    logger.info(f"Executing x8 on {url}")

    x8_params = {
        "url": url,
        "wordlist": data.get("wordlist", "/usr/share/wordlists/x8/params.txt"),
        "method": data.get("method", "GET"),
        "body": data.get("body", ""),
        "headers": data.get("headers", ""),
        "output_file": data.get("output_file", ""),
        "discover": data.get("discover", True),
        "learn": data.get("learn", False),
        "verify": data.get("verify", True),
        "max": data.get("max", 0),
        "workers": data.get("workers", 25),
        "as_body": data.get("as_body", False),
        "encode": data.get("encode", False),
        "force": data.get("force", False),
        "additional_args": data.get("additional_args", ""),
    }

    # Build x8 command - properly escape URL
    command = f"x8 -u {shlex.quote(url)} -X {x8_params['method']}"

    # Add wordlist
    if x8_params["wordlist"]:
        command += f" -w {shlex.quote(x8_params['wordlist'])}"

    # Add body data if provided
    if x8_params["body"]:
        command += f" -b {shlex.quote(x8_params['body'])}"

    # Add headers if provided
    if x8_params["headers"]:
        # Headers should be in format 'header:value'
        if isinstance(x8_params["headers"], str):
            command += f" -H {shlex.quote(x8_params['headers'])}"
        elif isinstance(x8_params["headers"], dict):
            for key, value in x8_params["headers"].items():
                command += f" -H {shlex.quote(f'{key}:{value}')}"

    # Add output file if specified
    if x8_params["output_file"]:
        command += f" -o {shlex.quote(x8_params['output_file'])}"

    # Add workers (concurrency)
    if x8_params["workers"] and x8_params["workers"] > 1:
        command += f" -c {x8_params['workers']}"

    # Add max parameters per request if specified
    if x8_params["max"] and x8_params["max"] > 0:
        command += f" -m {x8_params['max']}"

    # Add verification flag
    if x8_params["verify"]:
        command += " --verify"

    # Add encoding flag
    if x8_params["encode"]:
        command += " --encode"

    # Add force flag
    if x8_params["force"]:
        command += " --force"

    # Add body mode flag
    if x8_params["as_body"]:
        command += " --invert"

    # Add any additional arguments
    if x8_params["additional_args"]:
        command += f" {x8_params['additional_args']}"

    # Execute the command
    logger.info(f"Executing x8 command: {command}")
    cmd_result = execute_command(command, timeout=600)  # 10 minute timeout

    # Parse x8 output to extract discovered parameters
    discovered_parameters = []
    parameter_lines = []

    if cmd_result["stdout"]:
        lines = cmd_result["stdout"].split("\n")
        for line in lines:
            line = line.strip()
            # Look for parameter discovery patterns in x8 output
            # x8 typically outputs found parameters in a specific format
            if (
                line
                and not line.startswith("[")
                and "=" in line
                and (
                    "GET" in line
                    or "POST" in line
                    or "PUT" in line
                    or "PATCH" in line
                    or "DELETE" in line
                )
            ):
                parameter_lines.append(line)
            elif (
                line
                and ("parameter" in line.lower() or "found" in line.lower())
                and ("=" in line or ":" in line)
            ):
                parameter_lines.append(line)

    # Try to extract structured information from parameter lines
    for line in parameter_lines:
        try:
            # Basic parsing - this may need adjustment based on actual x8 output format
            parts = line.split()
            if len(parts) >= 2:
                param_info = {
                    "raw_line": line,
                    "method": "GET",  # Default
                    "confidence": "unknown",
                }

                # Try to extract method
                for method in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
                    if method in line:
                        param_info["method"] = method
                        break

                # Try to extract parameter name
                if "=" in line:
                    param_part = line.split("=")[0]
                    # Extract the last word before = as parameter name
                    param_name = (
                        param_part.strip().split()[-1]
                        if param_part.strip().split()
                        else "unknown"
                    )
                    param_info["name"] = param_name

                discovered_parameters.append(param_info)
        except Exception as parse_error:
            logger.warning(f"Error parsing parameter line '{line}': {str(parse_error)}")
            # Still add the raw line for manual inspection
            discovered_parameters.append(
                {"raw_line": line, "parse_error": str(parse_error)}
            )

    # Create result structure
    result = {
        "tool": "x8",
        "target": url,
        "parameters": x8_params,
        "command_executed": command,
        "status": "completed" if cmd_result["success"] else "failed",
        "raw_output": cmd_result["stdout"],
        "stderr": cmd_result["stderr"],
        "return_code": cmd_result["return_code"],
        "execution_time": cmd_result.get("execution_time", "unknown"),
        "discovered_parameters": discovered_parameters,
        "parameter_count": len(discovered_parameters),
        "parameter_lines": parameter_lines,  # For debugging/manual inspection
    }

    return result
