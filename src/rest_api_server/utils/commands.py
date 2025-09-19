"""Command execution utilities."""

import logging
import subprocess  # nosec B404 - subprocess is required for command execution
from typing import Any

logger = logging.getLogger(__name__)


def execute_command(command: str | list[str], timeout: int = 300) -> dict[str, Any]:
    """Execute a shell command and return the results.

    Args:
        command: The command to execute (string or list of strings)
        timeout: Command timeout in seconds

    Returns:
        A dictionary containing stdout, stderr, return_code, and success status
    """
    try:
        logger.info(f"Executing command: {command}")

        # Handle list commands by joining them (shell=False would be better
        # but requires more changes)
        if isinstance(command, list):
            cmd_str = " ".join(command)
            shell = True
        else:
            cmd_str = command
            shell = True

        result = subprocess.run(
            cmd_str,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout,  # nosec B602
        )

        return {
            "success": result.returncode == 0,
            "return_code": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "command": command,
        }

    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {command}")
        return {
            "success": False,
            "error": "Command timed out",
            "command": command,
            "timeout": timeout,
        }
    except Exception as e:
        logger.error(f"Error executing command: {str(e)}")
        return {"success": False, "error": str(e), "command": command}
