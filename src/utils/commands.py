"""Command execution utilities."""

import logging
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


def execute_command(command: str, timeout: int = 300) -> dict[str, Any]:
    """
    Execute a shell command and return the results.

    Args:
        command: The command to execute
        timeout: Command timeout in seconds

    Returns:
        A dictionary containing stdout, stderr, return_code, and success status
    """
    try:
        logger.info(f"Executing command: {command}")

        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=timeout
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
