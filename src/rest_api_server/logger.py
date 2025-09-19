"""Logging configuration for the Bug Bounty MCP Server."""

import logging
import os
import sys
from pathlib import Path

DEBUG_MODE = os.environ.get("DEBUG", "false").lower() == "true"

# Cache the logs directory location so we only compute it once.
LOG_DIR_NAME = "logs"
LOG_DIR = Path(__file__).resolve().parent.parent / LOG_DIR_NAME


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """Get a configured logger instance with console and file output."""
    logger = logging.getLogger(name)
    logger.propagate = False

    # Force fresh configuration: remove all existing handlers.
    logger.handlers.clear()

    effective_level = logging.DEBUG if DEBUG_MODE else level
    logger.setLevel(effective_level)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(effective_level)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    # Ensure the log directory exists before creating file handlers.
    os.makedirs(LOG_DIR, exist_ok=True)
    file_path = LOG_DIR / f"{name}.log"

    # Intentionally let this raise (e.g., PermissionError) if file is not writable.
    file_handler = logging.FileHandler(file_path)
    file_handler.setLevel(effective_level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger
