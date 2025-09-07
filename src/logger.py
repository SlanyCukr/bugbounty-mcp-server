import logging
import os
import sys

DEBUG_MODE = os.environ.get("DEBUG", "false").lower() == "true"


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.propagate = False

    # Force fresh configuration: remove all existing handlers.
    logger.handlers.clear()

    logger.setLevel(logging.DEBUG if DEBUG_MODE else level)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(level)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    file_path = f"logs/{name}.log"

    # Intentionally let this raise (e.g., PermissionError) if file is not writable.
    file_handler = logging.FileHandler(file_path)
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger
