"""
Logging configuration for Fino examples.
"""

from __future__ import annotations

import logging
import sys


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """
    Set up logging configuration for fino examples.

    Args:
        level: Logging level (default: logging.INFO)

    Returns:
        Configured logger instance.
    """
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    return logging.getLogger(__name__)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the specified name.

    Args:
        name: Logger name (typically __name__ from calling module)

    Returns:
        Logger instance.
    """
    return logging.getLogger(name)
