"""
Configuration and credentials management for Fino examples.
"""

from __future__ import annotations

import os
import sys

# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================

ACCESS_KEY = os.environ.get("INFINO_ACCESS_KEY", "")
SECRET_KEY = os.environ.get("INFINO_SECRET_KEY", "")
ENDPOINT = os.environ.get("INFINO_ENDPOINT", "https://api.infino.ws")

WEBSOCKET_TIMEOUT = 180.0  # seconds
CONNECTION_TIMEOUT = 15.0  # seconds


def get_credentials() -> tuple[str, str, str]:
    """
    Get API credentials from environment variables.

    Required environment variables:
    - INFINO_ACCESS_KEY: Your Infino access key
    - INFINO_SECRET_KEY: Your Infino secret key
    - INFINO_ENDPOINT: API endpoint (default: https://api.infino.ws)

    Returns:
        Tuple of (access_key, secret_key, endpoint)
    """
    access_key = os.environ.get("INFINO_ACCESS_KEY", "")
    secret_key = os.environ.get("INFINO_SECRET_KEY", "")
    endpoint = os.environ.get("INFINO_ENDPOINT", "https://api.infino.ws")
    return access_key, secret_key, endpoint


def validate_credentials(logger=None) -> None:
    """
    Validate that required credentials are set.

    Args:
        logger: Optional logger instance for error messages.
                If None, prints to stderr.

    Raises:
        SystemExit: If credentials are missing.
    """
    if not ACCESS_KEY or not SECRET_KEY:
        msg_lines = [
            "Missing credentials. Please set environment variables:",
            "  export INFINO_ACCESS_KEY='your_key'",
            "  export INFINO_SECRET_KEY='your_secret'",
        ]
        if logger:
            for line in msg_lines:
                logger.error(line)
        else:
            for line in msg_lines:
                print(line, file=sys.stderr)
        sys.exit(1)
