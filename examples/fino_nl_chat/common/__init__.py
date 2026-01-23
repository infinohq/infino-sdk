"""
Fino Examples - Common Utilities

This module provides shared functionality for fino examples including:
- Configuration and credential management
- Logging setup
- Streaming response handling
- Data utilities
"""

from .config import (
    ACCESS_KEY,
    CONNECTION_TIMEOUT,
    ENDPOINT,
    SECRET_KEY,
    WEBSOCKET_TIMEOUT,
    get_credentials,
    validate_credentials,
)
from .logging_config import get_logger, setup_logging
from .streaming import (
    StreamingResponse,
    handle_partial_message,
    handle_streaming_response,
)
from .utils import create_thread, generate_bulk_payload

__all__ = [
    # Config
    "ACCESS_KEY",
    "SECRET_KEY",
    "ENDPOINT",
    "WEBSOCKET_TIMEOUT",
    "CONNECTION_TIMEOUT",
    "get_credentials",
    "validate_credentials",
    # Logging
    "setup_logging",
    "get_logger",
    # Streaming
    "StreamingResponse",
    "handle_partial_message",
    "handle_streaming_response",
    # Utils
    "generate_bulk_payload",
    "create_thread",
]
