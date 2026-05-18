"""
Dashboard Examples - Common Utilities

This module provides shared functionality for dashboard examples
including:
- Configuration and credential management
- Logging setup
- HTML rendering with CSS Grid + ECharts
"""

from .config import (
    ACCESS_KEY,
    DEMO_DATASET,
    DEMO_MAPPING_DATASET,
    ENDPOINT,
    SECRET_KEY,
    get_credentials,
    validate_credentials,
)
from .logging_config import get_logger, setup_logging
from .render import build_dashboard_html

__all__ = [
    # Config
    "ACCESS_KEY",
    "SECRET_KEY",
    "ENDPOINT",
    "DEMO_DATASET",
    "DEMO_MAPPING_DATASET",
    "get_credentials",
    "validate_credentials",
    # Logging
    "setup_logging",
    "get_logger",
    # Render
    "build_dashboard_html",
]
