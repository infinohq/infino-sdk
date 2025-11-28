"""
Infino Python SDK

This module provides a Python interface to the Infino API.
"""

from .lib import InfinoError, InfinoSDK

__version__ = "0.3.0"
__all__ = ["InfinoSDK", "InfinoError"] 