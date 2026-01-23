"""
Streaming response handling for Fino examples.

This module provides common functionality for handling WebSocket streaming
responses from the Infino API.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from websockets.exceptions import ConnectionClosed

from .config import WEBSOCKET_TIMEOUT

logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class StreamingResponse:
    """Container for accumulated streaming response data."""

    summary: str = ""
    data: dict[str, Any] | None = None
    chart: dict[str, Any] | None = None
    sql: str | None = None
    querydsl: dict[str, Any] | None = None
    suggestions: list[str] = field(default_factory=list)
    error: str | None = None
    update_count: int = 0
    partial_count: int = 0


# =============================================================================
# STREAMING RESPONSE HANDLERS
# =============================================================================


def handle_partial_message(
    content: dict[str, Any],
    response: StreamingResponse,
    verbose: bool = True,
) -> None:
    """
    Handle a partial message: display immediately and store in response.

    This provides real-time streaming feedback while accumulating data.

    Args:
        content: The message content dictionary.
        response: The StreamingResponse to update.
        verbose: If True, print details to stdout. Default True.
    """
    sub_type = content.get("sub_type", "")
    value = content.get("value")

    if sub_type == "summary":
        response.summary = value
        logger.info("[partial:summary]")
        if verbose:
            print(f"\n{value}\n", flush=True)

    elif sub_type == "data":
        response.data = value
        logger.info("[partial:data]")
        if verbose and value:
            df = value.get("df", [])
            if df:
                data_str = json.dumps(df[:5], indent=2)
                print(f"  Data ({len(df)} rows): {data_str}", flush=True)
                if len(df) > 5:
                    print(f"  ... and {len(df) - 5} more rows", flush=True)

    elif sub_type == "chart":
        response.chart = value
        logger.info("[partial:chart]")
        if verbose and value:
            chart_type = value.get("chart", {}).get("type", "unknown")
            print(f"  Chart type: {chart_type}", flush=True)

    elif sub_type == "sql":
        response.sql = value
        logger.info("[partial:sql]")
        if verbose:
            print(f"  SQL: {value}", flush=True)

    elif sub_type == "querydsl":
        response.querydsl = value
        logger.info("[partial:querydsl]")
        if verbose:
            print(f"  QueryDSL: {json.dumps(value)}", flush=True)

    elif sub_type == "smart_suggestion":
        response.suggestions = value if isinstance(value, list) else []
        logger.info("[partial:smart_suggestion]")
        if verbose and response.suggestions:
            print("  Suggestions:", flush=True)
            for i, suggestion in enumerate(response.suggestions[:3], 1):
                print(f"    {i}. {suggestion}", flush=True)

    elif sub_type == "sources":
        sources = value if isinstance(value, list) else []
        logger.info("[partial:sources]")
        if verbose and sources:
            source_names = [s.get("index_name", "unknown") for s in sources]
            print(f"  Sources used: {', '.join(source_names)}", flush=True)

    else:
        logger.info("[partial:%s]", sub_type)
        if verbose and value is not None:
            print(f"  {sub_type}: {value}", flush=True)


def log_response_summary(response: StreamingResponse) -> None:
    """Log a brief summary of the streaming response."""
    print("-" * 70, flush=True)

    if response.error:
        logger.error("ERROR: %s", response.error)
        return

    received = []
    if response.summary:
        received.append("summary")
    if response.data:
        received.append("data")
    if response.chart:
        received.append("chart")
    if response.sql:
        received.append("sql")
    if response.querydsl:
        received.append("querydsl")
    if response.suggestions:
        received.append(f"{len(response.suggestions)} suggestions")

    logger.info(
        "Received: %s | Stats: %d updates, %d partial messages",
        ", ".join(received) if received else "none",
        response.update_count,
        response.partial_count,
    )


async def handle_streaming_response(
    ws: Any,
    question: str,
    mode_label: str | None = None,
    timeout: float = WEBSOCKET_TIMEOUT,
    verbose: bool = True,
) -> StreamingResponse:
    """
    Send a question and handle the streaming response.

    Message Types:
        Top-level (no "content" wrapper):
        - "heartbeat": Keep-alive, ignore
        - "error": Error occurred, stop listening

        Content types (inside "content" wrapper):
        - "update": Progress messages (optional to display)
        - "partial": Streaming content (sub_type determines value format)
        - "EOM": End of message, stop listening

    Args:
        ws: WebSocket connection object.
        question: The user's question to send.
        mode_label: Optional label to display (e.g., "RESTRICTED" or "AUTO").
        timeout: Timeout in seconds for receiving messages.
        verbose: If True, print detailed output.

    Returns:
        StreamingResponse containing all accumulated response data.
    """
    if verbose:
        print("\n" + "=" * 70, flush=True)
        if mode_label:
            print(f"MODE: {mode_label}", flush=True)
        print(f"QUESTION: {question}", flush=True)
        print("=" * 70, flush=True)

    # Send query
    await ws.send(json.dumps({"content": {"user_query": question}}))

    response = StreamingResponse()
    logger.info("Streaming response...")

    while True:
        try:
            raw_response = await asyncio.wait_for(ws.recv(), timeout=timeout)
        except ConnectionClosed as e:
            logger.error("Connection closed: %s", e)
            response.error = f"WebSocket connection closed: {e}"
            break
        except asyncio.TimeoutError:
            logger.error("Timeout: No response within %d seconds", timeout)
            response.error = "Timeout waiting for response"
            break

        data = json.loads(raw_response)

        # Handle heartbeat (no "content" wrapper)
        if data.get("type") == "heartbeat":
            logger.debug("Heartbeat received")
            continue

        # Handle error (no "content" wrapper)
        if data.get("type") == "error":
            error_summary = data.get("summary", "Unknown error")
            error_detail = data.get("data", {}).get("error", "")
            response.error = f"{error_summary}: {error_detail}"
            logger.error("Server error: %s", response.error)
            break

        content = data.get("content", {})
        msg_type = content.get("type", "")

        if msg_type == "update":
            response.update_count += 1
            sender = content.get("sender", "")
            message = content.get("message", "")
            display = message[:70] + "..." if len(message) > 70 else message
            logger.info("  [%s] %s", sender, display)

        elif msg_type == "partial":
            response.partial_count += 1
            handle_partial_message(content, response, verbose=verbose)

        elif msg_type == "EOM":
            trace_id = content.get("trace_id", "N/A")
            logger.info("Response complete (trace: %s)", trace_id)
            break

    # Log final response summary
    log_response_summary(response)

    return response
