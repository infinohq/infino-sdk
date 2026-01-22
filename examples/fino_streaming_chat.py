"""
Infino SDK - Streaming Mode Example

This example demonstrates how to use the Infino SDK with streaming mode enabled.
See docs/streaming_responses.md for the complete response format documentation.

Usage:
    export INFINO_ACCESS_KEY="your_key"
    export INFINO_SECRET_KEY="your_secret"
    python examples/fino_streaming_chat.py
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from websockets.exceptions import ConnectionClosed

from infino_sdk import InfinoError, InfinoSDK

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION
# =============================================================================

ACCESS_KEY = os.environ.get("INFINO_ACCESS_KEY", "")
SECRET_KEY = os.environ.get("INFINO_SECRET_KEY", "")
ENDPOINT = os.environ.get("INFINO_ENDPOINT", "https://api.infino.ws")

DATASET_NAME = "streaming_demo_products"
WEBSOCKET_TIMEOUT = 180.0  # seconds
CONNECTION_TIMEOUT = 15.0  # seconds


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
# SAMPLE DATA
# =============================================================================

SAMPLE_PRODUCTS = [
    {"id": 1, "name": "Wireless Headphones", "category": "electronics", "price": 79.99, "in_stock": True},
    {"id": 2, "name": "USB-C Cable", "category": "electronics", "price": 12.99, "in_stock": True},
    {"id": 3, "name": "Laptop Stand", "category": "accessories", "price": 45.00, "in_stock": True},
    {"id": 4, "name": "Mechanical Keyboard", "category": "electronics", "price": 129.99, "in_stock": False},
    {"id": 5, "name": "Mouse Pad XL", "category": "accessories", "price": 24.99, "in_stock": True},
]


def generate_bulk_payload(products: list[dict[str, Any]]) -> str:
    """
    Generate NDJSON bulk format payload for Elasticsearch-style ingestion.

    Args:
        products: List of product dictionaries to convert.

    Returns:
        NDJSON string with alternating index/document lines.
    """
    bulk_lines = []
    for product in products:
        bulk_lines.append(json.dumps({"index": {"_id": str(product["id"])}}))
        bulk_lines.append(json.dumps(product))
    return "\n".join(bulk_lines) + "\n"


# =============================================================================
# STREAMING RESPONSE HANDLER
# =============================================================================


def _handle_partial_message(content: dict[str, Any], response: StreamingResponse) -> None:
    """
    Handle a partial message: display immediately and store in response.

    This provides real-time streaming feedback while accumulating data.

    Args:
        content: The message content dictionary.
        response: The StreamingResponse to update.
    """
    sub_type = content.get("sub_type", "")
    value = content.get("value")

    if sub_type == "summary":
        response.summary = value
        logger.info("[partial:summary]")
        # Display the actual summary text as it streams
        print(f"\n{value}\n", flush=True)

    elif sub_type == "data":
        response.data = value
        logger.info("[partial:data]")
        # Display the data results
        if value:
            df = value.get("df", [])
            if df:
                print(f"  Data ({len(df)} rows): {json.dumps(df[:5], indent=2)}", flush=True)
                if len(df) > 5:
                    print(f"  ... and {len(df) - 5} more rows", flush=True)

    elif sub_type == "chart":
        response.chart = value
        logger.info("[partial:chart]")
        # Display chart type info
        if value:
            chart_type = value.get("chart", {}).get("type", "unknown")
            print(f"  Chart type: {chart_type}", flush=True)

    elif sub_type == "sql":
        response.sql = value
        logger.info("[partial:sql]")
        # Display the SQL query
        print(f"  SQL: {value}", flush=True)

    elif sub_type == "querydsl":
        response.querydsl = value
        logger.info("[partial:querydsl]")
        # Display QueryDSL (compact form)
        print(f"  QueryDSL: {json.dumps(value)}", flush=True)

    elif sub_type == "smart_suggestion":
        response.suggestions = value if isinstance(value, list) else []
        logger.info("[partial:smart_suggestion]")
        # Display suggestions
        if response.suggestions:
            print("  Suggestions:", flush=True)
            for i, suggestion in enumerate(response.suggestions[:3], 1):
                print(f"    {i}. {suggestion}", flush=True)

    elif sub_type == "sources":
        sources = value if isinstance(value, list) else []
        logger.info("[partial:sources]")
        # Display source names
        if sources:
            source_names = [s.get("index_name", "unknown") for s in sources]
            print(f"  Sources: {', '.join(source_names)}", flush=True)

    else:
        logger.info("[partial:%s]", sub_type)
        # Display unknown partial types for debugging
        print(f"  {sub_type}: {value}", flush=True)


async def handle_streaming_response(ws: Any, question: str) -> StreamingResponse:
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

    See docs/streaming_responses.md for full format documentation.

    Args:
        ws: WebSocket connection object.
        question: The user's question to send.

    Returns:
        StreamingResponse containing all accumulated response data.
    """
    logger.info("=" * 70)
    logger.info("QUESTION: %s", question)
    logger.info("=" * 70)

    # Send query
    await ws.send(json.dumps({"content": {"user_query": question}}))

    response = StreamingResponse()
    logger.info("Streaming response...")

    while True:
        try:
            raw_response = await asyncio.wait_for(ws.recv(), timeout=WEBSOCKET_TIMEOUT)
        except ConnectionClosed as e:
            logger.error("Connection closed: %s", e)
            response.error = f"WebSocket connection closed: {e}"
            break
        except asyncio.TimeoutError:
            logger.error("Timeout: No response within %d seconds", WEBSOCKET_TIMEOUT)
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
            _handle_partial_message(content, response)

        elif msg_type == "EOM":
            trace_id = content.get("trace_id", "N/A")
            logger.info("Response complete (trace: %s)", trace_id)
            break

    # Log final response summary
    _log_response_summary(response)

    return response


def _log_response_summary(response: StreamingResponse) -> None:
    """Log a brief summary of the streaming response (content already displayed above)."""
    print("-" * 70, flush=True)

    if response.error:
        logger.error("ERROR: %s", response.error)
        return

    # Summary of what was received (content was already displayed as it streamed)
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


# =============================================================================
# SETUP AND CLEANUP
# =============================================================================


def validate_credentials() -> None:
    """Validate that required credentials are set."""
    if not ACCESS_KEY or not SECRET_KEY:
        logger.error("Missing credentials. Please set environment variables:")
        logger.error("  export INFINO_ACCESS_KEY='your_key'")
        logger.error("  export INFINO_SECRET_KEY='your_secret'")
        sys.exit(1)


def setup_dataset(sdk: InfinoSDK) -> None:
    """
    Set up the demo dataset with sample data.

    Args:
        sdk: Initialized InfinoSDK instance.
    """
    # Clean up any existing dataset
    try:
        sdk.delete_dataset(DATASET_NAME)
        time.sleep(1)
    except InfinoError:
        pass

    sdk.create_dataset(DATASET_NAME)
    logger.info("Created dataset: %s", DATASET_NAME)

    payload = generate_bulk_payload(SAMPLE_PRODUCTS)
    sdk.upload_json_to_dataset(DATASET_NAME, payload)
    logger.info("Ingested %d sample products", len(SAMPLE_PRODUCTS))

    # Allow time for indexing
    time.sleep(2)


def cleanup_dataset(sdk: InfinoSDK) -> None:
    """
    Clean up the demo dataset.

    Args:
        sdk: Initialized InfinoSDK instance.
    """
    try:
        sdk.delete_dataset(DATASET_NAME)
        logger.info("Deleted dataset: %s", DATASET_NAME)
    except InfinoError as e:
        error_str = str(e).lower()
        if "not_found" in error_str or "404" in error_str:
            logger.info("Dataset already deleted or not found")
        else:
            logger.warning("Could not delete dataset: %s", e)
    except (OSError, ValueError, RuntimeError) as e:
        logger.warning("Cleanup error: %s", e)


async def create_streaming_thread(sdk: InfinoSDK) -> str:
    """
    Create a thread with streaming mode enabled.

    Args:
        sdk: Initialized InfinoSDK instance.

    Returns:
        The thread ID.
    """
    config = {
        "name": "Streaming Demo",
        "streaming": True,
        "sources": [{"index_name": DATASET_NAME, "connection_id": "infino"}],
    }
    url = f"{ENDPOINT}/_conversation/threads"
    thread_resp = sdk.request("POST", url, {}, json.dumps(config), {})
    thread_id = thread_resp["id"]

    logger.info("Thread ID: %s", thread_id)
    logger.info("Streaming: %s", thread_resp.get("streaming"))

    return thread_id


# =============================================================================
# MAIN
# =============================================================================


async def main() -> None:
    """
    Main entry point demonstrating streaming mode.

    Steps:
        1. Setup sample data
        2. Create streaming thread (streaming: true)
        3. Ask questions and observe streaming responses
        4. Cleanup
    """
    logger.info("=" * 70)
    logger.info("Infino SDK - Streaming Mode Example")
    logger.info("=" * 70)

    validate_credentials()

    sdk = InfinoSDK(ACCESS_KEY, SECRET_KEY, ENDPOINT)
    ws = None
    dataset_created = False

    try:
        # Step 1: Setup sample data
        logger.info("[STEP 1] Setting up sample data...")
        setup_dataset(sdk)
        dataset_created = True

        # Step 2: Create streaming thread
        logger.info("[STEP 2] Creating thread with streaming=true...")
        thread_id = await create_streaming_thread(sdk)

        # Step 3: Connect to WebSocket
        logger.info("[STEP 3] Connecting to WebSocket...")
        ws_headers = {
            "x-infino-thread-id": thread_id,
            "x-infino-client-id": f"stream-{uuid.uuid4().hex[:8]}",
        }
        ws = await asyncio.wait_for(
            sdk.websocket_connect("/_conversation/ws", headers=ws_headers),
            timeout=CONNECTION_TIMEOUT,
        )
        logger.info("Connected!")

        # Step 4: Ask questions with streaming
        logger.info("[STEP 4] Asking questions (observe the streaming!)...")

        # Question 1
        await handle_streaming_response(ws, "How many products do we have?")

        await asyncio.sleep(1)

        # Question 2 - Follow-up (AI remembers context from same thread)
        await handle_streaming_response(ws, "Which one is the most expensive?")

        logger.info("=" * 70)
        logger.info("Example complete!")
        logger.info("=" * 70)

    except asyncio.TimeoutError:
        logger.error("Timeout waiting for connection")
    except ConnectionClosed as e:
        logger.error("WebSocket connection closed: %s", e)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except (InfinoError, OSError, ValueError, RuntimeError) as e:
        logger.error("Error: %s: %s", type(e).__name__, e)
    finally:
        # Close WebSocket
        if ws:
            try:
                await ws.close()
            except (OSError, RuntimeError):
                pass  # Ignore errors during cleanup

        # Delete dataset
        logger.info("[CLEANUP] Deleting dataset...")
        if dataset_created:
            cleanup_dataset(sdk)

        sdk.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Exiting...")
