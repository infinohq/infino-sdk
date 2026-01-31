"""
Infino SDK - Streaming Mode Example

This example demonstrates how to use the Infino SDK with streaming mode
enabled. See docs/streaming_responses.md for the complete response format
documentation.

Usage:
    export INFINO_ACCESS_KEY="your_key"
    export INFINO_SECRET_KEY="your_secret"
    python examples/fino_nl_chat/streaming_chat.py
"""

from __future__ import annotations

import asyncio
import time
import uuid

from websockets.exceptions import ConnectionClosed

from infino_sdk import InfinoError, InfinoSDK

from .common import (ACCESS_KEY, CONNECTION_TIMEOUT, ENDPOINT, SECRET_KEY,
                     create_thread, generate_bulk_payload,
                     handle_streaming_response, setup_logging,
                     validate_credentials)

# =============================================================================
# SETUP
# =============================================================================

logger = setup_logging()

DATASET_NAME = "streaming_demo_products"

# =============================================================================
# SAMPLE DATA
# =============================================================================

SAMPLE_PRODUCTS = [
    {
        "id": 1, "name": "Wireless Headphones", "category": "electronics",
        "price": 79.99, "in_stock": True,
    },
    {
        "id": 2, "name": "USB-C Cable", "category": "electronics",
        "price": 12.99, "in_stock": True,
    },
    {
        "id": 3, "name": "Laptop Stand", "category": "accessories",
        "price": 45.00, "in_stock": True,
    },
    {
        "id": 4, "name": "Mechanical Keyboard", "category": "electronics",
        "price": 129.99, "in_stock": False,
    },
    {
        "id": 5, "name": "Mouse Pad XL", "category": "accessories",
        "price": 24.99, "in_stock": True,
    },
]


# =============================================================================
# SETUP AND CLEANUP
# =============================================================================


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

    validate_credentials(logger)

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
        sources = [{"index_name": DATASET_NAME, "connection_id": "infino"}]
        thread_id = create_thread(
            sdk, "Streaming Demo", streaming=True, sources=sources
        )

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
