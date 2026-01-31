"""
Infino SDK - Restricted Mode Demo

This example demonstrates the difference between:
1. Restricted mode: Thread is limited to specific indices (sources)
2. Auto mode: Infino automatically determines which indices to query

Scenario:
- Create 3 indices: product_1, product_2, and seller
- product_1 and product_2 have the same schema but different data
- seller table has seller information referenced by seller_id

Test:
- Thread 1 (Restricted): Only has access to product_1 and seller
- Thread 2 (Auto): Has access to all indices, Infino decides which to use

Both threads are asked:
"How many electrical products are in inventory for ABC seller?"

Usage:
    export INFINO_ACCESS_KEY="your_key"
    export INFINO_SECRET_KEY="your_secret"
    python examples/fino_nl_chat/restricted_mode_demo.py
"""

from __future__ import annotations

import asyncio
import time
import uuid

from websockets.exceptions import ConnectionClosed

from infino_sdk import InfinoError, InfinoSDK

from .common import (ACCESS_KEY, CONNECTION_TIMEOUT, ENDPOINT, SECRET_KEY,
                     StreamingResponse, create_thread, generate_bulk_payload,
                     handle_streaming_response, setup_logging,
                     validate_credentials)

# =============================================================================
# SETUP
# =============================================================================

logger = setup_logging()

# Index names
INDEX_PRODUCT_1 = "restricted_demo_product_1"
INDEX_PRODUCT_2 = "restricted_demo_product_2"
INDEX_SELLER = "restricted_demo_seller"

# =============================================================================
# SAMPLE DATA
# =============================================================================

# Seller data
SELLERS = [
    {
        "id": "S001", "name": "ABC Electronics",
        "location": "New York", "rating": 4.8,
    },
    {
        "id": "S002", "name": "XYZ Supplies",
        "location": "Los Angeles", "rating": 4.5,
    },
    {
        "id": "S003", "name": "Tech World",
        "location": "Chicago", "rating": 4.2,
    },
]

# Product 1 data - has ABC Electronics (S001) products
PRODUCTS_1 = [
    {
        "id": "P101", "name": "Wireless Mouse", "category": "electrical",
        "price": 29.99, "stock": 150, "seller_id": "S001",
    },
    {
        "id": "P102", "name": "USB Keyboard", "category": "electrical",
        "price": 49.99, "stock": 75, "seller_id": "S001",
    },
    {
        "id": "P103", "name": "Monitor Stand", "category": "accessories",
        "price": 35.00, "stock": 50, "seller_id": "S002",
    },
    {
        "id": "P104", "name": "Webcam HD", "category": "electrical",
        "price": 79.99, "stock": 30, "seller_id": "S001",
    },
    {
        "id": "P105", "name": "Mouse Pad", "category": "accessories",
        "price": 15.99, "stock": 200, "seller_id": "S003",
    },
]

# Product 2 data - has different products, some from ABC Electronics
PRODUCTS_2 = [
    {
        "id": "P201", "name": "Bluetooth Speaker", "category": "electrical",
        "price": 89.99, "stock": 60, "seller_id": "S002",
    },
    {
        "id": "P202", "name": "Power Bank", "category": "electrical",
        "price": 45.00, "stock": 100, "seller_id": "S001",
    },
    {
        "id": "P203", "name": "Laptop Bag", "category": "accessories",
        "price": 55.00, "stock": 80, "seller_id": "S003",
    },
    {
        "id": "P204", "name": "USB Hub", "category": "electrical",
        "price": 25.99, "stock": 120, "seller_id": "S001",
    },
    {
        "id": "P205", "name": "Screen Cleaner", "category": "accessories",
        "price": 9.99, "stock": 300, "seller_id": "S002",
    },
]


# =============================================================================
# SETUP AND CLEANUP
# =============================================================================


def setup_indices(sdk: InfinoSDK) -> None:
    """Create and populate all three indices."""
    # NOTE: Skipping delete step - takes too long when index doesn't exist
    # (server timeout)
    # create_dataset returns success even if dataset already exists

    # Create and populate indices
    logger.info("Creating index: %s", INDEX_SELLER)
    sdk.create_dataset(INDEX_SELLER)
    logger.info("  Created, now uploading data...")
    sdk.upload_json_to_dataset(INDEX_SELLER, generate_bulk_payload(SELLERS))
    logger.info("  Ingested %d sellers", len(SELLERS))

    logger.info("Creating index: %s", INDEX_PRODUCT_1)
    sdk.create_dataset(INDEX_PRODUCT_1)
    logger.info("  Created, now uploading data...")
    payload_1 = generate_bulk_payload(PRODUCTS_1)
    sdk.upload_json_to_dataset(INDEX_PRODUCT_1, payload_1)
    logger.info("  Ingested %d products", len(PRODUCTS_1))

    logger.info("Creating index: %s", INDEX_PRODUCT_2)
    sdk.create_dataset(INDEX_PRODUCT_2)
    logger.info("  Created, now uploading data...")
    payload_2 = generate_bulk_payload(PRODUCTS_2)
    sdk.upload_json_to_dataset(INDEX_PRODUCT_2, payload_2)
    logger.info("  Ingested %d products", len(PRODUCTS_2))

    # Allow time for indexing
    logger.info("Waiting for indexing...")
    time.sleep(3)


def cleanup_indices(sdk: InfinoSDK) -> None:
    """Clean up all indices."""
    indices = [INDEX_PRODUCT_1, INDEX_PRODUCT_2, INDEX_SELLER]
    for index_name in indices:
        try:
            sdk.delete_dataset(index_name)
            logger.info("Deleted: %s", index_name)
        except (InfinoError, OSError, ValueError, RuntimeError):
            pass  # Ignore errors during cleanup


# =============================================================================
# MAIN
# =============================================================================


async def main() -> None:
    """
    Main entry point demonstrating restricted vs auto mode.

    Steps:
        1. Setup 3 indices: product_1, product_2, seller
        2. Create restricted thread (product_1 + seller only)
        3. Create auto mode thread (no sources specified)
        4. Ask the same question to both threads
        5. Compare the responses
    """
    logger.info("=" * 70)
    logger.info("Infino SDK - Restricted Mode Demo")
    logger.info("=" * 70)

    validate_credentials(logger)

    sdk = InfinoSDK(ACCESS_KEY, SECRET_KEY, ENDPOINT)
    ws_restricted = None
    ws_auto = None
    indices_created = False

    # The question to ask both threads
    question = (
        "How many electrical products are in inventory "
        "for ABC Electronics seller?"
    )

    try:
        # Step 1: Setup indices
        logger.info("\n[STEP 1] Setting up indices...")
        setup_indices(sdk)
        indices_created = True

        # Print data summary
        print("\n" + "-" * 70, flush=True)
        print("DATA SUMMARY:", flush=True)
        print("-" * 70, flush=True)
        seller_info = f"  {INDEX_SELLER}: {len(SELLERS)} sellers (ABC = S001)"
        print(seller_info, flush=True)
        print(f"  {INDEX_PRODUCT_1}: {len(PRODUCTS_1)} products", flush=True)
        abc_in_p1 = [
            p for p in PRODUCTS_1
            if p["seller_id"] == "S001" and p["category"] == "electrical"
        ]
        stock_p1 = sum(p["stock"] for p in abc_in_p1)
        print(f"    -> ABC: {len(abc_in_p1)} items ({stock_p1})", flush=True)
        print(f"  {INDEX_PRODUCT_2}: {len(PRODUCTS_2)} products", flush=True)
        abc_in_p2 = [
            p for p in PRODUCTS_2
            if p["seller_id"] == "S001" and p["category"] == "electrical"
        ]
        stock_p2 = sum(p["stock"] for p in abc_in_p2)
        print(f"    -> ABC: {len(abc_in_p2)} items ({stock_p2})", flush=True)
        print("-" * 70, flush=True)

        # Step 2: Create RESTRICTED thread (product_1 + seller only)
        logger.info("\n[STEP 2] Creating RESTRICTED thread...")
        restricted_sources = [
            {"index_name": INDEX_PRODUCT_1, "connection_id": "infino"},
            {"index_name": INDEX_SELLER, "connection_id": "infino"},
        ]
        thread_id_restricted = create_thread(
            sdk,
            "Restricted Demo - Product 1 Only",
            streaming=True,
            sources=restricted_sources,
        )

        # Step 3: Create AUTO mode thread (no sources)
        logger.info("\n[STEP 3] Creating AUTO mode thread...")
        thread_id_auto = create_thread(
            sdk,
            "Auto Demo - All Indices",
            streaming=True,
            sources=None,  # Auto mode
        )

        # Step 4: Connect to WebSockets
        logger.info("\n[STEP 4] Connecting to WebSockets...")

        # Connect to restricted thread
        ws_headers_restricted = {
            "x-infino-thread-id": thread_id_restricted,
            "x-infino-client-id": f"restricted-{uuid.uuid4().hex[:8]}",
        }
        ws_restricted = await asyncio.wait_for(
            sdk.websocket_connect(
                "/_conversation/ws", headers=ws_headers_restricted
            ),
            timeout=CONNECTION_TIMEOUT,
        )
        logger.info("Connected to RESTRICTED thread!")

        # Connect to auto thread
        ws_headers_auto = {
            "x-infino-thread-id": thread_id_auto,
            "x-infino-client-id": f"auto-{uuid.uuid4().hex[:8]}",
        }
        ws_auto = await asyncio.wait_for(
            sdk.websocket_connect(
                "/_conversation/ws", headers=ws_headers_auto
            ),
            timeout=CONNECTION_TIMEOUT,
        )
        logger.info("Connected to AUTO thread!")

        # Step 5: Ask question to RESTRICTED thread
        logger.info("\n[STEP 5] Asking question to RESTRICTED thread...")
        print("\n" + "#" * 70, flush=True)
        print("# TEST 1: RESTRICTED MODE (product_1 + seller)", flush=True)
        print("#" * 70, flush=True)

        mode_label = f"RESTRICTED ({INDEX_PRODUCT_1}, {INDEX_SELLER})"
        response_restricted: StreamingResponse
        response_restricted = await handle_streaming_response(
            ws_restricted,
            question,
            mode_label,
        )

        await asyncio.sleep(2)

        # Step 6: Ask same question to AUTO thread
        logger.info("\n[STEP 6] Asking same question to AUTO thread...")
        print("\n" + "#" * 70, flush=True)
        print("# TEST 2: AUTO MODE (Infino decides which indices)", flush=True)
        print("#" * 70, flush=True)

        response_auto: StreamingResponse = await handle_streaming_response(
            ws_auto,
            question,
            "AUTO (no sources specified - Infino decides)",
        )

        # Step 7: Compare results
        print("\n" + "=" * 70, flush=True)
        print("COMPARISON SUMMARY", flush=True)
        print("=" * 70, flush=True)

        print("\nRESTRICTED MODE:", flush=True)
        summary_len = len(response_restricted.summary)
        print(f"  Summary length: {summary_len} chars", flush=True)
        has_data = response_restricted.data is not None
        print(f"  Has data: {has_data}", flush=True)
        has_err = response_restricted.error is not None
        print(f"  Has error: {has_err}", flush=True)

        print("\nAUTO MODE:", flush=True)
        summary_len = len(response_auto.summary)
        print(f"  Summary length: {summary_len} chars", flush=True)
        has_data = response_auto.data is not None
        print(f"  Has data: {has_data}", flush=True)
        has_err = response_auto.error is not None
        print(f"  Has error: {has_err}", flush=True)

        print("\n" + "=" * 70, flush=True)
        print("Demo complete!", flush=True)
        print("=" * 70, flush=True)

    except asyncio.TimeoutError:
        logger.error("Timeout waiting for connection")
    except ConnectionClosed as e:
        logger.error("WebSocket connection closed: %s", e)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except (InfinoError, OSError, ValueError, RuntimeError) as e:
        logger.error("Error: %s: %s", type(e).__name__, e)
    finally:
        # Close WebSockets
        for ws in [ws_restricted, ws_auto]:
            if ws:
                try:
                    await ws.close()
                except (OSError, RuntimeError):
                    pass

        # Cleanup indices
        logger.info("\n[CLEANUP] Deleting indices...")
        if indices_created:
            cleanup_indices(sdk)

        sdk.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Exiting...")
