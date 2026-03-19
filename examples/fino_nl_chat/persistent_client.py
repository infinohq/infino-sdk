"""
Infino SDK - Persistent WebSocket Client Example

``FinoWebSocketClient`` keeps a single WebSocket connection open for the
lifetime of a thread.  It auto-reconnects on unexpected drops, queues messages
sent while the socket is reconnecting, and re-sends any in-flight query after
reconnection so nothing is silently lost.

Use this pattern for long-running applications (chatbots, dashboards, agents)
where you want low-latency, streaming responses without the overhead of opening
a new connection for every query.

Usage:
    export INFINO_ACCESS_KEY="your_access_key"
    export INFINO_SECRET_KEY="your_secret_key"
    python examples/fino_nl_chat/persistent_client.py
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Dict

from infino_sdk import FinoWebSocketClient, InfinoError, InfinoSDK

ACCESS_KEY = os.environ["INFINO_ACCESS_KEY"]
SECRET_KEY = os.environ["INFINO_SECRET_KEY"]
ENDPOINT = os.environ.get("INFINO_ENDPOINT", "https://api.infino.ai")

DATASET_NAME = "persistent_client_demo"

SAMPLE_PRODUCTS = [
    {"id": 1, "name": "Wireless Headphones", "category": "electronics", "price": 79.99},
    {"id": 2, "name": "USB-C Cable", "category": "electronics", "price": 12.99},
    {"id": 3, "name": "Laptop Stand", "category": "accessories", "price": 45.00},
]


# ---------------------------------------------------------------------------
# Helper: build NDJSON bulk payload
# ---------------------------------------------------------------------------

def make_bulk_payload(docs: list) -> str:
    lines: list[str] = []
    for i, doc in enumerate(docs, start=1):
        lines.append(f'{{"index": {{"_id": "{i}"}}}}')
        import json
        lines.append(json.dumps(doc))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Example 1 – FinoWebSocketClient (persistent, streaming)
# ---------------------------------------------------------------------------

async def run_persistent_client(sdk: InfinoSDK, thread_id: str) -> None:
    """
    Demonstrates ``FinoWebSocketClient``: one persistent connection per thread.

    ``on_frame`` fires for every streaming frame the server sends.  The final
    frame has ``content.type == "result"`` (or ``"EOM"``); intermediate frames
    carry partial text, SQL, chart data, etc.
    """
    client = FinoWebSocketClient(
        sdk=sdk,
        thread_id=thread_id,
        ws_path="/fino/nl",
        client_id="persistent-client-demo",
    )

    received: list[Dict[str, Any]] = []

    def on_frame(frame: Dict[str, Any]) -> None:
        received.append(frame)
        content = frame.get("content", {})
        frame_type = content.get("type") if isinstance(content, dict) else frame.get("type")
        if frame_type in ("result", "EOM"):
            print(f"  [final] {content}")
        else:
            text = content.get("text") or content.get("message") if isinstance(content, dict) else None
            if text:
                print(f"  [stream] {text}", end="", flush=True)

    await client.connect()
    unsub = client.on_frame(on_frame)

    queries = [
        "How many products are in the dataset?",
        "Which product is the most expensive?",
    ]

    for query in queries:
        print(f"\nQuery: {query}")
        received.clear()
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        client.send({
            "id": now,
            "role": "user",
            "created_at": now,
            "content": {
                "user_query": query,
                "type": "user",
                "summary": "",
                "data": {},
                "vegaspec": {},
                "querydsl": {},
                "followup_queries": [],
                "sender_agent": "user",
                "user_context": {},
            },
        })
        # Wait for the final frame (simple poll; production code would use an event).
        for _ in range(60):
            if any(
                (f.get("content", {}).get("type") if isinstance(f.get("content"), dict) else f.get("type"))
                in ("result", "EOM")
                for f in received
            ):
                break
            await asyncio.sleep(0.5)
        print()

    unsub()
    client.close()


# ---------------------------------------------------------------------------
# Example 2 – High-level query_fino_nl (per-query, streaming callback)
# ---------------------------------------------------------------------------

async def run_high_level(sdk: InfinoSDK, thread_id: str) -> None:
    """
    ``sdk.query_fino_nl`` wraps the full per-query WebSocket lifecycle.

    The optional ``on_message`` callback streams intermediate frames; the
    method's return value is the final aggregated response.
    """
    print("\n--- High-level query_fino_nl ---")
    result = await sdk.query_fino_nl(
        query="What are the product categories?",
        timeout_ms=60_000,
        on_message=lambda frame: print(f"  [frame] {frame.get('content', {}).get('text', '')}"),
    )
    print(f"Final result: {result}")


# ---------------------------------------------------------------------------
# Example 3 – High-level query_fino_analyze (deep multi-step analysis)
# ---------------------------------------------------------------------------

async def run_analyze(sdk: InfinoSDK, thread_id: str) -> None:
    """
    ``sdk.query_fino_analyze`` is for complex investigations that need
    multiple analytical steps or a report.  Use ``query_fino_nl`` for
    simple Q&A.

    The optional ``on_message`` callback streams intermediate frames
    (``analyze_action``, ``partial``, ``cell_artifact``, etc.); the
    return value is the final collected response.
    """
    print("\n--- High-level query_fino_analyze ---")

    def on_frame(frame: Dict[str, Any]) -> None:
        frame_type = frame.get("type", "")
        if frame_type == "analyze_action":
            print(f"  [analyze] {frame.get('action_type', '')} — {frame.get('message', '')}")
        elif frame_type == "partial":
            sub = frame.get("sub_type", "")
            if sub == "summary":
                print(f"  [summary] {frame.get('value', '')[:80]}")

    result = await sdk.query_fino_analyze(
        query="Compare product prices by category and summarize findings",
        timeout_ms=120_000,
        on_message=on_frame,
    )
    print(f"Analyze responses received: {len(result.get('responses', []))}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> None:
    sdk = InfinoSDK(ACCESS_KEY, SECRET_KEY, ENDPOINT)

    # Ingest sample data
    try:
        sdk.delete_dataset(DATASET_NAME)
        time.sleep(1)
    except InfinoError:
        pass
    sdk.create_dataset(DATASET_NAME)
    sdk.upload_json_to_dataset(DATASET_NAME, make_bulk_payload(SAMPLE_PRODUCTS))
    time.sleep(2)

    # Create a thread scoped to the demo dataset
    sources = [{"index_name": DATASET_NAME, "connection_id": "infino"}]
    thread = sdk.create_thread(name="persistent-demo", sources=sources)
    thread_id: str = thread.get("id") or thread.get("thread_id") or thread["_id"]

    print("=== Persistent client (FinoWebSocketClient) ===")
    await run_persistent_client(sdk, thread_id)

    await run_high_level(sdk, thread_id)

    await run_analyze(sdk, thread_id)

    # Cleanup
    try:
        sdk.delete_dataset(DATASET_NAME)
    except InfinoError:
        pass
    sdk.close()


if __name__ == "__main__":
    asyncio.run(main())
