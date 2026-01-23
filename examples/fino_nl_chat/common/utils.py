"""
Utility functions for Fino examples.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from infino_sdk import InfinoSDK

from .config import ENDPOINT

logger = logging.getLogger(__name__)


def generate_bulk_payload(
    records: list[dict[str, Any]],
    id_field: str = "id",
) -> str:
    """
    Generate NDJSON bulk format payload for Elasticsearch-style ingestion.

    Args:
        records: List of record dictionaries to convert.
        id_field: Field name to use as document ID. Default "id".

    Returns:
        NDJSON string with alternating index/document lines.
    """
    bulk_lines = []
    for record in records:
        index_action = {"index": {"_id": str(record[id_field])}}
        bulk_lines.append(json.dumps(index_action))
        bulk_lines.append(json.dumps(record))
    return "\n".join(bulk_lines) + "\n"


def create_thread(
    sdk: InfinoSDK,
    name: str | None = None,
    streaming: bool = True,
    sources: list[dict[str, str]] | None = None,
    endpoint: str = ENDPOINT,
) -> str:
    """
    Create a conversation thread via REST API.

    Args:
        sdk: InfinoSDK instance
        name: Optional thread name. Auto-generated if not provided.
        streaming: Whether to enable streaming mode. Default True.
        sources: Optional list of sources for restricted mode.
                 Each source should have "index_name" and "connection_id".
                 If None, thread uses auto mode.
        endpoint: API endpoint URL.

    Returns:
        Thread ID string.
    """
    if name is None:
        name = f"Thread-{uuid.uuid4().hex[:8]}"

    config: dict[str, Any] = {
        "name": name,
        "streaming": streaming,
    }

    if sources is not None:
        config["sources"] = sources
        logger.info("Creating RESTRICTED thread: %s", name)
        logger.info("  Sources: %s", [s["index_name"] for s in sources])
    else:
        mode = "streaming" if streaming else "non-streaming"
        logger.info("Creating %s thread: %s", mode, name)

    url = f"{endpoint}/_conversation/threads"
    response = sdk.request("POST", url, {}, json.dumps(config), {})
    thread_id = response["id"]

    logger.info("  Thread ID: %s", thread_id)
    if streaming:
        logger.info("  Streaming: %s", response.get("streaming", True))

    return thread_id


def create_message(user_query: str) -> dict[str, Any]:
    """
    Create a message for the WebSocket API.

    Args:
        user_query: The user's question

    Returns:
        Message dictionary ready to send

    Example:
        {"content": {"user_query": "What happened yesterday?"}}
    """
    return {"content": {"user_query": user_query}}
