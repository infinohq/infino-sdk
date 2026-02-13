"""
Infino SDK - Query Elasticsearch/OpenSearch Example

This example demonstrates querying Elasticsearch or OpenSearch sources via Infino:
- Creating an Elasticsearch connection (if needed)
- Querying using QueryDSL (match_all, match, term, range, bool, aggregations)
- Fetching source metadata (field mappings, index settings)

For detailed request/response format documentation, see:
    docs/connectors.md#request-and-response-formats

Usage:
    export INFINO_ACCESS_KEY="your_key"
    export INFINO_SECRET_KEY="your_secret"
    export INFINO_ENDPOINT="https://api.infino.ws"
    # Optional: set ES_* env vars if you have a real Elasticsearch instance
    python examples/connectors/query_elasticsearch.py
"""

import json
import logging
import os

from infino_sdk import InfinoError, InfinoSDK

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Default connection and index for demo (replace with your connection_id and index name)
CONNECTION_ID = os.getenv("ES_CONNECTION_ID", "your_elasticsearch_connection_id")
INDEX_NAME = os.getenv("ES_INDEX_NAME", "logs-2024-01")


# =============================================================================
# QUERYDSL EXAMPLES
# =============================================================================

def query_match_all(size: int = 10) -> str:
    """QueryDSL: match_all (return up to size documents)."""
    return json.dumps({"query": {"match_all": {}}, "size": size})


def query_match(field: str, value: str, size: int = 10) -> str:
    """QueryDSL: match (full-text match on field)."""
    return json.dumps({"query": {"match": {field: value}}, "size": size})


def query_term(field: str, value: str, size: int = 10) -> str:
    """QueryDSL: term (exact match)."""
    return json.dumps({"query": {"term": {field: value}}, "size": size})


def query_range(field: str, gte=None, lte=None, size: int = 10) -> str:
    """QueryDSL: range query."""
    r = {}
    if gte is not None:
        r["gte"] = gte
    if lte is not None:
        r["lte"] = lte
    return json.dumps({"query": {"range": {field: r}}, "size": size})


def query_bool(must: list = None, filter_clauses: list = None, size: int = 10) -> str:
    """QueryDSL: bool (must/filter)."""
    body = {"query": {"bool": {}}, "size": size}
    if must:
        body["query"]["bool"]["must"] = must
    if filter_clauses:
        body["query"]["bool"]["filter"] = filter_clauses
    return json.dumps(body)


def query_aggregations(agg_name: str, agg_field: str, size: int = 0) -> str:
    """QueryDSL: terms aggregation."""
    return json.dumps({
        "size": size,
        "aggs": {
            agg_name: {"terms": {"field": agg_field, "size": 10}},
        },
    })


# =============================================================================
# MAIN
# =============================================================================


def main():
    """Run Elasticsearch query demo."""
    access_key = os.getenv("INFINO_ACCESS_KEY", "your_access_key")
    secret_key = os.getenv("INFINO_SECRET_KEY", "your_secret_key")
    endpoint = os.getenv("INFINO_ENDPOINT", "https://api.infino.ws")

    sdk = InfinoSDK(access_key, secret_key, endpoint)

    try:
        # ---------------------------------------------------------------------
        # Step 1: Get source metadata (schema, mappings)
        # ---------------------------------------------------------------------
        logger.info("[STEP 1] Getting source metadata for %s / %s...", CONNECTION_ID, INDEX_NAME)
        try:
            metadata = sdk.get_source_metadata(CONNECTION_ID, INDEX_NAME)
            logger.info("Metadata keys: %s", list(metadata.keys()))
            if "mappings" in metadata:
                logger.info("Mappings: %s", json.dumps(metadata["mappings"], indent=2)[:500])
        except InfinoError as e:
            logger.warning("Could not get metadata (connection or index may not exist): %s", e.message)
            logger.info("Continuing with query examples (they may fail without a real connection)...")

        # ---------------------------------------------------------------------
        # Step 2: Run various QueryDSL queries
        # ---------------------------------------------------------------------
        logger.info("[STEP 2] Running QueryDSL queries...")

        queries = [
            ("match_all", query_match_all(5)),
            ("match (message)", query_match("message", "error", 5)),
            ("term (level)", query_term("level", "error", 5)),
            ("range (timestamp)", query_range("@timestamp", gte="now-1d", lte="now", size=5)),
        ]

        for name, q in queries:
            try:
                results = sdk.query_source(CONNECTION_ID, INDEX_NAME, q)
                hits = (results.get("hits") or {}).get("hits", [])
                total = (results.get("hits") or {}).get("total")
                if isinstance(total, dict):
                    total = total.get("value", len(hits))
                logger.info("  %s: %s hits (total: %s)", name, len(hits), total)
            except InfinoError as e:
                logger.warning("  %s failed: %s", name, e.message)

        # ---------------------------------------------------------------------
        # Step 3: Aggregation example
        # ---------------------------------------------------------------------
        logger.info("[STEP 3] Running aggregation query...")
        try:
            agg_query = query_aggregations("by_level", "level")
            results = sdk.query_source(CONNECTION_ID, INDEX_NAME, agg_query)
            aggs = (results.get("aggregations") or {}).get("by_level", {})
            buckets = aggs.get("buckets", [])
            logger.info("  Aggregation buckets: %s", json.dumps(buckets[:5]))
        except InfinoError as e:
            logger.warning("  Aggregation failed: %s", e.message)

        logger.info("Elasticsearch query demo completed.")

    except InfinoError as e:
        logger.error("Infino error: %s", e.message)
        raise
    finally:
        sdk.close()


if __name__ == "__main__":
    main()
