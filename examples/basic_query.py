"""
Basic Query Operations with Infino SDK

This example demonstrates:
- Creating a dataset
- Ingesting sample data
- Querying datasets with QueryDSL
- Using different query types
- Working with records
"""

import json
import logging
import os
import time

from infino_sdk import InfinoError, InfinoSDK

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def generate_sample_products():
    """Generate sample product data in NDJSON bulk format."""
    products = [
        {"id": 1, "name": "Wireless Headphones", "category": "electronics", "price": 79.99, "in_stock": True, "rating": 4.5},
        {"id": 2, "name": "USB-C Cable", "category": "electronics", "price": 12.99, "in_stock": True, "rating": 4.2},
        {"id": 3, "name": "Laptop Stand", "category": "electronics", "price": 45.00, "in_stock": True, "rating": 4.7},
        {"id": 4, "name": "Mechanical Keyboard", "category": "electronics", "price": 129.99, "in_stock": False, "rating": 4.8},
        {"id": 5, "name": "Mouse Pad XL", "category": "accessories", "price": 24.99, "in_stock": True, "rating": 4.3},
        {"id": 6, "name": "Monitor Light Bar", "category": "electronics", "price": 89.99, "in_stock": True, "rating": 4.6},
        {"id": 7, "name": "Desk Organizer", "category": "home", "price": 19.99, "in_stock": True, "rating": 4.1},
        {"id": 8, "name": "Webcam HD", "category": "electronics", "price": 59.99, "in_stock": True, "rating": 4.4},
        {"id": 9, "name": "Used Laptop", "category": "used", "price": 299.99, "in_stock": True, "rating": 3.8},
        {"id": 10, "name": "Phone Charger", "category": "electronics", "price": 15.99, "in_stock": True, "rating": 4.0},
    ]

    bulk_lines = []
    for product in products:
        action = {"index": {"_id": str(product["id"])}}
        bulk_lines.append(json.dumps(action))
        bulk_lines.append(json.dumps(product))

    return "\n".join(bulk_lines) + "\n"


def main():
    # Get credentials from environment variables
    access_key = os.getenv("INFINO_ACCESS_KEY", "your_access_key")
    secret_key = os.getenv("INFINO_SECRET_KEY", "your_secret_key")
    endpoint = os.getenv("INFINO_ENDPOINT", "https://api.infino.ws")

    sdk = InfinoSDK(access_key, secret_key, endpoint)
    logger.info("Connected to Infino")

    # Create a dataset
    dataset_name = "demo_products"
    try:
        sdk.create_dataset(dataset_name)
        logger.info("Created dataset: %s", dataset_name)
    except InfinoError as e:
        if e.status_code() == 409:
            logger.info("Dataset %s already exists", dataset_name)
        else:
            raise

    try:
        # Ingest sample data
        logger.info("Ingesting sample data")
        bulk_data = generate_sample_products()
        result = sdk.upload_json_to_dataset(dataset_name, bulk_data)
        if result.get("errors"):
            logger.warning("Some records failed to ingest")
        else:
            logger.info("Ingested 10 sample products")

        # Wait for data to be indexed
        time.sleep(1)

        # Get dataset metadata
        logger.info("Fetching dataset metadata")
        metadata = sdk.get_dataset_metadata(dataset_name)
        logger.info(
            "Metadata - Index: %s, Health: %s, Status: %s, Docs: %s, Size: %s",
            metadata.get("index", "N/A"),
            metadata.get("health", "N/A"),
            metadata.get("status", "N/A"),
            metadata.get("docs.count", "N/A"),
            metadata.get("store.size", "N/A"),
        )

        # Get dataset schema
        logger.info("Fetching dataset schema")
        schema = sdk.get_dataset_schema(dataset_name)
        for field_name, field_info in schema.items():
            logger.debug("Field: %s, Type: %s", field_name, field_info.get("infino_type", "unknown"))

        # Match all query
        logger.info("Executing match_all query")
        query = '{"query": {"match_all": {}}, "size": 5}'
        results = sdk.query_dataset_in_querydsl(dataset_name, query)
        hits = results.get("hits", {}).get("hits", [])
        total = results.get("hits", {}).get("total", {}).get("value", 0)
        logger.info("Match all query returned %d total records", total)

        assert total == 10, f"Expected 10 total products, got {total}"
        assert len(hits) == 5, f"Expected 5 hits (size limit), got {len(hits)}"

        # Term query
        logger.info("Executing term query for category=electronics")
        query = '{"query": {"term": {"category": "electronics"}}}'
        results = sdk.query_dataset_in_querydsl(dataset_name, query)
        hits = results.get("hits", {}).get("hits", [])
        logger.info("Term query returned %d electronics products", len(hits))

        assert len(hits) == 7, f"Expected 7 electronics products, got {len(hits)}"
        for hit in hits:
            assert hit["_source"]["category"] == "electronics", f"Expected category 'electronics', got {hit['_source']['category']}"

        # Range query
        logger.info("Executing range query for price between $10-$100")
        query = """
        {
            "query": {
                "range": {
                    "price": {
                        "gte": 10,
                        "lte": 100
                    }
                }
            },
            "sort": [{"price": "asc"}]
        }
        """
        results = sdk.query_dataset_in_querydsl(dataset_name, query)
        hits = results.get("hits", {}).get("hits", [])
        logger.info("Range query returned %d products", len(hits))

        assert len(hits) == 8, f"Expected 8 products in $10-$100 range, got {len(hits)}"
        for hit in hits:
            price = hit["_source"]["price"]
            assert 10 <= price <= 100, f"Expected price between $10-$100, got ${price}"

        # Bool query (combining multiple conditions)
        logger.info("Executing bool query (in_stock=true, price<=50, category!=used)")
        query = """
        {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"in_stock": true}}
                    ],
                    "filter": [
                        {"range": {"price": {"lte": 50}}}
                    ],
                    "must_not": [
                        {"term": {"category": "used"}}
                    ]
                }
            }
        }
        """
        results = sdk.query_dataset_in_querydsl(dataset_name, query)
        hits = results.get("hits", {}).get("hits", [])
        logger.info("Bool query returned %d in-stock products under $50", len(hits))

        assert len(hits) == 5, f"Expected 5 in-stock products under $50, got {len(hits)}"
        for hit in hits:
            source = hit["_source"]
            assert source["in_stock"] is True, f"Expected in_stock=True, got {source['in_stock']}"
            assert source["price"] <= 50, f"Expected price <= $50, got ${source['price']}"
            assert source["category"] != "used", f"Expected category != 'used', got {source['category']}"

        # Search with aggregations
        logger.info("Executing aggregation query for categories")
        query = """
        {
            "size": 0,
            "aggs": {
                "categories": {
                    "terms": {
                        "field": "category.keyword",
                        "size": 10
                    }
                }
            }
        }
        """
        results = sdk.query_dataset_in_querydsl(dataset_name, query)
        aggs = results.get("aggregations", {})

        if "categories" in aggs:
            buckets = {b["key"]: b["doc_count"] for b in aggs["categories"]["buckets"]}
            logger.info("Aggregation results: %s", buckets)

            assert buckets.get("electronics") == 7, f"Expected 7 electronics, got {buckets.get('electronics')}"
            assert buckets.get("accessories") == 1, f"Expected 1 accessories, got {buckets.get('accessories')}"
            assert buckets.get("home") == 1, f"Expected 1 home, got {buckets.get('home')}"
            assert buckets.get("used") == 1, f"Expected 1 used, got {buckets.get('used')}"
            total_in_buckets = sum(buckets.values())
            assert total_in_buckets == 10, f"Expected 10 total in buckets, got {total_in_buckets}"
        else:
            raise AssertionError("Expected category aggregations but found none")

        logger.info("All assertions passed")

    finally:
        # Cleanup: always delete the dataset
        logger.info("Cleaning up - deleting dataset")
        sdk.delete_dataset(dataset_name)
        logger.info("Deleted dataset: %s", dataset_name)


if __name__ == "__main__":
    main()
