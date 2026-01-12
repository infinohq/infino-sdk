"""
Basic Query Operations with Infino SDK

This example demonstrates:
- Creating a dataset
- Querying datasets with QueryDSL
- Using different query types
- Working with records
"""

import os

from infino_sdk import InfinoError, InfinoSDK


def main():
    # Get credentials from environment variables
    access_key = os.getenv("INFINO_ACCESS_KEY", "your_access_key")
    secret_key = os.getenv("INFINO_SECRET_KEY", "your_secret_key")
    endpoint = os.getenv("INFINO_ENDPOINT", "https://api.infino.ws")

    sdk = InfinoSDK(access_key, secret_key, endpoint)
    print("✅ Connected to Infino")

    # Create a dataset
    dataset_name = "demo_products"
    try:
        sdk.create_dataset(dataset_name)
        print(f"✅ Created dataset: {dataset_name}")
    except InfinoError as e:
        if e.status_code() == 409:
            print(f"ℹ️  Dataset {dataset_name} already exists")
        else:
            raise

    try:
        # Get dataset metadata
        print("\n--- Dataset Metadata ---")
        metadata = sdk.get_dataset_metadata(dataset_name)
        print(f"Index: {metadata.get('index', 'N/A')}")
        print(f"Health: {metadata.get('health', 'N/A')}")
        print(f"Status: {metadata.get('status', 'N/A')}")
        print(f"Document count: {metadata.get('docs.count', 'N/A')}")
        print(f"Store size: {metadata.get('store.size', 'N/A')}")

        # Match all query
        print("\n--- Match All Query ---")
        query = '{"query": {"match_all": {}}, "size": 5}'
        results = sdk.query_dataset_in_querydsl(dataset_name, query)
        hits = results.get("hits", {}).get("hits", [])
        print(f"Found {results.get('hits', {}).get('total', {}).get('value', 0)} records")
        for hit in hits[:3]:
            print(f"  - ID: {hit['_id']}, Score: {hit['_score']}")

        # Term query
        print("\n--- Term Query ---")
        query = '{"query": {"term": {"category": "electronics"}}}'
        results = sdk.query_dataset_in_querydsl(dataset_name, query)
        hits = results.get("hits", {}).get("hits", [])
        print(f"Found {len(hits)} electronics products")

        # Range query
        print("\n--- Range Query ---")
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
        print(f"Found {len(hits)} products priced between $10-$100")
        for hit in hits[:5]:
            source = hit.get("_source", {})
            print(f"  - {source.get('name')}: ${source.get('price')}")

        # Bool query (combining multiple conditions)
        print("\n--- Bool Query (Multiple Conditions) ---")
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
        print(
            f"Found {len(results.get('hits', {}).get('hits', []))} in-stock products under $50"
        )

        # Search with aggregations
        print("\n--- Search with Aggregations ---")
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
            print("Categories:")
            for bucket in aggs["categories"]["buckets"]:
                print(f"  - {bucket['key']}: {bucket['doc_count']} products")
        else:
            print("No category aggregations found (dataset may be empty)")

    finally:
        # Cleanup: always delete the dataset
        print("\n--- Cleanup ---")
        sdk.delete_dataset(dataset_name)
        print(f"✅ Deleted dataset: {dataset_name}")


if __name__ == "__main__":
    main()
