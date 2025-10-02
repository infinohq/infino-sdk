"""
Basic Search Operations with Infino SDK

This example demonstrates:
- Creating an index
- Executing basic searches
- Using different query types
- Counting documents
"""

import os
from infino_sdk import InfinoSDK, InfinoError


def main():
    # Get credentials from environment variables
    access_key = os.getenv("INFINO_ACCESS_KEY", "your_access_key")
    secret_key = os.getenv("INFINO_SECRET_KEY", "your_secret_key")
    endpoint = os.getenv("INFINO_ENDPOINT", "https://api.infino.ws")

    sdk = InfinoSDK(access_key, secret_key, endpoint)
    print("✅ Connected to Infino")

    # Create an index
    index_name = "demo_products"
    try:
        sdk.create_index(index_name)
        print(f"✅ Created index: {index_name}")
    except InfinoError as e:
        if e.status_code() == 409:
            print(f"ℹ️  Index {index_name} already exists")
        else:
            raise

    # Match all query
    print("\n--- Match All Query ---")
    query = '{"query": {"match_all": {}}, "size": 5}'
    results = sdk.search(index_name, query)
    hits = results.get("hits", {}).get("hits", [])
    print(f"Found {results.get('hits', {}).get('total', {}).get('value', 0)} documents")
    for hit in hits[:3]:
        print(f"  - ID: {hit['_id']}, Score: {hit['_score']}")

    # Term query
    print("\n--- Term Query ---")
    query = '{"query": {"term": {"category": "electronics"}}}'
    results = sdk.search(index_name, query)
    hits = results.get("hits", {}).get("hits", [])
    print(f"Found {len(hits)} electronics products")

    # Range query
    print("\n--- Range Query ---")
    query = '''
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
    '''
    results = sdk.search(index_name, query)
    hits = results.get("hits", {}).get("hits", [])
    print(f"Found {len(hits)} products priced between $10-$100")
    for hit in hits[:5]:
        source = hit.get("_source", {})
        print(f"  - {source.get('name')}: ${source.get('price')}")

    # Bool query (combining multiple conditions)
    print("\n--- Bool Query (Multiple Conditions) ---")
    query = '''
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
    '''
    results = sdk.search(index_name, query)
    print(f"Found {len(results.get('hits', {}).get('hits', []))} in-stock products under $50")

    # Count documents
    print("\n--- Document Count ---")
    count_result = sdk.count(index_name)
    print(f"Total documents in {index_name}: {count_result.get('count', 0)}")

    # Search with aggregations
    print("\n--- Search with Aggregations ---")
    query = '''
    {
        "size": 0,
        "aggs": {
            "categories": {
                "terms": {
                    "field": "category.keyword",
                    "size": 10
                }
            },
            "price_stats": {
                "stats": {
                    "field": "price"
                }
            }
        }
    }
    '''
    results = sdk.search(index_name, query)
    aggs = results.get("aggregations", {})

    if "categories" in aggs:
        print("Categories:")
        for bucket in aggs["categories"]["buckets"]:
            print(f"  - {bucket['key']}: {bucket['doc_count']} products")

    if "price_stats" in aggs:
        stats = aggs["price_stats"]
        print("Price Statistics:")
        print(f"  - Min: ${stats.get('min', 0):.2f}")
        print(f"  - Max: ${stats.get('max', 0):.2f}")
        print(f"  - Avg: ${stats.get('avg', 0):.2f}")


if __name__ == "__main__":
    main()
