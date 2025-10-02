"""
Bulk Indexing with Infino SDK

This example demonstrates:
- Bulk document indexing in NDJSON format
- Handling bulk operation results
- Error handling for failed operations
- Best practices for large datasets
"""

import json
import os
import time
from infino_sdk import InfinoSDK, InfinoError


def generate_bulk_data(num_docs=1000):
    """Generate NDJSON bulk data for indexing"""
    bulk_lines = []
    
    for i in range(num_docs):
        # Action line
        action = {"index": {"_id": str(i)}}
        bulk_lines.append(json.dumps(action))
        
        # Document source
        doc = {
            "id": i,
            "name": f"Product {i}",
            "category": ["electronics", "home", "sports", "books"][i % 4],
            "price": round(10 + (i % 100) * 1.5, 2),
            "in_stock": i % 3 != 0,
            "rating": round(3 + (i % 3), 1),
            "description": f"This is product number {i} with great features",
            "tags": [f"tag{i % 5}", f"tag{i % 7}"],
            "created_at": f"2024-01-{(i % 28) + 1:02d}T10:00:00Z"
        }
        bulk_lines.append(json.dumps(doc))
    
    return '\n'.join(bulk_lines) + '\n'


def main():
    access_key = os.getenv("INFINO_ACCESS_KEY", "your_access_key")
    secret_key = os.getenv("INFINO_SECRET_KEY", "your_secret_key")
    endpoint = os.getenv("INFINO_ENDPOINT", "https://api.infino.ws")

    sdk = InfinoSDK(access_key, secret_key, endpoint)
    print("✅ Connected to Infino")
        
        index_name = "bulk_demo"
        
        # Create index with explicit mapping
        print(f"\n📦 Creating index: {index_name}")
        mapping = {
            "mappings": {
                "properties": {
                    "name": {"type": "text"},
                    "category": {"type": "keyword"},
                    "price": {"type": "float"},
                    "in_stock": {"type": "boolean"},
                    "rating": {"type": "float"},
                    "description": {"type": "text"},
                    "tags": {"type": "keyword"},
                    "created_at": {"type": "date"}
                }
            }
        }
        
        try:
            sdk.create_index_with_mapping(index_name, mapping)
            print(f"✅ Index created successfully")
        except InfinoError as e:
            if e.status_code() == 409:
                print(f"ℹ️  Index already exists, continuing...")
            else:
                raise

        # Bulk index documents
        print(f"\n📤 Generating and indexing documents...")
        batch_size = 500
        total_docs = 5000
        
        for batch_num in range(0, total_docs, batch_size):
            print(f"  Indexing batch {batch_num // batch_size + 1} (docs {batch_num} to {batch_num + batch_size})...")
            
            # Generate bulk data for this batch
            bulk_data = generate_bulk_data(batch_size)
            
            try:
                result = sdk.bulk_ingest(index_name, bulk_data)
                
                # Check for errors
                if result.get("errors"):
                    print(f"  ⚠️  Some operations failed:")
                    failed = 0
                    for item in result.get("items", []):
                        for action, details in item.items():
                            if details.get("status", 200) >= 400:
                                failed += 1
                                if failed <= 3:  # Show first 3 errors
                                    print(f"    - {action} failed for doc {details.get('_id')}: {details.get('error')}")
                    print(f"  Total failed: {failed}")
                else:
                    print(f"  ✅ Batch indexed successfully")
                    
            except InfinoError as e:
                print(f"  ❌ Bulk indexing failed: {e.message}")
                continue
        
        # Verify indexing
        print(f"\n🔍 Verifying indexed documents...")
        time.sleep(1)  # Wait for refresh
        
        count_result = sdk.count(index_name)
        total_count = count_result.get("count", 0)
        print(f"✅ Total documents indexed: {total_count}")
        
        # Sample query to verify data
        print(f"\n📊 Sample query results:")
        query = '{"query": {"match_all": {}}, "size": 3}'
        results = sdk.search(index_name, query)
        
        for hit in results.get("hits", {}).get("hits", []):
            source = hit["_source"]
            print(f"  - {source['name']} (${source['price']}) - {source['category']}")

        # Bulk update example
        print(f"\n🔄 Bulk update example...")
        update_data = '''
{"update": {"_id": "0"}}
{"doc": {"price": 99.99, "featured": true}}
{"update": {"_id": "1"}}
{"doc": {"price": 149.99, "featured": true}}
{"update": {"_id": "2"}}
{"doc": {"price": 199.99, "featured": true}}
'''
        
        result = sdk.bulk_ingest(index_name, update_data)
        print(f"✅ Updated {len(result.get('items', []))} documents")
        
        # Bulk delete example
        print(f"\n🗑️  Bulk delete example...")
        delete_data = '''
{"delete": {"_id": "4999"}}
{"delete": {"_id": "4998"}}
'''
        
        result = sdk.bulk_ingest(index_name, delete_data)
        print(f"✅ Deleted {len(result.get('items', []))} documents")


if __name__ == "__main__":
    main()
