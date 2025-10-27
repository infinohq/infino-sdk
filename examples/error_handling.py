"""
Error Handling Best Practices with Infino SDK

This example demonstrates:
- Proper error handling patterns
- Different error types
- Retry strategies
- Graceful degradation
"""

import os
from infino_sdk import InfinoSDK, InfinoError, RetryConfig


def handle_not_found_errors(sdk: InfinoSDK):
    """Example of handling 404 Not Found errors"""
    print("\n📍 Example 1: Handling Not Found Errors")
    print("-" * 50)
    
    try:
        record = sdk.get_record("nonexistent_dataset", "missing_record")
        print(f"Record found: {record}")
    except InfinoError as e:
        if e.status_code() == 404:
            print(f"✅ Handled gracefully: Record not found")
            print(f"   Error type: {e.error_type.value}")
            print(f"   Message: {e.message}")
        else:
            print(f"❌ Unexpected error: {e.message}")


def handle_auth_errors(sdk: InfinoSDK):
    """Example of handling authentication errors"""
    print("\n🔐 Example 2: Handling Authentication Errors")
    print("-" * 50)
    
    try:
        # This will fail if credentials are invalid
        sdk.get_user_account_info()
        print("✅ Authentication successful")
    except InfinoError as e:
        if e.status_code() == 401:
            print(f"❌ Authentication failed:")
            print(f"   - Check your access_key and secret_key")
            print(f"   - Verify credentials haven't expired")
            print(f"   - Error: {e.message}")
        elif e.status_code() == 403:
            print(f"❌ Authorization failed:")
            print(f"   - You don't have permission for this operation")
            print(f"   - Contact admin to adjust your permissions")
            print(f"   - Error: {e.message}")
        else:
            print(f"❌ Unexpected error: {e.message}")


def handle_network_errors():
    """Example of handling network errors"""
    print("\n🌐 Example 3: Handling Network Errors")
    print("-" * 50)
    
    # Try to connect to invalid endpoint
    sdk = InfinoSDK(
        access_key="test",
        secret_key="test",
        endpoint="http://invalid-endpoint-that-does-not-exist.com"
    )
    try:
        sdk.ping()
        print("✅ Connection successful")
    except InfinoError as e:
        if e.error_type == InfinoError.Type.NETWORK:
            print(f"❌ Network error occurred:")
            print(f"   - Check your internet connection")
            print(f"   - Verify the endpoint URL is correct")
            print(f"   - Check if the service is up")
            print(f"   - Error: {e.message}")
        elif e.error_type == InfinoError.Type.TIMEOUT:
            print(f"❌ Request timed out:")
            print(f"   - Service may be slow or unavailable")
            print(f"   - Consider increasing timeout")
            print(f"   - Error: {e.message}")
        else:
            print(f"❌ Unexpected error: {e.message}")


def handle_validation_errors(sdk: InfinoSDK):
    """Example of handling validation/bad request errors"""
    print("\n⚠️  Example 4: Handling Validation Errors")
    print("-" * 50)
    
    try:
        # Invalid JSON query
        sdk.query_finodb_querydsl("my_dataset", "this is not valid JSON")
    except InfinoError as e:
        if e.status_code() == 400:
            print(f"❌ Bad request:")
            print(f"   - Check your query syntax")
            print(f"   - Ensure all required fields are present")
            print(f"   - Error: {e.message}")
        elif e.error_type == InfinoError.Type.PARSE:
            print(f"❌ Parse error:")
            print(f"   - Response could not be parsed")
            print(f"   - Error: {e.message}")
        else:
            print(f"❌ Unexpected error: {e.message}")


def retry_with_custom_config():
    """Example of custom retry configuration"""
    print("\n🔄 Example 5: Custom Retry Configuration")
    print("-" * 50)
    
    # Create custom retry config
    retry_config = RetryConfig()
    retry_config.initial_interval = 500  # 500ms initial delay
    retry_config.max_interval = 10000    # Max 10 seconds between retries
    retry_config.max_elapsed_time = 60000  # Give up after 60 seconds
    retry_config.max_retries = 5         # Try up to 5 times
    
    sdk = InfinoSDK(
        access_key=os.getenv("INFINO_ACCESS_KEY", "test"),
        secret_key=os.getenv("INFINO_SECRET_KEY", "test"),
        endpoint=os.getenv("INFINO_ENDPOINT", "https://api.infino.ai"),
        retry_config=retry_config
    )
    try:
        # This will automatically retry on server errors
        result = sdk.ping()
        print(f"✅ Request successful: {result}")
    except InfinoError as e:
        print(f"❌ Request failed after {retry_config.max_retries} retries:")
        print(f"   Error: {e.message}")


def graceful_degradation(sdk: InfinoSDK):
    """Example of graceful degradation"""
    print("\n🛡️  Example 6: Graceful Degradation")
    print("-" * 50)
    
    # Try primary dataset first, fallback to secondary
    primary_dataset = "products_v2"
    fallback_dataset = "products"
    query = '{"query": {"match_all": {}}, "size": 10}'
    
    try:
        print(f"Trying primary dataset: {primary_dataset}")
        results = sdk.query_finodb_querydsl(primary_dataset, query)
        print(f"✅ Retrieved {len(results.get('hits', {}).get('hits', []))} records from primary")
    except InfinoError as e:
        if e.status_code() == 404:
            print(f"⚠️  Primary dataset not found, trying fallback...")
            try:
                results = sdk.query_finodb_querydsl(fallback_dataset, query)
                print(f"✅ Retrieved {len(results.get('hits', {}).get('hits', []))} records from fallback")
            except InfinoError as fallback_error:
                print(f"❌ Both datasets failed: {fallback_error.message}")
                # Use default/cached data or return empty result
                results = {"hits": {"hits": []}}
                print(f"ℹ️  Returning empty results")
        else:
            print(f"❌ Unexpected error: {e.message}")


def batch_operations_with_error_handling(sdk: InfinoSDK):
    """Example of handling errors in batch operations"""
    print("\n📦 Example 7: Batch Operations with Error Handling")
    print("-" * 50)
    
    datasets_to_check = ["dataset1", "dataset2", "dataset3", "nonexistent"]
    successful = []
    failed = []
    
    for dataset_name in datasets_to_check:
        try:
            metadata = sdk.get_finodb_dataset_metadata(dataset_name)
            successful.append(dataset_name)
            print(f"  ✅ {dataset_name}: OK")
        except InfinoError as e:
            failed.append((dataset_name, e))
            if e.status_code() == 404:
                print(f"  ⚠️  {dataset_name}: Not Found")
            else:
                print(f"  ❌ {dataset_name}: {e.message}")
    
    print(f"\nSummary:")
    print(f"  Successful: {len(successful)}")
    print(f"  Failed: {len(failed)}")


def context_manager_error_handling():
    """Example of error handling with context managers"""
    print("\n🎯 Example 8: Context Manager Error Handling")
    print("-" * 50)
    
    try:
        sdk = InfinoSDK(
            access_key=os.getenv("INFINO_ACCESS_KEY", "test"),
            secret_key=os.getenv("INFINO_SECRET_KEY", "test"),
            endpoint=os.getenv("INFINO_ENDPOINT", "https://api.infino.ai")
        )
        # Multiple operations
        sdk.ping()
        sdk.get_all_finodb_datasets()
        print("✅ All operations completed")
    except InfinoError as e:
        print(f"❌ Operation failed: {e.message}")


def main():
    print("=" * 50)
    print("Infino SDK Error Handling Examples")
    print("=" * 50)
    
    access_key = os.getenv("INFINO_ACCESS_KEY", "your_access_key")
    secret_key = os.getenv("INFINO_SECRET_KEY", "your_secret_key")
    endpoint = os.getenv("INFINO_ENDPOINT", "https://api.infino.ai")
    
    sdk = InfinoSDK(access_key, secret_key, endpoint)
    # Run examples
    handle_not_found_errors(sdk)
    handle_auth_errors(sdk)
    handle_validation_errors(sdk)
    graceful_degradation(sdk)
    batch_operations_with_error_handling(sdk)
    
    # Examples that create their own SDK instances
    handle_network_errors()
    retry_with_custom_config()
    context_manager_error_handling()
    
    print("\n" + "=" * 50)
    print("✅ All error handling examples completed!")
    print("=" * 50)


if __name__ == "__main__":
    main()
