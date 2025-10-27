"""
PromQL Metrics Example for Infino SDK

This example demonstrates how to:
1. Ingest metrics data in Prometheus format
2. Query metrics using PromQL
3. Perform range queries for time-series data
4. Work with metric labels and aggregations
"""

import time
from infino_sdk import InfinoSDK


def main():
    # Initialize SDK with credentials
    # Note: You need to create an account manually at app.infino.ws
    access_key = "your_access_key_here"
    secret_key = "your_secret_key_here"
    endpoint = "https://api.infino.ws"
    
    try:
        sdk = InfinoSDK(access_key, secret_key, endpoint)
        
        # Create a dataset for metrics (suffix .aly for analytics)
        dataset_name = "metrics_example.aly"
        print(f"Creating dataset: {dataset_name}")
        sdk.create_finodb_dataset(dataset_name)
        
        # Ingest metrics in Prometheus exposition format
        # Format: metric_name{label1="value1",label2="value2"} value timestamp
        now = int(time.time() * 1000)  # Current timestamp in milliseconds
        
        metrics_data = f"""cpu_usage{{host="server1",env="production",region="us-east"}} 75.5 {now}
memory_usage{{host="server1",env="production",region="us-east"}} 85.2 {now + 60000}
cpu_usage{{host="server2",env="production",region="us-west"}} 45.3 {now + 120000}
memory_usage{{host="server2",env="production",region="us-west"}} 62.8 {now + 180000}
cpu_usage{{host="server1",env="production",region="us-east"}} 80.1 {now + 240000}
memory_usage{{host="server1",env="production",region="us-east"}} 88.5 {now + 300000}
"""
        
        print("Uploading metrics data...")
        result = sdk.upload_finodb_metrics(dataset_name, metrics_data)
        print(f"Metrics ingested: {result}")
        
        # Wait a moment for indexing
        time.sleep(2)
        
        # Example 1: Simple PromQL instant query
        print("\n=== Example 1: Instant Query ===")
        promql_query = 'cpu_usage{host="server1"}'
        instant_result = sdk.query_finodb_promql(promql_query, dataset_name)
        print(f"Query: {promql_query}")
        print(f"Result: {instant_result}")
        
        # Example 2: PromQL range query
        print("\n=== Example 2: Range Query ===")
        start_time = now - 60000  # 1 minute before first metric
        end_time = now + 360000   # 6 minutes after first metric
        step = 60  # 60 second step
        
        range_result = sdk.query_finodb_promql_range(
            promql_query,
            start_time,
            end_time,
            step,
            dataset_name
        )
        print(f"Query: {promql_query}")
        print(f"Start: {start_time}, End: {end_time}, Step: {step}s")
        print(f"Result: {range_result}")
        
        # Example 3: PromQL with label selector
        print("\n=== Example 3: Label Selector ===")
        label_query = 'cpu_usage{env="production",region="us-east"}'
        label_result = sdk.prom_ql_query(label_query, index_name)
        print(f"Query: {label_query}")
        print(f"Result: {label_result}")
        
        # Example 4: PromQL aggregation
        print("\n=== Example 4: Aggregation ===")
        agg_query = 'avg(cpu_usage)'
        agg_result = sdk.prom_ql_query(agg_query, index_name)
        print(f"Query: {agg_query}")
        print(f"Result: {agg_result}")
        
        # Example 5: PromQL aggregation by label
        print("\n=== Example 5: Aggregation by Label ===")
        agg_by_label = 'avg(cpu_usage) by (host)'
        agg_by_result = sdk.prom_ql_query(agg_by_label, index_name)
        print(f"Query: {agg_by_label}")
        print(f"Result: {agg_by_result}")
        
        # Example 6: PromQL rate calculation
        print("\n=== Example 6: Rate Calculation ===")
        rate_query = 'rate(cpu_usage[5m])'
        rate_result = sdk.prom_ql_query_range(
            rate_query,
            start_time,
            end_time,
            step,
            index_name
        )
        print(f"Query: {rate_query}")
        print(f"Result: {rate_result}")
        
        # Example 7: Multiple metrics comparison
        print("\n=== Example 7: Multiple Metrics ===")
        multi_query = '{__name__=~"cpu_usage|memory_usage",host="server1"}'
        multi_result = sdk.prom_ql_query(multi_query, index_name)
        print(f"Query: {multi_query}")
        print(f"Result: {multi_result}")
        
        # Example 8: PromQL with arithmetic operations
        print("\n=== Example 8: Arithmetic Operations ===")
        arith_query = 'cpu_usage{host="server1"} * 2'
        arith_result = sdk.prom_ql_query(arith_query, index_name)
        print(f"Query: {arith_query}")
        print(f"Result: {arith_result}")
        
        # Cleanup
        print(f"\nCleaning up: Deleting dataset {dataset_name}")
        sdk.delete_finodb_dataset(dataset_name)
        print("Example completed successfully!")
        
    except Exception as e:
        print(f"Error: {e}")
        raise


if __name__ == "__main__":
    main()
