#!/usr/bin/env python3
"""
Example: File Upload to Infino

This example demonstrates how to upload files (JSON, JSONL, CSV) to Infino
using both synchronous and asynchronous modes.

Usage:
    # Set environment variables
    export INFINO_ACCESS_KEY="your_access_key"
    export INFINO_SECRET_KEY="your_secret_key"
    export INFINO_ENDPOINT="https://api.infino.ai"

    # Run the example
    python file_upload.py
"""
import json
import os
import sys
import tempfile
import time

from infino_sdk import InfinoSDK, InfinoError


def create_sample_files():
    """Create sample data files for testing."""
    # Sample data
    json_data = [
        {"id": 1, "name": "Alice", "department": "Engineering", "salary": 75000},
        {"id": 2, "name": "Bob", "department": "Sales", "salary": 65000},
        {"id": 3, "name": "Charlie", "department": "Engineering", "salary": 80000},
    ]

    # Create JSON file
    json_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json.dump(json_data, json_file)
    json_file.close()

    # Create JSONL file (newline-delimited JSON)
    jsonl_file = tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False)
    for record in json_data:
        jsonl_file.write(json.dumps(record) + '\n')
    jsonl_file.close()

    # Create CSV file
    csv_file = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False)
    csv_file.write("id,name,department,salary\n")
    for record in json_data:
        csv_file.write(f"{record['id']},{record['name']},{record['department']},{record['salary']}\n")
    csv_file.close()

    return json_file.name, jsonl_file.name, csv_file.name


def sync_upload_example(sdk: InfinoSDK, file_path: str, dataset: str, format: str):
    """Example: Synchronous file upload (waits for completion)."""
    print(f"\n{'='*60}")
    print(f"Sync Upload Example - {format.upper()} file")
    print(f"{'='*60}")

    try:
        print(f"Uploading {os.path.basename(file_path)} to dataset '{dataset}'...")

        result = sdk.upload_file(
            dataset=dataset,
            file_path=file_path,
            format=format,
            async_mode=False  # Wait for completion (default)
        )

        print(f"Status: {result['status']}")
        print(f"Message: {result.get('message', 'N/A')}")

        if result.get('stats'):
            stats = result['stats']
            print(f"Documents processed: {stats.get('documents_processed', 'N/A')}")
            print(f"Documents failed: {stats.get('documents_failed', 'N/A')}")
            if stats.get('duration_ms'):
                print(f"Duration: {stats['duration_ms']}ms")
            if stats.get('avg_throughput_docs_per_sec'):
                print(f"Throughput: {stats['avg_throughput_docs_per_sec']:.1f} docs/sec")

        if result.get('errors'):
            print(f"Errors: {result['errors']}")

        return True

    except InfinoError as e:
        print(f"Upload failed: {e.message}")
        if e.status_code():
            print(f"Status code: {e.status_code()}")
        return False


def async_upload_example(sdk: InfinoSDK, file_path: str, dataset: str):
    """Example: Asynchronous file upload with polling."""
    print(f"\n{'='*60}")
    print("Async Upload Example - Submit and Poll")
    print(f"{'='*60}")

    try:
        print(f"Submitting {os.path.basename(file_path)} for async processing...")

        # Submit file for async processing
        result = sdk.upload_file(
            dataset=dataset,
            file_path=file_path,
            format="auto",  # Auto-detect format
            async_mode=True  # Return immediately with job ID
        )

        run_id = result['run_id']
        print(f"Job submitted! Run ID: {run_id}")
        print(f"Initial status: {result['status']}")

        # Poll for completion
        print("\nPolling for job completion...")
        max_polls = 30
        poll_interval = 2  # seconds

        for i in range(max_polls):
            status = sdk.get_connector_job_status(run_id)
            current_status = status.get('status', 'unknown')

            print(f"  Poll {i+1}: Status = {current_status}")

            if current_status == 'completed':
                print("\nJob completed successfully!")
                if status.get('stats'):
                    stats = status['stats']
                    print(f"Documents processed: {stats.get('documents_processed', 'N/A')}")
                    print(f"Documents failed: {stats.get('documents_failed', 'N/A')}")
                return True

            elif current_status == 'failed':
                print(f"\nJob failed!")
                if status.get('errors'):
                    print(f"Errors: {status['errors']}")
                return False

            time.sleep(poll_interval)

        print("\nTimeout waiting for job completion")
        return False

    except InfinoError as e:
        print(f"Upload failed: {e.message}")
        return False


def main():
    """Main function demonstrating file upload functionality."""
    # Configuration - use environment variables or replace with your credentials
    ACCESS_KEY = os.environ.get("INFINO_ACCESS_KEY", "your_access_key")
    SECRET_KEY = os.environ.get("INFINO_SECRET_KEY", "your_secret_key")
    ENDPOINT = os.environ.get("INFINO_ENDPOINT", "https://api.infino.ai")
    DATASET = "file_upload_example"

    # Check for credentials
    if ACCESS_KEY == "your_access_key":
        print("Please set INFINO_ACCESS_KEY and INFINO_SECRET_KEY environment variables")
        print("Or update the credentials in this script")
        print("\nExample:")
        print("  export INFINO_ACCESS_KEY='your_key'")
        print("  export INFINO_SECRET_KEY='your_secret'")
        print("  export INFINO_ENDPOINT='https://api.infino.ai'")
        sys.exit(1)

    print(f"Connecting to Infino at {ENDPOINT}")
    print(f"Using dataset: {DATASET}")

    # Initialize SDK
    sdk = InfinoSDK(ACCESS_KEY, SECRET_KEY, ENDPOINT)

    try:
        # Create sample data files
        print("\nCreating sample data files...")
        json_file, jsonl_file, csv_file = create_sample_files()
        print(f"  JSON file: {json_file}")
        print(f"  JSONL file: {jsonl_file}")
        print(f"  CSV file: {csv_file}")

        # Create dataset (will succeed even if it already exists)
        print(f"\nCreating dataset '{DATASET}'...")
        try:
            sdk.create_dataset(DATASET)
            print("Dataset created successfully")
        except InfinoError as e:
            if e.status_code() == 409:
                print("Dataset already exists, continuing...")
            else:
                raise

        # Example 1: Sync JSON upload
        sync_upload_example(sdk, json_file, DATASET, "json")

        # Example 2: Sync CSV upload
        sync_upload_example(sdk, csv_file, DATASET, "csv")

        # Example 3: Sync JSONL upload
        sync_upload_example(sdk, jsonl_file, DATASET, "jsonl")

        # Example 4: Async upload with polling
        async_upload_example(sdk, json_file, DATASET)

        # Cleanup temp files
        print("\nCleaning up temporary files...")
        os.unlink(json_file)
        os.unlink(jsonl_file)
        os.unlink(csv_file)

        print(f"\n{'='*60}")
        print("All examples completed!")
        print(f"{'='*60}")

    except InfinoError as e:
        print(f"\nError: {e.message}")
        if e.status_code():
            print(f"Status code: {e.status_code()}")
        sys.exit(1)

    finally:
        sdk.close()


if __name__ == "__main__":
    main()
