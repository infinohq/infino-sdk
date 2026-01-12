#!/usr/bin/env python3
"""
Super simple SDK init + ping test.
"""

import logging
import os

from infino_sdk import InfinoError, InfinoSDK

# Enable debug logging
logging.basicConfig(level=logging.DEBUG, format="%(levelname)s - %(message)s")

print("=== INFINO SDK DEBUG ===\n")

# 1. Get creds
access_key = os.environ.get("INFINO_ACCESS_KEY", "")
secret_key = os.environ.get("INFINO_SECRET_KEY", "")
endpoint = os.environ.get("INFINO_ENDPOINT", "")

print(
    f"ACCESS_KEY: {'SET (' + str(len(access_key)) + ' chars)' if access_key else 'NOT SET'}"
)
print(
    f"SECRET_KEY: {'SET (' + str(len(secret_key)) + ' chars)' if secret_key else 'NOT SET'}"
)
print(f"ENDPOINT: {endpoint}")
print()

# 2. Init SDK
print("--- Initializing SDK ---")

sdk = InfinoSDK(access_key, secret_key, endpoint)
print(f"SDK created. endpoint={sdk.endpoint}")
print()

# 3. Ping
print("--- Pinging endpoint ---")
try:
    response = sdk.ping()
    print(f"SUCCESS: {response}")
except InfinoError as e:
    print(f"FAILED: {e}")

# 4. Cleanup
sdk.close()
print("\nDone.")
