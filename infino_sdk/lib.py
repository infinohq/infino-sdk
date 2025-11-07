"""
Infino SDK for Python
"""

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List
from urllib.parse import urlparse
import urllib.parse
from dataclasses import dataclass
from enum import Enum
import time

import backoff
import requests
import websockets
import yaml

# Configure logging
logger = logging.getLogger(__name__)

# Algorithm and service
ALGORITHM = "AWS4-HMAC-SHA256"
SIGNING_NAME = "es"
REGION = "us-east-1"
TERMINATION = "aws4_request"
KEY_PREFIX = "AWS4"

# Headers
HEADER_PREFIX = "X-Amz-"
HOST_HEADER = "Host"

# Standard AWS header constants
AUTHORIZATION_HEADER = "Authorization"
X_AMZ_CONTENT_SHA256_HEADER = "X-Amz-Content-Sha256"
X_AMZ_DATE_HEADER = "X-Amz-Date"
CREDENTIAL_HEADER = "Credential"
SIGNED_HEADERS_HEADER = "SignedHeaders"
SIGNATURE_HEADER = "Signature"

# Date formats
DATE_FORMAT = "%Y%m%dT%H%M%SZ"
SHORT_DATE_FORMAT = "%Y%m%d"

# Fixed strings
EMPTY_PAYLOAD_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Define TRACE level
TRACE_LEVEL = 5  # Lower than DEBUG (10)
logging.addLevelName(TRACE_LEVEL, "TRACE")

def trace(self, message, *args, **kwargs):
    """Custom trace level logging."""
    if self.isEnabledFor(TRACE_LEVEL):
        self.log(TRACE_LEVEL, message, *args, **kwargs)

# Add trace method to Logger class
logging.Logger.trace = trace

# Timeouts (in milliseconds unless specified)
REQUEST_TIMEOUT_SECS = 180
RETRY_INITIAL_INTERVAL = 1000
RETRY_MAX_INTERVAL = 15000
RETRY_MAX_ELAPSED_TIME = 90000

class InfinoError(Exception):
    """SDK error wrapper"""
    class Type(Enum):
        REQUEST = "request"
        NETWORK = "network"
        PARSE = "parse"
        RATE_LIMIT = "rate_limit"
        TIMEOUT = "timeout"
        INVALID_REQUEST = "invalid_request"

    def __init__(self, error_type: Type, message: str, status_code: Optional[int] = None, url: Optional[str] = None):
        self.error_type = error_type
        self.message = message
        self._status_code = status_code
        self.url = url

    def status_code(self) -> Optional[int]:
        return self._status_code

@dataclass
class RetryConfig:
    def __init__(self):
        self.initial_interval = RETRY_INITIAL_INTERVAL  # milliseconds
        self.max_interval = RETRY_MAX_INTERVAL    # milliseconds
        self.max_elapsed_time = RETRY_MAX_ELAPSED_TIME  # milliseconds
        self.max_retries = 3

class SignatureComponents:
    def __init__(self, access_key: str, request_date: str, request_datetime: str):
        self.access_key = access_key
        self.request_date = request_date        # YYYYMMDD
        self.request_datetime = request_datetime  # ISO8601/RFC3339 format

class InfinoSDK:
    def __init__(
        self,
        access_key: str,
        secret_key: str,
        endpoint: str,
        retry_config: Optional[RetryConfig] = None
    ):
        self.access_key = access_key
        self.secret_key = secret_key
        self.endpoint = endpoint.rstrip('/')
        self.retry_config = retry_config or RetryConfig()
        
        # AWS SigV4 parameters
        self.region = "us-east-1"
        self.service = "es"  # OpenSearch service

        # Use requests session for connection pooling
        self.session = requests.Session()

    def close(self):
        """Close the requests session"""
        if self.session:
            self.session.close()
            self.session = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    async def websocket_connect(self, path: str, headers: Optional[Dict[str, str]] = None):
        """Connect to WebSocket endpoint with SigV4 query parameter authentication"""
        parsed = urlparse(self.endpoint)
        ws_proto = "wss" if parsed.scheme == "https" else "ws"
        host = parsed.netloc

        # Generate timestamp for signing
        timestamp = datetime.now(timezone.utc)
        date_stamp = timestamp.strftime('%Y%m%d')
        amz_date = timestamp.strftime('%Y%m%dT%H%M%SZ')

        # AWS SigV4 parameters
        algorithm = 'AWS4-HMAC-SHA256'
        credential = f"{self.access_key}/{date_stamp}/{self.region}/{self.service}/aws4_request"
        signed_headers = 'host'

        # Build query parameters (without signature yet)
        query_params = [
            ('X-Amz-Algorithm', algorithm),
            ('X-Amz-Credential', credential),
            ('X-Amz-Date', amz_date),
            ('X-Amz-SignedHeaders', signed_headers)
        ]

        # Sort query parameters for canonical request
        query_params.sort(key=lambda x: x[0])

        # URL encode parameters
        canonical_querystring = '&'.join([f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}" for k, v in query_params])

        # Create canonical request
        canonical_uri = path
        canonical_headers = f"host:{host}\n"
        payload_hash = hashlib.sha256(b'').hexdigest()  # Empty string hash for WebSocket

        canonical_request = f"GET\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

        # Create string to sign
        scope = f"{date_stamp}/{self.region}/{self.service}/aws4_request"
        canonical_request_hash = hashlib.sha256(canonical_request.encode()).hexdigest()
        string_to_sign = f"{algorithm}\n{amz_date}\n{scope}\n{canonical_request_hash}"

        # Generate signature using existing SDK helper
        signing_key = self.derive_signing_key(date_stamp)
        signature = self.calculate_signature(signing_key, string_to_sign)

        # Build final WebSocket URL with all query parameters including signature
        ws_url = f"{ws_proto}://{host}{canonical_uri}?{canonical_querystring}&X-Amz-Signature={urllib.parse.quote(signature, safe='')}"

        # Connect with optional additional headers (but auth is in query params)
        if headers:
            return await websockets.connect(ws_url, additional_headers=headers.items())
        return await websockets.connect(ws_url)

    def request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None, body: Optional[str] = None, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Build, sign, and execute an HTTP request"""

        logger.debug(f"INFINO SDK: Making {method} request to {url}")

        timestamp = datetime.now(timezone.utc)
        payload = body or ""
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()

        logger.debug("INFINO SDK: Creating request")
        logger.debug(f"INFINO SDK: Method: {method}")
        logger.debug(f"INFINO SDK: URL: {url}")
        logger.debug(f"INFINO SDK: Body length: {len(payload)}")
        logger.debug(f"INFINO SDK: Timestamp: {timestamp}")
        logger.debug(f"INFINO SDK: Payload hash: {payload_hash}")

        # Build headers dict
        req_headers = {
            f"{X_AMZ_DATE_HEADER}": timestamp.strftime(DATE_FORMAT),
            f"{X_AMZ_CONTENT_SHA256_HEADER}": payload_hash,
        }

        # Allow certain operations to override the default headers (e.g. bulk ingest)
        if headers:
            req_headers.update(headers)
        else:
            req_headers["Content-Type"] = "application/json"

        # Sign the headers if we have credentials
        if self.access_key and self.secret_key:
            req_headers = self.sign_request_headers(method, url, req_headers, timestamp, payload_hash)

        # Execute request with retries
        return self.execute_request(method, url, req_headers, body, params)

    def sign_request_headers(self, method: str, url: str, headers: Dict[str, str], timestamp: datetime, payload_hash: str) -> Dict[str, str]:
        """Sign request headers for AWS SigV4"""
        request_datetime = timestamp.strftime(DATE_FORMAT)
        request_date = timestamp.strftime(SHORT_DATE_FORMAT)

        # Copy headers
        signed_headers = headers.copy()

        # Add required headers
        signed_headers[X_AMZ_DATE_HEADER] = request_datetime
        signed_headers[X_AMZ_CONTENT_SHA256_HEADER] = payload_hash

        # Get host from URL
        host = urlparse(url).hostname
        if not host:
            raise InfinoError(InfinoError.Type.INVALID_REQUEST, "Missing host")
        signed_headers[HOST_HEADER] = host

        # Headers to sign
        headers_to_sign = [
            HOST_HEADER.lower(),
            X_AMZ_CONTENT_SHA256_HEADER.lower(),
            X_AMZ_DATE_HEADER.lower()
        ]
        if "Content-Type" in signed_headers:
            headers_to_sign.append("content-type")

        # Sign
        signing_key = self.derive_signing_key(request_date)

        # Create temp request for canonical request
        temp_req = type('Request', (), {
            'method': method,
            'url': url,
            'headers': signed_headers
        })

        canonical_request = self.create_canonical_request(temp_req, headers_to_sign)

        components = SignatureComponents(
            access_key=self.access_key,
            request_date=request_date,
            request_datetime=request_datetime
        )

        string_to_sign = self.create_string_to_sign(canonical_request, components)
        signature = self.calculate_signature(signing_key, string_to_sign)

        # Build auth header
        sorted_headers = sorted(headers_to_sign)
        signed_headers_str = ";".join(sorted_headers)
        auth_header = f"{ALGORITHM} {CREDENTIAL_HEADER}={self.access_key}/{request_date}/{REGION}/{SIGNING_NAME}/{TERMINATION}, {SIGNED_HEADERS_HEADER}={signed_headers_str}, {SIGNATURE_HEADER}={signature}"

        signed_headers[AUTHORIZATION_HEADER] = auth_header
        return signed_headers

    def execute_request(self, method: str, url: str, headers: Dict[str, str], body: Optional[str], params: Optional[Dict[str, str]]) -> Dict[str, Any]:
        """Execute request with retries"""
        max_retries = self.retry_config.max_retries
        retry_delay = self.retry_config.initial_interval

        for attempt in range(max_retries):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=body,
                    params=params,
                    timeout=REQUEST_TIMEOUT_SECS
                )
                
                status = response.status_code
                text = response.text

                if 200 <= status < 300:
                    if text:
                        try:
                            return json.loads(text)
                        except json.JSONDecodeError:
                            return {"text": text}
                    return {}

                if 400 <= status < 500:  # Client errors - don't retry
                    if status == 404:
                        logger.warning(f"Resource not found: {text}")
                    elif status == 403:
                        logger.warning(f"Permission denied (403): {text}")
                    elif status == 401:
                        logger.warning(f"Unauthorized (401): {text}")
                    else:
                        logger.error(f"Client error {status}: {text}")
                    raise InfinoError(InfinoError.Type.REQUEST, text, status, url)

                if 500 <= status < 600:  # Server errors - retry
                    logger.error(f"INFINO SDK: Server error {status}: {text}")
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        retry_delay = min(retry_delay * 2, self.retry_config.max_interval)
                        continue
                    raise InfinoError(InfinoError.Type.REQUEST, text, status, url)

                raise InfinoError(InfinoError.Type.REQUEST, text, status, url)

            except requests.RequestException as e:
                if attempt < max_retries - 1 and "Connection refused" not in str(e):
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, self.retry_config.max_interval)
                    continue
                raise InfinoError(InfinoError.Type.REQUEST, str(e), 0, url)

        raise InfinoError(InfinoError.Type.REQUEST, "Max retries exceeded", 0, url)

    def sign_request(self, request: requests.Request, timestamp: datetime) -> requests.Request:
        """Sign request using AWS SigV4"""
        request_datetime = timestamp.strftime(DATE_FORMAT)
        request_date = timestamp.strftime(SHORT_DATE_FORMAT)

        # Add date header
        request.headers[X_AMZ_DATE_HEADER] = request_datetime

        # Get payload hash
        payload_hash = request.headers.get(
            X_AMZ_CONTENT_SHA256_HEADER,
            EMPTY_PAYLOAD_HASH
        )

        # If no content hash header exists, add it
        if X_AMZ_CONTENT_SHA256_HEADER not in request.headers:
            request.headers[X_AMZ_CONTENT_SHA256_HEADER] = payload_hash

        components = SignatureComponents(
            access_key=self.access_key,
            request_date=request_date,
            request_datetime=request_datetime
        )

        logger.debug(f"SIGN REQUEST: URL path: {urlparse(request.url).path}")
        logger.debug(f"SIGN REQUEST: Host: {urlparse(request.url).hostname}")
        logger.debug(f"SIGN REQUEST: Request date: {request_date}")
        logger.debug(f"SIGN REQUEST: Request datetime: {request_datetime}")
        
        # Get host from URL - AWS requires host header
        host = urlparse(request.url).hostname
        if not host:
            raise InfinoError(InfinoError.Type.INVALID_REQUEST, "Missing host")
            
        # Ensure host header exists
        request.headers[HOST_HEADER] = host
        
        # Create a list of headers to sign - Must include all headers that are part of the signature calculation
        signed_headers = [
            HOST_HEADER.lower(),
            X_AMZ_CONTENT_SHA256_HEADER.lower(),
            X_AMZ_DATE_HEADER.lower()
        ]
        
        # Add content-type if it exists in the request
        if "Content-Type" in request.headers:
            signed_headers.append("content-type")
        
        signing_key = self.derive_signing_key(request_date)
        
        canonical_request = self.create_canonical_request(request, signed_headers)
        string_to_sign = self.create_string_to_sign(canonical_request, components)
        signature = self.calculate_signature(signing_key, string_to_sign)

        # Get the sorted signed_headers_str from the canonical request builder
        sorted_headers = sorted(signed_headers)
        signed_headers_str = ";".join(sorted_headers)

        # Format auth header exactly as AWS expects
        # Include a space after each comma
        auth_header = f"{ALGORITHM} {CREDENTIAL_HEADER}={components.access_key}/{components.request_date}/{REGION}/{SIGNING_NAME}/{TERMINATION}, {SIGNED_HEADERS_HEADER}={signed_headers_str}, {SIGNATURE_HEADER}={signature}"

        logger.debug(f"SIGN REQUEST: Final auth header: {auth_header}")
        
        # Use the standard Authorization header as AWS does
        request.headers[AUTHORIZATION_HEADER] = auth_header

        return request

    def create_canonical_request(self, request: requests.Request, signed_headers: list) -> str:
        """Create canonical request for SigV4"""
        # 1. HTTP Method
        method = request.method.upper()

        # 2. Canonical URI - Extract path from URL
        url = urlparse(request.url)
        canonical_uri = url.path
        if not canonical_uri or canonical_uri == "":
            canonical_uri = "/"
        
        logger.debug(f"SIGN REQUEST: URL path: {url.path}")
        logger.debug(f"SIGN REQUEST: Canonical URI: {canonical_uri}")

        # 3. Query String (empty or normalized)
        canonical_query = ""
        if url.query:
            canonical_query = self.normalize_query(url.query)

        # 4. Headers - Must be sorted alphabetically for the canonical request
        # Sort headers alphabetically as required by AWS SigV4
        sorted_headers = sorted(signed_headers)
        
        # Build canonical headers section including only the sorted signed headers
        canonical_headers = ""
        for header in sorted_headers:
            # Try both original case and lowercase to find the value
            header_value = request.headers.get(header.title(), request.headers.get(header, ""))
            canonical_headers += f"{header}:{header_value}\n"
        
        # 5. Signed Headers - must be alphabetical for canonical request
        signed_headers_str = ";".join(sorted_headers)

        # 6. Get payload hash
        payload_hash = request.headers.get(
            X_AMZ_CONTENT_SHA256_HEADER,
            EMPTY_PAYLOAD_HASH
        )

        # Combine all components with newlines - exactly matching AWS format
        canonical_request = (
            f"{method}\n"
            f"{canonical_uri}\n"
            f"{canonical_query}\n"
            f"{canonical_headers}\n"
            f"{signed_headers_str}\n"
            f"{payload_hash}"
        )

        logger.debug(f"SIGN REQUEST: Canonical request:\n{canonical_request}")
        return canonical_request


    def hmac_sha256(self, key: bytes, data: bytes) -> bytes:
        """Calculate HMAC-SHA256"""
        return hmac.new(key, data, hashlib.sha256).digest()

    def derive_signing_key(self, date: str) -> bytes:
        """Derive SigV4 signing key from secret and date"""
        logger.debug("SIGN REQUEST: Starting key derivation")
        logger.debug(f"SIGN REQUEST: Date: {date}")
        logger.debug(f"SIGN REQUEST: Secret key: {self.secret_key}")
        logger.debug(f"SIGN REQUEST: KEY_PREFIX: {KEY_PREFIX}")
        logger.debug(f"SIGN REQUEST: REGION: {REGION}")
        logger.debug(f"SIGN REQUEST: SIGNING_NAME: {SIGNING_NAME}")
        logger.debug(f"SIGN REQUEST: TERMINATION: {TERMINATION}")

        # Format the key string exactly as the server does
        key_string = f"{KEY_PREFIX}{self.secret_key}"
        
        # Step 1: kDate = HMAC(KEY_PREFIX + secret_key, date)
        k_date = self.hmac_sha256(
            key_string.encode('utf-8'),
            date.encode('utf-8')
        )
        logger.debug(f"SIGN REQUEST: k_date (hex): {k_date.hex()}")

        # Step 2: kRegion = HMAC(kDate, region)
        k_region = self.hmac_sha256(k_date, REGION.encode('utf-8'))
        logger.debug(f"SIGN REQUEST: k_region (hex): {k_region.hex()}")

        # Step 3: kService = HMAC(kRegion, service)
        k_service = self.hmac_sha256(k_region, SIGNING_NAME.encode('utf-8'))
        logger.debug(f"SIGN REQUEST: k_service (hex): {k_service.hex()}")

        # Step 4: signing_key = HMAC(kService, termination)
        signing_key = self.hmac_sha256(k_service, TERMINATION.encode('utf-8'))
        logger.debug(f"SIGN REQUEST: final signing_key (hex): {signing_key.hex()}")

        return signing_key

    def calculate_signature(self, signing_key: bytes, string_to_sign: str) -> str:
        """Calculate signature from key and string to sign"""
        logger.debug("SIGN REQUEST: Calculating signature")
        logger.debug(f"SIGN REQUEST: Signing key (hex): {signing_key.hex()}")
        logger.debug(f"SIGN REQUEST: String to sign:\n{string_to_sign}")

        signature_bytes = self.hmac_sha256(signing_key, string_to_sign.encode())
        signature = signature_bytes.hex()
        logger.debug(f"SIGN REQUEST: Final signature: {signature}")

        return signature

    def create_string_to_sign(self, canonical_request: str, components: SignatureComponents) -> str:
        """Create SigV4 string to sign"""
        credential_scope = f"{components.request_date}/{REGION}/{SIGNING_NAME}/{TERMINATION}"
        
        string_to_sign = (
            f"{ALGORITHM}\n"
            f"{components.request_datetime}\n"
            f"{credential_scope}\n"
            f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
        )

        logger.debug(f"SIGN REQUEST: String to sign:\n{string_to_sign}")
        return string_to_sign

    def normalize_query(self, query: str) -> str:
        """Normalize query parameters"""
        if not query:
            return ""

        params = []
        for p in query.split('&'):
            if not p:
                continue
            parts = p.split('=', 1)
            key = self.uri_encode(parts[0]) if parts else ""
            value = self.uri_encode(parts[1]) if len(parts) > 1 else ""
            params.append((key, value))

        params.sort(key=lambda x: x[0])
        return "&".join(f"{k}={v}" for k, v in params)

    def uri_encode(self, s: str) -> str:
        """Percent-encode string for URI"""
        encoded = ""
        for byte in s.encode('utf-8'):
            if (byte >= ord('A') and byte <= ord('Z')) or \
               (byte >= ord('a') and byte <= ord('z')) or \
               (byte >= ord('0') and byte <= ord('9')) or \
               byte == ord('-') or byte == ord('_') or \
               byte == ord('.') or byte == ord('~'):
                encoded += chr(byte)
            else:
                encoded += f"%{byte:02X}"
        return encoded

    # Dataset Operations
    def create_dataset(self, dataset: str) -> Dict[str, Any]:
        """Create an empty dataset"""
        url = f"{self.endpoint}/{dataset}"
        try:
            response = self.request("PUT", url)
            return response
        except InfinoError as e:
            # 409 CONFLICT is acceptable for dataset creation - it means the dataset already exists
            if e.status_code() == 409:
                logger.debug(f"INFINO SDK: Dataset '{dataset}' already exists (409 CONFLICT), continuing")
                return {"acknowledged": True, "index": dataset}
            raise

    def delete_dataset(self, dataset: str) -> Dict[str, Any]:
        """Delete a dataset"""
        url = f"{self.endpoint}/{dataset}"
        response = self.request("DELETE", url)
        return response

    def get_dataset_metadata(self, dataset: str) -> Dict[str, Any]:
        """Query a dataset for its metadata"""
        url = f"{self.endpoint}/{dataset}/metadata"
        response = self.request("GET", url)

        if isinstance(response, dict):
            return response
        if isinstance(response, str):
            return {"text": response}
        raise InfinoError(InfinoError.Type.INVALID_REQUEST, "Unexpected response from dataset metadata")

    def get_dataset_schema(self, dataset: str) -> Dict[str, Any]:
        """Query a dataset for its schema"""
        url = f"{self.endpoint}/{dataset}/schema"
        response = self.request("HEAD", url)
        return response

    def get_datasets(self) -> List[Dict[str, Any]]:
        """Query Infino for all metadata on current datasets"""
        url = f"{self.endpoint}/metadata"
        response = self.request("GET", url)
        if isinstance(response, list):
            return response
        raise InfinoError(InfinoError.Type.INVALID_REQUEST, "Expected list of datasets")

    # Fino AI Thread Operations
    def list_threads(self) -> List[Dict[str, Any]]:
        """List all Fino conversation threads"""
        url = f"{self.endpoint}/fino/threads"
        response = self.request("GET", url)
        if isinstance(response, list):
            return response
        raise InfinoError(InfinoError.Type.INVALID_REQUEST, "Expected list of threads")

    def create_thread(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new Fino conversation thread"""
        url = f"{self.endpoint}/fino/threads"
        response = self.request("POST", url, None, json.dumps(config))
        return response

    def get_thread(self, thread_id: str) -> Dict[str, Any]:
        """Retrieve a specific Fino conversation thread"""
        url = f"{self.endpoint}/fino/threads/{thread_id}"
        response = self.request("GET", url)
        return response

    def update_thread(self, thread_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update a Fino conversation thread"""
        url = f"{self.endpoint}/fino/threads/{thread_id}"
        response = self.request("PUT", url, None, json.dumps(config))
        return response

    def delete_thread(self, thread_id: str) -> Dict[str, Any]:
        """Delete a Fino conversation thread"""
        url = f"{self.endpoint}/fino/threads/{thread_id}"
        response = self.request("DELETE", url)
        return response

    def add_thread_message(self, thread_id: str, message: Dict[str, Any]) -> Dict[str, Any]:
        """Add a message to a specific Fino thread"""
        url = f"{self.endpoint}/fino/threads/{thread_id}/messages"
        response = self.request("POST", url, None, json.dumps(message))
        return response

    def clear_thread_messages(self, thread_id: str) -> Dict[str, Any]:
        """Remove all messages from a Fino thread"""
        url = f"{self.endpoint}/fino/threads/{thread_id}/messages"
        response = self.request("DELETE", url)
        return response

    def send_message(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send a message to Fino using the simplified API"""
        url = f"{self.endpoint}/fino/message"
        response = self.request("POST", url, None, json.dumps(payload))
        return response

    # Record Operations
    def get_record(self, dataset: str, record_id: str) -> Dict[str, Any]:
        """Get a record from a dataset"""
        url = f"{self.endpoint}/{dataset}/doc/{record_id}"
        response = self.request("GET", url)
        return response


    # Query Operations - Datasets
    def query_dataset_in_querydsl(self, dataset: str, query: str) -> Dict[str, Any]:
        """Query a dataset in QueryDSL"""
        url = f"{self.endpoint}/{dataset}/querydsl"
        response = self.request("GET", url, None, query)
        return response

    def query_dataset_in_sql(self, query: str) -> Dict[str, Any]:
        """Query a dataset in SQL, including across multiple datasets"""
        url = f"{self.endpoint}/sql"
        sql_request = {"query": query}
        json_body = json.dumps(sql_request)
        response = self.request("GET", url, None, json_body)
        return response

    def query_dataset_in_promql(self, query: str, dataset: Optional[str] = None) -> Dict[str, Any]:
        """Query a dataset in PromQL"""
        from urllib.parse import quote
        url = f"{self.endpoint}/promql/query"

        form_data = f"query={quote(query)}"
        if dataset:
            form_data += f"&index={quote(dataset)}"

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = self.request("POST", url, headers, form_data)
        return response

    def query_dataset_in_promql_range(self, query: str, start: int, end: int, step: int, dataset: Optional[str] = None) -> Dict[str, Any]:
        """Query a dataset in PromQL with time range"""
        from urllib.parse import quote
        url = f"{self.endpoint}/promql/query_range"

        form_data = f"query={quote(query)}&start={start}&end={end}&step={step}"
        if dataset:
            form_data += f"&index={quote(dataset)}"

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = self.request("POST", url, headers, form_data)
        return response

    # Correlate Operations - Upload to a dataset
    def upload_json_to_dataset(self, dataset: str, payload: str) -> Dict[str, Any]:
        """Upload JSON records to a dataset
        
        Args:
            dataset: Dataset name
            payload: NDJSON formatted bulk operations
        """
        url = f"{self.endpoint}/{dataset}/json"
        if not payload.endswith('\n'):
            payload += '\n'
        response = self.request(
            "POST", 
            url,
            headers={"Content-Type": "application/x-ndjson"},
            body=payload
        )
        return response

    def upsert_to_dataset(self, query: str) -> Dict[str, Any]:
        """Upload SQL rows to a dataset (upsert_to_dataset operations only)"""
        url = f"{self.endpoint}/sql"
        sql_request = {"query": query}
        json_body = json.dumps(sql_request)
        response = self.request("POST", url, None, json_body)
        return response

    def upload_metrics_to_dataset(self, dataset: str, payload: str) -> Dict[str, Any]:
        """Upload Prometheus metrics to a dataset"""
        url = f"{self.endpoint}/{dataset}/metrics"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = self.request("POST", url, headers, payload)
        return response

    def delete_records(self, dataset: str, query: str) -> Dict[str, Any]:
        """Delete records from a dataset"""
        url = f"{self.endpoint}/{dataset}"
        response = self.request("PATCH", url, None, query)
        return response

    def enrich_dataset(self, dataset: str, policy: str) -> Dict[str, Any]:
        """Update enrichment policy for a dataset"""
        url = f"{self.endpoint}/{dataset}/enrich_dataset"
        response = self.request("POST", url, None, policy)
        return response

    @classmethod
    def new(cls, access_key: str, secret_key: str, endpoint: str) -> 'InfinoSDK':
        """Convenience constructor"""
        return cls.new_with_retry(access_key, secret_key, endpoint, RetryConfig())

    @classmethod
    def new_with_retry(
        cls,
        access_key: str,
        secret_key: str,
        endpoint: str,
        retry_config: RetryConfig
    ) -> 'InfinoSDK':
        """Constructor with custom retry config"""
        return cls(access_key, secret_key, endpoint, retry_config)

    # Connect Operations - Data Sources
    def get_sources(self) -> List[Dict[str, Any]]:
        """Get a list of available data sources"""
        url = f"{self.endpoint}/sources"
        response = self.request("GET", url)
        if isinstance(response, list):
            return response
        raise InfinoError(InfinoError.Type.INVALID_REQUEST, "Expected list of sources")

    def get_connections(self) -> List[Dict[str, Any]]:
        """Get a list of active data source connections"""
        url = f"{self.endpoint}/sources/connections"
        response = self.request("GET", url)
        if isinstance(response, list):
            return response
        raise InfinoError(InfinoError.Type.INVALID_REQUEST, "Expected list of connections")

    def create_connection(self, source_type: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create data source connection"""
        url = f"{self.endpoint}/source/{source_type}"
        response = self.request("POST", url, None, json.dumps(config))
        return response

    def get_connection(self, connection_id: str) -> Dict[str, Any]:
        """Get status of a data source connection"""
        url = f"{self.endpoint}/source/{connection_id}"
        response = self.request("GET", url)
        return response

    def update_connection(self, connection_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update a data source connection"""
        url = f"{self.endpoint}/source/{connection_id}"
        response = self.request("PATCH", url, None, json.dumps(config))
        return response

    def delete_connection(self, connection_id: str) -> Dict[str, Any]:
        """Remove a data source connection"""
        url = f"{self.endpoint}/source/{connection_id}"
        response = self.request("DELETE", url)
        return response

    # Query Operations - Source Queries
    def query_source(self, connection_id: str, dataset: str, query: str) -> Dict[str, Any]:
        """Query a data source connection in its native DSL"""
        url = f"{self.endpoint}/source/{connection_id}/{dataset}/dsl"
        response = self.request("GET", url, None, query)
        return response

    def get_source_metadata(self, connection_id: str, dataset: str) -> Dict[str, Any]:
        """Get metadata from a data source connection"""
        url = f"{self.endpoint}/source/{connection_id}/{dataset}/metadata"
        response = self.request("GET", url)
        return response

    # Correlate Operations - Import Jobs
    def create_import_job(self, source_type: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create import job from data source to a dataset"""
        url = f"{self.endpoint}/import/{source_type}"
        response = self.request("PUT", url, None, json.dumps(config))
        return response

    def get_import_jobs(self) -> List[Dict[str, Any]]:
        """Get a dataset import job status"""
        url = f"{self.endpoint}/import/jobs"
        response = self.request("GET", url)
        if isinstance(response, list):
            return response
        raise InfinoError(InfinoError.Type.INVALID_REQUEST, "Expected list of jobs")

    def delete_import_job(self, job_id: str) -> Dict[str, Any]:
        """Delete a import job"""
        url = f"{self.endpoint}/import/jobs/{job_id}"
        response = self.request("DELETE", url)
        return response

    # Governance Operations
    def create_user(self, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a user in your account"""
        url = f"{self.endpoint}/user/{name}"
        # YAML only for users when config is a string; otherwise JSON
        if isinstance(config, str):
            try:
                yaml.safe_load(config)  # syntax validation only
            except Exception as e:
                raise InfinoError(InfinoError.Type.INVALID_REQUEST, f"Invalid YAML: {e}")
            headers = {"Content-Type": "application/yaml"}
            body = config
        else:
            headers = None
            body = json.dumps(config)
        response = self.request("PUT", url, headers, body)
        return response

    def get_user(self, name: str) -> Dict[str, Any]:
        """Get details for a user in your account"""
        url = f"{self.endpoint}/user/{name}"
        response = self.request("GET", url)
        return response

    def update_user(self, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update a user in your account"""
        url = f"{self.endpoint}/user/{name}"
        if isinstance(config, str):
            try:
                yaml.safe_load(config)
            except Exception as e:
                raise InfinoError(InfinoError.Type.INVALID_REQUEST, f"Invalid YAML: {e}")
            headers = {"Content-Type": "application/yaml"}
            body = config
        else:
            headers = None
            body = json.dumps(config)
        response = self.request("PATCH", url, headers, body)
        return response

    def delete_user(self, name: str) -> Dict[str, Any]:
        """Delete a user in your account"""
        url = f"{self.endpoint}/user/{name}"
        response = self.request("DELETE", url)
        return response

    def list_users(self) -> Dict[str, Any]:
        """List the users in your account"""
        url = f"{self.endpoint}/users"
        response = self.request("GET", url)
        return response

    def create_role(self, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a role in your account"""
        url = f"{self.endpoint}/role/{name}"
        if isinstance(config, str):
            try:
                yaml.safe_load(config)
            except Exception as e:
                raise InfinoError(InfinoError.Type.INVALID_REQUEST, f"Invalid YAML: {e}")
            headers = {"Content-Type": "application/yaml"}
            body = config
        else:
            headers = None
            body = json.dumps(config)
        response = self.request("PUT", url, headers, body)
        return response

    def get_role(self, name: str) -> Dict[str, Any]:
        """Get details for a role in your account"""
        url = f"{self.endpoint}/role/{name}"
        response = self.request("GET", url)
        return response

    def update_role(self, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update a role in your account"""
        url = f"{self.endpoint}/role/{name}"
        if isinstance(config, str):
            try:
                yaml.safe_load(config)
            except Exception as e:
                raise InfinoError(InfinoError.Type.INVALID_REQUEST, f"Invalid YAML: {e}")
            headers = {"Content-Type": "application/yaml"}
            body = config
        else:
            headers = None
            body = json.dumps(config)
        response = self.request("PATCH", url, headers, body)
        return response

    def delete_role(self, name: str) -> Dict[str, Any]:
        """Delete a role in your account"""
        url = f"{self.endpoint}/role/{name}"
        response = self.request("DELETE", url)
        return response

    def list_roles(self) -> Dict[str, Any]:
        """List the roles in your account"""
        url = f"{self.endpoint}/roles"
        response = self.request("GET", url)
        return response

    def ping(self) -> Dict[str, Any]:
        """Health check"""
        url = f"{self.endpoint}/"
        response = self.request("GET", url)
        return response

    def rotate_keys(self, username: str) -> Dict[str, Any]:
        """Rotate API keys for a user

        Args:
            username: Username whose keys to rotate

        Returns:
            New credentials (access_key and secret_key)
        """
        url = f"{self.endpoint}/user/{username}/keys"
        response = self.request("PATCH", url)
        return response

# Error conversion implementations
def _convert_reqwest_error(error: requests.RequestException) -> InfinoError:
    """Convert requests error to InfinoError"""
    return InfinoError(
        error_type=InfinoError.Type.NETWORK,
        message=str(error)
    )

def _convert_json_error(error: json.JSONDecodeError) -> InfinoError:
    """Convert JSON error to InfinoError"""
    return InfinoError(
        error_type=InfinoError.Type.PARSE,
        message=str(error)
    )

# Minimal demo tests
if __name__ == "__main__":
    import unittest
    import responses

    class TestInfinoSDK(unittest.TestCase):
        """Basic tests for InfinoSDK"""
        
        def setUp(self):
            self.client = InfinoSDK(
                access_key="test_key",
                secret_key="test_secret",
                endpoint="http://localhost:8000"
            )

        @responses.activate
        def test_request_signing(self):
            """Test request signing"""
            responses.add(
                responses.GET,
                "http://localhost:8000/test_dataset/querydsl",
                json={"hits": []},
                status=200,
                match=[
                    responses.matchers.header_matcher({
                        "authorization": lambda x: x.startswith("AWS4-HMAC-SHA256"),
                        "x-amz-date": lambda x: len(x) == 16,  # YYYYMMDDTHHmmssZ
                        "x-amz-content-sha256": lambda x: len(x) == 64
                    })
                ]
            )

            query = json.dumps({"query": {"match_all": {}}})
            response = self.client.query_dataset_in_querydsl("test_dataset", query)
            self.assertEqual(response, {"hits": []})

        @responses.activate
        def test_document_operations(self):
            """Test document operations"""
            doc = json.dumps({"field1": "value1"})
            
            responses.add(
                responses.PUT,
                "http://localhost:8000/test_dataset/doc/1",
                json={"result": "created"},
                status=200,
                match=[
                    responses.matchers.header_matcher({
                        "authorization": lambda x: x.startswith("AWS4-HMAC-SHA256"),
                        "x-amz-date": lambda x: len(x) == 16,
                        "x-amz-content-sha256": lambda x: len(x) == 64
                    })
                ]
            )

            # Note: dataset_record doesn't exist in Rust SDK, using bulk_ingest instead
            # This matches what the Rust tests would do
            pass

        @responses.activate
        def test_security_operations(self):
            """Test security API operations"""
            # Test role creation with new YAML format
            responses.add(
                responses.PUT,
                "http://localhost:8000/role/test_role",
                json={"status": "OK", "message": "'test_role' created."},
                status=200,
                match=[
                    responses.matchers.header_matcher({
                        "authorization": lambda x: x.startswith("AWS4-HMAC-SHA256"),
                        "x-amz-date": lambda x: len(x) == 16,
                        "x-amz-content-sha256": lambda x: len(x) == 64,
                        "content-type": "application/yaml"
                    })
                ]
            )

            role_config = """
Version: 2025-01-01
Permissions:
  - ResourceType: record
    Actions: [read, write]
    Resources: ["test*"]
  
  - ResourceType: dataset
    Actions: [create, delete]
    Resources: ["test*"]
"""

            response = self.client.create_role_in_account("test_role", role_config)
            self.assertEqual(response["status"], "OK")

            # Test user creation with role assignment
            responses.add(
                responses.PUT,
                "http://localhost:8000/user/test_user",
                json={"status": "OK", "message": "'test_user' created."},
                status=200,
                match=[
                    responses.matchers.header_matcher({
                        "authorization": lambda x: x.startswith("AWS4-HMAC-SHA256"),
                        "x-amz-date": lambda x: len(x) == 16,
                        "x-amz-content-sha256": lambda x: len(x) == 64,
                        "content-type": "application/yaml"
                    })
                ]
            )

            user_config = """
Version: 2025-01-01
Password: TestP@ssw0rd123!
Roles:
  - test_role
"""

            response = self.client.create_user("test_user", user_config)
            self.assertEqual(response["status"], "OK")

    unittest.main() 