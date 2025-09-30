import base64
import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union, List
from urllib.parse import urlparse
import urllib.parse
from dataclasses import dataclass
from enum import Enum

import asyncio
import backoff
import aiohttp
import requests  # Still needed for type hints in legacy methods
import websockets

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

async def trace(self, message, *args, **kwargs):
    """Custom trace level logging."""
    if self.isEnabledFor(TRACE_LEVEL):
        self.log(TRACE_LEVEL, message, *args, **kwargs)

# Add trace method to Logger class
logging.Logger.trace = trace

# Timeouts
REQUEST_TIMEOUT_SECS = 180  # 180 seconds
RETRY_INITIAL_INTERVAL = 1000  # milliseconds
RETRY_MAX_INTERVAL = 15000  # milliseconds
RETRY_MAX_ELAPSED_TIME = 90000  # milliseconds

class InfinoError(Exception):
    """Exception raised for Infino SDK errors"""
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
        self.max_retries = 3  # Default max retries

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

        # Will create aiohttp session in async context
        self.session = None

    async def _ensure_session(self):
        """Ensure aiohttp session exists"""
        if self.session is None:
            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECS)
            connector = aiohttp.TCPConnector(limit=100, limit_per_host=100)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector
            )

    async def close(self):
        """Close the aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None

    async def __aenter__(self):
        await self._ensure_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

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

    async def request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None, body: Optional[str] = None, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Execute an HTTP request with AWS SigV4 authentication"""
        await self._ensure_session()

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
        return await self.execute_request_async(method, url, req_headers, body, params)

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

    async def execute_request_async(self, method: str, url: str, headers: Dict[str, str], body: Optional[str], params: Optional[Dict[str, str]]) -> Dict[str, Any]:
        """Execute async request with retries"""
        max_retries = self.retry_config.max_retries
        retry_delay = self.retry_config.initial_interval

        for attempt in range(max_retries):
            try:
                async with self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=body,
                    params=params
                ) as response:
                    status = response.status
                    text = await response.text()

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
                            await asyncio.sleep(retry_delay)
                            retry_delay = min(retry_delay * 2, self.retry_config.max_interval)
                            continue
                        raise InfinoError(InfinoError.Type.REQUEST, text, status, url)

                    raise InfinoError(InfinoError.Type.REQUEST, text, status, url)

            except aiohttp.ClientError as e:
                if attempt < max_retries - 1 and "Connection refused" not in str(e):
                    await asyncio.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, self.retry_config.max_interval)
                    continue
                raise InfinoError(InfinoError.Type.REQUEST, str(e), 0, url)

        raise InfinoError(InfinoError.Type.REQUEST, "Max retries exceeded", 0, url)

    def sign_request(self, request: requests.Request, timestamp: datetime) -> requests.Request:
        """Sign an HTTP request using AWS SigV4"""
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

        # Format auth header as AWS expects
        # Include a space after each comma
        auth_header = f"{ALGORITHM} {CREDENTIAL_HEADER}={components.access_key}/{components.request_date}/{REGION}/{SIGNING_NAME}/{TERMINATION}, {SIGNED_HEADERS_HEADER}={signed_headers_str}, {SIGNATURE_HEADER}={signature}"

        logger.debug(f"SIGN REQUEST: Final auth header: {auth_header}")
        
        # Use the standard Authorization header as AWS does
        request.headers[AUTHORIZATION_HEADER] = auth_header

        return request

    def create_canonical_request(self, request: requests.Request, signed_headers: list) -> str:
        """Create canonical request for AWS SigV4 signing"""
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
        # Sort headers alphabetically per AWS SigV4 spec
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

        # Combine all components with newlines per AWS format
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

    def execute_request(self, request: requests.Request) -> requests.Response:
        """Execute HTTP request with retry logic"""
        @backoff.on_exception(
            backoff.expo,
            (requests.exceptions.RequestException, InfinoError),
            max_tries=None,  # Unlimited retries
            max_value=self.retry_config.max_interval,
            base=self.retry_config.initial_interval,
            giveup=lambda e: (
                isinstance(e, InfinoError) and 400 <= e.status_code() < 500 or  # Don't retry any 4xx
                isinstance(e, requests.exceptions.RequestException) and 
                (400 <= getattr(e.response, 'status_code', 0) < 500) or  # Don't retry 4xx errors
                "Connection refused" in str(e)
            )
        )
        async def do_request():
            response = self.session.send(request.prepare())
            status = response.status_code

            if response.ok:
                return response

            if 400 <= status < 500:  # All 4xx errors
                message = response.text
                if status == 404:
                    logger.warning(f"Resource not found: {message}")
                elif status == 403:
                    logger.warning(f"Permission denied (403): {message}")
                elif status == 401:
                    logger.warning(f"Unauthorized (401): {message}")
                else:
                    logger.error(f"Client error {status}: {message}")
                raise InfinoError(InfinoError.Type.REQUEST, message, status, request.url)

            if 500 <= status < 600:
                message = response.text
                logger.error(f"INFINO SDK: Server error {status}: {message}")
                raise InfinoError(InfinoError.Type.REQUEST, message, status, request.url)

            message = response.text
            raise InfinoError(InfinoError.Type.REQUEST, message, status, request.url)

        return do_request()

    def hmac_sha256(self, key: bytes, data: bytes) -> bytes:
        """Compute HMAC-SHA256 signature"""
        return hmac.new(key, data, hashlib.sha256).digest()

    def derive_signing_key(self, date: str) -> bytes:
        """Derive AWS SigV4 signing key"""
        logger.debug("SIGN REQUEST: Starting key derivation")
        logger.debug(f"SIGN REQUEST: Date: {date}")
        logger.debug(f"SIGN REQUEST: Secret key: {self.secret_key}")
        logger.debug(f"SIGN REQUEST: KEY_PREFIX: {KEY_PREFIX}")
        logger.debug(f"SIGN REQUEST: REGION: {REGION}")
        logger.debug(f"SIGN REQUEST: SIGNING_NAME: {SIGNING_NAME}")
        logger.debug(f"SIGN REQUEST: TERMINATION: {TERMINATION}")

        # Format the key string for HMAC signing
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
        """Calculate request signature"""
        logger.debug("SIGN REQUEST: Calculating signature")
        logger.debug(f"SIGN REQUEST: Signing key (hex): {signing_key.hex()}")
        logger.debug(f"SIGN REQUEST: String to sign:\n{string_to_sign}")

        signature_bytes = self.hmac_sha256(signing_key, string_to_sign.encode())
        signature = signature_bytes.hex()
        logger.debug(f"SIGN REQUEST: Final signature: {signature}")

        return signature

    def create_string_to_sign(self, canonical_request: str, components: SignatureComponents) -> str:
        """Create string to sign for AWS SigV4"""
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
        """Normalize query string parameters"""
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
        """URI encode string for AWS SigV4"""
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

    # Index Operations
    async def create_index(self, index: str) -> Dict[str, Any]:
        """Create a new index"""
        url = f"{self.endpoint}/{index}"
        try:
            response = await self.request("PUT", url)
            return response
        except InfinoError as e:
            # 409 CONFLICT is acceptable for index creation - it means the index already exists
            if e.status_code() == 409:
                logger.debug(f"INFINO SDK: Index '{index}' already exists (409 CONFLICT), continuing")
                return {"acknowledged": True, "index": index}
            raise

    async def create_index_with_mapping(self, index: str, mapping: Dict[str, Any]) -> Dict[str, Any]:
        """Create index with custom mapping"""
        url = f"{self.endpoint}/{index}"
        try:
            response = await self.request("PUT", url, None, json.dumps(mapping))
            return response
        except InfinoError as e:
            # 409 CONFLICT is acceptable for index creation - it means the index already exists
            if e.status_code() == 409:
                logger.debug(f"INFINO SDK: Index '{index}' already exists (409 CONFLICT), continuing")
                return {"acknowledged": True, "index": index}
            raise

    async def delete_index(self, index: str) -> Dict[str, Any]:
        """Delete an index"""
        url = f"{self.endpoint}/{index}"
        response = await self.request("DELETE", url)
        return response

    async def get_index(self, index: str) -> Dict[str, Any]:
        """Get index information"""
        url = f"{self.endpoint}/{index}"
        response = await self.request("GET", url)
        return response


    async def get_index_settings(self, index: str) -> Dict[str, Any]:
        """Get index settings"""
        url = f"{self.endpoint}/{index}/_settings"
        response = await self.request("GET", url)
        return response

    # Document Operations
    async def get_document(self, index: str, id: str) -> Dict[str, Any]:
        """Get a document by ID"""
        url = f"{self.endpoint}/{index}/doc/{id}"
        response = await self.request("GET", url)
        return response


    # Search Operations
    async def search(self, index: str, query: str) -> Dict[str, Any]:
        """Execute a search query"""
        url = f"{self.endpoint}/{index}/_search"
        response = await self.request("GET", url, None, query)
        return response

    async def search_ai(self, index: str, query_text: str) -> Dict[str, Any]:
        """Execute an AI-powered search"""
        url = f"{self.endpoint}/{index}/_search_ai"
        body = f'"{query_text}"'
        response = await self.request("GET", url, None, body)
        return response

    async def msearch(self, queries: str) -> Dict[str, Any]:
        """Execute multiple search queries"""
        url = f"{self.endpoint}/_msearch"
        response = await self.request("POST", url, None, queries)
        return response

    async def msearch_index(self, index: str, queries: str) -> Dict[str, Any]:
        """Execute multiple searches on an index"""
        url = f"{self.endpoint}/{index}/_msearch"
        response = await self.request("POST", url, None, queries)
        return response

    async def sql(self, query: str) -> Dict[str, Any]:
        """Execute SQL query"""
        url = f"{self.endpoint}/_sql"
        sql_request = {"query": query}
        json_body = json.dumps(sql_request)
        response = await self.request("POST", url, None, json_body)
        return response

    # Alias for sql method to match test expectations
    async def sql_query(self, query: str) -> Dict[str, Any]:
        """Execute SQL query"""
        return await self.sql(query)

    # Bulk Operations
    async def bulk_ingest(self, index: str, payload: str) -> Dict[str, Any]:
        """Bulk ingest documents into an index
        
        Args:
            index: Index name
            payload: NDJSON formatted bulk operations, where each line is a valid JSON object
                    and operations are paired (action + source)
        """
        url = f"{self.endpoint}/{index}/_bulk"
        # Add newline at end as required by bulk API
        if not payload.endswith('\n'):
            payload += '\n'
        response = await self.request(
            "POST", 
            url,
            headers={"Content-Type": "application/x-ndjson"},
            body=payload
        )
        return response

    async def metrics(self, index: str, payload: str) -> Dict[str, Any]:
        """Ingest metrics data"""
        url = f"{self.endpoint}/{index}/_metrics"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = await self.request("POST", url, headers, payload)
        return response

    # Metrics/Prometheus API
    async def prom_ql_query(self, query: str, index: Optional[str] = None) -> Dict[str, Any]:
        """Execute PromQL query"""
        from urllib.parse import quote
        url = f"{self.endpoint}/api/v1/query"

        form_data = f"query={quote(query)}"
        if index:
            form_data += f"&index={quote(index)}"

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = await self.request("POST", url, headers, form_data)
        return response

    async def prom_ql_query_range(self, query: str, start: int, end: int, step: int, index: Optional[str] = None) -> Dict[str, Any]:
        """Execute PromQL range query"""
        from urllib.parse import quote
        url = f"{self.endpoint}/api/v1/query_range"

        form_data = f"query={quote(query)}&start={start}&end={end}&step={step}"
        if index:
            form_data += f"&index={quote(index)}"

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = await self.request("POST", url, headers, form_data)
        return response

    async def prom_ql_labels(self) -> Dict[str, Any]:
        """Get Prometheus labels"""
        url = f"{self.endpoint}/api/v1/labels"
        response = await self.request("GET", url)
        return response

    async def prom_ql_label_values(self, label: str) -> Dict[str, Any]:
        """Get label values"""
        url = f"{self.endpoint}/api/v1/label/{label}/values"
        response = await self.request("GET", url)
        return response

    async def prom_ql_series(self, matches: List[str]) -> Dict[str, Any]:
        """Query Prometheus series"""
        url = f"{self.endpoint}/api/v1/series"
        query = "&match[]=".join(matches)
        url = f"{url}?match[]={query}"
        response = await self.request("GET", url)
        return response

    async def prom_ql_build_info(self) -> Dict[str, Any]:
        """Get Prometheus build info"""
        url = f"{self.endpoint}/api/v1/status/buildinfo"
        response = await self.request("GET", url)
        return response


    async def nl_query(self, index: str, query: str) -> Dict[str, Any]:
        """Execute natural language query"""
        url = f"{self.endpoint}/{index}/_nl_query?q={query}"
        response = await self.request("GET", url)
        return response


    async def summarize(self, index: str, query: str) -> Dict[str, Any]:
        """Summarize query results"""
        url = f"{self.endpoint}/{index}/_summarize"
        response = await self.request("GET", url, None, query)
        return response


    @classmethod
    def new(cls, access_key: str, secret_key: str, endpoint: str) -> 'InfinoSDK':
        """Create new SDK instance"""
        return cls.new_with_retry(access_key, secret_key, endpoint, RetryConfig())

    @classmethod
    def new_with_retry(
        cls,
        access_key: str,
        secret_key: str,
        endpoint: str,
        retry_config: RetryConfig
    ) -> 'InfinoSDK':
        """Create SDK instance with custom retry config"""
        return cls(access_key, secret_key, endpoint, retry_config)

    # User Account/Auth Operations
    async def get_user_account_info(self) -> Dict[str, Any]:
        """Get current user account info"""
        url = f"{self.endpoint}/_plugins/_security/api/account"
        response = await self.request("GET", url)
        return response

    async def get_user_auth_info(self) -> Dict[str, Any]:
        """Get current user authentication info"""
        url = f"{self.endpoint}/_plugins/_security/api/authinfo"
        response = await self.request("GET", url)
        return response

    async def create_user(self, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new user"""
        return await self.create_security_resource("internaluser", name, config)

    async def get_user(self, name: str) -> Dict[str, Any]:
        """Get user by name"""
        return await self.get_security_resource("internaluser", name)

    async def update_user(self, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update user"""
        return await self.update_security_resource("internaluser", name, config)

    async def delete_user(self, name: str) -> Dict[str, Any]:
        """Delete user"""
        return await self.delete_security_resource("internaluser", name)

    async def list_users(self) -> Dict[str, Any]:
        """List all users"""
        url = f"{self.endpoint}/_plugins/_security/api/internalusers"
        response = await self.request("GET", url)
        return response

    async def list_roles(self) -> Dict[str, Any]:
        """List all roles"""
        url = f"{self.endpoint}/_plugins/_security/api/roles"
        response = await self.request("GET", url)
        return response

    async def list_role_mappings(self) -> Dict[str, Any]:
        """List role mappings"""
        url = f"{self.endpoint}/_plugins/_security/api/rolesmapping"
        response = await self.request("GET", url)
        return response

    async def list_action_groups(self) -> Dict[str, Any]:
        """List action groups"""
        url = f"{self.endpoint}/_plugins/_security/api/actiongroups"
        response = await self.request("GET", url)
        return response

    async def generate_user_token(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """Generate authentication token for a user"""
        url = f"{self.endpoint}/_plugins/_security/api/authtoken"
        response = await self.request("POST", url, None, json.dumps(credentials))
        return response

    # Account Operations
    async def get_account(self, account_id: str) -> Dict[str, Any]:
        """Get account information"""
        url = f"{self.endpoint}/_account/{account_id}"
        response = await self.request("GET", url)
        return response

    async def get_source(self, index: str, doc_id: str) -> Dict[str, Any]:
        """Get document source"""
        url = f"{self.endpoint}/{index}/_source/{doc_id}"
        response = await self.request("GET", url)
        return response

    async def ping(self) -> Dict[str, Any]:
        """Implementation for GET /"""
        url = f"{self.endpoint}/"
        response = await self.request("GET", url)
        return response

    async def mget(self, body: str) -> Dict[str, Any]:
        """Get multiple documents"""
        url = f"{self.endpoint}/_mget"
        response = await self.request("POST", url, None, body)
        return response

    async def mget_index(self, index: str, body: str) -> Dict[str, Any]:
        """Get multiple documents from index"""
        url = f"{self.endpoint}/{index}/_mget"
        response = await self.request("POST", url, None, body)
        return response

    async def count(self, index: str, query: Optional[str] = None) -> Dict[str, Any]:
        """Count documents matching query"""
        url = f"{self.endpoint}/{index}/_count"
        response = await self.request("GET", url, None, query)
        return response

    async def document_exists(self, index: str, doc_id: str) -> bool:
        """Check if document exists"""
        url = f"{self.endpoint}/{index}/_doc/{doc_id}"
        try:
            await self.request("HEAD", url)
            return True
        except InfinoError as e:
            if e.status_code() == 404:
                return False
            raise

    async def source_exists(self, index: str, doc_id: str) -> bool:
        """Check if document source exists"""
        url = f"{self.endpoint}/{index}/_source/{doc_id}"
        try:
            await self.request("HEAD", url)
            return True
        except InfinoError as e:
            if e.status_code() == 404:
                return False
            raise

    async def index_info(self, index: str) -> Dict[str, Any]:
        """Get index information"""
        url = f"{self.endpoint}/{index}"
        response = await self.request("GET", url)
        return response

    async def get_cat_indices(self) -> List[Dict[str, Any]]:
        """Get catalog of indices"""
        url = f"{self.endpoint}/_cat/indices"
        response = await self.request("GET", url)
        json_response = response

        # The response should be an array of indices
        if isinstance(json_response, list):
            return json_response
        else:
            raise InfinoError(
                InfinoError.Type.INVALID_REQUEST,
                "Unexpected response format from /_cat/indices endpoint"
            )

    async def delete_by_query(self, index: str, query: str) -> Dict[str, Any]:
        """Delete documents by query"""
        url = f"{self.endpoint}/{index}/_delete_by_query"
        response = await self.request("DELETE", url, None, query)
        return response

    async def get_schema(self, index: str) -> Dict[str, Any]:
        """Get index schema"""
        url = f"{self.endpoint}/{index}/_schema"
        response = await self.request("GET", url)
        return response

    async def get_mappings(self, index: str) -> Dict[str, Any]:
        """Get index mappings"""
        url = f"{self.endpoint}/{index}/_mapping"
        response = await self.request("GET", url)
        return response

    async def get_index_dir(self, index: str) -> Dict[str, Any]:
        """Get index directory information"""
        url = f"{self.endpoint}/{index}/_dir"
        response = await self.request("GET", url)
        return response

    async def flush(self) -> Dict[str, Any]:
        """Implementation for POST /_flush"""
        url = f"{self.endpoint}/_flush"
        response = await self.request("POST", url)
        return response

    # Specific Resource Type Operations
    async def get_role(self, name: str) -> Dict[str, Any]:
        """Get role configuration"""
        return await self.get_security_resource("role", name)

    async def create_role(self, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new role"""
        return await self.create_security_resource("role", name, config)

    async def update_role(self, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update role configuration"""
        return await self.update_security_resource("role", name, config)

    async def delete_role(self, name: str) -> Dict[str, Any]:
        """Delete a role"""
        return await self.delete_security_resource("role", name)

    async def get_role_mapping(self, name: str) -> Dict[str, Any]:
        """Get role mapping"""
        return await self.get_security_resource("rolesmapping", name)

    async def create_role_mapping(self, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create role mapping"""
        return await self.create_security_resource("rolesmapping", name, config)

    async def update_role_mapping(self, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update role mapping"""
        return await self.update_security_resource("rolesmapping", name, config)

    async def delete_role_mapping(self, name: str) -> Dict[str, Any]:
        """Delete role mapping"""
        return await self.delete_security_resource("rolesmapping", name)

    async def get_action_group(self, name: str) -> Dict[str, Any]:
        """Get action group"""
        return await self.get_security_resource("actiongroup", name)

    async def create_action_group(self, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create action group"""
        return await self.create_security_resource("actiongroup", name, config)

    async def update_action_group(self, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update action group"""
        return await self.update_security_resource("actiongroup", name, config)

    async def delete_action_group(self, name: str) -> Dict[str, Any]:
        """Delete action group"""
        return await self.delete_security_resource("actiongroup", name)

    # Security Config Operations
    async def get_security_config(self) -> Dict[str, Any]:
        """Get security configuration"""
        url = f"{self.endpoint}/_plugins/_security/api/securityconfig"
        response = await self.request("GET", url)
        return response

    async def update_security_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update security configuration"""
        url = f"{self.endpoint}/_plugins/_security/api/securityconfig"
        response = await self.request("PUT", url, None, json.dumps(config))
        return response

    async def get_security_health(self) -> Dict[str, Any]:
        """Get security health status"""
        url = f"{self.endpoint}/_plugins/_security/health"
        response = await self.request("GET", url)
        return response

    async def get_tenant(self, name: str) -> Dict[str, Any]:
        """Get tenant configuration"""
        return await self.get_security_resource("tenant", name)

    async def create_tenant(self, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a tenant"""
        return await self.create_security_resource("tenant", name, config)

    async def update_tenant(self, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update tenant configuration"""
        return await self.update_security_resource("tenant", name, config)

    async def delete_tenant(self, name: str) -> Dict[str, Any]:
        """Delete a tenant"""
        return await self.delete_security_resource("tenant", name)


    async def get_security_resource(self, resource_type: str, name: str) -> Dict[str, Any]:
        """Get a security resource"""
        plural = "" if resource_type == "rolesmapping" else "s"
        url = f"{self.endpoint}/_plugins/_security/api/{resource_type}{plural}/{name}"
        response = await self.request("GET", url)
        return response

    async def create_security_resource(self, resource_type: str, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a security resource"""
        plural = "" if resource_type == "rolesmapping" else "s"
        url = f"{self.endpoint}/_plugins/_security/api/{resource_type}{plural}/{name}"
        logger.debug(f"Creating security resource: {resource_type} {name} at {url}")
        try:
            response = await self.request("PUT", url, None, json.dumps(config))
            logger.debug(f"Security resource created successfully: {response}")
            return response
        except Exception as e:
            logger.error(f"Failed to create security resource {resource_type} {name}: {e}")
            raise

    async def update_security_resource(self, resource_type: str, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update a security resource"""
        plural = "" if resource_type == "rolesmapping" else "s"
        url = f"{self.endpoint}/_plugins/_security/api/{resource_type}{plural}/{name}"
        response = await self.request("PATCH", url, None, json.dumps(config))
        return response

    async def delete_security_resource(self, resource_type: str, name: str) -> Dict[str, Any]:
        """Delete a security resource"""
        plural = "" if resource_type == "rolesmapping" else "s"
        url = f"{self.endpoint}/_plugins/_security/api/{resource_type}{plural}/{name}"
        response = await self.request("DELETE", url)
        return response

    async def rotate_api_keys(self, username: str) -> Dict[str, Any]:
        """Rotate API keys for a user

        Args:
            username: Username to rotate keys for

        Returns:
            New credentials (access_key and secret_key)
        """
        url = f"{self.endpoint}/_account/users/{username}/rotate_keys"
        response = await self.request("GET", url)
        return response

    # ML Commons Plugin Operations
    async def register_model(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Register ML model"""
        url = f"{self.endpoint}/_plugins/_ml/models/_register"
        logger.debug(f"INFINO SDK: Registering model: {config}")
        response = await self.request("POST", url, None, json.dumps(config))
        return response

    async def deploy_model(self, model_id: str) -> Dict[str, Any]:
        """Deploy ML model"""
        url = f"{self.endpoint}/_plugins/_ml/models/{model_id}/_deploy"
        response = await self.request("POST", url)
        return response

    async def undeploy_model(self, model_id: str) -> Dict[str, Any]:
        """Undeploy ML model"""
        url = f"{self.endpoint}/_plugins/_ml/models/{model_id}/_undeploy"
        response = await self.request("POST", url)
        return response

    async def get_model(self, model_id: str) -> Dict[str, Any]:
        """Get ML model information"""
        url = f"{self.endpoint}/_plugins/_ml/models/{model_id}"
        response = await self.request("GET", url)
        return response

    async def delete_model(self, model_id: str) -> Dict[str, Any]:
        """Delete ML model"""
        url = f"{self.endpoint}/_plugins/_ml/models/{model_id}"
        response = await self.request("DELETE", url)
        return response

    async def search_models(self, query: Dict[str, Any]) -> Dict[str, Any]:
        """Search ML models"""
        url = f"{self.endpoint}/_plugins/_ml/models/_search"
        response = await self.request("POST", url, None, json.dumps(query))
        return response

    async def update_model(self, model_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update ML model"""
        url = f"{self.endpoint}/_plugins/_ml/models/{model_id}"
        response = await self.request("PUT", url, None, json.dumps(config))
        return response

    async def train_model(self, algorithm: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Train ML model"""
        url = f"{self.endpoint}/_plugins/_ml/_train/{algorithm}"
        response = await self.request("POST", url, None, json.dumps(config))
        return response

    # Model prediction API
    async def predict(self, model_id: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Make prediction using model"""
        url = f"{self.endpoint}/_plugins/_ml/models/{model_id}/_predict"
        response = await self.request("POST", url, None, json.dumps(input_data))
        return response

    async def train_and_predict(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Train model and make prediction"""
        url = f"{self.endpoint}/_plugins/_ml/train_and_predict"
        response = await self.request("POST", url, None, json.dumps(config))
        return response

    async def batch_predict(self, model_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Batch prediction"""
        predict_config = config.copy()
        if isinstance(predict_config, dict):
            predict_config["model_id"] = model_id
        url = f"{self.endpoint}/_plugins/_ml/models/_batch_predict"
        response = await self.request("POST", url, None, json.dumps(predict_config))
        return response

    async def cancel_batch_predict(self, task_id: str) -> Dict[str, Any]:
        """Cancel batch prediction"""
        url = f"{self.endpoint}/_plugins/_ml/tasks/{task_id}/_cancel_batch"
        response = await self.request("POST", url)
        return response

    async def list_models(self) -> Dict[str, Any]:
        """List all ML models"""
        url = f"{self.endpoint}/_plugins/_ml/models"
        response = await self.request("GET", url)
        return response

    async def get_ml_stats(self) -> Dict[str, Any]:
        """Get ML statistics"""
        url = f"{self.endpoint}/_plugins/_ml/stats"
        response = await self.request("GET", url)
        return response

    async def get_task_list(self) -> Dict[str, Any]:
        """Get list of ML tasks"""
        url = f"{self.endpoint}/_plugins/_ml/tasks"
        response = await self.request("GET", url)
        return response

    async def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Get ML task status"""
        url = f"{self.endpoint}/_plugins/_ml/tasks/{task_id}"
        response = await self.request("GET", url)
        return response

    async def get_ml_profile(self) -> Dict[str, Any]:
        """Get ML profile"""
        url = f"{self.endpoint}/_plugins/_ml/profile"
        response = await self.request("GET", url)
        return response

    async def get_model_metrics(self, model_id: str) -> Dict[str, Any]:
        """Get model metrics"""
        url = f"{self.endpoint}/_plugins/_ml/models/{model_id}/metrics"
        response = await self.request("GET", url)
        return response

    # ML Commons Connector Operations
    async def create_connector(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create ML connector"""
        url = f"{self.endpoint}/_plugins/_ml/connectors/_create"
        response = await self.request("POST", url, None, json.dumps(config))
        return response

    async def get_connector(self, connector_id: str) -> Dict[str, Any]:
        """Get connector information"""
        url = f"{self.endpoint}/_plugins/_ml/connectors/{connector_id}"
        response = await self.request("GET", url)
        return response

    async def list_connectors(self) -> Dict[str, Any]:
        """List all connectors"""
        url = f"{self.endpoint}/_plugins/_ml/connectors"
        response = await self.request("GET", url)
        return response

    async def delete_connector(self, connector_id: str) -> Dict[str, Any]:
        """Delete connector"""
        url = f"{self.endpoint}/_plugins/_ml/connectors/{connector_id}"
        response = await self.request("DELETE", url)
        return response

    # Additional ML Commons Plugin Operations
    async def register_model_group(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Register model group"""
        url = f"{self.endpoint}/_plugins/_ml/model_groups/_register"
        response = await self.request("POST", url, None, json.dumps(config))
        return response

    async def get_model_group(self, model_group_id: str) -> Dict[str, Any]:
        """Get model group"""
        url = f"{self.endpoint}/_plugins/_ml/model_groups/{model_group_id}"
        response = await self.request("GET", url)
        return response

    async def delete_model_group(self, model_group_id: str) -> Dict[str, Any]:
        """Delete model group"""
        url = f"{self.endpoint}/_plugins/_ml/model_groups/{model_group_id}"
        response = await self.request("DELETE", url)
        return response

    async def list_model_groups(self) -> Dict[str, Any]:
        """List model groups"""
        url = f"{self.endpoint}/_plugins/_ml/model_groups"
        response = await self.request("GET", url)
        return response

    async def register_agent(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Register ML agent"""
        url = f"{self.endpoint}/_plugins/_ml/agents/_register"
        response = await self.request("POST", url, None, json.dumps(config))
        return response

    async def get_agent(self, agent_id: str) -> Dict[str, Any]:
        """Get agent information"""
        url = f"{self.endpoint}/_plugins/_ml/agents/{agent_id}"
        response = await self.request("GET", url)
        return response

    async def delete_agent(self, agent_id: str) -> Dict[str, Any]:
        """Delete agent"""
        url = f"{self.endpoint}/_plugins/_ml/agents/{agent_id}"
        response = await self.request("DELETE", url)
        return response

    async def list_agents(self) -> Dict[str, Any]:
        """List all agents"""
        url = f"{self.endpoint}/_plugins/_ml/agents"
        response = await self.request("GET", url)
        return response

    async def create_memory(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create memory"""
        url = f"{self.endpoint}/_plugins/_ml/memory"
        response = await self.request("POST", url, None, json.dumps(config))
        return response

    async def update_memory(self, memory_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update memory"""
        url = f"{self.endpoint}/_plugins/_ml/memory/{memory_id}"
        response = await self.request("PUT", url, None, json.dumps(config))
        return response

    async def get_memory(self, memory_id: str) -> Dict[str, Any]:
        """Get memory"""
        url = f"{self.endpoint}/_plugins/_ml/memory/{memory_id}"
        response = await self.request("GET", url)
        return response

    async def get_all_memories(self, max_results: Optional[int] = None, next_token: Optional[int] = None) -> Dict[str, Any]:
        """Get all memories"""
        url = f"{self.endpoint}/_plugins/_ml/memory"
        if max_results is not None:
            url += f"?max_results={max_results}"
            if next_token is not None:
                url += f"&next_token={next_token}"
        elif next_token is not None:
            url += f"?next_token={next_token}"
        response = await self.request("GET", url)
        return response

    async def search_memories(self, query: Dict[str, Any]) -> Dict[str, Any]:
        """Search memories"""
        url = f"{self.endpoint}/_plugins/_ml/memory/_search"
        response = await self.request("POST", url, None, json.dumps(query))
        return response

    async def delete_memory(self, memory_id: str) -> Dict[str, Any]:
        """Delete memory"""
        url = f"{self.endpoint}/_plugins/_ml/memory/{memory_id}"
        response = await self.request("DELETE", url)
        return response

    # Message APIs
    async def create_message(self, memory_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create message"""
        url = f"{self.endpoint}/_plugins/_ml/memory/{memory_id}/messages"
        response = await self.request("POST", url, None, json.dumps(config))
        return response

    async def update_message(self, message_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update message"""
        url = f"{self.endpoint}/_plugins/_ml/memory/message/{message_id}"
        response = await self.request("PUT", url, None, json.dumps(config))
        return response

    async def get_message(self, message_id: str) -> Dict[str, Any]:
        """Get message"""
        url = f"{self.endpoint}/_plugins/_ml/memory/message/{message_id}"
        response = await self.request("GET", url)
        return response

    async def get_memory_messages(self, memory_id: str) -> Dict[str, Any]:
        """Get memory messages"""
        url = f"{self.endpoint}/_plugins/_ml/memory/{memory_id}/messages"
        response = await self.request("GET", url)
        return response

    async def search_memory_messages(self, memory_id: str, query: Dict[str, Any]) -> Dict[str, Any]:
        """Search memory messages"""
        url = f"{self.endpoint}/_plugins/_ml/memory/{memory_id}/_search"
        response = await self.request("POST", url, None, json.dumps(query))
        return response

    async def get_message_traces(self, message_id: str) -> Dict[str, Any]:
        """Get message traces"""
        url = f"{self.endpoint}/_plugins/_ml/memory/message/{message_id}/traces"
        response = await self.request("GET", url)
        return response

    # Controller APIs
    async def create_controller(self, model_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create controller"""
        url = f"{self.endpoint}/_plugins/_ml/controllers/{model_id}"
        response = await self.request("POST", url, None, json.dumps(config))
        return response

    async def get_controller(self, controller_id: str) -> Dict[str, Any]:
        """Get controller"""
        url = f"{self.endpoint}/_plugins/_ml/controllers/{controller_id}"
        response = await self.request("GET", url)
        return response

    async def update_controller(self, controller_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update controller"""
        url = f"{self.endpoint}/_plugins/_ml/controllers/{controller_id}"
        response = await self.request("PUT", url, None, json.dumps(config))
        return response

    async def delete_controller(self, controller_id: str) -> Dict[str, Any]:
        """Delete controller"""
        url = f"{self.endpoint}/_plugins/_ml/controllers/{controller_id}"
        response = await self.request("DELETE", url)
        return response

    async def get_controller_status(self) -> Dict[str, Any]:
        """Get controller status"""
        url = f"{self.endpoint}/_plugins/_ml/controller"
        response = await self.request("GET", url)
        return response

    # Task APIs
    async def get_task(self, task_id: str) -> Dict[str, Any]:
        """Get task information"""
        url = f"{self.endpoint}/_plugins/_ml/tasks/{task_id}"
        response = await self.request("GET", url)
        return response

    async def search_tasks(self, query: Dict[str, Any]) -> Dict[str, Any]:
        """Search tasks"""
        url = f"{self.endpoint}/_plugins/_ml/tasks/_search"
        response = await self.request("POST", url, None, json.dumps(query))
        return response

    async def stop_task(self, task_id: str) -> Dict[str, Any]:
        """Stop task"""
        url = f"{self.endpoint}/_plugins/_ml/tasks/{task_id}/_stop"
        response = await self.request("POST", url)
        return response

    async def delete_task(self, task_id: str) -> Dict[str, Any]:
        """Delete task"""
        url = f"{self.endpoint}/_plugins/_ml/tasks/{task_id}"
        response = await self.request("DELETE", url)
        return response

    # Profile APIs
    async def get_profile(self, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Get profile"""
        url = f"{self.endpoint}/_plugins/_ml/profile"
        body = json.dumps(config) if config else None
        response = await self.request("GET", url, None, body)
        return response

    async def get_models_profile(self) -> Dict[str, Any]:
        """Get models profile"""
        url = f"{self.endpoint}/_plugins/_ml/profile/models"
        response = await self.request("GET", url)
        return response

    async def get_model_profile(self, model_id: str) -> Dict[str, Any]:
        """Get model profile"""
        url = f"{self.endpoint}/_plugins/_ml/profile/models/{model_id}"
        response = await self.request("GET", url)
        return response

    async def get_tasks_profile(self) -> Dict[str, Any]:
        """Get tasks profile"""
        url = f"{self.endpoint}/_plugins/_ml/profile/tasks"
        response = await self.request("GET", url)
        return response

    async def get_task_profile(self, task_id: str) -> Dict[str, Any]:
        """Get task profile"""
        url = f"{self.endpoint}/_plugins/_ml/profile/tasks/{task_id}"
        response = await self.request("GET", url)
        return response

    # Stats APIs
    async def get_stats(self) -> Dict[str, Any]:
        """Get statistics"""
        url = f"{self.endpoint}/_plugins/_ml/stats"
        response = await self.request("GET", url)
        return response

    async def get_stat(self, stat: str) -> Dict[str, Any]:
        """Get specific statistic"""
        url = f"{self.endpoint}/_plugins/_ml/stats/{stat}"
        response = await self.request("GET", url)
        return response

    # Ingest Pipeline Operations
    async def create_ingest_pipeline(self, pipeline_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create ingest pipeline"""
        url = f"{self.endpoint}/_ingest/pipeline/{pipeline_name}"
        try:
            response = await self.request("PUT", url, None, json.dumps(config))
            return response
        except InfinoError as e:
            # 409 CONFLICT is acceptable for pipeline creation - it means the pipeline already exists
            if e.status_code() == 409:
                logger.debug(f"INFINO SDK: Ingest pipeline '{pipeline_name}' already exists (409 CONFLICT), continuing")
                return {"acknowledged": True}
            raise

    async def get_ingest_pipeline(self, pipeline_name: str) -> Dict[str, Any]:
        """Get ingest pipeline"""
        url = f"{self.endpoint}/_ingest/pipeline/{pipeline_name}"
        response = await self.request("GET", url)
        return response

    async def delete_ingest_pipeline(self, pipeline_name: str) -> Dict[str, Any]:
        """Delete ingest pipeline"""
        url = f"{self.endpoint}/_ingest/pipeline/{pipeline_name}"
        response = await self.request("DELETE", url)
        return response

    # Search Pipeline Operations
    async def create_search_pipeline(self, pipeline_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create search pipeline"""
        url = f"{self.endpoint}/_search/pipeline/{pipeline_name}"
        try:
            response = await self.request("PUT", url, None, json.dumps(config))
            return response
        except InfinoError as e:
            # 409 CONFLICT is acceptable for pipeline creation - it means the pipeline already exists
            if e.status_code() == 409:
                logger.debug(f"INFINO SDK: Search pipeline '{pipeline_name}' already exists (409 CONFLICT), continuing")
                return {"acknowledged": True}
            raise

    async def get_search_pipeline(self, pipeline_name: str) -> Dict[str, Any]:
        """Get search pipeline"""
        url = f"{self.endpoint}/_search/pipeline/{pipeline_name}"
        response = await self.request("GET", url)
        return response

    async def delete_search_pipeline(self, pipeline_name: str) -> Dict[str, Any]:
        """Delete search pipeline"""
        url = f"{self.endpoint}/_search/pipeline/{pipeline_name}"
        response = await self.request("DELETE", url)
        return response

# Error conversion implementations
def _convert_reqwest_error(error: requests.RequestException) -> InfinoError:
    """Convert network error to InfinoError"""
    return InfinoError(
        error_type=InfinoError.Type.NETWORK,
        message=str(error)
    )

def _convert_json_error(error: json.JSONDecodeError) -> InfinoError:
    """Convert JSON parsing error to InfinoError"""
    return InfinoError(
        error_type=InfinoError.Type.PARSE,
        message=str(error)
    )

# Test module
if __name__ == "__main__":
    import unittest
    import responses

    class TestInfinoSDK(unittest.TestCase):
        """Test suite for Infino SDK"""
        
        async def setUp(self):
            self.client = InfinoSDK(
                access_key="test_key",
                secret_key="test_secret",
                endpoint="http://localhost:8000"
            )

        @responses.activate
        async def test_request_signing(self):
            """Test request signing"""
            responses.add(
                responses.GET,
                "http://localhost:8000/test_index/_search",
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
            response = self.client.search("test_index", query)
            self.assertEqual(response, {"hits": []})

        @responses.activate
        async def test_document_operations(self):
            """Test document operations"""
            doc = json.dumps({"field1": "value1"})
            
            responses.add(
                responses.PUT,
                "http://localhost:8000/test_index/doc/1",
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

            # Document indexing is done via bulk_ingest
            pass

        @responses.activate
        async def test_security_operations(self):
            """Test security API operations"""
            # Test role operations
            responses.add(
                responses.PUT,
                "http://localhost:8000/_plugins/_security/api/roles/test_role",
                json={"status": "created"},
                status=200,
                match=[
                    responses.matchers.header_matcher({
                        "authorization": lambda x: x.startswith("AWS4-HMAC-SHA256"),
                        "x-amz-date": lambda x: len(x) == 16,
                        "x-amz-content-sha256": lambda x: len(x) == 64
                    })
                ]
            )

            role_config = {
                "cluster_permissions": ["*"],
                "index_permissions": [{
                    "index_patterns": ["test*"],
                    "allowed_actions": ["*"]
                }]
            }

            response = self.client.create_role("test_role", role_config)
            self.assertEqual(response, {"status": "created"})

            # Test role mapping operations
            responses.add(
                responses.PUT,
                "http://localhost:8000/_plugins/_security/api/rolesmapping/test_mapping",
                json={"status": "created"},
                status=200,
                match=[
                    responses.matchers.header_matcher({
                        "authorization": lambda x: x.startswith("AWS4-HMAC-SHA256"),
                        "x-amz-date": lambda x: len(x) == 16,
                        "x-amz-content-sha256": lambda x: len(x) == 64
                    })
                ]
            )

            mapping_config = {
                "users": ["test_user"],
                "backend_roles": ["test_role"]
            }

            response = self.client.create_role_mapping("test_mapping", mapping_config)
            self.assertEqual(response, {"status": "created"})

    unittest.main() 