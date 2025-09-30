"""
WebSocket Chat Example for Infino SDK

This example demonstrates how to:
1. Establish WebSocket connection with SigV4 authentication
2. Send and receive real-time messages
3. Handle conversation threads
4. Process streaming responses
5. Gracefully handle connection lifecycle

Based on patterns from infino/tests/api/python/src/utils/iai.py
"""

import asyncio
import json
import uuid
from infino_sdk import InfinoSDK


async def simple_websocket_connection():
    """
    Example 1: Simple WebSocket connection test
    
    Establishes a WebSocket connection and verifies authentication works.
    """
    print("=" * 60)
    print("Example 1: Simple WebSocket Connection")
    print("=" * 60)
    
    # Initialize SDK
    access_key = "your_access_key_here"
    secret_key = "your_secret_key_here"
    endpoint = "https://api.infino.ws"
    
    sdk = InfinoSDK(access_key, secret_key, endpoint)
    
    try:
        # Connect to WebSocket endpoint
        # SDK handles AWS SigV4 authentication automatically
        print("Establishing WebSocket connection...")
        
        async with sdk.websocket_connect("/_conversation/ws") as websocket:
            print("✓ WebSocket connection established successfully!")
            print(f"  Connection state: {websocket.open}")
            
            # Connection is authenticated and ready for use
            # Close will happen automatically when exiting context
            
    except Exception as e:
        print(f"✗ WebSocket connection failed: {e}")
    finally:
        sdk.close()
    
    print()


async def send_query_and_receive_response():
    """
    Example 2: Send query and receive AI response
    
    Demonstrates sending a user query and receiving the AI response
    via WebSocket.
    """
    print("=" * 60)
    print("Example 2: Send Query and Receive Response")
    print("=" * 60)
    
    access_key = "your_access_key_here"
    secret_key = "your_secret_key_here"
    endpoint = "https://api.infino.ws"
    
    sdk = InfinoSDK(access_key, secret_key, endpoint)
    
    # Generate unique client and thread IDs
    client_id = f"client-{uuid.uuid4()}"
    thread_id = f"thread-{uuid.uuid4()}"
    
    print(f"Client ID: {client_id}")
    print(f"Thread ID: {thread_id}")
    
    try:
        # Required headers for WebSocket connection
        headers = {
            "x-infino-client-id": client_id,
            "x-infino-thread-id": thread_id,
        }
        
        print("\nConnecting to WebSocket...")
        async with sdk.websocket_connect("/_conversation/ws", headers=headers) as websocket:
            print("✓ Connected!")
            
            # Send a user query
            user_query = {
                "content": {
                    "user_query": "Show me the top 10 error messages from the logs"
                }
            }
            
            print(f"\nSending query: {user_query['content']['user_query']}")
            await websocket.send(json.dumps(user_query))
            print("✓ Query sent")
            
            # Receive response(s)
            print("\nWaiting for response...")
            response_count = 0
            
            try:
                # Set a timeout for receiving messages
                async with asyncio.timeout(30):
                    async for message in websocket:
                        response_count += 1
                        data = json.loads(message)
                        
                        print(f"\n--- Response {response_count} ---")
                        
                        # Check message type
                        content = data.get("content", {})
                        msg_type = content.get("type", "unknown")
                        
                        print(f"Type: {msg_type}")
                        
                        if msg_type == "update":
                            # Streaming update (thinking process)
                            print(f"Update: {content.get('text', '')}")
                        elif msg_type == "message":
                            # Final response
                            print(f"Final Response: {content.get('text', '')}")
                            
                            # Check for SQL query
                            if "sql_query" in content:
                                print(f"SQL Query: {content['sql_query']}")
                            
                            # Check for results
                            if "results" in content:
                                print(f"Results: {json.dumps(content['results'], indent=2)}")
                            
                            # Final message received, break
                            break
                        else:
                            print(f"Content: {json.dumps(content, indent=2)}")
                            
            except asyncio.TimeoutError:
                print("\n✗ Timeout waiting for response")
            
            print(f"\nReceived {response_count} message(s)")
            
    except Exception as e:
        print(f"✗ Error: {e}")
    finally:
        sdk.close()
    
    print()


async def conversation_with_multiple_messages():
    """
    Example 3: Multi-turn conversation
    
    Demonstrates having a conversation with multiple back-and-forth messages
    in the same thread.
    """
    print("=" * 60)
    print("Example 3: Multi-turn Conversation")
    print("=" * 60)
    
    access_key = "your_access_key_here"
    secret_key = "your_secret_key_here"
    endpoint = "https://api.infino.ws"
    
    sdk = InfinoSDK(access_key, secret_key, endpoint)
    
    client_id = f"client-{uuid.uuid4()}"
    thread_id = f"thread-{uuid.uuid4()}"
    
    print(f"Starting conversation in thread: {thread_id}")
    
    queries = [
        "What indices are available?",
        "Show me a sample document from logs",
        "Count the total number of log entries",
    ]
    
    try:
        headers = {
            "x-infino-client-id": client_id,
            "x-infino-thread-id": thread_id,
        }
        
        async with sdk.websocket_connect("/_conversation/ws", headers=headers) as websocket:
            print("✓ Connected")
            
            for i, query_text in enumerate(queries, 1):
                print(f"\n{'=' * 40}")
                print(f"Query {i}: {query_text}")
                print('=' * 40)
                
                # Send query
                query = {
                    "content": {
                        "user_query": query_text
                    }
                }
                await websocket.send(json.dumps(query))
                
                # Receive response
                try:
                    async with asyncio.timeout(20):
                        async for message in websocket:
                            data = json.loads(message)
                            content = data.get("content", {})
                            msg_type = content.get("type", "unknown")
                            
                            if msg_type == "update":
                                # Show thinking process
                                print(f"  [Thinking] {content.get('text', '')}")
                            elif msg_type == "message":
                                # Final response
                                print(f"\n  Response: {content.get('text', '')}")
                                break
                                
                except asyncio.TimeoutError:
                    print(f"  ✗ Timeout for query {i}")
                    continue
                
                # Brief pause between queries
                await asyncio.sleep(1)
            
            print(f"\n{'=' * 40}")
            print("Conversation complete!")
            
    except Exception as e:
        print(f"✗ Error: {e}")
    finally:
        sdk.close()
    
    print()


async def handle_websocket_errors():
    """
    Example 4: WebSocket error handling
    
    Demonstrates proper error handling for various WebSocket scenarios.
    """
    print("=" * 60)
    print("Example 4: WebSocket Error Handling")
    print("=" * 60)
    
    access_key = "your_access_key_here"
    secret_key = "your_secret_key_here"
    endpoint = "https://api.infino.ws"
    
    sdk = InfinoSDK(access_key, secret_key, endpoint)
    
    client_id = f"client-{uuid.uuid4()}"
    thread_id = f"thread-{uuid.uuid4()}"
    
    try:
        headers = {
            "x-infino-client-id": client_id,
            "x-infino-thread-id": thread_id,
        }
        
        print("Attempting connection...")
        async with sdk.websocket_connect("/_conversation/ws", headers=headers) as websocket:
            print("✓ Connected")
            
            try:
                # Send query
                query = {
                    "content": {
                        "user_query": "Test query"
                    }
                }
                await websocket.send(json.dumps(query))
                print("✓ Query sent")
                
                # Handle responses with timeout
                async with asyncio.timeout(30):
                    message_count = 0
                    async for message in websocket:
                        message_count += 1
                        data = json.loads(message)
                        
                        content = data.get("content", {})
                        if content.get("type") == "message":
                            print(f"✓ Received final response after {message_count} message(s)")
                            break
                        
            except asyncio.TimeoutError:
                print("✗ Timeout: No response received within 30 seconds")
            except json.JSONDecodeError as e:
                print(f"✗ JSON Parse Error: {e}")
            except Exception as e:
                print(f"✗ Unexpected error during message handling: {e}")
                
    except ConnectionError as e:
        print(f"✗ Connection Error: {e}")
    except Exception as e:
        print(f"✗ WebSocket Error: {e}")
    finally:
        sdk.close()
        print("✓ SDK closed")
    
    print()


async def websocket_with_reconnection():
    """
    Example 5: WebSocket with reconnection logic
    
    Demonstrates handling disconnections and implementing reconnection logic.
    """
    print("=" * 60)
    print("Example 5: WebSocket with Reconnection")
    print("=" * 60)
    
    access_key = "your_access_key_here"
    secret_key = "your_secret_key_here"
    endpoint = "https://api.infino.ws"
    
    sdk = InfinoSDK(access_key, secret_key, endpoint)
    
    client_id = f"client-{uuid.uuid4()}"
    thread_id = f"thread-{uuid.uuid4()}"
    
    max_retries = 3
    retry_delay = 2  # seconds
    
    for attempt in range(1, max_retries + 1):
        print(f"\nConnection attempt {attempt}/{max_retries}...")
        
        try:
            headers = {
                "x-infino-client-id": client_id,
                "x-infino-thread-id": thread_id,
            }
            
            async with sdk.websocket_connect("/_conversation/ws", headers=headers) as websocket:
                print(f"✓ Connected on attempt {attempt}")
                
                # Send a query
                query = {
                    "content": {
                        "user_query": "What is the current system status?"
                    }
                }
                await websocket.send(json.dumps(query))
                
                # Receive response
                async with asyncio.timeout(15):
                    async for message in websocket:
                        data = json.loads(message)
                        content = data.get("content", {})
                        
                        if content.get("type") == "message":
                            print(f"✓ Response: {content.get('text', '')}")
                            break
                
                # Success - exit retry loop
                print("✓ Query completed successfully")
                break
                
        except (ConnectionError, asyncio.TimeoutError) as e:
            print(f"✗ Attempt {attempt} failed: {e}")
            
            if attempt < max_retries:
                print(f"  Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
            else:
                print(f"✗ All {max_retries} attempts failed")
                
        except Exception as e:
            print(f"✗ Unexpected error: {e}")
            break
    
    sdk.close()
    print()


async def streaming_data_visualization():
    """
    Example 6: Stream and process data in real-time
    
    Demonstrates processing streaming updates for data visualization or
    progress tracking.
    """
    print("=" * 60)
    print("Example 6: Streaming Data Visualization")
    print("=" * 60)
    
    access_key = "your_access_key_here"
    secret_key = "your_secret_key_here"
    endpoint = "https://api.infino.ws"
    
    sdk = InfinoSDK(access_key, secret_key, endpoint)
    
    client_id = f"client-{uuid.uuid4()}"
    thread_id = f"thread-{uuid.uuid4()}"
    
    try:
        headers = {
            "x-infino-client-id": client_id,
            "x-infino-thread-id": thread_id,
        }
        
        async with sdk.websocket_connect("/_conversation/ws", headers=headers) as websocket:
            print("✓ Connected\n")
            
            # Send a complex query
            query = {
                "content": {
                    "user_query": "Analyze error patterns in the last 24 hours"
                }
            }
            await websocket.send(json.dumps(query))
            
            print("Processing query...")
            print("-" * 60)
            
            thinking_messages = []
            
            try:
                async with asyncio.timeout(45):
                    async for message in websocket:
                        data = json.loads(message)
                        content = data.get("content", {})
                        msg_type = content.get("type", "unknown")
                        
                        if msg_type == "update":
                            # Streaming update - show progress
                            update_text = content.get("text", "")
                            thinking_messages.append(update_text)
                            print(f"  [Step {len(thinking_messages)}] {update_text}")
                            
                        elif msg_type == "message":
                            # Final response
                            print("-" * 60)
                            print("\n✓ Analysis Complete!")
                            print(f"\nSteps taken: {len(thinking_messages)}")
                            print(f"\nFinal Response:\n{content.get('text', '')}")
                            
                            # Check for structured results
                            if "results" in content:
                                print(f"\nResults:\n{json.dumps(content['results'], indent=2)}")
                            
                            break
                            
            except asyncio.TimeoutError:
                print("\n✗ Query timed out")
            
    except Exception as e:
        print(f"✗ Error: {e}")
    finally:
        sdk.close()
    
    print()


async def main():
    """Run all WebSocket examples"""
    print("\n" + "=" * 60)
    print("Infino SDK - WebSocket Examples")
    print("=" * 60 + "\n")
    
    # Example 1: Simple connection
    await simple_websocket_connection()
    
    # Example 2: Send query and receive response
    await send_query_and_receive_response()
    
    # Example 3: Multi-turn conversation
    await conversation_with_multiple_messages()
    
    # Example 4: Error handling
    await handle_websocket_errors()
    
    # Example 5: Reconnection logic
    await websocket_with_reconnection()
    
    # Example 6: Streaming data
    await streaming_data_visualization()
    
    print("\n" + "=" * 60)
    print("All examples completed!")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main())
