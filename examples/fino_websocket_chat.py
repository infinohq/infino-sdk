"""
Infino SDK - WebSocket Chat Example

This example demonstrates how to use the Infino SDK to:
1. Create a conversation thread via REST API
2. Connect to WebSocket for real-time chat
3. Send queries and receive streaming responses

================================================================================
WORKFLOW
================================================================================

Step 1: Create a thread via REST API
    POST /_conversation/threads
    Body: {"name": "My Thread"}
    Response: {"id": "5f45ec9b-223d-464b-9819-fff45039604a", ...}

Step 2: Connect to WebSocket with thread ID
    URL: /_conversation/ws?threadId={thread_id}&clientId={client_id}

Step 3: Send message (see REQUEST FORMAT below)

Step 4: Receive messages until you get type="result"

================================================================================
REQUEST FORMAT (what you send)
================================================================================

{
    "content": {
        "user_query": "What happened in the last 10 days?"
    }
}

================================================================================
RESPONSE FORMAT (what you receive)
================================================================================

You will receive multiple messages. Handle these two types:

----- TYPE 1: "update" (progress messages) -----

These come while the AI is processing. You'll receive several of these.

Example 1 - Router starting:
{
    "content": {
        "type": "update",
        "sender": "router",
        "message": "Gathering sources and refreshing metadata..."
    },
    "role": "assistant",
    "created_at": "2025-12-17T11:17:29.214152+00:00"
}

Example 2 - Analyzing history:
{
    "content": {
        "type": "update",
        "sender": "history_analyzer",
        "message": "Analyzing conversation context..."
    },
    "role": "assistant",
    "created_at": "2025-12-17T11:17:29.349836+00:00"
}

Example 3 - Classifying intent:
{
    "content": {
        "type": "update",
        "sender": "intent_classifier",
        "message": "Analyzing query intent..."
    },
    "role": "assistant",
    "created_at": "2025-12-17T11:17:29.350536+00:00"
}

Example 4 - Selecting data source:
{
    "content": {
        "type": "update",
        "sender": "connection_selector",
        "message": "Analyzing query to determine best data source from 3 available datasets..."
    },
    "role": "assistant",
    "created_at": "2025-12-17T11:17:30.281848+00:00"
}

Example 5 - Formulating response:
{
    "content": {
        "type": "update",
        "sender": "chatbot",
        "message": "Formulating response"
    },
    "role": "assistant",
    "created_at": "2025-12-17T11:17:31.867349+00:00"
}

----- TYPE 2: "result" (final response) -----

This is the final message. Stop listening after receiving this.

{
    "content": {
        "user_query": "Hello, I want to see what happened in the last 10 days",
        "query_id": "7613ad54-8ab3-4917-b4b6-d4e2d65b36f4",
        "type": "result",
        "user_intent": null,
        "user_context": null,
        "summary": "Hello! I can help you see what happened in the last 10 days. I found the following data sources available:\\n\\n1. **'application_logs'**: Contains application event logs with timestamps.\\n2. **'system_metrics'**: Contains system performance metrics over time.\\n\\nWhich data source would you like me to query?",
        "data": {
            "df": {},
            "index_schema": null
        },
        "chart": {},
        "querydsl": {},
        "sql": "",
        "followup_queries": [
            "Show me recent error logs",
            "What are the top events?",
            "Show me a summary"
        ]
    },
    "role": "assistant",
    "created_at": "2025-12-17T11:17:32.865712+00:00"
}

================================================================================
HANDLING RESPONSES (Python code)
================================================================================

while True:
    response = await ws.recv()
    data = json.loads(response)
    content = data["content"]
    msg_type = content["type"]

    if msg_type == "update":
        # Progress update - optional to display
        print(f"[{content['sender']}] {content['message']}")

    elif msg_type == "result":
        # Final answer - extract and display
        print(content["summary"])
        break  # Stop listening

================================================================================
"""

import asyncio
import json
import os
import uuid

from infino_sdk import InfinoSDK

# =============================================================================
# CONFIGURATION
# =============================================================================

def get_credentials():
    """
    Get API credentials from environment variables.
    
    Required environment variables:
    - INFINO_ACCESS_KEY: Your Infino access key
    - INFINO_SECRET_KEY: Your Infino secret key
    - INFINO_ENDPOINT: API endpoint (default: https://api.infino.ws)
    """
    access_key = os.environ.get("INFINO_ACCESS_KEY", "your_access_key_here")
    secret_key = os.environ.get("INFINO_SECRET_KEY", "your_secret_key_here")
    endpoint = os.environ.get("INFINO_ENDPOINT", "https://api.infino.ws")
    return access_key, secret_key, endpoint


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def create_thread(sdk: InfinoSDK, endpoint: str, name: str = None) -> str:
    """
    Create a new conversation thread via REST API.
    
    Args:
        sdk: InfinoSDK instance
        endpoint: API endpoint URL
        name: Optional thread name
    
    Returns:
        Thread ID string
    """
    if name is None:
        name = f"Thread-{uuid.uuid4().hex[:8]}"
    
    url = f"{endpoint}/_conversation/threads"
    response = sdk.request(
        method="POST",
        url=url,
        headers={},
        body=json.dumps({"name": name}),
        params={}
    )
    return response['id']


def create_message(user_query: str) -> dict:
    """
    Create a message for the WebSocket API.
    
    Args:
        user_query: The user's question
    
    Returns:
        Message dictionary ready to send
    
    Example:
        {"content": {"user_query": "What happened yesterday?"}}
    """
    return {
        "content": {
            "user_query": user_query
        }
    }


# =============================================================================
# EXAMPLE 1: SIMPLE CONNECTION TEST
# =============================================================================

async def example_simple_connection():
    """
    Test basic WebSocket connection.
    
    Steps:
    1. Create a conversation thread
    2. Connect to WebSocket
    3. Verify connection is open
    """
    print("=" * 60)
    print("Example 1: Simple WebSocket Connection")
    print("=" * 60)

    access_key, secret_key, endpoint = get_credentials()
    ws = None
    sdk = None

    try:
        # Step 1: Create thread via REST API
        print("Creating conversation thread...")
        with InfinoSDK(access_key, secret_key, endpoint) as sdk_rest:
            thread_id = create_thread(sdk_rest, endpoint, "Connection Test")
        print(f"✓ Thread created: {thread_id}")

        # Step 2: Connect to WebSocket
        client_id = f"client-{uuid.uuid4().hex[:8]}"
        ws_path = f"/_conversation/ws?threadId={thread_id}&clientId={client_id}"
        
        print("Connecting to WebSocket...")
        sdk = InfinoSDK(access_key, secret_key, endpoint)
        ws = await asyncio.wait_for(sdk.websocket_connect(ws_path), timeout=10.0)
        
        print("✓ Connected successfully!")
        print(f"  Thread ID: {thread_id}")
        print(f"  Client ID: {client_id}")

    except (ConnectionError, OSError, ValueError) as e:
        print(f"✗ Error: {e}")
    finally:
        if ws:
            await ws.close()
        if sdk:
            sdk.close()
    print()


# =============================================================================
# EXAMPLE 2: SEND QUERY AND RECEIVE RESPONSE
# =============================================================================

async def example_query_response():
    """
    Send a query and receive the AI response.
    
    This example shows how to:
    - Send a user query
    - Handle streaming "update" messages (progress)
    - Receive final "result" message (answer)
    """
    print("=" * 60)
    print("Example 2: Send Query and Receive Response")
    print("=" * 60)

    access_key, secret_key, endpoint = get_credentials()
    ws = None
    sdk = None

    try:
        # Step 1: Create thread
        print("Creating conversation thread...")
        with InfinoSDK(access_key, secret_key, endpoint) as sdk_rest:
            thread_id = create_thread(sdk_rest, endpoint, "Query Test")
        print(f"✓ Thread created: {thread_id}")

        # Step 2: Connect to WebSocket
        client_id = f"client-{uuid.uuid4().hex[:8]}"
        ws_path = f"/_conversation/ws?threadId={thread_id}&clientId={client_id}"
        
        sdk = InfinoSDK(access_key, secret_key, endpoint)
        ws = await asyncio.wait_for(sdk.websocket_connect(ws_path), timeout=10.0)
        print("✓ Connected!")

        # Step 3: Send query
        query = "Hello, I want to see what happened in the last 10 days"
        message = create_message(query)
        
        print(f"\nSending: {query}")
        await ws.send(json.dumps(message))

        # Step 4: Receive responses
        print("\nWaiting for response...\n")
        
        while True:
            response = await asyncio.wait_for(ws.recv(), timeout=60.0)
            data = json.loads(response)
            content = data.get("content", {})
            msg_type = content.get("type", "")

            if msg_type == "update":
                # Progress update - show what the AI is doing
                sender = content.get("sender", "")
                message_text = content.get("message", "")
                print(f"  [{sender}] {message_text}")

            elif msg_type == "result":
                # Final response - extract the answer
                summary = content.get("summary", "")
                print(f"\n{'='*40}")
                print("RESPONSE:")
                print(f"{'='*40}")
                print(summary)
                
                # Optional: Show follow-up suggestions
                followups = content.get("followup_queries", [])
                if followups:
                    print("\nSuggested follow-ups:")
                    for q in followups[:3]:
                        print(f"  • {q}")
                break

    except asyncio.TimeoutError:
        print("✗ Timeout waiting for response")
    except (ConnectionError, OSError, ValueError) as e:
        print(f"✗ Error: {e}")
    finally:
        if ws:
            await ws.close()
        if sdk:
            sdk.close()
    print()


# =============================================================================
# EXAMPLE 3: MULTI-TURN CONVERSATION
# =============================================================================

async def example_multi_turn():
    """
    Have a multi-turn conversation with context.
    
    All messages in the same thread share conversation history,
    so the AI remembers previous questions and answers.
    """
    print("=" * 60)
    print("Example 3: Multi-turn Conversation")
    print("=" * 60)

    access_key, secret_key, endpoint = get_credentials()
    ws = None
    sdk = None

    queries = [
        "What datasets are available?",
        "Show me a sample from the first one",
        "How many records are there in total?",
    ]

    try:
        # Create thread
        print("Creating conversation thread...")
        with InfinoSDK(access_key, secret_key, endpoint) as sdk_rest:
            thread_id = create_thread(sdk_rest, endpoint, "Multi-turn Chat")
        print(f"✓ Thread created: {thread_id}")

        # Connect to WebSocket
        client_id = f"client-{uuid.uuid4().hex[:8]}"
        ws_path = f"/_conversation/ws?threadId={thread_id}&clientId={client_id}"
        
        sdk = InfinoSDK(access_key, secret_key, endpoint)
        ws = await asyncio.wait_for(sdk.websocket_connect(ws_path), timeout=10.0)
        print("✓ Connected!\n")

        # Send each query
        for i, query in enumerate(queries, 1):
            print(f"{'='*50}")
            print(f"Query {i}: {query}")
            print(f"{'='*50}")

            # Send message
            message = create_message(query)
            await ws.send(json.dumps(message))

            # Wait for result
            while True:
                response = await asyncio.wait_for(ws.recv(), timeout=90.0)
                data = json.loads(response)
                content = data.get("content", {})
                msg_type = content.get("type", "")

                if msg_type == "update":
                    sender = content.get("sender", "")
                    print(f"  [{sender}] Processing...")

                elif msg_type == "result":
                    summary = content.get("summary", "")
                    # Show first 300 chars of response
                    display = summary[:300] + "..." if len(summary) > 300 else summary
                    print(f"\nResponse: {display}\n")
                    break

            # Small delay between queries
            await asyncio.sleep(1)

        print("✓ Conversation complete!")

    except asyncio.TimeoutError:
        print("✗ Timeout")
    except (ConnectionError, OSError, ValueError) as e:
        print(f"✗ Error: {e}")
    finally:
        if ws:
            await ws.close()
        if sdk:
            sdk.close()
    print()


# =============================================================================
# EXAMPLE 4: INTERACTIVE CHAT
# =============================================================================

async def example_interactive_chat():
    """
    Interactive chat session where you can type questions.
    
    Type 'quit' or 'exit' to end the session.
    """
    print("=" * 60)
    print("Example 4: Interactive Chat")
    print("=" * 60)

    access_key, secret_key, endpoint = get_credentials()
    ws = None
    sdk = None

    try:
        # Create thread
        print("Creating conversation thread...")
        with InfinoSDK(access_key, secret_key, endpoint) as sdk_rest:
            thread_id = create_thread(sdk_rest, endpoint, "Interactive Chat")
        print(f"✓ Thread created: {thread_id}")

        # Connect
        client_id = f"client-{uuid.uuid4().hex[:8]}"
        ws_path = f"/_conversation/ws?threadId={thread_id}&clientId={client_id}"
        
        sdk = InfinoSDK(access_key, secret_key, endpoint)
        ws = await asyncio.wait_for(sdk.websocket_connect(ws_path), timeout=10.0)
        
        print("✓ Connected!")
        print("\nType your questions below. Type 'quit' to exit.\n")
        print("-" * 40)

        while True:
            # Get user input
            try:
                user_input = input("\nYou: ").strip()
            except EOFError:
                break

            if not user_input:
                continue
            if user_input.lower() in ("quit", "exit"):
                print("Goodbye!")
                break

            # Send query
            message = create_message(user_input)
            await ws.send(json.dumps(message))

            # Show progress and wait for result
            print("\nInfino: ", end="", flush=True)
            
            while True:
                response = await asyncio.wait_for(ws.recv(), timeout=90.0)
                data = json.loads(response)
                content = data.get("content", {})
                msg_type = content.get("type", "")

                if msg_type == "update":
                    sender = content.get("sender", "")
                    message_text = content.get("message", "")
                    print(f"  [{sender}] {message_text}")

                elif msg_type == "result":
                    summary = content.get("summary", "")
                    print(f"\n\n{summary}")
                    break

    except KeyboardInterrupt:
        print("\n\nChat interrupted.")
    except asyncio.TimeoutError:
        print("\n✗ Timeout")
    except (ConnectionError, OSError, ValueError) as e:
        print(f"\n✗ Error: {e}")
    finally:
        if ws:
            await ws.close()
        if sdk:
            sdk.close()
    print()


# =============================================================================
# MAIN MENU
# =============================================================================

async def main():
    """Main menu for running examples."""
    print("\n" + "=" * 60)
    print("Infino SDK - WebSocket Examples")
    print("=" * 60)
    print("""
Make sure to set environment variables:
  export INFINO_ACCESS_KEY="your_key"
  export INFINO_SECRET_KEY="your_secret"
  export INFINO_ENDPOINT="https://api.infino.ws"
""")

    print("Select an example:")
    print("  1. Simple Connection Test")
    print("  2. Send Query and Receive Response")
    print("  3. Multi-turn Conversation")
    print("  4. Interactive Chat")
    print("  0. Exit")
    print()

    while True:
        try:
            choice = input("Enter choice (0-4): ").strip()
        except EOFError:
            break

        if choice == "0":
            print("Goodbye!")
            break
        elif choice == "1":
            await example_simple_connection()
        elif choice == "2":
            await example_query_response()
        elif choice == "3":
            await example_multi_turn()
        elif choice == "4":
            await example_interactive_chat()
        else:
            print("Invalid choice. Enter 0-4.")
        print()


if __name__ == "__main__":
    asyncio.run(main())
