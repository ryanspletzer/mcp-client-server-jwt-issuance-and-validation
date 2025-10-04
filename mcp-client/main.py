"""
MCP Client with OAuth2 Authorization Code Flow and PKCE
Supports both confidential clients (with client_secret) and public clients (with PKCE)
"""

import asyncio
import hashlib
import base64
import secrets
import sys
from typing import Optional, Dict, Any
import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


# Configuration
ISSUER = "http://localhost:8000"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
CLIENT_ID_CONFIDENTIAL = "confidential-client-id"
CLIENT_SECRET = "confidential-client-secret"
CLIENT_ID_PUBLIC = "public-client-id"
REDIRECT_URI = "http://localhost:9999/callback"
SCOPE = "openid profile"


def generate_pkce_pair() -> tuple[str, str]:
    """Generate PKCE code verifier and challenge"""
    # Generate code verifier (43-128 characters)
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    
    # Generate code challenge (SHA256 hash of verifier)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode('utf-8').rstrip('=')
    
    return code_verifier, code_challenge


async def discover_endpoints() -> Dict[str, str]:
    """Discover OAuth2/OIDC endpoints from discovery document"""
    async with httpx.AsyncClient() as client:
        response = await client.get(DISCOVERY_URL)
        response.raise_for_status()
        config = response.json()
        
        return {
            "authorization_endpoint": config["authorization_endpoint"],
            "token_endpoint": config["token_endpoint"],
            "jwks_uri": config["jwks_uri"],
        }


async def acquire_token_with_client_secret() -> str:
    """Acquire token using confidential client with client_secret"""
    print("\n=== Acquiring token with client_secret (Confidential Client) ===")
    
    # Discover endpoints
    endpoints = await discover_endpoints()
    auth_endpoint = endpoints["authorization_endpoint"]
    token_endpoint = endpoints["token_endpoint"]
    
    # Build authorization URL
    state = secrets.token_urlsafe(16)
    auth_url = (
        f"{auth_endpoint}?"
        f"client_id={CLIENT_ID_CONFIDENTIAL}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"response_type=code&"
        f"scope={SCOPE}&"
        f"state={state}"
    )
    
    print(f"\nAuthorization URL: {auth_url}")
    print("\nSimulating authorization flow...")
    
    # Simulate the authorization flow (in real scenario, user would be redirected)
    async with httpx.AsyncClient(follow_redirects=False) as client:
        # Get authorization code
        auth_response = await client.get(auth_url)
        
        if auth_response.status_code == 307:
            # Extract code from redirect URL
            redirect_location = auth_response.headers.get("location")
            if redirect_location and "code=" in redirect_location:
                code = redirect_location.split("code=")[1].split("&")[0]
                print(f"✓ Received authorization code: {code[:20]}...")
                
                # Exchange code for token
                print("\nExchanging authorization code for access token...")
                token_response = await client.post(
                    token_endpoint,
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": REDIRECT_URI,
                        "client_id": CLIENT_ID_CONFIDENTIAL,
                        "client_secret": CLIENT_SECRET,
                    }
                )
                token_response.raise_for_status()
                token_data = token_response.json()
                
                access_token = token_data["access_token"]
                print(f"✓ Received access token: {access_token[:50]}...")
                return access_token
    
    raise Exception("Failed to acquire token")


async def acquire_token_with_pkce() -> str:
    """Acquire token using public client with PKCE"""
    print("\n=== Acquiring token with PKCE (Public Client) ===")
    
    # Generate PKCE pair
    code_verifier, code_challenge = generate_pkce_pair()
    print(f"✓ Generated PKCE code verifier: {code_verifier[:20]}...")
    print(f"✓ Generated PKCE code challenge: {code_challenge[:20]}...")
    
    # Discover endpoints
    endpoints = await discover_endpoints()
    auth_endpoint = endpoints["authorization_endpoint"]
    token_endpoint = endpoints["token_endpoint"]
    
    # Build authorization URL with PKCE
    state = secrets.token_urlsafe(16)
    auth_url = (
        f"{auth_endpoint}?"
        f"client_id={CLIENT_ID_PUBLIC}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"response_type=code&"
        f"scope={SCOPE}&"
        f"state={state}&"
        f"code_challenge={code_challenge}&"
        f"code_challenge_method=S256"
    )
    
    print(f"\nAuthorization URL: {auth_url}")
    print("\nSimulating authorization flow...")
    
    # Simulate the authorization flow
    async with httpx.AsyncClient(follow_redirects=False) as client:
        # Get authorization code
        auth_response = await client.get(auth_url)
        
        if auth_response.status_code == 307:
            # Extract code from redirect URL
            redirect_location = auth_response.headers.get("location")
            if redirect_location and "code=" in redirect_location:
                code = redirect_location.split("code=")[1].split("&")[0]
                print(f"✓ Received authorization code: {code[:20]}...")
                
                # Exchange code for token with PKCE verifier
                print("\nExchanging authorization code for access token (with PKCE verifier)...")
                token_response = await client.post(
                    token_endpoint,
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": REDIRECT_URI,
                        "client_id": CLIENT_ID_PUBLIC,
                        "code_verifier": code_verifier,
                    }
                )
                token_response.raise_for_status()
                token_data = token_response.json()
                
                access_token = token_data["access_token"]
                print(f"✓ Received access token: {access_token[:50]}...")
                return access_token
    
    raise Exception("Failed to acquire token with PKCE")


async def connect_to_mcp_server(access_token: str):
    """Connect to MCP server and call tools with authentication"""
    print("\n=== Connecting to MCP Server ===")
    
    # Set up server parameters for stdio communication
    server_params = StdioServerParameters(
        command="python",
        args=["../mcp-server/main.py"],
        env=None,
    )
    
    print("✓ Starting MCP server via stdio...")
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            print("✓ Connected to MCP server")
            
            # Initialize the session
            await session.initialize()
            print("✓ Session initialized")
            
            # List available tools
            tools = await session.list_tools()
            print(f"\n✓ Available tools: {[tool.name for tool in tools.tools]}")
            
            # Call hello_world tool
            print("\n--- Calling hello_world tool ---")
            result = await session.call_tool("hello_world", arguments={"name": "OAuth2 Demo"})
            print(f"Result: {result.content}")
            
            # Call get_user_info tool with token
            print("\n--- Calling get_user_info tool ---")
            result = await session.call_tool("get_user_info", arguments={"auth_token": access_token})
            print(f"Result: {result.content}")
            
            # Call echo tool with token
            print("\n--- Calling echo tool ---")
            result = await session.call_tool("echo", arguments={
                "message": "This is a test message!",
                "auth_token": access_token
            })
            print(f"Result: {result.content}")
            
            # Get user profile resource
            print("\n--- Getting user profile resource ---")
            resources = await session.list_resources()
            print(f"Available resources: {[r.uri for r in resources.resources]}")
            
            if resources.resources:
                resource_result = await session.read_resource(
                    resources.resources[0].uri
                )
                print(f"Resource content:\n{resource_result.contents[0].text if resource_result.contents else 'No content'}")


async def main():
    """Main entry point"""
    print("=" * 70)
    print("MCP Client - OAuth2 Authorization Code Flow Demo")
    print("=" * 70)
    
    # Choose authentication method
    if len(sys.argv) > 1 and sys.argv[1] == "--pkce":
        use_pkce = True
    else:
        use_pkce = False
    
    print(f"\nAuthentication method: {'PKCE (Public Client)' if use_pkce else 'Client Secret (Confidential Client)'}")
    
    try:
        # Acquire token
        if use_pkce:
            access_token = await acquire_token_with_pkce()
        else:
            access_token = await acquire_token_with_client_secret()
        
        print("\n✓ Successfully acquired access token!")
        
        # Connect to MCP server and use the token
        await connect_to_mcp_server(access_token)
        
        print("\n" + "=" * 70)
        print("Demo completed successfully!")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n✗ Error: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
