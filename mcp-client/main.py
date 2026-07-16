"""
MCP Client with OAuth2 Authorization Code Flow and PKCE
Supports both confidential clients (with client_secret) and public clients (with PKCE)
"""

import argparse
import asyncio
import base64
import hashlib
import os
import secrets
import sys
import urllib.parse
from typing import Any

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


def extract_code_from_redirect(location: str | None, expected_state: str) -> str:
    """Parse an authorization redirect's Location header and return the auth code.

    This is where a real client defends against CSRF: the `state` value echoed
    back by the authorization server must match the one we originally sent.
    If it doesn't, someone may be trying to inject their own authorization
    code into our flow, and we must refuse to continue.
    """
    if not location:
        raise ValueError("Redirect response did not include a Location header")

    parsed = urllib.parse.urlparse(location)
    query_params = urllib.parse.parse_qs(parsed.query)

    returned_state = query_params.get("state", [None])[0]
    if returned_state != expected_state:
        raise ValueError(
            f"State mismatch! Expected {expected_state!r} but received "
            f"{returned_state!r}. This could indicate a CSRF attack - aborting."
        )
    print("✓ State verified (CSRF check passed)")

    code = query_params.get("code", [None])[0]
    if not code:
        raise ValueError(f"No authorization code found in redirect: {location}")

    return code


async def discover_endpoints() -> dict[str, str]:
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


async def acquire_token(use_pkce: bool) -> str:
    """Acquire an access token via the OAuth2 Authorization Code flow.

    Supports both confidential clients (client_secret) and public clients
    (PKCE), selected via `use_pkce`.
    """
    label = "PKCE (Public Client)" if use_pkce else "client_secret (Confidential Client)"
    print(f"\n=== Acquiring token with {label} ===")

    code_verifier: str | None = None
    code_challenge: str | None = None
    if use_pkce:
        code_verifier, code_challenge = generate_pkce_pair()
        print(f"✓ Generated PKCE code verifier: {code_verifier[:20]}...")
        print(f"✓ Generated PKCE code challenge: {code_challenge[:20]}...")

    # Discover endpoints
    endpoints = await discover_endpoints()
    auth_endpoint = endpoints["authorization_endpoint"]
    token_endpoint = endpoints["token_endpoint"]

    client_id = CLIENT_ID_PUBLIC if use_pkce else CLIENT_ID_CONFIDENTIAL

    # Build authorization URL. `state` is a CSRF token: we generate it here,
    # send it to the authorization server, and must verify it comes back
    # unchanged on the redirect before trusting the authorization code.
    state = secrets.token_urlsafe(16)
    params: dict[str, str] = {
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": SCOPE,
        "state": state,
    }
    if use_pkce:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"

    auth_url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"

    print(f"\nAuthorization URL: {auth_url}")
    print("\nSimulating authorization flow...")

    # Simulate the authorization flow (in real scenario, user would be redirected)
    async with httpx.AsyncClient(follow_redirects=False) as client:
        auth_response = await client.get(auth_url)

        if not auth_response.is_redirect:
            raise RuntimeError(
                "Expected a redirect from the authorization endpoint, got "
                f"status {auth_response.status_code}"
            )

        redirect_location = auth_response.headers.get("location")
        code = extract_code_from_redirect(redirect_location, state)
        print(f"✓ Received authorization code: {code[:20]}...")

        # Exchange code for token
        verifier_note = " (with PKCE verifier)" if use_pkce else ""
        print(f"\nExchanging authorization code for access token{verifier_note}...")

        token_data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
        }
        if use_pkce:
            token_data["code_verifier"] = code_verifier
        else:
            token_data["client_secret"] = CLIENT_SECRET

        token_response = await client.post(token_endpoint, data=token_data)
        token_response.raise_for_status()
        token_payload: dict[str, Any] = token_response.json()

        access_token = token_payload["access_token"]
        print(f"✓ Received access token: {access_token[:50]}...")
        return access_token


async def connect_to_mcp_server(access_token: str):
    """Connect to MCP server and call tools with authentication"""
    print("\n=== Connecting to MCP Server ===")

    # Set up server parameters for stdio communication
    mcp_server_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "mcp-server", "main.py")
    )

    server_params = StdioServerParameters(
        command="uv",
        args=["run", "--directory", os.path.dirname(mcp_server_path), "python", "main.py"],
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
            result = await session.call_tool(
                "get_user_info", arguments={"auth_token": access_token}
            )
            print(f"Result: {result.content}")

            # Call echo tool with token
            print("\n--- Calling echo tool ---")
            result = await session.call_tool("echo", arguments={
                "message": "This is a test message!",
                "auth_token": access_token
            })
            print(f"Result: {result.content}")


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser"""
    parser = argparse.ArgumentParser(
        description="MCP Client - OAuth2 Authorization Code Flow Demo"
    )
    parser.add_argument(
        "--pkce",
        action="store_true",
        help="Use PKCE (public client) instead of client_secret (confidential client)",
    )
    return parser


async def main():
    """Main entry point"""
    print("=" * 70)
    print("MCP Client - OAuth2 Authorization Code Flow Demo")
    print("=" * 70)

    args = build_arg_parser().parse_args()
    use_pkce = args.pkce

    auth_method = "PKCE (Public Client)" if use_pkce else "Client Secret (Confidential Client)"
    print(f"\nAuthentication method: {auth_method}")

    try:
        # Acquire token
        access_token = await acquire_token(use_pkce)

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
