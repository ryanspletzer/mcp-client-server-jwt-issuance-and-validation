"""
MCP Client with OAuth2 Authorization Code Flow and PKCE
Supports both confidential clients (with client_secret) and public clients (with PKCE)
"""

import argparse
import asyncio
import base64
import hashlib
import os
import re
import secrets
import sys
import urllib.parse
from typing import Any

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from pydantic import AnyUrl

# Configuration
ISSUER = "http://localhost:8000"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
CLIENT_ID_CONFIDENTIAL = "confidential-client-id"
CLIENT_SECRET = "confidential-client-secret"  # noqa: S105 — intentional demo credential, see README
CLIENT_ID_PUBLIC = "public-client-id"
REDIRECT_URI = "http://localhost:9999/callback"
SCOPE = "openid profile"

# Canonical resource identifier of the MCP server, per RFC 8707. Must match
# the constant of the same name in identity-provider/main.py and
# mcp-server/main.py exactly — the three components are independent
# processes/packages in this demo, so the value is kept in sync by
# convention rather than a shared import. This is also the streamable-HTTP
# URL the client connects to in --transport http mode.
MCP_RESOURCE = "http://localhost:8001/mcp"


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


async def discover_endpoints(discovery_url: str = DISCOVERY_URL) -> dict[str, str]:
    """Discover OAuth2/OIDC endpoints from a discovery document.

    Parameterized by `discovery_url` so this same helper serves both the
    identity provider's own OIDC discovery (stdio mode, using the module
    default) and the dynamic discovery-against-whatever-authorization-server-
    the-resource-names flow used in HTTP mode (see
    `discover_protected_resource_metadata` / `acquire_token_http`).
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(discovery_url)
        response.raise_for_status()
        config = response.json()

        return {
            "authorization_endpoint": config["authorization_endpoint"],
            "token_endpoint": config["token_endpoint"],
            "jwks_uri": config["jwks_uri"],
        }


async def acquire_token(use_pkce: bool, discovery_url: str = DISCOVERY_URL) -> str:
    """Acquire an access token via the OAuth2 Authorization Code flow.

    Supports both confidential clients (client_secret) and public clients
    (PKCE), selected via `use_pkce`. `discovery_url` selects which
    authorization server to run the flow against — the identity provider by
    default, or an authorization server discovered dynamically in HTTP mode.
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
    endpoints = await discover_endpoints(discovery_url)
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
        # RFC 8707 resource indicator: MCP clients MUST send `resource` on
        # the authorization request, identifying which resource server (the
        # MCP server) the requested token is for. We send it regardless of
        # whether this particular authorization server advertises
        # resource-indicator support in its discovery metadata — the MCP
        # spec requires it unconditionally, not just opportunistically.
        "resource": MCP_RESOURCE,
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
            # RFC 8707: send `resource` on the token request too, so the
            # issued access token's `aud` is bound to the MCP server rather
            # than defaulting to this client's own client_id.
            "resource": MCP_RESOURCE,
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


async def discover_protected_resource_metadata(mcp_url: str) -> dict[str, Any]:
    """Steps 1-2 of the MCP authorization discovery dance.

    1. POST to the MCP endpoint with no Authorization header. A
       spec-compliant resource server must respond 401 with a
       `WWW-Authenticate` header carrying a `resource_metadata` URL
       (RFC 9728 §5.1 / RFC 6750 §3).
    2. GET that URL and return the RFC 9728 protected-resource metadata
       document, which lists the resource's `authorization_servers`.

    Falls back to the RFC 9728 §3.1 well-known path convention
    (`/.well-known/oauth-protected-resource<resource-path>`) if the
    `WWW-Authenticate` header doesn't include `resource_metadata` — some
    resource servers only publish it at the conventional location.
    """
    async with httpx.AsyncClient() as client:
        print(f"\n--- Step 1: POST {mcp_url} without a token ---")
        probe = await client.post(
            mcp_url, headers={"Accept": "application/json, text/event-stream"}
        )
        print(f"✓ Got HTTP {probe.status_code} (expected 401 Unauthorized)")

        www_authenticate = probe.headers.get("www-authenticate", "")
        match = re.search(r'resource_metadata="([^"]+)"', www_authenticate)
        if match:
            metadata_url = match.group(1)
            print(f"✓ Parsed resource_metadata from WWW-Authenticate header: {metadata_url}")
        else:
            parsed = urllib.parse.urlparse(mcp_url)
            resource_path = parsed.path if parsed.path != "/" else ""
            metadata_url = (
                f"{parsed.scheme}://{parsed.netloc}"
                f"/.well-known/oauth-protected-resource{resource_path}"
            )
            print(
                "✗ No resource_metadata in WWW-Authenticate header; "
                f"falling back to the well-known path: {metadata_url}"
            )

        print(f"\n--- Step 2: GET {metadata_url} (RFC 9728 protected resource metadata) ---")
        metadata_response = await client.get(metadata_url)
        metadata_response.raise_for_status()
        metadata: dict[str, Any] = metadata_response.json()
        print(f"✓ Protected resource: {metadata.get('resource')}")
        print(f"✓ Authorization servers: {metadata.get('authorization_servers')}")
        return metadata


async def acquire_token_http(use_pkce: bool) -> str:
    """Acquire an access token for HTTP-mode use via the full discovery dance.

    Runs the RFC 9728 protected-resource discovery (steps 1-2), then OIDC
    discovery against whichever authorization server the resource names
    (step 3), then the ordinary authorization code flow with `resource`
    attached (step 4's token half — the connection itself is step 4's
    other half, done by the caller once it has this token).
    """
    metadata = await discover_protected_resource_metadata(MCP_RESOURCE)
    authorization_servers = metadata.get("authorization_servers") or []
    if not authorization_servers:
        raise RuntimeError(
            "Protected resource metadata did not list any authorization_servers"
        )
    issuer = str(authorization_servers[0]).rstrip("/")

    print(f"\n--- Step 3: OIDC discovery against authorization server {issuer} ---")
    discovery_url = f"{issuer}/.well-known/openid-configuration"
    return await acquire_token(use_pkce, discovery_url=discovery_url)


async def _run_tool_demo(session: ClientSession) -> None:
    """List tools, call each one, and read the user://profile resource.

    Shared between stdio and HTTP connection paths so both transports
    exercise the same demo surface.
    """
    tools = await session.list_tools()
    print(f"\n✓ Available tools: {[tool.name for tool in tools.tools]}")

    # Call hello_world tool
    print("\n--- Calling hello_world tool ---")
    result = await session.call_tool("hello_world", arguments={"name": "OAuth2 Demo"})
    print(f"Result: {result.content}")

    # Call get_user_info tool. No auth_token argument: the server obtains
    # the caller's identity itself (env var in stdio mode, the validated
    # Bearer token in HTTP mode) rather than trusting a client-supplied
    # token as a plain tool argument.
    print("\n--- Calling get_user_info tool ---")
    result = await session.call_tool("get_user_info", arguments={})
    print(f"Result: {result.content}")

    # Call echo tool
    print("\n--- Calling echo tool ---")
    result = await session.call_tool("echo", arguments={"message": "This is a test message!"})
    print(f"Result: {result.content}")

    # Read the user://profile resource - the same validated identity as
    # get_user_info, but surfaced as an MCP resource instead of a tool call.
    print("\n--- Reading user://profile resource ---")
    resource_result = await session.read_resource(AnyUrl("user://profile"))
    print(f"Result: {resource_result.contents}")


async def connect_to_mcp_server_stdio(access_token: str):
    """Connect to the MCP server over stdio and call its tools."""
    print("\n=== Connecting to MCP Server (stdio) ===")

    # Set up server parameters for stdio communication
    mcp_server_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "mcp-server", "main.py")
    )

    # Per the MCP spec, stdio servers have no HTTP data channel to carry a
    # Bearer token on, so credentials travel via the environment instead of
    # a tool argument. mcp.client.stdio.stdio_client merges this dict with
    # get_default_environment()'s safe subset of the current environment
    # (see mcp/client/stdio/__init__.py: `{**get_default_environment(),
    # **server.env}` when env is not None) rather than replacing it
    # outright, so `uv run` still resolves normally inside the spawned
    # server process.
    server_params = StdioServerParameters(
        command="uv",
        args=["run", "--directory", os.path.dirname(mcp_server_path), "python", "main.py"],
        env={"MCP_ACCESS_TOKEN": access_token},
    )

    print("✓ Starting MCP server via stdio (MCP_ACCESS_TOKEN set in its environment)...")

    async with (
        stdio_client(server_params) as (read, write),
        ClientSession(read, write) as session,
    ):
        print("✓ Connected to MCP server")

        # Initialize the session
        await session.initialize()
        print("✓ Session initialized")

        await _run_tool_demo(session)


async def connect_to_mcp_server_http(access_token: str):
    """Connect to the MCP server over streamable HTTP and call its tools.

    This is step 4 of the discovery dance: with a resource-bound access
    token in hand, connect to the MCP endpoint sending it as
    `Authorization: Bearer <token>`.
    """
    print("\n=== Connecting to MCP Server (streamable HTTP) ===")
    print(f"\n--- Step 4: connecting to {MCP_RESOURCE} with Authorization: Bearer ... ---")

    async with (
        httpx.AsyncClient(headers={"Authorization": f"Bearer {access_token}"}) as http_client,
        streamable_http_client(MCP_RESOURCE, http_client=http_client) as (
            read,
            write,
            _get_session_id,
        ),
        ClientSession(read, write) as session,
    ):
        print("✓ Connected to MCP server")

        await session.initialize()
        print("✓ Session initialized")

        await _run_tool_demo(session)


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
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help=(
            "Transport to talk to the MCP server over: 'stdio' (default; "
            "spawns the server as a subprocess) or 'http' (streamable HTTP "
            "against a server already running with --transport http, "
            "demonstrating the full 401 -> RFC 9728 -> RFC 8414/OIDC -> "
            "RFC 8707 discovery dance)"
        ),
    )
    return parser


async def main():
    """Main entry point"""
    print("=" * 70)
    print("MCP Client - OAuth2 Authorization Code Flow Demo")
    print("=" * 70)

    args = build_arg_parser().parse_args()
    use_pkce = args.pkce
    transport = args.transport

    auth_method = "PKCE (Public Client)" if use_pkce else "Client Secret (Confidential Client)"
    print(f"\nAuthentication method: {auth_method}")
    print(f"Transport: {transport}")

    try:
        # Acquire token. HTTP mode discovers the authorization server
        # dynamically from the MCP server's own protected-resource
        # metadata; stdio mode talks to the identity provider directly
        # since there's no HTTP resource server to discover it from.
        if transport == "http":
            access_token = await acquire_token_http(use_pkce)
        else:
            access_token = await acquire_token(use_pkce)

        print("\n✓ Successfully acquired access token!")

        # Connect to MCP server and use the token
        if transport == "http":
            await connect_to_mcp_server_http(access_token)
        else:
            await connect_to_mcp_server_stdio(access_token)

        print("\n" + "=" * 70)
        print("Demo completed successfully!")
        print("=" * 70)

    except Exception as e:
        print(f"\n✗ Error: {e!s}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
