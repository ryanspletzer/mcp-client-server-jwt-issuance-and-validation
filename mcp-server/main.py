"""
MCP Server with JWT Token Validation
Validates tokens from the identity provider and provides MCP tools
"""

import argparse
import os
from typing import Any

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken, RemoteAuthProvider, TokenVerifier
from fastmcp.server.dependencies import get_access_token
from jose import JWTError, jwt
from pydantic import AnyHttpUrl

# Configuration
ISSUER = "http://localhost:8000"
JWKS_URI = f"{ISSUER}/discovery/v2.0/keys"

# Canonical resource identifier of this MCP server, per RFC 8707 (Resource
# Indicators for OAuth 2.0) and the MCP authorization spec. This is the URL
# FastMCP's RemoteAuthProvider advertises as `resource` in its RFC 9728
# protected-resource metadata when base_url="http://localhost:8001" and the
# streamable-HTTP path is "/mcp" (FastMCP computes resource = base_url +
# path — verified against fastmcp/server/auth/auth.py's
# AuthProvider._get_resource_url and fastmcp/server/http.py's
# create_streamable_http_app). It must match the constant of the same name
# in identity-provider/main.py and mcp-client/main.py exactly — the three
# components are independent processes/packages in this demo, so the value
# is kept in sync by convention rather than a shared import.
#
# stdio-mode servers have no URL of their own — there's no HTTP endpoint to
# be "the resource" — but we still use this identifier as the token
# `aud` in stdio mode too, so a client only ever has to mint one kind of
# token (resource-bound to this identifier) regardless of which transport
# it ends up talking over.
MCP_RESOURCE = "http://localhost:8001/mcp"
MCP_BASE_URL = "http://localhost:8001"  # base_url + MCP_HTTP_PATH == MCP_RESOURCE
MCP_HTTP_HOST = "127.0.0.1"
MCP_HTTP_PORT = 8001
MCP_HTTP_PATH = "/mcp"

# Cache for JWKS
jwks_cache: dict[str, Any] | None = None

# Which transport this process is running under. Set by main() before
# mcp.run() based on --transport; read by get_current_claims() to decide how
# to obtain the caller's identity. Defaults to "stdio" so anything that
# imports this module without going through main() (tests, in particular)
# behaves like the original stdio-only server.
_TRANSPORT_MODE = "stdio"


async def get_jwks(force_refresh: bool = False) -> dict[str, Any]:
    """Fetch JWKS from the identity provider, using a cached copy unless
    force_refresh is set (e.g. when a token's kid isn't found, which can
    happen after the identity provider rotates its signing keys)."""
    global jwks_cache

    if jwks_cache is None or force_refresh:
        async with httpx.AsyncClient() as client:
            response = await client.get(JWKS_URI)
            response.raise_for_status()
            jwks_cache = response.json()

    return jwks_cache


def _find_key(jwks: dict[str, Any], kid: str) -> dict[str, Any] | None:
    """Find the JWKS key matching the given kid, if any."""
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return key
    return None


async def validate_token(token: str) -> dict[str, Any]:
    """Validate JWT token and return claims"""
    try:
        # Figure out which key signed this token so we validate against the
        # matching JWKS entry instead of assuming a single/first key.
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")

        jwks = await get_jwks()
        signing_key = _find_key(jwks, kid)

        if signing_key is None:
            # The key may not be in our cache yet, e.g. the identity
            # provider rotated its signing keys. Refresh once and retry.
            jwks = await get_jwks(force_refresh=True)
            signing_key = _find_key(jwks, kid)

        if signing_key is None:
            raise ValueError(f"No matching signing key found for kid {kid}")

        # This server has exactly one valid audience: its own resource
        # identifier. python-jose's built-in `audience=` check enforces that
        # directly, which is the MCP spec's audience-binding requirement in
        # practice — a token minted for some other resource (or bound only
        # to an OAuth client_id, never a resource) is rejected by jose
        # itself before we ever see the claims. That's what closes off the
        # "token passthrough" anti-pattern the spec forbids: this server
        # will not accept a token just because it's a validly-signed JWT
        # from the right issuer if it wasn't minted for *this* resource.
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=MCP_RESOURCE,
        )

        return claims

    except JWTError as e:
        raise ValueError(f"Token validation failed: {e!s}") from e


class JoseTokenVerifier(TokenVerifier):
    """Adapts the hand-rolled `validate_token` above to FastMCP's HTTP auth.

    The JWKS-fetch-and-jose-decode logic in `validate_token` stays the
    teaching centerpiece of this server; this class just bridges it to the
    interface `RemoteAuthProvider` expects (`verify_token` returning a
    FastMCP `AccessToken` or None). It stashes the full claim set on
    `AccessToken.claims` — a field FastMCP's AccessToken carries specifically
    for this purpose (see fastmcp/server/auth/auth.py) — so tools can get at
    the caller's identity via `get_access_token()` in HTTP mode.
    """

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            claims = await validate_token(token)
        except ValueError:
            return None

        scope = claims.get("scope", "")
        return AccessToken(
            token=token,
            client_id=claims.get("azp") or claims.get("aud", ""),
            scopes=scope.split() if scope else [],
            expires_at=claims.get("exp"),
            resource=claims.get("aud"),
            claims=claims,
        )


# Built once at import time (cheap — no I/O), but only wired onto `mcp.auth`
# in main() if --transport http is requested. In stdio mode `mcp.auth` stays
# None, matching the original no-auth-object stdio behavior.
_http_auth_provider = RemoteAuthProvider(
    token_verifier=JoseTokenVerifier(),
    authorization_servers=[AnyHttpUrl(ISSUER)],
    base_url=MCP_BASE_URL,
)


_stdio_claims_cache: dict[str, Any] | None = None


async def _get_stdio_claims() -> dict[str, Any]:
    """Validate (once) and cache the token this stdio server was started with.

    Per the MCP spec, stdio servers have no HTTP data channel to carry a
    Bearer header on, so credentials travel via the environment instead: the
    MCP_ACCESS_TOKEN variable the client sets when it spawns this process
    (see mcp-client/main.py). Validation happens lazily, on first use by a
    tool that actually needs identity, rather than at process startup, so
    e.g. hello_world still works even if the variable is missing.
    """
    global _stdio_claims_cache
    if _stdio_claims_cache is None:
        token = os.environ.get("MCP_ACCESS_TOKEN")
        if not token:
            raise ValueError(
                "MCP_ACCESS_TOKEN environment variable is not set. In stdio "
                "mode the caller must pass the access token via the "
                "environment, not as a tool argument - see how mcp-client/"
                "main.py sets env={'MCP_ACCESS_TOKEN': ...} on "
                "StdioServerParameters."
            )
        _stdio_claims_cache = await validate_token(token)
    return _stdio_claims_cache


async def get_current_claims() -> dict[str, Any]:
    """Return the validated claims for the caller of the current tool call.

    Dispatches on which transport this process is running under so tools
    stay transport-agnostic:
    - http: FastMCP's auth layer (JoseTokenVerifier, above) already
      validated the Bearer token before the tool ran; we just read the
      claims it stashed on the current request's AccessToken.
    - stdio: there's no per-request auth layer, so we validate (and cache)
      the token from MCP_ACCESS_TOKEN the first time it's needed.
    """
    if _TRANSPORT_MODE == "http":
        access_token = get_access_token()
        if access_token is None:
            raise ValueError("No authenticated access token in the current request context")
        return access_token.claims or {}
    return await _get_stdio_claims()


# Create FastMCP server. `auth` is left unset here and only assigned in
# main() for --transport http, since the auth provider must be known before
# mcp.run(transport="http", ...) builds the ASGI app, but stdio mode must
# not advertise (or require) any auth machinery at all.
mcp = FastMCP("Demo MCP Server")


@mcp.tool()
async def hello_world(name: str = "World") -> str:
    """
    A simple hello world tool

    Args:
        name: The name to greet (default: "World")

    Returns:
        A greeting message
    """
    # Tokenless by design. In stdio mode there's nothing to check anyway.
    # In HTTP mode, FastMCP's auth layer (RequireAuthMiddleware, wired up by
    # RemoteAuthProvider) already rejects unauthenticated requests with a
    # 401 before the /mcp endpoint — and therefore this tool — is ever
    # reached, so a request that gets this far is implicitly authenticated
    # even though the tool itself doesn't look at the token.
    return f"Hello, {name}! This message is from an authenticated MCP server."


@mcp.tool()
async def get_user_info() -> dict[str, Any]:
    """
    Get user information from the caller's validated token.

    Returns:
        User information extracted from the token's claims
    """
    try:
        claims = await get_current_claims()
        return {
            "user_id": claims.get("sub"),
            "name": claims.get("name"),
            "email": claims.get("email"),
            "preferred_username": claims.get("preferred_username"),
            "scope": claims.get("scope"),
            "tenant_id": claims.get("tid"),
        }
    except ValueError as e:
        return {"error": str(e)}


@mcp.tool()
async def echo(message: str) -> str:
    """
    Echo a message back, tagged with the caller's identity.

    Args:
        message: The message to echo

    Returns:
        The echoed message with user information
    """
    try:
        claims = await get_current_claims()
        user_name = claims.get("name", "Unknown User")
        return f"[Authenticated as {user_name}] Echo: {message}"
    except ValueError as e:
        return f"Authentication failed: {e!s}"


@mcp.resource("user://profile")
async def user_profile() -> dict[str, Any]:
    """
    The caller's validated identity, as an MCP resource rather than a tool.

    Works the same way in both transports via get_current_claims().
    """
    claims = await get_current_claims()
    return {
        "user_id": claims.get("sub"),
        "name": claims.get("name"),
        "email": claims.get("email"),
        "preferred_username": claims.get("preferred_username"),
        "scope": claims.get("scope"),
        "tenant_id": claims.get("tid"),
    }


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser"""
    parser = argparse.ArgumentParser(description="MCP Server with JWT token validation")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help=(
            "Transport to serve on: 'stdio' (default; credentials via the "
            "MCP_ACCESS_TOKEN environment variable) or 'http' (streamable "
            "HTTP with RFC 9728 protected-resource metadata and Bearer auth)"
        ),
    )
    return parser


def main():
    """Run the MCP server"""
    global _TRANSPORT_MODE

    args = build_arg_parser().parse_args()
    _TRANSPORT_MODE = args.transport

    if args.transport == "http":
        mcp.auth = _http_auth_provider
        mcp.run(transport="http", host=MCP_HTTP_HOST, port=MCP_HTTP_PORT, path=MCP_HTTP_PATH)
    else:
        # FastMCP handles the server lifecycle
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
