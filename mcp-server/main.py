"""
MCP Server with JWT Token Validation
Validates tokens from the identity provider and provides MCP tools
"""

from typing import Any

import httpx
from fastmcp import FastMCP
from jose import JWTError, jwt

# Configuration
ISSUER = "http://localhost:8000"
JWKS_URI = f"{ISSUER}/discovery/v2.0/keys"

# The identity provider issues tokens to two clients in this demo; either
# one is an acceptable audience for tokens presented to this server.
ALLOWED_AUDIENCES = {"confidential-client-id", "public-client-id"}

# Cache for JWKS
jwks_cache: dict[str, Any] | None = None


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

        # python-jose's `audience=` parameter only accepts a single expected
        # audience, but this demo has multiple valid client audiences, so we
        # skip its built-in check and validate the audience claim ourselves.
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            issuer=ISSUER,
            options={"verify_aud": False},
        )

        if claims.get("aud") not in ALLOWED_AUDIENCES:
            raise ValueError(f"Invalid audience: {claims.get('aud')}")

        return claims

    except JWTError as e:
        raise ValueError(f"Token validation failed: {e!s}") from e


# Create FastMCP server with authentication
mcp = FastMCP("Demo MCP Server")


# Middleware to validate authorization
@mcp.tool()
async def hello_world(name: str = "World") -> str:
    """
    A simple hello world tool

    Args:
        name: The name to greet (default: "World")

    Returns:
        A greeting message
    """
    return f"Hello, {name}! This message is from an authenticated MCP server."


@mcp.tool()
async def get_user_info(auth_token: str) -> dict[str, Any]:
    """
    Get user information from the validated token

    Args:
        auth_token: The JWT access token

    Returns:
        User information extracted from the token
    """
    try:
        claims = await validate_token(auth_token)
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
async def echo(message: str, auth_token: str) -> str:
    """
    Echo a message back with authentication

    Args:
        message: The message to echo
        auth_token: The JWT access token for authentication

    Returns:
        The echoed message with user information
    """
    try:
        claims = await validate_token(auth_token)
        user_name = claims.get("name", "Unknown User")
        return f"[Authenticated as {user_name}] Echo: {message}"
    except ValueError as e:
        return f"Authentication failed: {e!s}"


def main():
    """Run the MCP server"""
    # FastMCP handles the server lifecycle
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
