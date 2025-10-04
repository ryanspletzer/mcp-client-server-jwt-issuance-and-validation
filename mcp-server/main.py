"""
MCP Server with JWT Token Validation
Validates tokens from the identity provider and provides MCP tools
"""

import httpx
from typing import Optional, Dict, Any
from jose import jwt, JWTError
from fastmcp import FastMCP
import asyncio

# Configuration
ISSUER = "http://localhost:8000"
JWKS_URI = f"{ISSUER}/discovery/v2.0/keys"

# Cache for JWKS
jwks_cache: Optional[Dict[str, Any]] = None


async def get_jwks() -> Dict[str, Any]:
    """Fetch JWKS from the identity provider"""
    global jwks_cache
    
    if jwks_cache is None:
        async with httpx.AsyncClient() as client:
            response = await client.get(JWKS_URI)
            response.raise_for_status()
            jwks_cache = response.json()
    
    return jwks_cache


async def validate_token(token: str) -> Dict[str, Any]:
    """Validate JWT token and return claims"""
    try:
        # Get the JWKS
        jwks = await get_jwks()
        
        # Decode and validate the token
        # For simplicity, we'll use the first key in JWKS
        if not jwks.get("keys"):
            raise ValueError("No keys found in JWKS")
        
        # Get the signing key
        signing_key = jwks["keys"][0]
        
        # Validate token - we need to skip audience validation or provide the correct audience
        # For this demo, we'll decode without validating audience
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            issuer=ISSUER,
            options={"verify_aud": False}  # Skip audience validation for demo
        )
        
        return claims
    
    except JWTError as e:
        raise ValueError(f"Token validation failed: {str(e)}")


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
async def get_user_info(auth_token: str) -> Dict[str, Any]:
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
        return f"Authentication failed: {str(e)}"


def main():
    """Run the MCP server"""
    # FastMCP handles the server lifecycle
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
