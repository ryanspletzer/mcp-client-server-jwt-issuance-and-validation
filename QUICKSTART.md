# Quick Start Guide

This guide will get you up and running with the OAuth2/OIDC MCP demo in under 5 minutes.

## Prerequisites

- Python 3.12 or higher
- Terminal/command prompt

## Installation

Install `uv` if you haven't already:

```bash
pip install uv
```

## Setup

Navigate to each component directory and sync dependencies:

```bash
# Identity Provider
cd identity-provider
uv sync
cd ..

# MCP Server
cd mcp-server
uv sync
cd ..

# MCP Client
cd mcp-client
uv sync
cd ..
```

## Running the Demo

### Terminal 1: Start the Identity Provider

```bash
cd identity-provider
uv run python main.py
```

Keep this running. You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### Terminal 2: Run the MCP Client

**Option A: Test with Confidential Client (client_secret)**

```bash
cd mcp-client
uv run python main.py
```

**Option B: Test with Public Client (PKCE)**

```bash
cd mcp-client
uv run python main.py --pkce
```

## What You'll See

The client will:
1. ✓ Acquire an access token from the Identity Provider
2. ✓ Connect to the MCP Server (started automatically)
3. ✓ Call three tools:
   - `hello_world`: Simple greeting
   - `get_user_info`: Extract user info from JWT token
   - `echo`: Echo a message with authentication

## Understanding the Flow

### Confidential Client (with client_secret)
- Uses client_id: `confidential-client-id`
- Uses client_secret: `confidential-client-secret`
- Standard OAuth2 flow for server-to-server authentication

### Public Client (with PKCE)
- Uses client_id: `public-client-id`
- No client_secret (not secure for public clients)
- Uses PKCE (Proof Key for Code Exchange) for enhanced security
- Ideal for mobile apps and SPAs

## Testing the Endpoints

You can also test the Identity Provider directly:

```bash
# Discovery endpoint
curl http://localhost:8000/.well-known/openid-configuration | python -m json.tool

# JWKS endpoint
curl http://localhost:8000/discovery/v2.0/keys | python -m json.tool

# Service info
curl http://localhost:8000/ | python -m json.tool
```

## Troubleshooting

**Port 8000 already in use?**
- Stop any other services using port 8000
- Or modify the `ISSUER` variable in both identity-provider and mcp-server main.py files

**MCP Server connection failed?**
- Ensure the identity provider is running on port 8000
- Check that all dependencies are installed (`uv sync` in each directory)

**Import errors?**
- Run `uv sync` in the relevant component directory
- Ensure you're using Python 3.12 or higher

## Next Steps

- Read the full [README.md](README.md) for detailed architecture and API documentation
- Experiment with modifying the token claims in `identity-provider/main.py`
- Add your own MCP tools to `mcp-server/main.py`
- Explore token expiration and refresh token flows

## Learn More

- [OAuth 2.0 RFC](https://oauth.net/2/)
- [PKCE RFC](https://oauth.net/2/pkce/)
- [OpenID Connect](https://openid.net/connect/)
- [MCP Protocol](https://modelcontextprotocol.io/)
- [FastAPI](https://fastapi.tiangolo.com/)
- [FastMCP](https://github.com/jlowin/fastmcp)
