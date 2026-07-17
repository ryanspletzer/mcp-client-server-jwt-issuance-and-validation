# Quick Start Guide

This guide will get you up and running with the OAuth2/OIDC MCP demo in under 5 minutes.

This demo aligns with the MCP authorization specification, revision **2025-11-25** — see
[README.md](README.md) for the RFCs it implements.

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

## Running the Demo (stdio transport)

This is the default and simplest path: the client spawns the MCP server itself as a subprocess.

### Terminal 1: Start the Identity Provider

```bash
cd identity-provider
uv run python main.py
```

Keep this running.
You should see:

```text
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### Terminal 2: Run the MCP Client

The client is built with argparse; run `uv run python main.py --help` to see all available options.

#### Option A: Test with Confidential Client (client_secret)

```bash
cd mcp-client
uv run python main.py
```

#### Option B: Test with Public Client (PKCE)

```bash
cd mcp-client
uv run python main.py --pkce
```

## Running the Demo (HTTP transport)

`--transport http` runs the MCP server as a standalone process, protected by RFC 9728 metadata
and `Authorization: Bearer` tokens instead of the `MCP_ACCESS_TOKEN` environment variable used in
stdio mode.
This needs three terminals.

### Terminal A: Start the Identity Provider

```bash
cd identity-provider
uv run python main.py
```

### Terminal B: Start the MCP Server in HTTP mode

```bash
cd mcp-server
uv run python main.py --transport http
```

You should see it start on `http://127.0.0.1:8001`, serving the MCP endpoint at `/mcp`.

### Terminal C: Run the MCP Client against it

```bash
cd mcp-client
uv run python main.py --transport http
# or, for the public client / PKCE flow:
uv run python main.py --transport http --pkce
```

## What You'll See

The client will:

1. ✓ Discover the authorization server — directly via OIDC discovery in stdio mode, or via the
   full RFC 9728 discovery dance (unauthenticated 401, protected-resource metadata, then OIDC
   discovery against whatever authorization server that metadata names) in HTTP mode
2. ✓ Acquire an access token from the Identity Provider, sending `resource=http://localhost:8001/mcp`
   on both the authorization and token requests (RFC 8707)
3. ✓ Verify the `state` parameter on the redirect (CSRF protection) before trusting the
   authorization code
4. ✓ Connect to the MCP Server — over stdio (spawned automatically, credentials passed via the
   `MCP_ACCESS_TOKEN` environment variable) or streamable HTTP (`Authorization: Bearer <token>`)
5. ✓ Call three tools:
   - `hello_world`: Simple greeting
   - `get_user_info`: Extract user info from the validated token
   - `echo`: Echo a message with authentication
6. ✓ Read the `user://profile` MCP resource: the same validated identity, as a resource instead
   of a tool call

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

### stdio vs. HTTP transport

- `--transport stdio` (default): the client spawns the MCP server as a subprocess and passes the
  access token via the `MCP_ACCESS_TOKEN` environment variable — stdio has no HTTP channel to
  carry a `Bearer` header on, so the MCP spec has servers read credentials from the environment
  instead
- `--transport http`: the client connects to an already-running `mcp-server --transport http`
  process over streamable HTTP, discovering the authorization server dynamically and
  authenticating with `Authorization: Bearer <token>` on every request

## Testing the Endpoints

You can also test the Identity Provider directly:

```bash
# OIDC discovery endpoint
curl http://localhost:8000/.well-known/openid-configuration | python -m json.tool

# RFC 8414 authorization server metadata (same document, plain-OAuth well-known path)
curl http://localhost:8000/.well-known/oauth-authorization-server | python -m json.tool

# JWKS endpoint
curl http://localhost:8000/discovery/v2.0/keys | python -m json.tool

# Service info
curl http://localhost:8000/ | python -m json.tool
```

With the MCP server running in HTTP mode, you can see the RFC 9728 discovery dance for yourself:

```bash
# Unauthenticated request -> 401 with a WWW-Authenticate header
curl -i -X POST http://localhost:8001/mcp

# Protected resource metadata named by that header
curl http://localhost:8001/.well-known/oauth-protected-resource/mcp | python -m json.tool
```

## Troubleshooting

**Port 8000 already in use?**

- Stop any other services using port 8000
- Or modify the `ISSUER` variable in identity-provider, mcp-server, and mcp-client main.py files

**Port 8001 (HTTP transport) already in use?**

- Stop any other services using port 8001
- Or modify `MCP_RESOURCE` / `MCP_HTTP_PORT` in mcp-server/main.py and the matching `MCP_RESOURCE`
  constants in identity-provider/main.py and mcp-client/main.py

**MCP Server connection failed?**

- stdio mode: ensure the identity provider is running on port 8000
- HTTP mode: ensure both the identity provider (port 8000) and `mcp-server --transport http`
  (port 8001) are running before starting the client
- Check that all dependencies are installed (`uv sync` in each directory)

**"MCP_ACCESS_TOKEN environment variable is not set"?**

- This means a stdio-mode MCP server process didn't get a token via its environment.
  The client sets this automatically; if you're running `mcp-server/main.py` by hand, set
  `MCP_ACCESS_TOKEN` yourself first.

**Import errors?**

- Run `uv sync` in the relevant component directory
- Ensure you're using Python 3.12 or higher

## Next Steps

- Read the full [README.md](README.md) for detailed architecture and API documentation
- Experiment with modifying the token claims in `identity-provider/main.py`
- Add your own MCP tools to `mcp-server/main.py`
- Explore refresh token rotation: call the `refresh_token` grant twice with the same token and
  watch the second call fail
- Run each component's test suite with `uv run pytest` (see the Development section in
  [README.md](README.md))

## Learn More

- [OAuth 2.0 RFC](https://oauth.net/2/)
- [PKCE RFC](https://oauth.net/2/pkce/)
- [RFC 8707: Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707)
- [RFC 8414: OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414)
- [RFC 9728: OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728)
- [OpenID Connect](https://openid.net/connect/)
- [MCP Protocol](https://modelcontextprotocol.io/)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [FastAPI](https://fastapi.tiangolo.com/)
- [FastMCP](https://github.com/jlowin/fastmcp)
