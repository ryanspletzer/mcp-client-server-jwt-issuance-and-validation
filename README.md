# mcp-client-server-jwt-issuance-and-validation

A comprehensive demonstration of OAuth2/OIDC authentication flow with MCP (Model Context Protocol)
integration.
This project consists of three components that work together to simulate a complete authentication
and authorization workflow similar to Microsoft Entra ID (formerly Azure AD).

This demo aligns with the MCP authorization specification, revision **2025-11-25**.
It implements:

- [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) (Resource Indicators for OAuth 2.0) —
  clients declare which resource server a token is for, and the identity provider binds the
  token's `aud` claim to it
- [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) (OAuth 2.0 Protected Resource Metadata) —
  the MCP server, in HTTP mode, advertises where to find its authorization server
- [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) (OAuth 2.0 Authorization Server Metadata) —
  the identity provider publishes discovery metadata at the plain-OAuth well-known path, not just
  the OIDC one
- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) (Bearer Token Usage) — HTTP-mode tool calls
  authenticate with `Authorization: Bearer <token>`
- OAuth 2.1-style refresh token rotation — every `refresh_token` grant issues a new refresh token
  and invalidates the one that was used

> **🚀 Quick Start**: See [QUICKSTART.md](QUICKSTART.md) for a 5-minute getting started guide.

## Architecture

The project includes three independent components:

> **📐 Architecture Details**: See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed diagrams and flow charts.

1. **Identity Provider** (`identity-provider/`) - OAuth2/OIDC server that emulates Entra ID
   - Authorization Code Flow support
   - PKCE (Proof Key for Code Exchange) support, also enforced for confidential clients when a
     `code_challenge` was bound to the authorization code (RFC 7636)
   - JWT token issuance with RSA signing, `aud` bound to the requested `resource` (RFC 8707)
   - Refresh token rotation: each `refresh_token` grant issues a new refresh token and invalidates
     the one that was used
   - OIDC Discovery endpoint, plus a plain RFC 8414 authorization server metadata endpoint
   - JWKS (JSON Web Key Set) endpoint
   - Rejects unsupported `response_type` values, unregistered `resource` values
     (`invalid_target`), and URL-encodes redirect parameters

2. **MCP Server** (`mcp-server/`) - FastMCP server with JWT validation
   - Validates tokens from the identity provider
   - Selects the JWKS signing key matching the token's `kid`, refreshing the JWKS cache once if the
     key isn't found yet (handles key rotation)
   - Validates the `aud` claim against this server's own resource identifier
     (`http://localhost:8001/mcp`), rejecting tokens minted for anything else
   - Two transports, selected with `--transport`:
     - `stdio` (default): the caller passes credentials via the `MCP_ACCESS_TOKEN` environment
       variable, per the MCP spec
     - `http`: streamable HTTP with RFC 9728 protected-resource metadata and
       `Authorization: Bearer` auth, wired through FastMCP's auth provider machinery
   - Exposes MCP tools (`hello_world`, `get_user_info`, `echo`)
   - Exposes the caller's validated identity as a real MCP resource (`user://profile`)
   - Built with FastMCP framework

3. **MCP Client** (`mcp-client/`) - Client application with OAuth2 flows
   - Supports both Confidential and Public client types
   - Authorization Code Flow with client_secret
   - Authorization Code Flow with PKCE (for public clients)
   - Sends `resource=http://localhost:8001/mcp` on every authorization and token request
     (RFC 8707), so issued tokens are bound to the MCP server
   - Verifies the `state` parameter on the redirect before trusting the authorization code (CSRF
     protection)
   - Two transports, selected with `--transport` (orthogonal to `--pkce`):
     - `stdio` (default): spawns the MCP server as a subprocess and passes the token via the
       `MCP_ACCESS_TOKEN` environment variable
     - `http`: demonstrates the full MCP authorization discovery dance against a running
       `--transport http` MCP server — an unauthenticated probe, RFC 9728 metadata, RFC 8414/OIDC
       discovery of the authorization server it names, then the ordinary authorization code flow
     - CLI built with argparse (`--pkce`, `--transport`; `--help` for usage)
   - Builds authorization URLs with proper URL encoding
   - Connects to the MCP server with the acquired token and calls its tools and resource

## Prerequisites

- Python 3.12 or higher
- `uv` package manager (installed automatically if not present)

## Installation

Each component is a separate uv project with its own dependencies.
Navigate to each directory and sync dependencies:

### 1. Identity Provider

```bash
cd identity-provider
uv sync
```

### 2. MCP Server

```bash
cd mcp-server
uv sync
```

### 3. MCP Client

```bash
cd mcp-client
uv sync
```

## Usage

You need to run the components in the following order.

### Step 1: Start the Identity Provider

Open a terminal and run:

```bash
cd identity-provider
uv run python main.py
```

The identity provider will start on `http://localhost:8000`.
You should see:

```text
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

You can verify it's working by visiting:

- OIDC discovery endpoint: <http://localhost:8000/.well-known/openid-configuration>
- RFC 8414 authorization server metadata: <http://localhost:8000/.well-known/oauth-authorization-server>
- Root endpoint: <http://localhost:8000/>

### Step 2 (stdio transport): Run the MCP Client

By default the MCP client spawns the MCP server itself as a subprocess over stdio, so you don't
need a separate terminal for it.
Run `uv run python main.py --help` at any time to see all available options.

#### Option A: Using Confidential Client (with client_secret)

Open a new terminal and run:

```bash
cd mcp-client
uv run python main.py
```

#### Option B: Using Public Client (with PKCE)

```bash
cd mcp-client
uv run python main.py --pkce
```

### Step 2 (HTTP transport): Start the MCP Server, then run the MCP Client

`--transport http` runs the MCP server as its own long-lived process, protected by RFC 9728 /
Bearer-token auth, instead of being spawned per-client-run over stdio.

Open a second terminal and run:

```bash
cd mcp-server
uv run python main.py --transport http
```

The MCP server will start on `http://127.0.0.1:8001`, serving the MCP endpoint at `/mcp`.

Open a third terminal and run the client against it:

```bash
cd mcp-client
uv run python main.py --transport http
# or, for the public client / PKCE flow:
uv run python main.py --transport http --pkce
```

## How It Works

### Component Interaction Flow (stdio transport)

1. **Identity Provider starts** on port 8000 and waits for authentication requests
2. **MCP Client starts** and initiates the OAuth2 flow:
   - Generates a `state` value (CSRF token) and, if using a public client, a PKCE challenge
   - Requests an authorization code from the Identity Provider, including
     `resource=http://localhost:8001/mcp` (RFC 8707)
   - Receives the authorization code via redirect
   - Verifies the returned `state` matches before trusting the redirect (aborts on mismatch)
   - Exchanges the authorization code for a JWT access token, again sending `resource`
3. **MCP Client spawns MCP Server** as a subprocess using stdio transport, setting
   `MCP_ACCESS_TOKEN` in its environment — stdio servers have no HTTP channel to carry a
   `Bearer` header on, so the MCP spec has them read credentials from the environment instead
4. **MCP Client connects to MCP Server** and calls tools and reads the `user://profile` resource:
   - Tool calls carry no token argument; the server already has the token via its environment
   - MCP Server validates the token on first use: it fetches JWKS from the Identity Provider,
     selects the signing key matching the token's `kid` (refreshing the cache once if not found,
     to handle key rotation), and checks the `iss`, `exp`, and `aud` claims — `aud` must equal the
     MCP server's own resource identifier, not just any known client ID
   - MCP Server extracts user information from the validated token's claims
   - Returns results to the client

### Component Interaction Flow (HTTP transport)

1. **Identity Provider starts** on port 8000, **MCP Server starts** on port 8001 with
   `--transport http`
2. **MCP Client probes the MCP server** with an unauthenticated POST to `/mcp` and receives
   `401 Unauthorized` with a `WWW-Authenticate: Bearer resource_metadata="..."` header
   (RFC 6750 / RFC 9728)
3. **MCP Client fetches the RFC 9728 protected-resource metadata** at that URL, reading which
   `authorization_servers` the MCP server trusts
4. **MCP Client runs OIDC discovery** against that authorization server (the identity provider),
   using the RFC 8414-shaped document at `/.well-known/openid-configuration`
5. **MCP Client runs the ordinary authorization code flow** (client_secret or PKCE) against the
   discovered endpoints, sending `resource=http://localhost:8001/mcp` throughout
6. **MCP Client connects over streamable HTTP**, sending `Authorization: Bearer <token>` on every
   request
7. **MCP Server validates the token** via the same JWKS/`kid`/`aud` logic as stdio mode, wired
   into FastMCP's HTTP auth layer; an invalid or missing token yields `401` before any tool runs
8. **MCP Client calls tools and reads `user://profile`**; results come back over the HTTP stream

### Authentication Flows

#### Confidential Client Flow (with client_secret)

1. Client generates a `state` value and initiates the authorization request, including
   `resource=http://localhost:8001/mcp`
2. Identity provider validates `resource` against its registry and issues an authorization code,
   echoing back `state`
3. Client verifies the returned `state` matches before trusting the code (CSRF protection)
4. Client exchanges the code for an access token using client_secret, sending `resource` again;
   the issued token's `aud` is the resource, not the client_id
5. Client uses the access token to call MCP server tools

**Client Credentials:**

- Client ID: `confidential-client-id`
- Client Secret: `confidential-client-secret`

#### Public Client Flow (with PKCE)

1. Client generates a PKCE code verifier, code challenge, and a `state` value
2. Client initiates the authorization request with the code challenge and `resource`
3. Identity provider issues an authorization code and echoes back `state`
4. Client verifies the returned `state` matches before trusting the code (CSRF protection)
5. Client exchanges the code for an access token using the code verifier (proves possession) and
   `resource`
6. Client uses the access token to call MCP server tools

**Client Credentials:**

- Client ID: `public-client-id`
- No client secret (uses PKCE instead)

## What the Demo Does

When you run the MCP client, it will:

1. **Acquire Token**: Perform the OAuth2 Authorization Code flow (with or without PKCE),
   verifying the `state` parameter on the redirect and sending `resource` on every request
2. **Connect to MCP Server**: over stdio (default) or streamable HTTP (`--transport http`),
   running the full discovery dance first in HTTP mode
3. **List Tools**: Discover available MCP tools
4. **Call hello_world**: Simple greeting; tokenless by design
5. **Call get_user_info**: Extract user information from the caller's validated token
6. **Call echo**: Echo a message with authenticated user context
7. **Read user://profile**: Retrieve the same validated identity, as an MCP resource this time

## Example Output

When you run the MCP client with confidential client authentication over stdio:

```bash
cd mcp-client
uv run python main.py
```

You'll see output like this:

```text
======================================================================
MCP Client - OAuth2 Authorization Code Flow Demo
======================================================================

Authentication method: Client Secret (Confidential Client)
Transport: stdio

=== Acquiring token with client_secret (Confidential Client) ===

Authorization URL: http://localhost:8000/oauth2/v2.0/authorize?client_id=...&resource=http%3A%2F%2Flocalhost%3A8001%2Fmcp
Simulating authorization flow...
✓ State verified (CSRF check passed)
✓ Received authorization code: RhRDOk86w2FozAtifs7Z...

Exchanging authorization code for access token...
✓ Received access token: eyJhbGciOiJSUzI1NiIsImtpZCI6ImRlZmF1bHQta2V5LWlkIi...

✓ Successfully acquired access token!

=== Connecting to MCP Server (stdio) ===
✓ Starting MCP server via stdio (MCP_ACCESS_TOKEN set in its environment)...
✓ Connected to MCP server
✓ Session initialized

✓ Available tools: ['hello_world', 'get_user_info', 'echo']

--- Calling hello_world tool ---
Result: Hello, OAuth2 Demo! This message is from an authenticated MCP server.

--- Calling get_user_info tool ---
Result: {
  "user_id": "demo-user",
  "name": "Demo User demo-user",
  "email": "demo-user@example.com",
  "preferred_username": "demo-user",
  "scope": "openid profile",
  "tenant_id": "12345678-1234-1234-1234-123456789012"
}

--- Calling echo tool ---
Result: [Authenticated as Demo User demo-user] Echo: This is a test message!

--- Reading user://profile resource ---
Result: {"user_id": "demo-user", "name": "Demo User demo-user", ...}

======================================================================
Demo completed successfully!
======================================================================
```

When you run with `--transport http`, the client prints each discovery step before connecting:

```text
--- Step 1: POST http://localhost:8001/mcp without a token ---
✓ Got HTTP 401 (expected 401 Unauthorized)
✓ Parsed resource_metadata from WWW-Authenticate header: http://localhost:8001/.well-known/oauth-protected-resource/mcp

--- Step 2: GET http://localhost:8001/.well-known/oauth-protected-resource/mcp (RFC 9728 protected resource metadata) ---
✓ Protected resource: http://localhost:8001/mcp
✓ Authorization servers: ['http://localhost:8000/']

--- Step 3: OIDC discovery against authorization server http://localhost:8000 ---
...
--- Step 4: connecting to http://localhost:8001/mcp with Authorization: Bearer ... ---
✓ Connected to MCP server
```

When you run with PKCE (public client), you'll see similar output but with PKCE-specific
information:

```text
Authentication method: PKCE (Public Client)

=== Acquiring token with PKCE (Public Client) ===
✓ Generated PKCE code verifier: qUy8XdJLYaE9cX3NPYe4...
✓ Generated PKCE code challenge: UI26-pOmmj8N3p7bEjOc...
✓ State verified (CSRF check passed)
✓ Received authorization code: ...
...
```

## API Endpoints (Identity Provider)

### OIDC / OAuth Discovery

- `GET /.well-known/openid-configuration` - OpenID Connect configuration
- `GET /.well-known/oauth-authorization-server` - RFC 8414 authorization server metadata
  (identical document; for plain-OAuth clients that don't do OIDC discovery)

### JWKS

- `GET /discovery/v2.0/keys` - JSON Web Key Set

### OAuth2 Endpoints

- `GET /oauth2/v2.0/authorize` - Authorization endpoint (accepts an optional `resource` query
  parameter, RFC 8707)
- `POST /oauth2/v2.0/token` - Token endpoint (accepts an optional `resource` form parameter on
  both the `authorization_code` and `refresh_token` grants)

### Information

- `GET /` - Service information and client details

## MCP Server Endpoints (HTTP transport)

When started with `--transport http`, the MCP server additionally serves:

- `POST/GET/DELETE /mcp` - the streamable-HTTP MCP endpoint, gated by `Authorization: Bearer`
- `GET /.well-known/oauth-protected-resource/mcp` - RFC 9728 protected-resource metadata

## MCP Server Tools

### hello_world

Simple greeting tool.
Tokenless by design: in stdio mode there's nothing to check, and in HTTP mode FastMCP's auth layer
already rejects unauthenticated requests before any tool runs.

**Arguments:**

- `name` (optional): Name to greet (default: "World")

### get_user_info

Extracts user information from the caller's validated token.
No token argument: the server obtains the caller's identity itself — from the `MCP_ACCESS_TOKEN`
environment variable in stdio mode, or from the request's validated `Authorization: Bearer` token
in HTTP mode.

**Returns:**
User information including user_id, name, email, preferred_username, scope, and tenant_id

### echo

Echoes a message with authenticated user context.

**Arguments:**

- `message` (required): Message to echo

**Returns:**
The echoed message prefixed with the authenticated user's name

## MCP Server Resources

### user://profile

The caller's validated identity claims, exposed as an MCP resource rather than a tool call.
Same claims as `get_user_info`, obtained the same transport-appropriate way.

## Technical Details

### Token Format (JWT)

The identity provider issues JWT tokens with the following claims:

- `iss`: Issuer (<http://localhost:8000>)
- `sub`: Subject (user ID)
- `aud`: Audience — the requested `resource` (the MCP server) if one was sent (RFC 8707), the
  client ID otherwise. Real MCP flows always send `resource`, so `aud` is the MCP server's
  identifier in practice; validated by the MCP server against its own resource identifier,
  never a client ID
- `iat`: Issued at timestamp
- `exp`: Expiration timestamp (1 hour)
- `scope`: Requested scopes
- `tid`: Tenant ID
- `azp`: Authorized party (the client ID the token was issued to, independent of `aud`)
- `preferred_username`: User's preferred username
- `name`: User's display name
- `email`: User's email address

### Audience Binding (RFC 8707)

Binding `aud` to the resource server rather than the client ID is a core MCP-spec requirement:
a resource server must only accept tokens minted for itself.
Accepting a token just because it's validly signed by the right issuer — without checking it was
actually minted *for this resource* — is the "token passthrough" anti-pattern the spec forbids,
since it would let a token intended for one resource be replayed at another.
The MCP server enforces this with python-jose's built-in `audience=` check against its own
resource identifier (`http://localhost:8001/mcp`), rejecting anything else outright.

### PKCE Implementation

The PKCE implementation uses:

- Code verifier: 43-character random string (base64url-encoded)
- Code challenge method: S256 (SHA-256 hash) —
  the only supported method, since `plain` was removed in OAuth 2.1
- Code challenge: base64url(SHA256(code_verifier))
- Verifier comparison: constant-time (`secrets.compare_digest`)

### Security Features

- RSA 2048-bit key pair for JWT signing
- Authorization code expires in 10 minutes
- Access tokens expire in 1 hour
- Refresh tokens expire in 30 days, and rotate on every use: each `refresh_token` grant deletes
  the token that was presented and issues a new one, so a leaked-and-replayed old refresh token
  stops working once the legitimate client has rotated
- PKCE required for public clients; also verified for confidential clients when a `code_challenge`
  was bound to the authorization code (RFC 7636)
- Client secret required for confidential clients
- `state` parameter verified by the client on the redirect to prevent CSRF
- Access tokens validated by the MCP server against the token's `kid` (matching JWKS signing key,
  with a one-time cache refresh on key rotation), `iss`, `exp`, and `aud` (bound to the MCP
  server's own resource identifier, never a client ID) claims
- `resource` values validated against a registry (RFC 8707); unregistered values are rejected with
  `invalid_target`, and a `resource` sent to `/token` must match whatever was bound at `/authorize`
- Refresh tokens bound to the client they were issued to; the `refresh_token` grant revalidates
  `client_id` (and `client_secret` for the confidential client) before issuing a new access token
- Unsupported `response_type` values rejected by the authorization endpoint
- Redirect URIs pre-registered per client;
  authorization requests with an unregistered `redirect_uri` are rejected
- Only the S256 PKCE code-challenge method is accepted
  (`plain` was removed in OAuth 2.1)
- Client secrets and PKCE challenges compared in constant time
  (`secrets.compare_digest`)
- Redirect parameters URL-encoded to prevent injection
- stdio-mode credentials travel via the `MCP_ACCESS_TOKEN` environment variable, never as a tool
  argument, per the MCP spec's guidance for transports with no HTTP data channel

## Project Structure

```text
.
├── identity-provider/
│   ├── main.py               # OAuth2/OIDC server implementation
│   ├── tests/                # pytest suite
│   ├── pyproject.toml        # Dependencies (FastAPI, python-jose)
│   └── .python-version
├── mcp-server/
│   ├── main.py                # MCP server with JWT validation
│   ├── tests/                 # pytest suite
│   ├── pyproject.toml         # Dependencies (FastMCP, python-jose)
│   └── .python-version
├── mcp-client/
│   ├── main.py                # MCP client with OAuth2 flows
│   ├── tests/                 # pytest suite
│   ├── pyproject.toml         # Dependencies (mcp, httpx)
│   └── .python-version
├── .github/
│   └── workflows/
│       └── ci.yml              # CI: ruff + pytest per component, markdownlint
├── ruff.toml                   # Shared lint configuration (ruff check .)
├── .markdownlint.yaml           # markdownlint rule configuration
├── .markdownlint-cli2.yaml       # markdownlint-cli2 runner configuration
├── README.md                   # This file
├── QUICKSTART.md                # Quick start guide
├── ARCHITECTURE.md              # Architecture diagrams and flow charts
└── LICENSE
```

## Dependencies

### Identity Provider

- FastAPI: Web framework for OAuth2 endpoints
- uvicorn: ASGI server
- python-jose (>=3.4.0, for CVE fixes): JWT creation and validation
- cryptography: RSA key generation and signing

### MCP Server

- FastMCP (>=3.4, <4): MCP server framework; provides the `RemoteAuthProvider` / `TokenVerifier`
  machinery used for HTTP-mode auth and RFC 9728 metadata
- python-jose (>=3.4.0, for CVE fixes): JWT validation
- httpx: HTTP client for JWKS fetching

### MCP Client

- mcp (>=1.27, <2): MCP protocol client library; `<2` because MCP 2.0 targets the breaking
  2026-07-28 revision of the spec, out of scope for this demo
- httpx: HTTP client for OAuth2 flows and the HTTP-mode discovery dance

## Development

### Running Tests

Each component has its own pytest suite under its `tests/` directory.
Run tests from inside the component directory:

```bash
cd identity-provider
uv run pytest

cd ../mcp-server
uv run pytest

cd ../mcp-client
uv run pytest
```

### Linting

Python code is linted with [ruff](https://docs.astral.sh/ruff/) using the shared `ruff.toml` at the
repo root.
Run it from the repo root so all three components are checked with the same configuration:

```bash
uvx ruff check .
```

Markdown files are linted with [markdownlint-cli2](https://github.com/DavidAnson/markdownlint-cli2),
configured via `.markdownlint.yaml` and `.markdownlint-cli2.yaml`.
Run it from the repo root:

```bash
markdownlint-cli2 "**/*.md"
```

### Continuous Integration

`.github/workflows/ci.yml` runs on every push and pull request to `main`.
It lints and tests each component (ruff + pytest) in a matrix job, and separately lints all Markdown
files with markdownlint-cli2.

## Troubleshooting

### Identity Provider not starting

- Ensure port 8000 is not in use
- Check that all dependencies are installed: `uv sync`

### MCP Server (HTTP transport) not starting

- Ensure port 8001 is not in use
- Start it with `uv run python main.py --transport http` from `mcp-server/`

### MCP Client connection failed

- stdio mode: ensure the identity provider is running on port 8000, and that the MCP server path
  the client resolves (`../mcp-server/main.py`) is correct
- HTTP mode: ensure both the identity provider (port 8000) and the MCP server
  (`--transport http`, port 8001) are running before starting the client

### Token validation failed

- Ensure the identity provider is running and accessible
- Check that the JWKS endpoint is reachable: <http://localhost:8000/discovery/v2.0/keys>
- Confirm the token's `aud` is the MCP server's resource identifier
  (`http://localhost:8001/mcp`) — a token minted without `resource` (older, non-MCP-aware
  clients) will have `aud` set to the client ID instead and will be rejected

### stdio tool calls fail with "MCP_ACCESS_TOKEN environment variable is not set"

- This means the MCP server process didn't receive the token via its environment. If you're
  running `mcp-server/main.py` manually rather than through `mcp-client`, set
  `MCP_ACCESS_TOKEN` yourself before starting it in stdio mode.

## License

This is free and unencumbered software released into the public domain.
See LICENSE for details.

## Educational Purpose

This project is designed for educational purposes to demonstrate:

- OAuth2 Authorization Code Flow
- PKCE for public clients
- JWT token issuance and validation, with resource-bound audiences (RFC 8707)
- OIDC Discovery and RFC 8414 authorization server metadata
- RFC 9728 protected resource metadata and the MCP authorization discovery dance
- Refresh token rotation
- MCP (Model Context Protocol) integration over both stdio and streamable HTTP
- Token-based authentication in distributed systems

It should not be used in production without significant security enhancements and proper credential
management.
