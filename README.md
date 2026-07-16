# mcp-client-server-jwt-issuance-and-validation

A comprehensive demonstration of OAuth2/OIDC authentication flow with MCP (Model Context Protocol)
integration.
This project consists of three components that work together to simulate a complete authentication
and authorization workflow similar to Microsoft Entra ID (formerly Azure AD).

> **🚀 Quick Start**: See [QUICKSTART.md](QUICKSTART.md) for a 5-minute getting started guide.

## Architecture

The project includes three independent components:

> **📐 Architecture Details**: See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed diagrams and flow charts.

1. **Identity Provider** (`identity-provider/`) - OAuth2/OIDC server that emulates Entra ID
   - Authorization Code Flow support
   - PKCE (Proof Key for Code Exchange) support, also enforced for confidential clients when a
     `code_challenge` was bound to the authorization code (RFC 7636)
   - JWT token issuance with RSA signing
   - OIDC Discovery endpoint
   - JWKS (JSON Web Key Set) endpoint
   - Rejects unsupported `response_type` values and URL-encodes redirect parameters

2. **MCP Server** (`mcp-server/`) - FastMCP server with JWT validation
   - Validates tokens from the identity provider
   - Selects the JWKS signing key matching the token's `kid`, refreshing the JWKS cache once if the
     key isn't found yet (handles key rotation)
   - Validates the `aud` claim against the known client IDs
   - Exposes MCP tools (hello_world, get_user_info, echo)
   - Provides user profile as an MCP resource
   - Built with FastMCP framework

3. **MCP Client** (`mcp-client/`) - Client application with OAuth2 flows
   - Supports both Confidential and Public client types
   - Authorization Code Flow with client_secret
   - Authorization Code Flow with PKCE (for public clients)
   - Verifies the `state` parameter on the redirect before trusting the authorization code (CSRF
     protection)
   - CLI built with argparse (`--pkce` flag; `--help` for usage)
   - Builds authorization URLs with proper URL encoding
   - Connects to MCP server with acquired tokens
   - Demonstrates tool calling with authentication

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

You need to run the components in the following order:

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

- Discovery endpoint: <http://localhost:8000/.well-known/openid-configuration>
- Root endpoint: <http://localhost:8000/>

### Step 2: Run the MCP Client (which starts the MCP Server)

The MCP client automatically starts the MCP server as a subprocess for stdio communication.
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

## How It Works

### Component Interaction Flow

1. **Identity Provider starts** on port 8000 and waits for authentication requests
2. **MCP Client starts** and initiates the OAuth2 flow:
   - Generates a `state` value (CSRF token) and, if using a public client, a PKCE challenge
   - Requests authorization code from Identity Provider
   - Receives authorization code via redirect
   - Verifies the returned `state` matches before trusting the redirect (aborts on mismatch)
   - Exchanges authorization code for JWT access token
3. **MCP Client spawns MCP Server** as a subprocess using stdio transport
4. **MCP Client connects to MCP Server** and calls tools:
   - Passes JWT token as a parameter to authenticated tools
   - MCP Server validates the token: it fetches JWKS from the Identity Provider, selects the signing
     key matching the token's `kid` (refreshing the cache once if not found, to handle key rotation),
     and checks the `aud` claim against the known client IDs
   - MCP Server extracts user information from validated token
   - Returns results to the client

### Authentication Flows

#### Confidential Client Flow (with client_secret)

1. Client generates a `state` value and initiates authorization request
2. Identity provider issues authorization code and echoes back the `state`
3. Client verifies the returned `state` matches before trusting the code (CSRF protection)
4. Client exchanges code for access token using client_secret
5. Client uses access token to call MCP server tools

**Client Credentials:**

- Client ID: `confidential-client-id`
- Client Secret: `confidential-client-secret`

#### Public Client Flow (with PKCE)

1. Client generates a PKCE code verifier, code challenge, and a `state` value
2. Client initiates authorization request with the code challenge
3. Identity provider issues authorization code and echoes back the `state`
4. Client verifies the returned `state` matches before trusting the code (CSRF protection)
5. Client exchanges code for access token using code verifier (proves possession)
6. Client uses access token to call MCP server tools

**Client Credentials:**

- Client ID: `public-client-id`
- No client secret (uses PKCE instead)

## What the Demo Does

When you run the MCP client, it will:

1. **Acquire Token**: Perform OAuth2 Authorization Code flow (with or without PKCE), verifying the
   `state` parameter on the redirect
2. **Connect to MCP Server**: Establish stdio connection to the MCP server
3. **List Tools**: Discover available MCP tools
4. **Call hello_world**: Simple greeting without authentication
5. **Call get_user_info**: Extract user information from the JWT token
6. **Call echo**: Echo a message with authenticated user context
7. **Get user profile**: Retrieve user profile as an MCP resource

## Example Output

When you run the MCP client with confidential client authentication:

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

=== Acquiring token with client_secret (Confidential Client) ===

Authorization URL: http://localhost:8000/oauth2/v2.0/authorize?client_id=...
Simulating authorization flow...
✓ State verified (CSRF check passed)
✓ Received authorization code: RhRDOk86w2FozAtifs7Z...

Exchanging authorization code for access token...
✓ Received access token: eyJhbGciOiJSUzI1NiIsImtpZCI6ImRlZmF1bHQta2V5LWlkIi...

✓ Successfully acquired access token!

=== Connecting to MCP Server ===
✓ Starting MCP server via stdio...
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

======================================================================
Demo completed successfully!
======================================================================
```

When you run with PKCE (public client):

```bash
cd mcp-client
uv run python main.py --pkce
```

You'll see similar output but with PKCE-specific information:

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

### OIDC Discovery

- `GET /.well-known/openid-configuration` - OpenID Connect configuration

### JWKS

- `GET /discovery/v2.0/keys` - JSON Web Key Set

### OAuth2 Endpoints

- `GET /oauth2/v2.0/authorize` - Authorization endpoint
- `POST /oauth2/v2.0/token` - Token endpoint

### Information

- `GET /` - Service information and client details

## MCP Server Tools

### hello_world

Simple greeting tool that doesn't require authentication.

**Arguments:**

- `name` (optional): Name to greet (default: "World")

### get_user_info

Extracts user information from a JWT token.

**Arguments:**

- `auth_token` (required): JWT access token

**Returns:**
User information including user_id, name, email, preferred_username, scope, and tenant_id

### echo

Echoes a message with authenticated user context.

**Arguments:**

- `message` (required): Message to echo
- `auth_token` (required): JWT access token

**Returns:**
The echoed message prefixed with the authenticated user's name

## Technical Details

### Token Format (JWT)

The identity provider issues JWT tokens with the following claims:

- `iss`: Issuer (<http://localhost:8000>)
- `sub`: Subject (user ID)
- `aud`: Audience (client ID; validated by the MCP server against the known client IDs)
- `iat`: Issued at timestamp
- `exp`: Expiration timestamp (1 hour)
- `scope`: Requested scopes
- `tid`: Tenant ID
- `azp`: Authorized party (client ID)
- `preferred_username`: User's preferred username
- `name`: User's display name
- `email`: User's email address

### PKCE Implementation

The PKCE implementation uses:

- Code verifier: 43-character random string (base64url-encoded)
- Code challenge method: S256 (SHA-256 hash)
- Code challenge: base64url(SHA256(code_verifier))

### Security Features

- RSA 2048-bit key pair for JWT signing
- Authorization code expires in 10 minutes
- Access tokens expire in 1 hour
- Refresh tokens expire in 30 days
- PKCE required for public clients; also verified for confidential clients when a `code_challenge`
  was bound to the authorization code (RFC 7636)
- Client secret required for confidential clients
- `state` parameter verified by the client on the redirect to prevent CSRF
- Access tokens validated by the MCP server against the token's `kid` (matching JWKS signing key,
  with a one-time cache refresh on key rotation) and `aud` (audience) claims
- Refresh tokens bound to the client they were issued to; the `refresh_token` grant revalidates
  `client_id` (and `client_secret` for the confidential client) before issuing a new access token
- Unsupported `response_type` values rejected by the authorization endpoint
- Redirect parameters URL-encoded to prevent injection

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
├── .markdownlint.yaml          # markdownlint rule configuration
├── .markdownlint-cli2.yaml     # markdownlint-cli2 runner configuration
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

- FastMCP: MCP server framework
- python-jose (>=3.4.0, for CVE fixes): JWT validation
- httpx: HTTP client for JWKS fetching

### MCP Client

- mcp: MCP protocol client library
- httpx: HTTP client for OAuth2 flows

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

### MCP Client connection failed

- Ensure the identity provider is running on port 8000
- Ensure the MCP server path in client is correct (`../mcp-server/main.py`)

### Token validation failed

- Ensure identity provider is running and accessible
- Check that JWKS endpoint is reachable: <http://localhost:8000/discovery/v2.0/keys>

## License

This is free and unencumbered software released into the public domain.
See LICENSE for details.

## Educational Purpose

This project is designed for educational purposes to demonstrate:

- OAuth2 Authorization Code Flow
- PKCE for public clients
- JWT token issuance and validation
- OIDC Discovery protocol
- MCP (Model Context Protocol) integration
- Token-based authentication in distributed systems

It should not be used in production without significant security enhancements and proper credential
management.
