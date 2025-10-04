# mcp-client-server-jwt-issuance-and-validation

A comprehensive demonstration of OAuth2/OIDC authentication flow with MCP (Model Context Protocol) integration. This project consists of three components that work together to simulate a complete authentication and authorization workflow similar to Microsoft Entra ID (formerly Azure AD).

> **🚀 Quick Start**: See [QUICKSTART.md](QUICKSTART.md) for a 5-minute getting started guide.

## Architecture

The project includes three independent components:

> **📐 Architecture Details**: See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed diagrams and flow charts.

1. **Identity Provider** (`identity-provider/`) - OAuth2/OIDC server that emulates Entra ID
   - Authorization Code Flow support
   - PKCE (Proof Key for Code Exchange) support
   - JWT token issuance with RSA signing
   - OIDC Discovery endpoint
   - JWKS (JSON Web Key Set) endpoint

2. **MCP Server** (`mcp-server/`) - FastMCP server with JWT validation
   - Validates tokens from the identity provider
   - Exposes MCP tools (hello_world, get_user_info, echo)
   - Provides user profile as an MCP resource
   - Built with FastMCP framework

3. **MCP Client** (`mcp-client/`) - Client application with OAuth2 flows
   - Supports both Confidential and Public client types
   - Authorization Code Flow with client_secret
   - Authorization Code Flow with PKCE (for public clients)
   - Connects to MCP server with acquired tokens
   - Demonstrates tool calling with authentication

## Prerequisites

- Python 3.12 or higher
- `uv` package manager (installed automatically if not present)

## Installation

Each component is a separate uv project with its own dependencies. Navigate to each directory and sync dependencies:

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

The identity provider will start on `http://localhost:8000`. You should see:

```
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

You can verify it's working by visiting:
- Discovery endpoint: http://localhost:8000/.well-known/openid-configuration
- Root endpoint: http://localhost:8000/

### Step 2: Run the MCP Client (which starts the MCP Server)

The MCP client automatically starts the MCP server as a subprocess for stdio communication.

**Option A: Using Confidential Client (with client_secret)**

Open a new terminal and run:

```bash
cd mcp-client
uv run python main.py
```

**Option B: Using Public Client (with PKCE)**

```bash
cd mcp-client
uv run python main.py --pkce
```

## How It Works

### Component Interaction Flow

1. **Identity Provider starts** on port 8000 and waits for authentication requests
2. **MCP Client starts** and initiates the OAuth2 flow:
   - Generates PKCE challenge (if using public client)
   - Requests authorization code from Identity Provider
   - Receives authorization code via redirect
   - Exchanges authorization code for JWT access token
3. **MCP Client spawns MCP Server** as a subprocess using stdio transport
4. **MCP Client connects to MCP Server** and calls tools:
   - Passes JWT token as a parameter to authenticated tools
   - MCP Server validates the token by fetching JWKS from Identity Provider
   - MCP Server extracts user information from validated token
   - Returns results to the client

### Authentication Flows

#### Confidential Client Flow (with client_secret)

1. Client initiates authorization request
2. Identity provider issues authorization code
3. Client exchanges code for access token using client_secret
4. Client uses access token to call MCP server tools

**Client Credentials:**
- Client ID: `confidential-client-id`
- Client Secret: `confidential-client-secret`

#### Public Client Flow (with PKCE)

1. Client generates PKCE code verifier and challenge
2. Client initiates authorization request with code challenge
3. Identity provider issues authorization code
4. Client exchanges code for access token using code verifier (proves possession)
5. Client uses access token to call MCP server tools

**Client Credentials:**
- Client ID: `public-client-id`
- No client secret (uses PKCE instead)

## What the Demo Does

When you run the MCP client, it will:

1. **Acquire Token**: Perform OAuth2 Authorization Code flow (with or without PKCE)
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

```
======================================================================
MCP Client - OAuth2 Authorization Code Flow Demo
======================================================================

Authentication method: Client Secret (Confidential Client)

=== Acquiring token with client_secret (Confidential Client) ===

Authorization URL: http://localhost:8000/oauth2/v2.0/authorize?client_id=...
Simulating authorization flow...
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

```
Authentication method: PKCE (Public Client)

=== Acquiring token with PKCE (Public Client) ===
✓ Generated PKCE code verifier: qUy8XdJLYaE9cX3NPYe4...
✓ Generated PKCE code challenge: UI26-pOmmj8N3p7bEjOc...
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
- `iss`: Issuer (http://localhost:8000)
- `sub`: Subject (user ID)
- `aud`: Audience (client ID)
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
- PKCE required for public clients
- Client secret required for confidential clients

## Project Structure

```
.
├── identity-provider/
│   ├── main.py              # OAuth2/OIDC server implementation
│   ├── pyproject.toml       # Dependencies (FastAPI, python-jose)
│   └── .python-version
├── mcp-server/
│   ├── main.py              # MCP server with JWT validation
│   ├── pyproject.toml       # Dependencies (FastMCP, python-jose)
│   └── .python-version
├── mcp-client/
│   ├── main.py              # MCP client with OAuth2 flows
│   ├── pyproject.toml       # Dependencies (mcp, httpx)
│   └── .python-version
├── README.md                # This file
└── LICENSE
```

## Dependencies

### Identity Provider
- FastAPI: Web framework for OAuth2 endpoints
- uvicorn: ASGI server
- python-jose: JWT creation and validation
- cryptography: RSA key generation and signing

### MCP Server
- FastMCP: MCP server framework
- python-jose: JWT validation
- httpx: HTTP client for JWKS fetching

### MCP Client
- mcp: MCP protocol client library
- httpx: HTTP client for OAuth2 flows

## Troubleshooting

### Identity Provider not starting
- Ensure port 8000 is not in use
- Check that all dependencies are installed: `uv sync`

### MCP Client connection failed
- Ensure the identity provider is running on port 8000
- Ensure the MCP server path in client is correct (`../mcp-server/main.py`)

### Token validation failed
- Ensure identity provider is running and accessible
- Check that JWKS endpoint is reachable: http://localhost:8000/discovery/v2.0/keys

## License

This is free and unencumbered software released into the public domain. See LICENSE for details.

## Educational Purpose

This project is designed for educational purposes to demonstrate:
- OAuth2 Authorization Code Flow
- PKCE for public clients
- JWT token issuance and validation
- OIDC Discovery protocol
- MCP (Model Context Protocol) integration
- Token-based authentication in distributed systems

It should not be used in production without significant security enhancements and proper credential management.
