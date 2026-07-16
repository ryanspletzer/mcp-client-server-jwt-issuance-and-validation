# System Architecture Diagram

## Component Overview

```text
┌─────────────────────────────────────────────────────────────────────┐
│                         Three-Component System                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────┐      ┌──────────────────┐                   │
│  │  Identity        │      │  MCP Server      │                   │
│  │  Provider        │      │  (FastMCP)       │                   │
│  │  (FastAPI)       │      │                  │                   │
│  │                  │      │  - Validates JWT │                   │
│  │  - Issues JWT    │      │    (kid + aud)   │                   │
│  │  - OIDC/OAuth2   │      │  - MCP Tools     │                   │
│  │  - PKCE Support  │      │    * hello_world │                   │
│  │                  │      │    * get_user_   │                   │
│  │  Port: 8000      │      │      info        │                   │
│  │                  │      │    * echo        │                   │
│  └────────┬─────────┘      └────────▲─────────┘                   │
│           │                         │                             │
│           │                         │                             │
│           │                         │                             │
│           │                    ┌────┴─────────┐                   │
│           │                    │              │                   │
│           │                    │              │                   │
│           └────────────────────► MCP Client   │                   │
│                                │              │                   │
│                                │  - OAuth2    │                   │
│                                │    Flow      │                   │
│                                │  - Verifies  │                   │
│                                │    state     │                   │
│                                │  - PKCE      │                   │
│                                │  - Calls MCP │                   │
│                                │    Tools     │                   │
│                                └──────────────┘                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Authentication Flow: Confidential Client

```text
┌──────────┐          ┌────────────┐          ┌────────────┐
│  MCP     │          │  Identity  │          │  MCP       │
│  Client  │          │  Provider  │          │  Server    │
└────┬─────┘          └─────┬──────┘          └─────┬──────┘
     │                      │                       │
     │  1. Request Auth     │                       │
     │  + client_id         │                       │
     │  + client_secret     │                       │
     │  + state             │                       │
     ├─────────────────────►│                       │
     │                      │                       │
     │  2. Auth Code        │                       │
     │  + state             │                       │
     │◄─────────────────────┤                       │
     │                      │                       │
     │  (Verify state)      │                       │
     │                      │                       │
     │  3. Exchange Code    │                       │
     │  + client_secret     │                       │
     ├─────────────────────►│                       │
     │                      │                       │
     │  4. JWT Token        │                       │
     │◄─────────────────────┤                       │
     │                      │                       │
     │  5. Call Tool        │                       │
     │  + auth_token        │                       │
     ├──────────────────────┼──────────────────────►│
     │                      │                       │
     │                      │  6. Validate Token    │
     │                      │  (fetch JWKS,         │
     │                      │   match kid, aud)     │
     │                      │◄──────────────────────┤
     │                      │                       │
     │                      │  7. JWKS              │
     │                      ├──────────────────────►│
     │                      │                       │
     │  8. Tool Result      │                       │
     │◄─────────────────────┼───────────────────────┤
     │                      │                       │
```

The client generates the `state` value before step 1 and verifies it matches the value echoed back
in step 2 before trusting the authorization code; a mismatch aborts the flow (CSRF protection).
If a `code_challenge` was also included in step 1, the identity provider verifies it in step 3 the
same way it does for public clients (RFC 7636), even though this is a confidential client.

## Authentication Flow: Public Client (PKCE)

```text
┌──────────┐          ┌────────────┐          ┌────────────┐
│  MCP     │          │  Identity  │          │  MCP       │
│  Client  │          │  Provider  │          │  Server    │
└────┬─────┘          └─────┬──────┘          └─────┬──────┘
     │                      │                       │
     │  1. Generate PKCE    │                       │
     │  - code_verifier     │                       │
     │  - code_challenge    │                       │
     │  - state             │                       │
     │                      │                       │
     │  2. Request Auth     │                       │
     │  + client_id         │                       │
     │  + code_challenge    │                       │
     │  + state             │                       │
     ├─────────────────────►│                       │
     │                      │                       │
     │  3. Auth Code        │                       │
     │  + state             │                       │
     │◄─────────────────────┤                       │
     │                      │                       │
     │  (Verify state)      │                       │
     │                      │                       │
     │  4. Exchange Code    │                       │
     │  + code_verifier     │                       │
     ├─────────────────────►│                       │
     │                      │                       │
     │  (Verify PKCE)       │                       │
     │                      │                       │
     │  5. JWT Token        │                       │
     │◄─────────────────────┤                       │
     │                      │                       │
     │  6. Call Tool        │                       │
     │  + auth_token        │                       │
     ├──────────────────────┼──────────────────────►│
     │                      │                       │
     │                      │  7. Validate Token    │
     │                      │  (fetch JWKS,         │
     │                      │   match kid, aud)     │
     │                      │◄──────────────────────┤
     │                      │                       │
     │                      │  8. JWKS              │
     │                      ├──────────────────────►│
     │                      │                       │
     │  9. Tool Result      │                       │
     │◄─────────────────────┼───────────────────────┤
     │                      │                       │
```

## Token Flow Details

### JWT Token Structure

```text
Header:
{
  "alg": "RS256",
  "kid": "default-key-id"                   // Key ID used to select the matching JWKS signing key
}

Payload:
{
  "iss": "http://localhost:8000",           // Issuer
  "sub": "demo-user",                       // Subject (user ID)
  "aud": "confidential-client-id",          // Audience (checked against known client IDs)
  "iat": 1234567890,                        // Issued At
  "exp": 1234571490,                        // Expiration (1 hour)
  "scope": "openid profile",                // Scopes
  "tid": "12345678-1234-...",              // Tenant ID
  "azp": "confidential-client-id",          // Authorized Party
  "preferred_username": "demo-user",
  "name": "Demo User demo-user",
  "email": "demo-user@example.com"
}

Signature:
RSASHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  private_key
)
```

### PKCE Flow Details

1. **Code Verifier Generation**
   - Generate random 32-byte value
   - Base64URL encode (43 characters)
   - Example: `qUy8XdJLYaE9cX3NPYe4TxRw_KzMqN-r5vGwHxI2jAk`

2. **Code Challenge Computation**
   - SHA-256 hash the code verifier
   - Base64URL encode the hash
   - Example: `UI26-pOmmj8N3p7bEjOchiDErT3VnBjkFBtXZWckLQY`

3. **Verification**
   - Server receives code_verifier
   - Computes SHA-256 and Base64URL encodes
   - Compares with stored code_challenge
   - Applied to public clients always, and to confidential clients whenever a code_challenge was
     bound to the authorization code (RFC 7636)

## Token Validation Details

The MCP server validates a presented token in three steps:

1. **Key selection** - it reads the unverified token header's `kid` and looks up the matching key in
   its cached JWKS document, refreshing the cache once (and retrying the lookup) if the `kid` isn't
   found, which handles identity-provider key rotation.
2. **Signature and claims** - it verifies the RS256 signature against the matching key and checks the
   `iss` (issuer) and `exp` (expiration) claims.
3. **Audience** - it checks the `aud` claim against the set of known client IDs
   (`confidential-client-id` and `public-client-id`), since python-jose's built-in audience check only
   supports a single expected value.

## Directory Structure

```text
mcp-client-server-jwt-issuance-and-validation/
│
├── identity-provider/          # OAuth2/OIDC Server
│   ├── main.py                # FastAPI application
│   ├── tests/                  # pytest suite
│   ├── pyproject.toml         # Dependencies
│   └── .venv/                 # Virtual environment (auto-generated)
│
├── mcp-server/                # MCP Server
│   ├── main.py                # FastMCP server with tools
│   ├── tests/                  # pytest suite
│   ├── pyproject.toml         # Dependencies
│   └── .venv/                 # Virtual environment (auto-generated)
│
├── mcp-client/                # MCP Client
│   ├── main.py                # Client with OAuth2 flows
│   ├── tests/                  # pytest suite
│   ├── pyproject.toml         # Dependencies
│   └── .venv/                 # Virtual environment (auto-generated)
│
├── .github/
│   └── workflows/
│       └── ci.yml               # CI: ruff + pytest per component, markdownlint
│
├── ruff.toml                    # Shared lint configuration
├── .markdownlint.yaml           # markdownlint rule configuration
├── .markdownlint-cli2.yaml      # markdownlint-cli2 runner configuration
├── README.md                  # Full documentation
├── QUICKSTART.md               # Quick start guide
├── ARCHITECTURE.md             # This file
├── LICENSE                    # Public domain license
└── .gitignore                 # Git ignore patterns
```

## Key Technologies

- **FastAPI**: Modern Python web framework for the Identity Provider
- **FastMCP**: Framework for building MCP servers
- **MCP SDK**: Model Context Protocol client library
- **python-jose** (>=3.4.0, for CVE fixes): JWT creation and validation
- **httpx**: Async HTTP client
- **uvicorn**: ASGI server
- **uv**: Fast Python package manager

## Security Features

1. **RSA 2048-bit Signing**: Tokens signed with industry-standard key size
2. **PKCE Support**: Protection for public clients; also enforced for confidential clients when a
   `code_challenge` was bound to the authorization code (RFC 7636)
3. **State / CSRF Protection**: The client verifies the `state` parameter returned on the redirect
   before trusting the authorization code
4. **Token Expiration**: Access tokens expire in 1 hour
5. **JWKS Endpoint**: Public keys available for verification; the MCP server selects the key matching
   the token's `kid` and refreshes its cache once if the key isn't found (key rotation support)
6. **Audience Validation**: The MCP server checks the token's `aud` claim against the known client IDs
7. **Issuer Validation**: Tokens validated against expected issuer
8. **Code Expiration**: Authorization codes expire in 10 minutes
9. **Refresh Token Binding**: The `refresh_token` grant revalidates `client_id` (and `client_secret`
   for the confidential client) before issuing a new access token
10. **Registered Redirect URIs**: Authorization codes are only sent to redirect URIs pre-registered
    for the requesting client, as real identity providers require
11. **S256-only PKCE**: The `plain` code-challenge method (removed in OAuth 2.1) is rejected
12. **Constant-Time Comparisons**: Client secrets and PKCE challenges are compared with
    `secrets.compare_digest` to avoid timing side channels

## Educational Purpose

This implementation demonstrates:

- OAuth 2.0 Authorization Code flow
- PKCE for public clients
- JWT token structure and validation
- OIDC Discovery protocol
- MCP protocol integration
- Token-based authentication in distributed systems

**Note**: This is for educational purposes.
Production systems require:

- HTTPS/TLS encryption
- Secure credential storage
- Database persistence
- Proper error handling
- Rate limiting
- Audit logging
- Token revocation
- Multi-factor authentication
