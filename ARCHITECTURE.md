# System Architecture Diagram

This demo aligns with the MCP authorization specification, revision **2025-11-25**.
See [README.md](README.md) for the full list of RFCs it implements.

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
│  │  - OIDC/OAuth2   │      │  - stdio or HTTP │                   │
│  │  - PKCE Support  │      │  - MCP Tools     │                   │
│  │  - RFC 8707/8414 │      │    * hello_world │                   │
│  │                  │      │    * get_user_   │                   │
│  │  Port: 8000      │      │      info        │                   │
│  │                  │      │    * echo        │                   │
│  │                  │      │  - user://profile│                   │
│  │                  │      │    resource      │                   │
│  └────────┬─────────┘      └────────▲─────────┘                   │
│           │                         │                             │
│           │                         │ stdio (env var) or          │
│           │                         │ HTTP (Bearer token)         │
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
│                                │  - RFC 9728  │                   │
│                                │    discovery │                   │
│                                │    (HTTP)    │                   │
│                                │  - Calls MCP │                   │
│                                │    Tools     │                   │
│                                └──────────────┘                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Authentication Flow: Confidential Client (stdio transport)

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
     │  + resource (8707)   │                       │
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
     │  + resource (8707)   │                       │
     ├─────────────────────►│                       │
     │                      │                       │
     │  4. JWT Token         │                       │
     │  (aud = resource)     │                       │
     │◄─────────────────────┤                       │
     │                      │                       │
     │  5. Spawn MCP Server  │                       │
     │  env: MCP_ACCESS_TOKEN│                       │
     ├──────────────────────┼──────────────────────►│
     │                      │                       │
     │  6. Call Tool          │                       │
     │  (no token argument)  │                       │
     ├──────────────────────┼──────────────────────►│
     │                      │                       │
     │                      │  7. Validate Token     │
     │                      │  (fetch JWKS, match    │
     │                      │   kid, iss, exp, aud)  │
     │                      │◄──────────────────────┤
     │                      │                       │
     │                      │  8. JWKS              │
     │                      ├──────────────────────►│
     │                      │                       │
     │  9. Tool Result        │                       │
     │◄─────────────────────┼───────────────────────┤
     │                      │                       │
```

The client generates the `state` value before step 1 and verifies it matches the value echoed back
in step 2 before trusting the authorization code; a mismatch aborts the flow (CSRF protection).
If a `code_challenge` was also included in step 1, the identity provider verifies it in step 3 the
same way it does for public clients (RFC 7636), even though this is a confidential client.
`resource` is sent on both steps 1 and 3 (RFC 8707), and the identity provider binds the token's
`aud` claim to it in step 4 rather than to the client_id.
Stdio servers have no HTTP channel to carry a `Bearer` header on, so credentials travel via the
`MCP_ACCESS_TOKEN` environment variable set when the client spawns the server (step 5) instead of a
tool argument (step 6).

## Authentication Flow: Public Client (PKCE, stdio transport)

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
     │  + resource (8707)   │                       │
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
     │  + resource (8707)   │                       │
     ├─────────────────────►│                       │
     │                      │                       │
     │  (Verify PKCE)       │                       │
     │                      │                       │
     │  5. JWT Token          │                       │
     │  (aud = resource)     │                       │
     │◄─────────────────────┤                       │
     │                      │                       │
     │  6. Spawn MCP Server  │                       │
     │  env: MCP_ACCESS_TOKEN│                       │
     ├──────────────────────┼──────────────────────►│
     │                      │                       │
     │  7. Call Tool          │                       │
     │  (no token argument)  │                       │
     ├──────────────────────┼──────────────────────►│
     │                      │                       │
     │                      │  8. Validate Token     │
     │                      │  (fetch JWKS, match    │
     │                      │   kid, iss, exp, aud)  │
     │                      │◄──────────────────────┤
     │                      │                       │
     │                      │  9. JWKS              │
     │                      ├──────────────────────►│
     │                      │                       │
     │  10. Tool Result       │                       │
     │◄─────────────────────┼───────────────────────┤
     │                      │                       │
```

## Authentication Flow: HTTP transport (RFC 9728 discovery dance)

Streamable-HTTP mode looks different: the client doesn't know in advance which authorization
server to talk to, so it discovers it from the MCP server itself before running the flow above.

```text
┌──────────┐             ┌────────────┐             ┌────────────┐
│  MCP     │             │  MCP       │             │  Identity  │
│  Client  │             │  Server    │             │  Provider  │
└────┬─────┘             └─────┬──────┘             └─────┬──────┘
     │                         │                          │
     │  1. POST /mcp           │                          │
     │  (no Authorization)     │                          │
     ├────────────────────────►│                          │
     │                         │                          │
     │  2. 401 Unauthorized    │                          │
     │  WWW-Authenticate:      │                          │
     │  Bearer resource_       │                          │
     │  metadata="..."         │                          │
     │◄────────────────────────┤                          │
     │                         │                          │
     │  3. GET resource_metadata (RFC 9728)                │
     ├────────────────────────►│                          │
     │  4. { resource,          │                          │
     │       authorization_    │                          │
     │       servers: [...] }  │                          │
     │◄────────────────────────┤                          │
     │                         │                          │
     │  5. GET /.well-known/openid-configuration           │
     │  against the named authorization server (RFC 8414)  │
     ├──────────────────────────────────────────────────►│
     │  6. Discovery document                              │
     │◄──────────────────────────────────────────────────┤
     │                         │                          │
     │  7. Ordinary authorization code flow                │
     │     (client_secret or PKCE) + resource (RFC 8707)   │
     ├──────────────────────────────────────────────────►│
     │  8. JWT Token (aud = resource)                      │
     │◄──────────────────────────────────────────────────┤
     │                         │                          │
     │  9. Connect: streamable HTTP                        │
     │     Authorization: Bearer <token>                   │
     ├────────────────────────►│                          │
     │                         │                          │
     │                         │  10. Validate Token       │
     │                         │  (fetch JWKS, match kid,  │
     │                         │   iss, exp, aud)          │
     │                         │◄─────────────────────────┤
     │  11. Tool / resource     │                          │
     │      results             │                          │
     │◄────────────────────────┤                          │
     │                         │                          │
```

The MCP server never has to be told where its authorization server is out of band: the metadata
it serves at step 4 names it, and the client discovers the actual authorize/token endpoints
dynamically at step 5-6.
This is what lets an MCP client work against MCP servers backed by authorization servers it has
never seen before.

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
  "aud": "http://localhost:8001/mcp",       // Audience: the resource server (RFC 8707), not a client ID
  "iat": 1234567890,                        // Issued At
  "exp": 1234571490,                        // Expiration (1 hour)
  "scope": "openid profile",                // Scopes
  "tid": "12345678-1234-...",              // Tenant ID
  "azp": "confidential-client-id",          // Authorized Party (the OAuth client, independent of aud)
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

`aud` falls back to the client_id only when a caller doesn't send `resource` at all — a
pre-RFC-8707 OIDC client, not an MCP-spec-compliant one.
The demo's own client always sends `resource`, so in practice `aud` is always the MCP server's
resource identifier.

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

The MCP server validates a presented token in three steps, in both transports (the token just
arrives differently — via `MCP_ACCESS_TOKEN` in stdio mode, via `Authorization: Bearer` in HTTP
mode):

1. **Key selection** - it reads the unverified token header's `kid` and looks up the matching key in
   its cached JWKS document, refreshing the cache once (and retrying the lookup) if the `kid` isn't
   found, which handles identity-provider key rotation.
2. **Signature and claims** - it verifies the RS256 signature against the matching key and checks the
   `iss` (issuer) and `exp` (expiration) claims.
3. **Audience** - it checks the `aud` claim against its own resource identifier
   (`http://localhost:8001/mcp`) using python-jose's built-in single-value `audience=` check.
   This is the audience-binding requirement the MCP spec adds on top of plain OAuth 2.1: a
   resource server must reject tokens that weren't minted for it specifically, closing off the
   "token passthrough" pattern where a token for one resource gets replayed at another.

## Refresh Token Rotation

Every `refresh_token` grant deletes the refresh token that was presented and issues a brand-new
one alongside the new access token:

```text
┌──────────┐                              ┌────────────┐
│  MCP     │                              │  Identity  │
│  Client  │                              │  Provider  │
└────┬─────┘                              └─────┬──────┘
     │                                          │
     │  1. refresh_token grant                 │
     │  + refresh_token (old)                  │
     ├─────────────────────────────────────────►│
     │                                          │
     │                          (delete old refresh token,
     │                           issue new access + refresh token)
     │                                          │
     │  2. New access_token + refresh_token     │
     │◄─────────────────────────────────────────┤
     │                                          │
     │  3. Replay old refresh_token (attacker?) │
     ├─────────────────────────────────────────►│
     │                                          │
     │  4. 400 invalid: token already used      │
     │◄─────────────────────────────────────────┤
```

A leaked-and-replayed refresh token is only useful until the legitimate client's next refresh —
after that, it's already been deleted.

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
- **FastMCP** (>=3.4, <4): Framework for building MCP servers; supplies the `RemoteAuthProvider`
  and `TokenVerifier` types used to wire the hand-rolled JWT validation into HTTP-mode auth and
  RFC 9728 metadata
- **MCP SDK** (>=1.27, <2): Model Context Protocol client library; pinned below 2.0 because that
  release targets the breaking 2026-07-28 spec revision
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
6. **Audience Validation (RFC 8707)**: The MCP server checks the token's `aud` claim against its own
   resource identifier, not a set of known client IDs — a token minted for a different resource, or
   only for a client, is rejected
7. **Issuer Validation**: Tokens validated against expected issuer
8. **Code Expiration**: Authorization codes expire in 10 minutes
9. **Refresh Token Rotation**: Every `refresh_token` grant deletes the token that was presented and
   issues a new one, in addition to revalidating `client_id` (and `client_secret` for the
   confidential client)
10. **Registered Redirect URIs**: Authorization codes are only sent to redirect URIs pre-registered
    for the requesting client, as real identity providers require
11. **Registered Resources (RFC 8707)**: `resource` values are checked against a registry;
    unregistered values are rejected with `invalid_target`
12. **S256-only PKCE**: The `plain` code-challenge method (removed in OAuth 2.1) is rejected
13. **Constant-Time Comparisons**: Client secrets and PKCE challenges are compared with
    `secrets.compare_digest` to avoid timing side channels
14. **stdio Credential Isolation**: In stdio mode, credentials travel via the `MCP_ACCESS_TOKEN`
    environment variable rather than a tool argument, per the MCP spec

## Educational Purpose

This implementation demonstrates:

- OAuth 2.0 Authorization Code flow
- PKCE for public clients
- JWT token structure and validation, with RFC 8707 resource-bound audiences
- OIDC Discovery and RFC 8414 authorization server metadata
- RFC 9728 protected resource metadata and the MCP authorization discovery dance
- Refresh token rotation
- MCP protocol integration over both stdio and streamable HTTP
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
