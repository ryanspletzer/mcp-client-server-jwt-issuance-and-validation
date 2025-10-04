# System Architecture Diagram

## Component Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Three-Component System                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────┐      ┌──────────────────┐                   │
│  │  Identity        │      │  MCP Server      │                   │
│  │  Provider        │      │  (FastMCP)       │                   │
│  │  (FastAPI)       │      │                  │                   │
│  │                  │      │  - Validates JWT │                   │
│  │  - Issues JWT    │      │  - MCP Tools     │                   │
│  │  - OIDC/OAuth2   │      │    * hello_world │                   │
│  │  - PKCE Support  │      │    * get_user_   │                   │
│  │                  │      │      info        │                   │
│  │  Port: 8000      │      │    * echo        │                   │
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
│                                │  - PKCE      │                   │
│                                │  - Calls MCP │                   │
│                                │    Tools     │                   │
│                                └──────────────┘                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Authentication Flow: Confidential Client

```
┌──────────┐          ┌────────────┐          ┌────────────┐
│  MCP     │          │  Identity  │          │  MCP       │
│  Client  │          │  Provider  │          │  Server    │
└────┬─────┘          └─────┬──────┘          └─────┬──────┘
     │                      │                       │
     │  1. Request Auth     │                       │
     │  + client_id         │                       │
     │  + client_secret     │                       │
     ├─────────────────────►│                       │
     │                      │                       │
     │  2. Auth Code        │                       │
     │◄─────────────────────┤                       │
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
     │                      │  (fetch JWKS)         │
     │                      │◄──────────────────────┤
     │                      │                       │
     │                      │  7. JWKS              │
     │                      ├──────────────────────►│
     │                      │                       │
     │  8. Tool Result      │                       │
     │◄─────────────────────┼───────────────────────┤
     │                      │                       │
```

## Authentication Flow: Public Client (PKCE)

```
┌──────────┐          ┌────────────┐          ┌────────────┐
│  MCP     │          │  Identity  │          │  MCP       │
│  Client  │          │  Provider  │          │  Server    │
└────┬─────┘          └─────┬──────┘          └─────┬──────┘
     │                      │                       │
     │  1. Generate PKCE    │                       │
     │  - code_verifier     │                       │
     │  - code_challenge    │                       │
     │                      │                       │
     │  2. Request Auth     │                       │
     │  + client_id         │                       │
     │  + code_challenge    │                       │
     ├─────────────────────►│                       │
     │                      │                       │
     │  3. Auth Code        │                       │
     │◄─────────────────────┤                       │
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
     │                      │  (fetch JWKS)         │
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

```
Header:
{
  "alg": "RS256",
  "kid": "default-key-id"
}

Payload:
{
  "iss": "http://localhost:8000",           // Issuer
  "sub": "demo-user",                       // Subject (user ID)
  "aud": "confidential-client-id",          // Audience
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

## Directory Structure

```
mcp-client-server-jwt-issuance-and-validation/
│
├── identity-provider/          # OAuth2/OIDC Server
│   ├── main.py                # FastAPI application
│   ├── pyproject.toml         # Dependencies
│   └── .venv/                 # Virtual environment (auto-generated)
│
├── mcp-server/                # MCP Server
│   ├── main.py                # FastMCP server with tools
│   ├── pyproject.toml         # Dependencies
│   └── .venv/                 # Virtual environment (auto-generated)
│
├── mcp-client/                # MCP Client
│   ├── main.py                # Client with OAuth2 flows
│   ├── pyproject.toml         # Dependencies
│   └── .venv/                 # Virtual environment (auto-generated)
│
├── README.md                  # Full documentation
├── QUICKSTART.md              # Quick start guide
├── ARCHITECTURE.md            # This file
├── LICENSE                    # Public domain license
└── .gitignore                 # Git ignore patterns
```

## Key Technologies

- **FastAPI**: Modern Python web framework for the Identity Provider
- **FastMCP**: Framework for building MCP servers
- **MCP SDK**: Model Context Protocol client library
- **python-jose**: JWT creation and validation
- **httpx**: Async HTTP client
- **uvicorn**: ASGI server
- **uv**: Fast Python package manager

## Security Features

1. **RSA 2048-bit Signing**: Tokens signed with industry-standard key size
2. **PKCE Support**: Protection for public clients
3. **Token Expiration**: Access tokens expire in 1 hour
4. **JWKS Endpoint**: Public keys available for verification
5. **Issuer Validation**: Tokens validated against expected issuer
6. **Code Expiration**: Authorization codes expire in 10 minutes

## Educational Purpose

This implementation demonstrates:
- OAuth 2.0 Authorization Code flow
- PKCE for public clients
- JWT token structure and validation
- OIDC Discovery protocol
- MCP protocol integration
- Token-based authentication in distributed systems

**Note**: This is for educational purposes. Production systems require:
- HTTPS/TLS encryption
- Secure credential storage
- Database persistence
- Proper error handling
- Rate limiting
- Audit logging
- Token revocation
- Multi-factor authentication
