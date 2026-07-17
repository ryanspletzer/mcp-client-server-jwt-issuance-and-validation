"""
OAuth2/OIDC Identity Provider
Emulates Entra ID's OpenID Connect ecosystem with support for:
- Authorization Code Flow
- PKCE (Proof Key for Code Exchange)
- JWT token issuance
- OIDC Discovery
"""

import base64
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

import uvicorn
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, HTTPException, Query
from fastapi.responses import RedirectResponse
from jose import jwt
from jose.backends.cryptography_backend import CryptographyRSAKey
from jose.constants import ALGORITHMS
from pydantic import BaseModel

# Configuration
ISSUER = "http://localhost:8000"
TENANT_ID = "12345678-1234-1234-1234-123456789012"
CLIENT_ID_CONFIDENTIAL = "confidential-client-id"
CLIENT_SECRET = "confidential-client-secret"  # noqa: S105 — intentional demo credential, see README
CLIENT_ID_PUBLIC = "public-client-id"

# Canonical resource identifier of the MCP server this demo protects, per
# RFC 8707 (Resource Indicators for OAuth 2.0). This is the MCP server's
# streamable-HTTP URL (see mcp-server/main.py). It must match the constant
# of the same name in mcp-server/main.py and mcp-client/main.py exactly —
# the three components are independent processes/packages in this demo, so
# the value is kept in sync by convention rather than a shared import.
MCP_RESOURCE = "http://localhost:8001/mcp"

# RFC 8707 requires the authorization server to reject `resource` values it
# doesn't recognize. In a real deployment this would be a dynamic client/
# resource registry; here it's the single MCP server the demo protects.
REGISTERED_RESOURCES: set[str] = {MCP_RESOURCE}

# Redirect URIs must be pre-registered per client, as real identity providers
# (including Entra ID) require. Codes are only ever sent to these locations.
REGISTERED_REDIRECT_URIS: dict[str, set[str]] = {
    CLIENT_ID_CONFIDENTIAL: {"http://localhost:9999/callback"},
    CLIENT_ID_PUBLIC: {"http://localhost:9999/callback"},
}

# In-memory stores
authorization_codes: dict[str, dict[str, Any]] = {}
refresh_tokens: dict[str, dict[str, Any]] = {}

# Generate RSA key pair for signing tokens
private_key_obj = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

private_key_pem = private_key_obj.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

public_key_obj = private_key_obj.public_key()
public_key_pem = public_key_obj.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# Precompute the JWK representation of the public key once at startup, since
# the key never changes for the lifetime of the process.
_jwk_key = CryptographyRSAKey(public_key_pem, ALGORITHMS.RS256)
jwk_dict = _jwk_key.to_dict()
jwk_dict['kid'] = 'default-key-id'
jwk_dict['use'] = 'sig'
jwk_dict['alg'] = 'RS256'

app = FastAPI(title="Identity Provider", description="OAuth2/OIDC Identity Provider")


# Models
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"  # noqa: S105 — OAuth2 token type literal, not a credential
    expires_in: int
    refresh_token: str | None = None
    scope: str | None = None


def verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    """Verify a PKCE code verifier against its S256 code challenge.

    Only S256 is supported; the `plain` method was removed in OAuth 2.1.
    The comparison is constant-time to avoid leaking how much of the
    challenge matched.
    """
    computed_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip('=')
    return secrets.compare_digest(computed_challenge, code_challenge)


def validate_resource(resource: str | None) -> None:
    """Validate an RFC 8707 `resource` parameter against the registry.

    Per RFC 8707, an authorization server that receives a `resource` value
    it doesn't recognize MUST reject the request. We use the `invalid_target`
    error code the RFC defines for exactly this case.
    """
    if resource is not None and resource not in REGISTERED_RESOURCES:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_target",
                "error_description": f"Unknown resource: {resource}",
            },
        )


def create_jwt_token(
    user_id: str, client_id: str, scope: str = "openid profile", resource: str | None = None
) -> str:
    """Create a JWT access token.

    `aud` (audience) is bound to `resource` — the MCP server the token is
    for — rather than to `client_id`. This is the MCP spec's audience-binding
    requirement: a resource server must only accept tokens minted for itself,
    never tokens minted for some other resource or for the client that
    obtained them. Accepting client-audience tokens at a resource server is
    exactly the forbidden "token passthrough" anti-pattern the spec calls
    out — it lets a token intended for one resource be replayed at another.

    `azp` ("authorized party") still records which OAuth client the token
    was issued to, independent of what resource it's bound to.

    Real MCP clients always send `resource` (see mcp-client/main.py), so in
    practice `aud` is always the resource. Plain OIDC clients that predate
    RFC 8707 may not send it, though; for those we fall back to the old
    aud=client_id behavior rather than breaking them outright.
    """
    now = datetime.now(UTC)
    audience = resource if resource is not None else client_id
    payload = {
        "iss": ISSUER,
        "sub": user_id,
        "aud": audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "scope": scope,
        "tid": TENANT_ID,
        "azp": client_id,
        "preferred_username": user_id,
        "name": f"Demo User {user_id}",
        "email": f"{user_id}@example.com",
    }

    token = jwt.encode(
        payload, private_key_pem, algorithm=ALGORITHMS.RS256, headers={"kid": "default-key-id"}
    )
    return token


def _metadata_document() -> dict[str, Any]:
    """Build the authorization server metadata document.

    Shared by the OIDC discovery endpoint (/.well-known/openid-configuration)
    and the RFC 8414 OAuth 2.0 Authorization Server Metadata endpoint
    (/.well-known/oauth-authorization-server) — both describe the same
    server, so there's no reason to maintain two copies of the dict.

    RFC 8707 (resource indicators) doesn't define any metadata fields of its
    own beyond what's already here, so there's nothing resource-specific to
    advertise.
    """
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/oauth2/v2.0/authorize",
        "token_endpoint": f"{ISSUER}/oauth2/v2.0/token",
        "jwks_uri": f"{ISSUER}/discovery/v2.0/keys",
        "response_types_supported": ["code"],
        "subject_types_supported": ["pairwise"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "name", "email", "preferred_username",
        ],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
    }


@app.get("/.well-known/openid-configuration")
async def openid_configuration():
    """OIDC Discovery endpoint"""
    return _metadata_document()


@app.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server():
    """RFC 8414 OAuth 2.0 Authorization Server Metadata endpoint.

    MCP clients that aren't doing OIDC (just plain OAuth 2.1) discover the
    authorization server via this well-known path rather than the OIDC one.
    The document is identical to OIDC discovery — this server is both an
    OIDC provider and a plain OAuth 2.1 authorization server.
    """
    return _metadata_document()


@app.get("/discovery/v2.0/keys")
async def jwks():
    """JSON Web Key Set endpoint"""
    return {"keys": [jwk_dict]}


@app.get("/oauth2/v2.0/authorize")
async def authorize(
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    response_type: str = Query("code"),
    scope: str = Query("openid profile"),
    state: str | None = Query(None),
    code_challenge: str | None = Query(None),
    code_challenge_method: str | None = Query("S256"),
    resource: str | None = Query(None),
):
    """Authorization endpoint - presents login form and issues authorization code"""

    # Validate client_id
    if client_id not in [CLIENT_ID_CONFIDENTIAL, CLIENT_ID_PUBLIC]:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    # We only support the authorization code flow
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Unsupported response_type")

    # Only pre-registered redirect URIs may receive authorization codes;
    # accepting arbitrary URIs would let an attacker steer codes anywhere.
    if redirect_uri not in REGISTERED_REDIRECT_URIS[client_id]:
        raise HTTPException(status_code=400, detail="Unregistered redirect_uri")

    # Only the S256 challenge method is supported (plain was removed in OAuth 2.1)
    if code_challenge is not None and code_challenge_method != "S256":
        raise HTTPException(status_code=400, detail="Unsupported code_challenge_method")

    # RFC 8707: reject resource values we don't recognize up front, before
    # ever issuing a code for them.
    validate_resource(resource)

    # For demo purposes, auto-approve with a dummy user
    # In a real system, this would show a login page
    user_id = "demo-user"

    # Generate authorization code
    auth_code = secrets.token_urlsafe(32)

    # Store authorization code with associated data
    authorization_codes[auth_code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "user_id": user_id,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "resource": resource,
        "expires_at": datetime.now(UTC) + timedelta(minutes=10),
    }

    # Build redirect URL, letting urlencode handle escaping of state and friends
    redirect_params = {"code": auth_code}
    if state is not None:
        redirect_params["state"] = state
    redirect_url = f"{redirect_uri}?{urlencode(redirect_params)}"

    return RedirectResponse(url=redirect_url)


@app.post("/oauth2/v2.0/token")
async def token(
    grant_type: str = Form(...),
    code: str | None = Form(None),
    redirect_uri: str | None = Form(None),
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
    code_verifier: str | None = Form(None),
    refresh_token_param: str | None = Form(None, alias="refresh_token"),
    resource: str | None = Form(None),
):
    """Token endpoint - exchanges authorization code for access token"""

    # RFC 8707: validate the resource on every grant type that accepts one,
    # before touching any stored code/token state.
    validate_resource(resource)

    if grant_type == "authorization_code":
        if not code:
            raise HTTPException(status_code=400, detail="code is required")

        # Retrieve authorization code data
        if code not in authorization_codes:
            raise HTTPException(status_code=400, detail="Invalid or expired authorization code")

        auth_data = authorization_codes[code]

        # Check expiration
        if datetime.now(UTC) > auth_data["expires_at"]:
            del authorization_codes[code]
            raise HTTPException(status_code=400, detail="Authorization code expired")

        # Validate client_id
        if client_id != auth_data["client_id"]:
            raise HTTPException(status_code=400, detail="Client ID mismatch")

        # Validate redirect_uri
        if redirect_uri != auth_data["redirect_uri"]:
            raise HTTPException(status_code=400, detail="Redirect URI mismatch")

        # Validate client authentication
        if client_id == CLIENT_ID_CONFIDENTIAL:
            # Confidential client requires client_secret (constant-time compare)
            if not secrets.compare_digest(client_secret or "", CLIENT_SECRET):
                raise HTTPException(status_code=401, detail="Invalid client credentials")

            # Per RFC 7636, if a code_challenge was bound to this authorization
            # code the server must verify the PKCE verifier regardless of
            # client type - client_secret alone doesn't satisfy a bound challenge.
            if auth_data.get("code_challenge"):
                if not code_verifier:
                    raise HTTPException(status_code=400, detail="code_verifier is required")

                if not verify_pkce(code_verifier, auth_data["code_challenge"]):
                    raise HTTPException(status_code=400, detail="Invalid code_verifier")
        else:
            # Public client requires PKCE
            if not auth_data.get("code_challenge"):
                raise HTTPException(status_code=400, detail="PKCE required for public clients")

            if not code_verifier:
                raise HTTPException(status_code=400, detail="code_verifier is required")

            if not verify_pkce(code_verifier, auth_data["code_challenge"]):
                raise HTTPException(status_code=400, detail="Invalid code_verifier")

        # RFC 8707: if `resource` was bound to the authorization code at the
        # authorize step, the token request must not silently switch it to a
        # different resource. A request that omits `resource` here falls
        # back to whatever was bound at authorize time.
        stored_resource = auth_data.get("resource")
        if resource is not None and stored_resource is not None and resource != stored_resource:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_target",
                    "error_description": "resource does not match the value sent to /authorize",
                },
            )
        effective_resource = resource or stored_resource

        # Issue tokens
        access_token = create_jwt_token(
            auth_data["user_id"], client_id, auth_data["scope"], resource=effective_resource
        )
        refresh_token_value = secrets.token_urlsafe(32)

        # Store refresh token
        refresh_tokens[refresh_token_value] = {
            "client_id": client_id,
            "user_id": auth_data["user_id"],
            "scope": auth_data["scope"],
            "resource": effective_resource,
            "expires_at": datetime.now(UTC) + timedelta(days=30),
        }

        # Delete used authorization code so it cannot be redeemed twice
        del authorization_codes[code]

        return TokenResponse(
            access_token=access_token,
            token_type="Bearer",  # noqa: S106 — OAuth2 token type literal, not a credential
            expires_in=3600,
            refresh_token=refresh_token_value,
            scope=auth_data["scope"],
        )

    elif grant_type == "refresh_token":
        if not refresh_token_param:
            raise HTTPException(status_code=400, detail="refresh_token is required")

        if refresh_token_param not in refresh_tokens:
            raise HTTPException(status_code=400, detail="Invalid refresh token")

        refresh_data = refresh_tokens[refresh_token_param]

        # Validate that the caller is the same client the refresh token was
        # issued to - otherwise anyone who obtains the token string could
        # redeem it regardless of who they are.
        if client_id != refresh_data["client_id"]:
            raise HTTPException(status_code=401, detail="Client ID mismatch")

        if refresh_data["client_id"] == CLIENT_ID_CONFIDENTIAL and not secrets.compare_digest(
            client_secret or "", CLIENT_SECRET
        ):
            raise HTTPException(status_code=401, detail="Invalid client credentials")

        if datetime.now(UTC) > refresh_data["expires_at"]:
            del refresh_tokens[refresh_token_param]
            raise HTTPException(status_code=400, detail="Refresh token expired")

        # RFC 8707: same matching rule as the authorization_code grant - a
        # resource supplied here must agree with whatever this refresh token
        # was originally bound to.
        stored_resource = refresh_data.get("resource")
        if resource is not None and stored_resource is not None and resource != stored_resource:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_target",
                    "error_description": (
                        "resource does not match the value bound to this refresh token"
                    ),
                },
            )
        effective_resource = resource or stored_resource

        # Issue new access token
        access_token = create_jwt_token(
            refresh_data["user_id"],
            refresh_data["client_id"],
            refresh_data["scope"],
            resource=effective_resource,
        )

        # Refresh token rotation (OAuth 2.1): the used refresh token is
        # single-use. Delete it and issue a fresh one bound to the same
        # client/user/scope/resource, so a leaked-and-replayed old token is
        # immediately worthless once the legitimate client has rotated.
        del refresh_tokens[refresh_token_param]
        new_refresh_token_value = secrets.token_urlsafe(32)
        refresh_tokens[new_refresh_token_value] = {
            "client_id": refresh_data["client_id"],
            "user_id": refresh_data["user_id"],
            "scope": refresh_data["scope"],
            "resource": effective_resource,
            "expires_at": datetime.now(UTC) + timedelta(days=30),
        }

        return TokenResponse(
            access_token=access_token,
            token_type="Bearer",  # noqa: S106 — OAuth2 token type literal, not a credential
            expires_in=3600,
            refresh_token=new_refresh_token_value,
            scope=refresh_data["scope"],
        )

    else:
        raise HTTPException(status_code=400, detail="Unsupported grant_type")


@app.get("/")
async def root():
    """Root endpoint with service information"""
    return {
        "service": "OAuth2/OIDC Identity Provider",
        "discovery": f"{ISSUER}/.well-known/openid-configuration",
        "clients": {
            "confidential": {
                "client_id": CLIENT_ID_CONFIDENTIAL,
                "client_secret": CLIENT_SECRET,
                "description": "Use with client_secret authentication"
            },
            "public": {
                "client_id": CLIENT_ID_PUBLIC,
                "description": "Use with PKCE authentication (no client_secret)"
            }
        }
    }


def main():
    uvicorn.run(app, host="0.0.0.0", port=8000)  # noqa: S104 — intentional demo bind-all, see README


if __name__ == "__main__":
    main()
