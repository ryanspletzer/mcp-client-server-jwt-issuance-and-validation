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


def verify_pkce(
    code_verifier: str, code_challenge: str, code_challenge_method: str = "S256"
) -> bool:
    """Verify PKCE code verifier against code challenge"""
    if code_challenge_method == "S256":
        computed_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip('=')
        return computed_challenge == code_challenge
    elif code_challenge_method == "plain":
        return code_verifier == code_challenge
    return False


def create_jwt_token(user_id: str, client_id: str, scope: str = "openid profile") -> str:
    """Create a JWT access token"""
    now = datetime.now(UTC)
    payload = {
        "iss": ISSUER,
        "sub": user_id,
        "aud": client_id,
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


@app.get("/.well-known/openid-configuration")
async def openid_configuration():
    """OIDC Discovery endpoint"""
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
        "code_challenge_methods_supported": ["S256", "plain"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
    }


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
):
    """Authorization endpoint - presents login form and issues authorization code"""

    # Validate client_id
    if client_id not in [CLIENT_ID_CONFIDENTIAL, CLIENT_ID_PUBLIC]:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    # We only support the authorization code flow
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Unsupported response_type")

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
):
    """Token endpoint - exchanges authorization code for access token"""

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
            # Confidential client requires client_secret
            if client_secret != CLIENT_SECRET:
                raise HTTPException(status_code=401, detail="Invalid client credentials")

            # Per RFC 7636, if a code_challenge was bound to this authorization
            # code the server must verify the PKCE verifier regardless of
            # client type - client_secret alone doesn't satisfy a bound challenge.
            if auth_data.get("code_challenge"):
                if not code_verifier:
                    raise HTTPException(status_code=400, detail="code_verifier is required")

                if not verify_pkce(
                    code_verifier,
                    auth_data["code_challenge"],
                    auth_data.get("code_challenge_method", "S256"),
                ):
                    raise HTTPException(status_code=400, detail="Invalid code_verifier")
        else:
            # Public client requires PKCE
            if not auth_data.get("code_challenge"):
                raise HTTPException(status_code=400, detail="PKCE required for public clients")

            if not code_verifier:
                raise HTTPException(status_code=400, detail="code_verifier is required")

            if not verify_pkce(
                code_verifier,
                auth_data["code_challenge"],
                auth_data.get("code_challenge_method", "S256"),
            ):
                raise HTTPException(status_code=400, detail="Invalid code_verifier")

        # Issue tokens
        access_token = create_jwt_token(auth_data["user_id"], client_id, auth_data["scope"])
        refresh_token_value = secrets.token_urlsafe(32)

        # Store refresh token
        refresh_tokens[refresh_token_value] = {
            "client_id": client_id,
            "user_id": auth_data["user_id"],
            "scope": auth_data["scope"],
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

        if refresh_data["client_id"] == CLIENT_ID_CONFIDENTIAL and client_secret != CLIENT_SECRET:
            raise HTTPException(status_code=401, detail="Invalid client credentials")

        if datetime.now(UTC) > refresh_data["expires_at"]:
            del refresh_tokens[refresh_token_param]
            raise HTTPException(status_code=400, detail="Refresh token expired")

        # Issue new access token
        access_token = create_jwt_token(
            refresh_data["user_id"], refresh_data["client_id"], refresh_data["scope"]
        )

        return TokenResponse(
            access_token=access_token,
            token_type="Bearer",  # noqa: S106 — OAuth2 token type literal, not a credential
            expires_in=3600,
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
