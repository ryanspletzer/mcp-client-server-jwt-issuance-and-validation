"""
OAuth2/OIDC Identity Provider
Emulates Entra ID's OpenID Connect ecosystem with support for:
- Authorization Code Flow
- PKCE (Proof Key for Code Exchange)
- JWT token issuance
- OIDC Discovery
"""

import secrets
import hashlib
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from jose import jwt, jwk
from jose.constants import ALGORITHMS
from pydantic import BaseModel
import uvicorn

# Configuration
ISSUER = "http://localhost:8000"
TENANT_ID = "12345678-1234-1234-1234-123456789012"
CLIENT_ID_CONFIDENTIAL = "confidential-client-id"
CLIENT_SECRET = "confidential-client-secret"
CLIENT_ID_PUBLIC = "public-client-id"

# In-memory stores
authorization_codes: Dict[str, Dict[str, Any]] = {}
refresh_tokens: Dict[str, Dict[str, Any]] = {}

# Generate RSA key pair for signing tokens
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

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

# Create JWK from public key
public_jwk = jwk.RSAKey(algorithm=ALGORITHMS.RS256).to_dict()
public_jwk['kid'] = 'default-key-id'
public_jwk['use'] = 'sig'
public_jwk['alg'] = 'RS256'

app = FastAPI(title="Identity Provider", description="OAuth2/OIDC Identity Provider")


# Models
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    scope: Optional[str] = None


def verify_pkce(code_verifier: str, code_challenge: str, code_challenge_method: str = "S256") -> bool:
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
    now = datetime.utcnow()
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
    
    token = jwt.encode(payload, private_key_pem, algorithm=ALGORITHMS.RS256, headers={"kid": "default-key-id"})
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
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "name", "email", "preferred_username"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
    }


@app.get("/discovery/v2.0/keys")
async def jwks():
    """JSON Web Key Set endpoint"""
    # Convert the PEM public key to JWK format
    from jose.backends.cryptography_backend import CryptographyRSAKey
    key = CryptographyRSAKey(public_key_pem, ALGORITHMS.RS256)
    jwk_dict = key.to_dict()
    jwk_dict['kid'] = 'default-key-id'
    jwk_dict['use'] = 'sig'
    jwk_dict['alg'] = 'RS256'
    
    return {"keys": [jwk_dict]}


@app.get("/oauth2/v2.0/authorize", response_class=HTMLResponse)
async def authorize(
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    response_type: str = Query("code"),
    scope: str = Query("openid profile"),
    state: Optional[str] = Query(None),
    code_challenge: Optional[str] = Query(None),
    code_challenge_method: Optional[str] = Query("S256"),
):
    """Authorization endpoint - presents login form and issues authorization code"""
    
    # Validate client_id
    if client_id not in [CLIENT_ID_CONFIDENTIAL, CLIENT_ID_PUBLIC]:
        raise HTTPException(status_code=400, detail="Invalid client_id")
    
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
        "expires_at": datetime.utcnow() + timedelta(minutes=10),
    }
    
    # Build redirect URL
    redirect_url = f"{redirect_uri}?code={auth_code}"
    if state:
        redirect_url += f"&state={state}"
    
    return RedirectResponse(url=redirect_url)


@app.post("/oauth2/v2.0/token")
async def token(
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None),
    refresh_token_param: Optional[str] = Form(None, alias="refresh_token"),
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
        if datetime.utcnow() > auth_data["expires_at"]:
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
        else:
            # Public client requires PKCE
            if not auth_data.get("code_challenge"):
                raise HTTPException(status_code=400, detail="PKCE required for public clients")
            
            if not code_verifier:
                raise HTTPException(status_code=400, detail="code_verifier is required")
            
            if not verify_pkce(code_verifier, auth_data["code_challenge"], auth_data.get("code_challenge_method", "S256")):
                raise HTTPException(status_code=400, detail="Invalid code_verifier")
        
        # Issue tokens
        access_token = create_jwt_token(auth_data["user_id"], client_id, auth_data["scope"])
        refresh_token_value = secrets.token_urlsafe(32)
        
        # Store refresh token
        refresh_tokens[refresh_token_value] = {
            "client_id": client_id,
            "user_id": auth_data["user_id"],
            "scope": auth_data["scope"],
            "expires_at": datetime.utcnow() + timedelta(days=30),
        }
        
        # Delete used authorization code
        del authorization_codes[code]
        
        return TokenResponse(
            access_token=access_token,
            token_type="Bearer",
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
        
        if datetime.utcnow() > refresh_data["expires_at"]:
            del refresh_tokens[refresh_token_param]
            raise HTTPException(status_code=400, detail="Refresh token expired")
        
        # Issue new access token
        access_token = create_jwt_token(refresh_data["user_id"], refresh_data["client_id"], refresh_data["scope"])
        
        return TokenResponse(
            access_token=access_token,
            token_type="Bearer",
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
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
