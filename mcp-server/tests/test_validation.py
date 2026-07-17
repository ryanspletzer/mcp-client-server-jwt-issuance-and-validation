"""
Tests for JWT validation logic and auth wiring in main.py.

All tests generate their own RSA keypair(s) and mint tokens locally, then
monkeypatch main.jwks_cache / main.get_jwks so no real identity provider
or network access is required.
"""

import time

import main
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwk, jwt


def _generate_rsa_keypair():
    """Generate an RSA keypair and return (private_pem, public_pem)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_pem, public_pem


def _jwk_for(public_pem: str, kid: str) -> dict:
    """Build a JWKS-style key entry from a PEM public key."""
    key_dict = jwk.construct(public_pem, algorithm="RS256").to_dict()
    key_dict["kid"] = kid
    key_dict["use"] = "sig"
    key_dict["alg"] = "RS256"
    return key_dict


def _mint_token(
    private_pem: str,
    kid: str,
    *,
    sub: str = "user-123",
    aud: str = main.MCP_RESOURCE,
    issuer: str = main.ISSUER,
    expires_in: int = 3600,
) -> str:
    """Mint a JWT signed with private_pem, headers carrying kid.

    `aud` defaults to `main.MCP_RESOURCE` — the only audience this server
    now accepts, since tokens are bound to the resource server rather than
    to an OAuth client_id (see main.create_jwt_token's docstring analog in
    identity-provider/main.py).
    """
    now = int(time.time())
    claims = {
        "sub": sub,
        "aud": aud,
        "iss": issuer,
        "iat": now,
        "exp": now + expires_in,
        "azp": "confidential-client-id",
        "name": "Test User",
        "email": f"{sub}@example.com",
        "preferred_username": sub,
        "scope": "openid profile",
        "tid": "12345678-1234-1234-1234-123456789012",
    }
    return jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": kid})


@pytest.fixture
def keypair():
    """A single RSA keypair with kid 'kid-1'."""
    private_pem, public_pem = _generate_rsa_keypair()
    return {
        "kid": "kid-1",
        "private_pem": private_pem,
        "public_pem": public_pem,
        "jwks": {"keys": [_jwk_for(public_pem, "kid-1")]},
    }


@pytest.fixture(autouse=True)
def reset_jwks_cache():
    """Ensure each test starts with a clean JWKS cache."""
    original = main.jwks_cache
    main.jwks_cache = None
    yield
    main.jwks_cache = original


@pytest.fixture(autouse=True)
def reset_stdio_claims_cache():
    """Ensure each test starts with a clean stdio-mode claims cache.

    get_current_claims() caches the validated claims for the process's
    MCP_ACCESS_TOKEN on first use; without resetting this between tests, a
    later test could see a cached identity from an earlier one instead of
    validating its own token.
    """
    original = main._stdio_claims_cache
    main._stdio_claims_cache = None
    yield
    main._stdio_claims_cache = original


@pytest.fixture(autouse=True)
def reset_transport_mode():
    """Ensure each test starts in the default stdio transport mode."""
    original = main._TRANSPORT_MODE
    main._TRANSPORT_MODE = "stdio"
    yield
    main._TRANSPORT_MODE = original


# ---------------------------------------------------------------------------
# validate_token
# ---------------------------------------------------------------------------


async def test_valid_token_returns_claims(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(keypair["private_pem"], keypair["kid"])

    claims = await main.validate_token(token)

    assert claims["sub"] == "user-123"
    assert claims["aud"] == main.MCP_RESOURCE


async def test_wrong_kid_raises_no_matching_key(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])

    async def fake_get_jwks(force_refresh: bool = False):
        # Simulate a refresh that returns the same JWKS (kid still absent).
        return keypair["jwks"]

    monkeypatch.setattr(main, "get_jwks", fake_get_jwks)

    token = _mint_token(keypair["private_pem"], "unknown-kid")

    with pytest.raises(ValueError, match="No matching signing key found"):
        await main.validate_token(token)


async def test_kid_rotation_forces_refresh_and_succeeds(keypair, monkeypatch):
    """Cache holds an OLD jwks (without the new kid). A forced refresh
    should pick up the new key and validation should succeed."""
    old_jwks = {"keys": []}
    monkeypatch.setattr(main, "jwks_cache", old_jwks)

    calls = {"count": 0}

    async def fake_get_jwks(force_refresh: bool = False):
        calls["count"] += 1
        if force_refresh:
            return keypair["jwks"]
        return old_jwks

    monkeypatch.setattr(main, "get_jwks", fake_get_jwks)

    token = _mint_token(keypair["private_pem"], keypair["kid"])

    claims = await main.validate_token(token)

    assert claims["sub"] == "user-123"
    assert calls["count"] == 2  # initial lookup + forced refresh retry


async def test_expired_token_raises(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(keypair["private_pem"], keypair["kid"], expires_in=-3600)

    with pytest.raises(ValueError, match="Token validation failed"):
        await main.validate_token(token)


async def test_wrong_issuer_raises(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(
        keypair["private_pem"], keypair["kid"], issuer="http://evil.example.com"
    )

    with pytest.raises(ValueError, match="Token validation failed"):
        await main.validate_token(token)


async def test_invalid_audience_raises(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(keypair["private_pem"], keypair["kid"], aud="some-other-resource")

    with pytest.raises(ValueError, match="Invalid audience"):
        await main.validate_token(token)


async def test_client_audience_token_is_rejected(keypair, monkeypatch):
    """A token whose `aud` is an OAuth client_id (the pre-MCP-spec shape,
    and the forbidden "token passthrough" pattern the audience-binding
    requirement exists to prevent) must be rejected, not just tokens with
    some arbitrary wrong audience."""
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(keypair["private_pem"], keypair["kid"], aud="confidential-client-id")

    with pytest.raises(ValueError, match="Invalid audience"):
        await main.validate_token(token)


async def test_bad_signature_raises(keypair, monkeypatch):
    """A token whose header claims the right kid, but was actually signed
    by a different key, must fail signature verification."""
    other_private_pem, _ = _generate_rsa_keypair()
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])

    # Signed with a different private key, but headers claim kid-1.
    token = _mint_token(other_private_pem, keypair["kid"])

    with pytest.raises(ValueError, match="Token validation failed"):
        await main.validate_token(token)


# ---------------------------------------------------------------------------
# stdio-mode claims: MCP_ACCESS_TOKEN environment variable
# ---------------------------------------------------------------------------


def _tool_fn(tool):
    """Return the underlying coroutine function for a FastMCP tool.

    FastMCP 2.x wraps tools in FunctionTool objects exposing `.fn`;
    FastMCP 3.x returns the original function unchanged.
    """
    return getattr(tool, "fn", tool)


async def test_stdio_claims_missing_env_var_raises(monkeypatch):
    monkeypatch.delenv("MCP_ACCESS_TOKEN", raising=False)

    with pytest.raises(ValueError, match="MCP_ACCESS_TOKEN"):
        await main.get_current_claims()


async def test_stdio_claims_reads_and_caches_env_var(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(keypair["private_pem"], keypair["kid"])
    monkeypatch.setenv("MCP_ACCESS_TOKEN", token)

    claims = await main.get_current_claims()
    assert claims["sub"] == "user-123"

    # Cached: even if the env var disappears, the second call still works.
    monkeypatch.delenv("MCP_ACCESS_TOKEN", raising=False)
    cached_claims = await main.get_current_claims()
    assert cached_claims["sub"] == "user-123"


async def test_stdio_claims_invalid_token_raises(monkeypatch):
    monkeypatch.setenv("MCP_ACCESS_TOKEN", "not-a-real-jwt")

    with pytest.raises(ValueError, match="Token validation failed"):
        await main.get_current_claims()


# ---------------------------------------------------------------------------
# Tool-level error paths (get_user_info / echo), driven via MCP_ACCESS_TOKEN
# ---------------------------------------------------------------------------


async def test_get_user_info_returns_claims_on_valid_token(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(keypair["private_pem"], keypair["kid"])
    monkeypatch.setenv("MCP_ACCESS_TOKEN", token)

    result = await _tool_fn(main.get_user_info)()

    assert result["user_id"] == "user-123"
    assert result["name"] == "Test User"


async def test_get_user_info_returns_error_on_invalid_token(monkeypatch):
    monkeypatch.delenv("MCP_ACCESS_TOKEN", raising=False)

    result = await _tool_fn(main.get_user_info)()

    assert "error" in result
    assert "MCP_ACCESS_TOKEN" in result["error"]


async def test_echo_returns_authenticated_message_on_valid_token(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(keypair["private_pem"], keypair["kid"])
    monkeypatch.setenv("MCP_ACCESS_TOKEN", token)

    result = await _tool_fn(main.echo)(message="hi there")

    assert result == "[Authenticated as Test User] Echo: hi there"


async def test_echo_returns_auth_failure_message_on_invalid_token(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(keypair["private_pem"], keypair["kid"], expires_in=-3600)
    monkeypatch.setenv("MCP_ACCESS_TOKEN", token)

    result = await _tool_fn(main.echo)(message="hi there")

    assert result.startswith("Authentication failed: ")


async def test_user_profile_resource_returns_claims(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(keypair["private_pem"], keypair["kid"])
    monkeypatch.setenv("MCP_ACCESS_TOKEN", token)

    profile = await _tool_fn(main.user_profile)()

    assert profile["user_id"] == "user-123"
    assert profile["name"] == "Test User"
    assert profile["email"] == "user-123@example.com"
    assert profile["preferred_username"] == "user-123"
    assert profile["scope"] == "openid profile"
    assert profile["tenant_id"] == "12345678-1234-1234-1234-123456789012"


# ---------------------------------------------------------------------------
# HTTP-mode claims: FastMCP access-token dependency
# ---------------------------------------------------------------------------


async def test_http_claims_reads_from_access_token_dependency(monkeypatch):
    main._TRANSPORT_MODE = "http"
    fake_claims = {"sub": "http-user", "name": "HTTP User"}

    class _FakeAccessToken:
        claims = fake_claims

    monkeypatch.setattr(main, "get_access_token", lambda: _FakeAccessToken())

    claims = await main.get_current_claims()
    assert claims == fake_claims


async def test_http_claims_missing_access_token_raises(monkeypatch):
    main._TRANSPORT_MODE = "http"
    monkeypatch.setattr(main, "get_access_token", lambda: None)

    with pytest.raises(ValueError, match="No authenticated access token"):
        await main.get_current_claims()


# ---------------------------------------------------------------------------
# JoseTokenVerifier (FastMCP HTTP auth integration)
# ---------------------------------------------------------------------------


async def test_jose_token_verifier_valid_token_returns_access_token(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(keypair["private_pem"], keypair["kid"])

    verifier = main.JoseTokenVerifier()
    access_token = await verifier.verify_token(token)

    assert access_token is not None
    assert access_token.token == token
    assert access_token.client_id == "confidential-client-id"
    assert access_token.resource == main.MCP_RESOURCE
    assert access_token.claims["sub"] == "user-123"
    assert "openid" in access_token.scopes


async def test_jose_token_verifier_invalid_token_returns_none(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(keypair["private_pem"], keypair["kid"], expires_in=-3600)

    verifier = main.JoseTokenVerifier()
    access_token = await verifier.verify_token(token)

    assert access_token is None


async def test_jose_token_verifier_wrong_audience_returns_none(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(keypair["private_pem"], keypair["kid"], aud="confidential-client-id")

    verifier = main.JoseTokenVerifier()
    access_token = await verifier.verify_token(token)

    assert access_token is None
