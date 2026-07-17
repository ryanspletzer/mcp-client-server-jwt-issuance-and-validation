"""
End-to-end integration tests for the mcp-client demo.

These tests exercise the *real* OAuth2 authorization code flow against a
live identity provider process (launched via `uv run`), then use the
resulting access token to spin up the mcp-server over stdio, exactly as
the demo's `main()` does.

They are marked `e2e` and excluded from the default `uv run pytest`
invocation (see `addopts` in pyproject.toml). Run them explicitly with:

    uv run pytest -m e2e

They require port 8000 to be free (the identity provider binds there) and
will be skipped automatically if something else is already listening on
it.
"""

import asyncio
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main

IDENTITY_PROVIDER_DIR = str(Path(__file__).resolve().parent.parent.parent / "identity-provider")
IDENTITY_PROVIDER_URL = "http://localhost:8000/"
STARTUP_TIMEOUT_SECONDS = 30

pytestmark = pytest.mark.e2e


def _port_8000_in_use() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("localhost", 8000)) == 0


@pytest.fixture(scope="session")
def identity_provider():
    """Launch a real identity provider process for the duration of the session.

    Skips the whole e2e session if port 8000 is already occupied by
    something else, rather than trying (and likely failing) to bind it.
    """
    if _port_8000_in_use():
        pytest.skip("port 8000 in use")

    # "uv" is intentionally resolved via PATH (same pattern main.py itself uses
    # to spawn mcp-server via StdioServerParameters); argv is fixed, no shell,
    # no untrusted input.
    process = subprocess.Popen(  # noqa: S603
        ["uv", "run", "--directory", IDENTITY_PROVIDER_DIR, "python", "main.py"],  # noqa: S607
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            if process.poll() is not None:
                output = process.stdout.read().decode(errors="replace") if process.stdout else ""
                raise RuntimeError(
                    f"identity provider process exited early (code {process.returncode}):\n"
                    f"{output}"
                )
            try:
                httpx.get(IDENTITY_PROVIDER_URL, timeout=1.0)
            except httpx.HTTPError as exc:
                last_error = exc
                time.sleep(0.25)
            else:
                break
        else:
            raise RuntimeError(
                f"identity provider did not respond within {STARTUP_TIMEOUT_SECONDS}s"
            ) from last_error

        yield process
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def _assert_looks_like_jwt(token: str) -> None:
    assert isinstance(token, str)
    assert len(token.split(".")) == 3


def test_confidential_client_flow_end_to_end(identity_provider):
    access_token = asyncio.run(main.acquire_token(use_pkce=False))
    _assert_looks_like_jwt(access_token)

    # Prove the token is actually accepted by the MCP server, not just
    # well-formed.
    asyncio.run(main.connect_to_mcp_server_stdio(access_token))


def test_pkce_flow_end_to_end(identity_provider):
    access_token = asyncio.run(main.acquire_token(use_pkce=True))
    _assert_looks_like_jwt(access_token)
