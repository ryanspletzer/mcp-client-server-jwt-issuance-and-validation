# mcp-client-server-jwt-issuance-and-validation

An educational three-component demo of OAuth2/OIDC token issuance and validation
with MCP (Model Context Protocol) integration.
`CLAUDE.md` in this repo is a symlink to this file;
`AGENTS.md` is the canonical source.

## Layout

Each top-level component directory is an independent `uv` project
with its own `pyproject.toml`, `uv.lock`, and `.python-version` (3.12):

- `identity-provider/` — FastAPI OAuth2/OIDC server emulating Entra ID
  (authorization code flow, PKCE, RS256 JWT issuance, OIDC discovery, JWKS).
- `mcp-server/` — FastMCP stdio server that validates JWTs against the
  identity provider's JWKS and exposes demo tools.
- `mcp-client/` — demo client that runs the OAuth2 flows
  (confidential client with `client_secret`, or public client with `--pkce`),
  then spawns the MCP server over stdio and calls its tools.

Each component is a single `main.py` by design —
this is a teaching repo, so clarity beats abstraction.
Tests live in `tests/` inside each component directory.

## Working on this repo

- Always use `uv` (`uv sync`, `uv add`, `uv run pytest`) — never bare `pip`.
- Run commands from within the component directory you are working on.
- Lint Python with `ruff check` (config in the root `ruff.toml`).
- Lint Markdown with `markdownlint-cli2` run from the repo root
  (config in `.markdownlint.yaml`).
- The demo requires the identity provider running on port 8000
  before the client will work end to end;
  unit tests do not need any server running.
- Credentials, keys, and tokens here are intentionally ephemeral demo values;
  do not add real secrets.
