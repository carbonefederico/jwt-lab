# JWT Lab

When I build or test something that consumes tokens (an API, a gateway, an MCP server, a policy enforcement point, etc.), I need valid tokens. Real RS256 JWTs with the right `aud`, `scope`, and `act` claims, signed by an issuer the resource server can verify against a JWKS.

Real identity providers can do this, but they are heavy when the IdP is only a dependency. Issuing a token with the claims I want usually means registering clients, configuring signing keys and mappings, and having the environment reachable. That is worth it when I am testing the IdP itself. It is slow when what I actually want to test is the resource server, the gateway policy, or how an agent handles an actor chain.

JWT Lab is a minimal token issuer that plays the role an identity provider plays in token-based testing. You supply the claims you need — subject, audience, scopes, delegation — and it signs them into a real RS256 JWT with a stable key and kid, publishing the matching JWKS so a resource server can validate the token exactly the way it would validate an IdP-issued one. Everything else an IdP does is intentionally absent: no grant flows, no sign-in, no consent, no client registration. Tokens are stateless, and the issuer never sees who requested them.

**Live instance: [https://jwt-lab-beta.vercel.app](https://jwt-lab-beta.vercel.app)** (hosted on Vercel; the code is host-agnostic and runs anywhere Node does).

- Web UI: pick a preset scenario, edit the claims JSON, mint a token, copy it.
- REST API: POST /api/token for scripted and CI-driven tests, plus RFC 7662 introspection.
- MCP server: five tools so an agent can issue and introspect tokens itself.

## Local development

```bash
npm install
npm run dev
```

Without `JWT_PRIVATE_KEY_B64`, local development uses an ephemeral RSA key.

## Generate a fixed signing key

```bash
npm run generate:key
```

Set the printed value as `JWT_PRIVATE_KEY_B64` in your hosting environment and configure:

```text
JWT_ISSUER=https://your-lab.example.com
JWT_KID=jwt-lab-rs256-1
```

Do not allow a production instance to generate its own ephemeral keys — without a fixed key, tokens minted by one invocation may stop validating against the JWKS served by another.

## REST example

```bash
curl https://your-lab.example.com/api/token \
  -H 'content-type: application/json' \
  -d '{
    "preset":"delegated-agent",
    "claims":{
      "sub":"alice",
      "aud":"https://bank.example/mcp",
      "scope":"portfolio.read",
      "act":{"sub":"advisor-agent"}
    }
  }'
```

## MCP

Configure a Streamable HTTP MCP client with:

```text
https://your-lab.example.com/mcp
```

Tools:

- `issue_token`
- `introspect_token`
- `list_presets`
- `get_jwks`
- `get_oauth_metadata`

## Security

JWT Lab is intentionally unsafe as an identity system: anyone who can reach it can mint trusted test tokens. It is for development/testing only. Never configure a production resource server to trust the JWT Lab issuer.

### CI

Every push to `main` (and every pull request) runs in GitHub Actions:

- **Smoke** — waits for the Vercel deployment of the pushed commit (via Vercel's commit status, no token needed), then runs the 37-check smoke suite against the live `git-main` deployment.
- **Security** — CodeQL static analysis, gitleaks over the full git history, `npm audit --omit=dev --audit-level=high`, and (on PRs only) a dependency-review diff that fails on high-severity advisories. Also scheduled weekly.

## Preset reference

| Category | Presets |
|---|---|
| Core | `basic-user` (conforming JWT access-token shape, RFC 9068), `machine-client` (client_credentials shape, RFC 9068 claims) |
| Delegation | `delegated-agent`, `nested-delegation` (RFC 8693 `act` chains) |
| Token profiles | `spiffe-jwt-svid`, `transaction-token` (`typ: txntoken+jwt`, auto-generated `txn`), `id-jag` (`typ: oauth-id-jag+jwt`) |
| Negative tests | `expired`, `not-yet-valid` (401 / `active: false`) |
| Edge cases | `multi-audience` (aud array) |
