# JWT Lab

A deliberately small test token issuer for API, OAuth-shaped, MCP and authorization testing.

- Beautiful web UI with presets and arbitrary JSON claims
- `POST /api/token`
- RS256 signatures + stable `kid`
- `/.well-known/jwks.json`
- `/.well-known/oauth-authorization-server`
- `/.well-known/openid-configuration` (compatibility metadata, not a full OP)
- `POST /api/introspect` — RFC 7662 token introspection (signature + expiry checked server-side, unauthenticated, stateless)
- Streamable HTTP MCP endpoint at `/mcp`
- Presets for users, workloads, MCP, delegation/token-exchange-style claims, negative tests and token profiles (RFC 9068 `at+jwt`, SPIFFE JWT-SVID, transaction tokens, ID-JAG)

## Local development

```bash
npm install
npm run dev
```

Without `JWT_PRIVATE_KEY_B64`, local development uses an ephemeral RSA key.

## Generate the production signing key

```bash
npm run generate:key
```

Copy the printed value into Vercel as `JWT_PRIVATE_KEY_B64` and set:

```text
JWT_ISSUER=https://jwt-lab.vercel.app
JWT_KID=jwt-lab-rs256-1
```

Do not allow production Vercel instances to generate their own ephemeral keys.

## REST example

```bash
curl https://jwt-lab.vercel.app/api/token \
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
https://jwt-lab.vercel.app/mcp
```

Tools:

- `issue_token`
- `introspect_token`
- `list_presets`
- `get_jwks`
- `get_oauth_metadata`

## Security

JWT Lab is intentionally unsafe as an identity system: anyone who can reach it can mint trusted test tokens. It is for development/testing only. Never configure a production resource server to trust the JWT Lab issuer.

## Preset reference

| Category | Presets |
|---|---|
| Core | `basic-user` (conforming JWT access-token shape, RFC 9068), `machine-client` (client_credentials shape, RFC 9068 claims) |
| Delegation | `delegated-agent`, `nested-delegation` (RFC 8693 `act` chains) |
| Token profiles | `spiffe-jwt-svid`, `transaction-token` (`typ: txntoken+jwt`, auto-generated `txn`), `id-jag` (`typ: oauth-id-jag+jwt`) |
| Negative tests | `missing-scope` (403), `wrong-audience`, `wrong-issuer`, `expired`, `not-yet-valid` (401 / `active: false`) |
| Edge cases | `multi-audience` (aud array) |
