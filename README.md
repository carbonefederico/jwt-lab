# JWT Lab

When I build or test something that consumes tokens (an API, a gateway, an MCP server, a policy enforcement point, etc.), I need valid tokens. Real RS256 JWTs with the right `aud`, `scope`, and `act` claims, signed by an issuer the resource server can verify against a JWKS.

Real identity providers can do this, but they are heavy when the IdP is only a dependency. Issuing a token with the claims I want usually means registering clients, configuring signing keys and mappings, and having the environment reachable. That is worth it when I am testing the IdP itself. It is slow when what I actually want to test is the resource server, the gateway policy, or how an agent handles an actor chain.

JWT Lab is a test token mint: submit claims, receive a correctly signed RS256 JWT, and validate it against the published JWKS. It is deliberately not an authorization server. There are no grants, no sign-in, no consent, no client registration. Tokens are stateless and the issuer never sees who requested them.

- Web UI with presets and arbitrary JSON claims
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
| Token profiles | `rfc9068-access-token` (`typ: at+jwt`), `spiffe-jwt-svid`, `transaction-token` (`typ: txntoken+jwt`, auto-generated `txn`), `id-jag` (`typ: oauth-id-jag+jwt`) |
| Negative tests | `expired`, `not-yet-valid` (401 / `active: false`) |
| Edge cases | `multi-audience` (aud array) |
