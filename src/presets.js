export const presets = [
  // ---------- Core ----------
  {
    id: 'basic-user',
    name: 'Basic user token',
    category: 'Core',
    description: 'A minimal user access token: sub is the user, client_id the OAuth client, aud the target API, scope the delegated permissions. Conforming JWT access-token shape (RFC 9068): typ at+jwt plus required iss, sub, client_id, aud, iat, exp and jti.',
    header: { typ: 'at+jwt' },
    claims: {
      sub: 'alice',
      client_id: 'desktop-client',
      aud: 'https://api.example.com',
      scope: 'profile.read orders.read'
    }
  },
  {
    id: 'machine-client',
    name: 'Machine / client token',
    category: 'Core',
    description: 'A client_credentials workload token. RFC 9068 requires client_id on JWT access tokens, and sub is the client itself — no human user is involved.',
    claims: {
      sub: 'inventory-sync-service',
      client_id: 'inventory-sync-service',
      aud: 'https://inventory.example.com',
      scope: 'inventory.read inventory.write'
    }
  },

  // ---------- Delegation (RFC 8693) ----------
  {
    id: 'delegated-agent',
    name: 'Delegated user → agent',
    category: 'Delegation',
    description: 'Token-exchange output shape (RFC 8693): sub remains the user and the outermost act is the current actor. Resource servers must authorize on sub plus the outermost act only — inner acts are history.',
    claims: {
      sub: 'alice',
      aud: 'https://mcp.example.com',
      scope: 'portfolio.read',
      act: {
        sub: 'investment-advisor-agent'
      }
    }
  },
  {
    id: 'nested-delegation',
    name: 'Nested delegation chain',
    category: 'Delegation',
    description: 'User → orchestrator-agent → payment-specialist. Reading order: outermost act (payment-specialist) is the current actor; each nested act is an earlier hop.',
    claims: {
      sub: 'alice',
      aud: 'https://mcp.example.com',
      scope: 'payments.read',
      act: {
        sub: 'payment-specialist',
        act: {
          sub: 'orchestrator-agent'
        }
      }
    }
  },

  // ---------- Token profiles ----------
  {
    id: 'rfc9068-access-token',
    name: 'JWT access token (RFC 9068)',
    category: 'Token profiles',
    description: 'The RFC 9068 JWT access-token profile: typ at+jwt in the header plus required iss, exp, aud, sub, client_id, iat and jti (added automatically).',
    header: { typ: 'at+jwt' },
    claims: {
      sub: 'alice',
      client_id: 'desktop-client',
      aud: 'https://api.example.com',
      scope: 'orders.read orders.write'
    }
  },
  {
    id: 'spiffe-jwt-svid',
    name: 'SPIFFE JWT-SVID (SPIRE)',
    category: 'Token profiles',
    description: 'A SPIFFE JWT-SVID as SPIRE issues it: sub is a SPIFFE ID, aud the expected audiences, 5-minute lifetime. Only sub, aud and exp are required; JWT Lab adds iss, iat and jti like SPIRE does.',
    claims: {
      sub: 'spiffe://example.org/ns/prod/sa/inventory-sync',
      aud: ['https://api.example.com']
    },
    options: { expiresIn: 300 }
  },
  {
    id: 'transaction-token',
    name: 'Transaction token (Txn-Token)',
    category: 'Token profiles',
    description: 'A Txn-Token per the OAuth transaction-tokens draft: typ txntoken+jwt, aud is the trust domain, and txn, sub, scope, req_wl are required; tctx and rctx are recommended. Short-lived and immutable.',
    header: { typ: 'txntoken+jwt' },
    claims: {
      sub: 'alice',
      aud: 'https://trust-domain.bank.example',
      scope: 'payments.read payments.write',
      req_wl: 'api-gateway.trust-domain.bank.example',
      tctx: { purpose: 'payment-authorization', authorization_id: 'authz-7f3a' },
      rctx: { source_ip: '203.0.113.7', acr: 'mfa' }
    },
    options: { expiresIn: 300, generateTxn: true }
  },
  {
    id: 'id-jag',
    name: 'Identity Assertion JWT Grant (ID-JAG)',
    category: 'Token profiles',
    description: 'An ID-JAG per the identity-assertion-authorization-grant draft: typ oauth-id-jag+jwt; aud is the resource authorization server, client_id the OAuth client that will redeem the grant. Short-lived by design.',
    header: { typ: 'oauth-id-jag+jwt' },
    claims: {
      sub: 'alice',
      aud: 'https://authorization.example.net',
      client_id: 'client-at-resource-as',
      resource: ['https://api.example.net'],
      scope: 'files.read files.write',
      email: 'alice@example.com'
    },
    options: { expiresIn: 300 }
  },

  // ---------- Negative tests ----------
  {
    id: 'missing-scope',
    name: 'Insufficient scope',
    category: 'Negative tests',
    description: 'Valid signature and audience, but scope (payments.read) does not cover what the RS requires (e.g. payments.write). Expect 403 insufficient_scope (RFC 6750): an authorization failure, not a token failure.',
    claims: {
      sub: 'alice',
      aud: 'https://mcp.example.com',
      scope: 'payments.read'
    }
  },
  {
    id: 'wrong-audience',
    name: 'Wrong audience',
    category: 'Negative tests',
    description: 'A validly signed token minted for a different resource server. Audience binding (RFC 8707 / RFC 9068 / MCP authorization) requires the RS to reject it with 401 invalid_token.',
    claims: {
      sub: 'alice',
      aud: 'https://wrong-resource.example.com',
      scope: 'customers.read'
    }
  },
  {
    id: 'wrong-issuer',
    name: 'Wrong issuer',
    category: 'Negative tests',
    description: 'Signed with the JWT Lab key but claims a different iss. A conforming RS only trusts its configured issuer and rejects with 401 invalid_token; introspection returns active: false.',
    claims: {
      iss: 'https://attacker.example.com',
      sub: 'alice',
      aud: 'https://api.example.com',
      scope: 'profile.read'
    },
    options: { advanced: true }
  },
  {
    id: 'expired',
    name: 'Expired token',
    category: 'Negative tests',
    description: 'Signature, iss and aud are fine but exp is in the past. A conforming RS rejects with 401 invalid_token; introspection returns active: false.',
    claims: {
      sub: 'alice',
      aud: 'https://api.example.com',
      scope: 'profile.read'
    },
    options: { expiresIn: -300 }
  },
  {
    id: 'not-yet-valid',
    name: 'Not yet valid (nbf)',
    category: 'Negative tests',
    description: 'Valid signature and exp in the future, but nbf has not passed. A conforming RS rejects with 401 invalid_token until nbf is reached; introspection returns active: false.',
    claims: {
      sub: 'alice',
      aud: 'https://api.example.com',
      scope: 'profile.read'
    },
    options: { nbfOffset: 3600, expiresIn: 7200 }
  },

  // ---------- Edge cases ----------
  {
    id: 'multi-audience',
    name: 'Multiple audiences',
    category: 'Edge cases',
    description: 'JWT aud represented as an array (legal per RFC 7519): the RS must accept it if it recognizes itself among the audiences.',
    claims: {
      sub: 'alice',
      aud: ['https://api.example.com', 'https://mcp.example.com'],
      scope: 'profile.read tools.read'
    }
  }
];

export function getPreset(id) {
  return presets.find((preset) => preset.id === id);
}
