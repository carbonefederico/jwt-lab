import { randomUUID } from 'node:crypto';
import { SignJWT, decodeJwt, decodeProtectedHeader } from 'jose';
import { getKeyMaterial } from './keys.js';
import { resolveIssuer } from './token.js';

// RFC 8693 OAuth 2.0 Token Exchange. Compliant request surface; the lab
// policy deliberately deviates in two documented places: inbound tokens are
// decoded but never validated (they are inputs to be embedded, not proofs to
// be checked) and any client_id/client_secret is accepted unvalidated.
const EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
const JWT_TYPE = 'urn:ietf:params:oauth:token-type:jwt';
const DEFAULT_TTL = Number(process.env.JWT_DEFAULT_TTL || 3600);

// RFC 8693 §4.1: non-identity claims are not meaningful within act and are
// not used there.
const ACT_FORBIDDEN = new Set(['exp', 'nbf', 'aud']);

class ExchangeError extends Error {
  constructor(code, description) {
    super(description);
    this.code = code;
  }
}

// express.urlencoded collapses repeated params to the last value, so the
// route hands us the raw body; parse it here keeping every value. A param
// given once stays a string, repeated params become arrays.
function parseForm(rawBody) {
  const params = new URLSearchParams(rawBody);
  const result = {};
  for (const key of new Set(params.keys())) {
    const values = params.getAll(key);
    result[key] = values.length > 1 ? values : values[0];
  }
  return result;
}

function toList(value) {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

function identityClaims(claims) {
  return Object.fromEntries(Object.entries(claims).filter(([key]) => !ACT_FORBIDDEN.has(key)));
}

// The act claim composes per RFC 8693 §4.1 (Figure 6): the current actor —
// the actor token's identity claims — goes outermost; prior chains nest
// beneath, least recent deepest. The actor token's own act chain keeps its
// place directly beneath the actor's identity, and the subject token's act
// chain appends at the deepest point so no history is dropped.
function buildAct(subjectClaims, actorClaims) {
  const subjectChain = subjectClaims.act ? structuredClone(subjectClaims.act) : undefined;
  if (!actorClaims) return subjectChain;

  const outer = identityClaims(structuredClone(actorClaims));
  if (outer.act && subjectChain) {
    let node = outer.act;
    while (node.act) node = node.act;
    node.act = subjectChain;
  } else if (subjectChain) {
    outer.act = subjectChain;
  }
  return Object.keys(outer).length > 0 ? outer : undefined;
}

export async function exchangeToken(rawBody, { origin, basicClientId } = {}) {
  const params = parseForm(rawBody);

  if (params.grant_type === undefined) {
    throw new ExchangeError('invalid_request', 'Missing "grant_type" parameter.');
  }
  if (params.grant_type !== EXCHANGE_GRANT) {
    throw new ExchangeError('unsupported_grant_type', `Unsupported "grant_type" value; expected "${EXCHANGE_GRANT}".`);
  }

  const subject = decodeInput(params, 'subject_token', 'subject_token_type');
  let actorClaims;
  if (params.actor_token !== undefined) {
    if (params.actor_token_type === undefined) {
      throw new ExchangeError('invalid_request', 'The "actor_token_type" parameter is required when "actor_token" is present.');
    }
    actorClaims = decodeInput(params, 'actor_token', 'actor_token_type').claims;
  } else if (params.actor_token_type !== undefined) {
    throw new ExchangeError('invalid_request', 'The "actor_token_type" parameter must not be included without "actor_token".');
  }

  const resourceValues = toList(params.resource);
  for (const uri of resourceValues) {
    // RFC 8693 §2.1: resource MUST be an absolute URI and MUST NOT include
    // a fragment.
    if (!/^[a-z][a-z0-9+.-]*:/i.test(uri) || uri.includes('#')) {
      throw new ExchangeError('invalid_target', `The "resource" parameter must be an absolute URI without a fragment: ${uri}`);
    }
  }
  if (Array.isArray(params.scope) || Array.isArray(params.client_id)) {
    throw new ExchangeError('invalid_request', 'The "scope" and "client_id" parameters must appear at most once.');
  }

  // audience/resource params override; fall back to the subject token's
  // embedded aud, and omit aud entirely when neither is present.
  const audiences = [...toList(params.audience), ...resourceValues];
  const aud = audiences.length > 0 ? (audiences.length > 1 ? audiences : audiences[0]) : subject.claims.aud;
  const scope = typeof params.scope === 'string' ? params.scope : subject.claims.scope;

  const claims = {
    ...structuredClone(subject.claims),
    ...(aud !== undefined ? { aud } : {}),
    ...(scope !== undefined ? { scope } : {}),
    // Form client_id wins; the Basic auth username is the fallback. The
    // secret is never read anywhere.
    ...(() => {
      const clientId = typeof params.client_id === 'string' && params.client_id !== ''
        ? params.client_id
        : (typeof basicClientId === 'string' && basicClientId !== '' ? basicClientId : undefined);
      return clientId !== undefined ? { client_id: clientId } : {};
    })()
  };
  if (claims.sub === undefined) {
    throw new ExchangeError('invalid_request', 'The subject token carries no "sub" claim.');
  }
  const act = buildAct(subject.claims, actorClaims);
  if (act !== undefined) claims.act = act;

  const keyMaterial = await getKeyMaterial();
  const now = Math.floor(Date.now() / 1000);
  const issuer = resolveIssuer(origin);
  const jwt = await new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: keyMaterial.kid })
    .setIssuer(issuer)
    .setIssuedAt(now)
    .setExpirationTime(now + DEFAULT_TTL)
    .setJti(randomUUID())
    .sign(keyMaterial.privateKey);

  return {
    access_token: jwt,
    issued_token_type: JWT_TYPE,
    token_type: 'Bearer',
    expires_in: DEFAULT_TTL,
    // Same decode-on-issuance convenience as the presets API.
    decoded: {
      header: decodeProtectedHeader(jwt),
      payload: decodeJwt(jwt)
    },
    // RFC 8693 §2.2.1: optional here because the issued scope always equals
    // the requested scope when a scope was requested.
    ...(typeof params.scope === 'string' ? { scope: params.scope } : {})
  };
}

function decodeInput(params, name, typeParam) {
  const token = params[name];
  const type = params[typeParam];
  if (typeof token !== 'string' || token === '' || typeof type !== 'string' || type === '') {
    throw new ExchangeError('invalid_request', `Missing or invalid "${name}" or "${typeParam}" parameter.`);
  }
  let claims;
  try {
    claims = decodeJwt(token);
  } catch {
    throw new ExchangeError('invalid_request', `The "${name}" parameter is not a decodable JWT.`);
  }
  return { token, type, claims };
}

export { ExchangeError, EXCHANGE_GRANT };
