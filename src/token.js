import { randomUUID } from 'node:crypto';
import { SignJWT, decodeJwt, decodeProtectedHeader } from 'jose';
import { getKeyMaterial } from './keys.js';
import { getPreset } from './presets.js';

// Canonical issuer. Host-agnostic: JWT_ISSUER overrides; otherwise the
// issuer is derived from the request origin so any deployment URL works.
export const ISSUER = process.env.JWT_ISSUER || '';
const FALLBACK_ISSUER = 'http://localhost:3000';
export function resolveIssuer(origin) {
  return ISSUER || origin || FALLBACK_ISSUER;
}
const DEFAULT_TTL = Number(process.env.JWT_DEFAULT_TTL || 3600);

const RESERVED = new Set(['iss', 'iat', 'exp', 'nbf', 'jti']);

// A null value in claims means "drop this preset default" rather than emit null.
function cleanClaims(input = {}, allowReserved = false) {
  return Object.fromEntries(
    Object.entries(input).filter(([key, value]) => value !== undefined && value !== null && value !== '' && (allowReserved || !RESERVED.has(key)))
  );
}

export async function issueToken({ claims = {}, preset, expiresIn, advanced = false, header = {}, origin } = {}) {
  const basePreset = preset ? getPreset(preset) : undefined;
  if (preset && !basePreset) throw new Error(`Unknown preset: ${preset}`);

  const presetOptions = basePreset?.options || {};
  // Presets that need reserved claims themselves opt in via
  // options.advanced; the caller can pass
  // advanced as usual. Caller-supplied reserved keys still require
  // advanced even on an advanced preset — only the preset's own claims
  // are exempt.
  const allowAdvanced = advanced === true || presetOptions.advanced === true;

  if (!allowAdvanced) {
    const reservedKeys = Object.keys(claims).filter((key) => RESERVED.has(key));
    if (reservedKeys.length > 0) {
      throw new Error(
        `Reserved claim(s) ${reservedKeys.map((key) => `'${key}'`).join(', ')} cannot be set directly. ` +
        `Pass advanced: true to override reserved claims (${[...RESERVED].join(', ')}).`
      );
    }
  } else if (presetOptions.advanced === true) {
    const presetOwned = new Set(Object.keys(basePreset.claims || {}));
    const callerReserved = Object.keys(claims).filter((key) => RESERVED.has(key) && !presetOwned.has(key));
    if (advanced !== true && callerReserved.length > 0) {
      throw new Error(
        `Reserved claim(s) ${callerReserved.map((key) => `'${key}'`).join(', ')} cannot be set directly. ` +
        `Pass advanced: true to override reserved claims (${[...RESERVED].join(', ')}).`
      );
    }
  }

  const mergedClaims = {
    ...(basePreset?.claims || {}),
    ...claims
  };

  // Transaction tokens (draft-ietf-oauth-transaction-tokens) require a unique txn per token.
  if (presetOptions.generateTxn && mergedClaims.txn === undefined) {
    mergedClaims.txn = randomUUID();
  }

  const keyMaterial = await getKeyMaterial();
  const now = Math.floor(Date.now() / 1000);
  const ttl = Number(expiresIn ?? presetOptions.expiresIn ?? DEFAULT_TTL);

  // Spec-mandated typ values (at+jwt, txntoken+jwt, oauth-id-jag+jwt) come from
  // the preset; explicit header overrides stay behind the advanced flag.
  const protectedHeader = {
    alg: 'RS256',
    typ: 'JWT',
    kid: keyMaterial.kid,
    ...(basePreset?.header || {}),
    ...(advanced === true ? header : {})
  };

  let jwt = new SignJWT(cleanClaims(mergedClaims, allowAdvanced)).setProtectedHeader(protectedHeader);

  const issuer = resolveIssuer(origin);

  if (allowAdvanced && mergedClaims.iss !== undefined) jwt = jwt.setIssuer(String(mergedClaims.iss));
  else jwt = jwt.setIssuer(issuer);

  if (allowAdvanced && mergedClaims.iat !== undefined) jwt = jwt.setIssuedAt(Number(mergedClaims.iat));
  else jwt = jwt.setIssuedAt(now);

  if (allowAdvanced && mergedClaims.exp !== undefined) jwt = jwt.setExpirationTime(Number(mergedClaims.exp));
  else jwt = jwt.setExpirationTime(now + ttl);

  if (mergedClaims.nbf !== undefined) jwt = jwt.setNotBefore(Number(mergedClaims.nbf));
  else if (presetOptions.nbfOffset !== undefined) jwt = jwt.setNotBefore(now + Number(presetOptions.nbfOffset));

  if (allowAdvanced && mergedClaims.jti !== undefined) jwt = jwt.setJti(String(mergedClaims.jti));
  else jwt = jwt.setJti(randomUUID());

  const token = await jwt.sign(keyMaterial.privateKey);

  return {
    access_token: token,
    token_type: 'Bearer',
    expires_in: ttl,
    issuer: decodeJwt(token).iss,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    decoded: {
      header: decodeProtectedHeader(token),
      payload: decodeJwt(token)
    }
  };
}
