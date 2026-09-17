import { randomUUID } from 'node:crypto';
import { SignJWT, decodeJwt, decodeProtectedHeader } from 'jose';
import { getKeyMaterial } from './keys.js';
import { getPreset } from './presets.js';

export const ISSUER = process.env.JWT_ISSUER || 'https://jwt-lab.vercel.app';
const DEFAULT_TTL = Number(process.env.JWT_DEFAULT_TTL || 3600);

const RESERVED = new Set(['iss', 'iat', 'exp', 'nbf', 'jti']);

function cleanClaims(input = {}, allowReserved = false) {
  return Object.fromEntries(
    Object.entries(input).filter(([key, value]) => value !== undefined && value !== '' && (allowReserved || !RESERVED.has(key)))
  );
}

export async function issueToken({ claims = {}, preset, expiresIn, advanced = false, header = {} } = {}) {
  const basePreset = preset ? getPreset(preset) : undefined;
  if (preset && !basePreset) throw new Error(`Unknown preset: ${preset}`);

  if (!advanced) {
    const reservedKeys = Object.keys(claims).filter((key) => RESERVED.has(key));
    if (reservedKeys.length > 0) {
      throw new Error(
        `Reserved claim(s) ${reservedKeys.map((key) => `'${key}'`).join(', ')} cannot be set directly. ` +
        `Pass advanced: true to override reserved claims (${[...RESERVED].join(', ')}).`
      );
    }
  }

  const mergedClaims = {
    ...(basePreset?.claims || {}),
    ...claims
  };

  const keyMaterial = await getKeyMaterial();
  const now = Math.floor(Date.now() / 1000);
  const presetTtl = basePreset?.options?.expiresIn;
  const ttl = Number(expiresIn ?? presetTtl ?? DEFAULT_TTL);

  let payload = cleanClaims(mergedClaims, advanced);
  let jwt = new SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: keyMaterial.kid, ...(advanced ? header : {}) });

  if (advanced && mergedClaims.iss !== undefined) jwt = jwt.setIssuer(String(mergedClaims.iss));
  else jwt = jwt.setIssuer(ISSUER);

  if (advanced && mergedClaims.iat !== undefined) jwt = jwt.setIssuedAt(Number(mergedClaims.iat));
  else jwt = jwt.setIssuedAt(now);

  if (advanced && mergedClaims.exp !== undefined) jwt = jwt.setExpirationTime(Number(mergedClaims.exp));
  else jwt = jwt.setExpirationTime(now + ttl);

  if (advanced && mergedClaims.nbf !== undefined) jwt = jwt.setNotBefore(Number(mergedClaims.nbf));

  if (advanced && mergedClaims.jti !== undefined) jwt = jwt.setJti(String(mergedClaims.jti));
  else jwt = jwt.setJti(randomUUID());

  const token = await jwt.sign(keyMaterial.privateKey);

  return {
    access_token: token,
    token_type: 'Bearer',
    expires_in: ttl,
    issuer: decodeJwt(token).iss,
    jwks_uri: `${ISSUER}/.well-known/jwks.json`,
    decoded: {
      header: decodeProtectedHeader(token),
      payload: decodeJwt(token)
    }
  };
}
