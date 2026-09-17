import { generateKeyPairSync, createPrivateKey, createPublicKey } from 'node:crypto';
import { exportJWK, importPKCS8 } from 'jose';

let cache;

function loadPem() {
  const configured = process.env.JWT_PRIVATE_KEY_B64;
  if (configured) {
    return Buffer.from(configured, 'base64').toString('utf8');
  }

  if (process.env.NODE_ENV === 'production' || process.env.VERCEL_ENV === 'production') {
    throw new Error('JWT_PRIVATE_KEY_B64 is required in production. Run `npm run generate:key` and set JWT_PRIVATE_KEY_B64 in the hosting environment.');
  }

  console.warn('[jwt-lab] JWT_PRIVATE_KEY_B64 not set; generating an ephemeral development key. Tokens may stop validating after restart.');
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
}

export async function getKeyMaterial() {
  if (cache) return cache;

  const privatePem = loadPem();
  const privateKey = await importPKCS8(privatePem, 'RS256');
  const publicKey = createPublicKey(createPrivateKey(privatePem));
  const publicJwk = await exportJWK(publicKey);
  const kid = process.env.JWT_KID || 'jwt-lab-rs256-1';

  cache = {
    privateKey,
    publicKey,
    publicJwk: {
      ...publicJwk,
      kid,
      use: 'sig',
      alg: 'RS256'
    },
    kid
  };

  return cache;
}
