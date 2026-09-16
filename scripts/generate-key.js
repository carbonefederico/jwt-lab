import { generateKeyPairSync } from 'node:crypto';

const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const encoded = Buffer.from(pem, 'utf8').toString('base64');

console.log('\nAdd this environment variable to Vercel:\n');
console.log(`JWT_PRIVATE_KEY_B64=${encoded}`);
console.log('\nOptional:\nJWT_ISSUER=https://jwt-lab.vercel.app\nJWT_KID=jwt-lab-rs256-1\n');
