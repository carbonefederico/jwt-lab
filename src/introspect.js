import { jwtVerify } from 'jose';
import { getKeyMaterial } from './keys.js';

export async function introspectToken(token) {
  const { publicKey } = await getKeyMaterial();
  try {
    const { payload } = await jwtVerify(token, publicKey, { algorithms: ['RS256'] });
    return {
      active: true,
      token_type: 'Bearer',
      ...payload
    };
  } catch {
    return { active: false };
  }
}
