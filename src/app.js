import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { issueToken, ISSUER } from './token.js';
import { introspectToken } from './introspect.js';
import { getKeyMaterial } from './keys.js';
import { presets } from './presets.js';
import { handleMcp } from './mcp.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.resolve(__dirname, '../public');

export const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, MCP-Protocol-Version, MCP-Session-Id');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

app.get('/api/health', (_req, res) => res.json({ ok: true, issuer: ISSUER }));
app.get('/api/presets', (_req, res) => res.json({ presets }));

app.post('/api/token', async (req, res) => {
  try {
    const result = await issueToken(req.body || {});
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: 'invalid_request', error_description: error.message });
  }
});

// RFC 7662 token introspection. Unauthenticated by design: tokens here are
// public-key-signed JWTs anyone holding them can already decode, so the
// endpoint only adds the issuer's live opinion on signature and expiry.
// Statelessness means it can never report a valid token as revoked.
app.post('/api/introspect', async (req, res) => {
  const token = req.body?.token;
  if (!token || typeof token !== 'string') {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Missing "token" parameter (form-encoded per RFC 7662).' });
  }
  res.json(await introspectToken(token));
});

app.get('/.well-known/jwks.json', async (_req, res, next) => {
  try {
    const { publicJwk } = await getKeyMaterial();
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.json({ keys: [publicJwk] });
  } catch (error) {
    next(error);
  }
});

app.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json({
    issuer: ISSUER,
    jwks_uri: `${ISSUER}/.well-known/jwks.json`,
    introspection_endpoint: `${ISSUER}/api/introspect`,
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
    token_endpoint_auth_methods_supported: [],
    id_token_signing_alg_values_supported: ['RS256'],
    jwt_lab: {
      token_issuance_api: `${ISSUER}/api/token`,
      presets_api: `${ISSUER}/api/presets`,
      mcp_endpoint: `${ISSUER}/mcp`,
      note: 'JWT Lab intentionally does not implement OAuth authorization or grant flows.'
    }
  });
});

app.get('/.well-known/openid-configuration', (_req, res) => {
  res.json({
    issuer: ISSUER,
    jwks_uri: `${ISSUER}/.well-known/jwks.json`,
    introspection_endpoint: `${ISSUER}/api/introspect`,
    response_types_supported: [],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    jwt_lab: {
      token_issuance_api: `${ISSUER}/api/token`,
      mcp_endpoint: `${ISSUER}/mcp`,
      note: 'Compatibility metadata only. JWT Lab is not a complete OpenID Provider.'
    }
  });
});

app.all('/mcp', async (req, res) => {
  if (!['POST', 'GET', 'DELETE'].includes(req.method)) return res.status(405).end();
  try {
    await handleMcp(req, res);
  } catch (error) {
    console.error('[mcp]', error);
    if (!res.headersSent) res.status(500).json({ error: 'mcp_error', error_description: error.message });
  }
});

app.use(express.static(publicDir, { extensions: ['html'] }));

app.get('/app', (_req, res) => res.sendFile(path.join(publicDir, 'app.html')));
app.get('/docs', (_req, res) => res.sendFile(path.join(publicDir, 'docs.html')));
app.use((_req, res) => res.sendFile(path.join(publicDir, 'index.html')));

app.use((error, _req, res, _next) => {
  console.error(error);
  res.status(500).json({ error: 'server_error', error_description: error.message });
});
