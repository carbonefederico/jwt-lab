import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import { issueToken, ISSUER } from './token.js';
import { introspectToken } from './introspect.js';
import { getKeyMaterial } from './keys.js';
import { presets } from './presets.js';

function result(value) {
  return {
    content: [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    structuredContent: value
  };
}

function buildServer() {
  const server = new McpServer({
    name: 'jwt-lab',
    version: '1.0.0'
  });

  server.registerTool('issue_token', {
    title: 'Issue JWT',
    description: 'Mint an RS256 JWT for testing. Claims are arbitrary. You can start from a JWT Lab preset and override any normal claim.',
    inputSchema: {
      preset: z.string().optional().describe('Optional preset id, for example basic-user or delegated-agent.'),
      claims: z.record(z.any()).optional().describe('JWT payload claims to add or override.'),
      expiresIn: z.number().int().optional().describe('Lifetime in seconds. Negative values intentionally create expired tokens.'),
      advanced: z.boolean().optional().describe('Allow overriding reserved claims such as iss, iat, exp, nbf and jti.'),
      header: z.record(z.any()).optional().describe('Advanced protected-header overrides. Only used when advanced=true.')
    }
  }, async (args) => result(await issueToken(args)));

  server.registerTool('introspect_token', {
    title: 'Introspect JWT',
    description: 'RFC 7662 token introspection: verify an RS256 JWT against JWT Lab keys and return its active status and claims. Tests introspection-mode resource servers and negative paths (expired, tampered, garbage).',
    inputSchema: {
      token: z.string().min(1).describe('The JWT string to introspect.')
    }
  }, async ({ token }) => result(await introspectToken(token)));

  server.registerTool('list_presets', {
    title: 'List JWT presets',
    description: 'List built-in JWT testing scenarios and their default claims.',
    inputSchema: {}
  }, async () => result(presets));

  server.registerTool('get_jwks', {
    title: 'Get JWKS',
    description: 'Return the public JSON Web Key Set used to validate JWT Lab tokens.',
    inputSchema: {}
  }, async () => {
    const { publicJwk } = await getKeyMaterial();
    return result({ keys: [publicJwk] });
  });

  server.registerTool('get_oauth_metadata', {
    title: 'Get OAuth metadata',
    description: 'Return JWT Lab OAuth Authorization Server metadata.',
    inputSchema: {}
  }, async () => result({
    issuer: ISSUER,
    jwks_uri: `${ISSUER}/.well-known/jwks.json`,
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
    token_endpoint_auth_methods_supported: [],
    id_token_signing_alg_values_supported: ['RS256'],
    jwt_lab: {
      token_issuance_api: `${ISSUER}/api/token`,
      mcp_endpoint: `${ISSUER}/mcp`,
      note: 'JWT Lab is a test token issuer, not a complete OAuth authorization server.'
    }
  }));

  return server;
}

export async function handleMcp(req, res) {
  const server = buildServer();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined
  });

  res.on('close', () => {
    transport.close().catch(() => {});
    server.close().catch(() => {});
  });

  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
}
