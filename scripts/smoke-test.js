// Smoke test for JWT Lab. Boots the real app on a random port (or targets
// SMOKE_BASE_URL when set, e.g. a deployed instance) and exercises both
// surfaces: the HTTP API and the MCP endpoint. Exits non-zero on failure.
//
//   npm test                              # boots server on 127.0.0.1:<random>
//   SMOKE_BASE_URL=https://... npm test   # runs the same checks against a deployment
import net from 'node:net';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

let BASE = process.env.SMOKE_BASE_URL?.replace(/\/$/, '');
const TIMEOUT = 10_000;

const results = [];
function assert(cond, name, detail = '') {
  results.push({ ok: !!cond, name, detail });
  console.log(`  ${cond ? '✓' : '✗'} ${name}${cond || !detail ? '' : ` — ${detail}`}`);
}
function section(title) {
  console.log(`\n${title}`);
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

async function startServer() {
  const port = await freePort();
  // Boot src/app.js directly rather than src/local.js so a local .env file
  // cannot skew issuer expectations. JWT_ISSUER is cleared so the issuer
  // resolves from the request origin.
  const env = { ...process.env, PORT: String(port), JWT_ISSUER: '' };
  const child = spawn(process.execPath, ['-e', "import('./src/app.js').then(({app}) => app.listen(Number(process.env.PORT), '127.0.0.1'))"], {
    cwd: fileURLToPath(new URL('..', import.meta.url)),
    env,
    stdio: 'ignore'
  });
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`server exited early with code ${child.exitCode}`);
    try {
      const res = await fetch(`http://127.0.0.1:${port}/api/health`, { signal: AbortSignal.timeout(1000) });
      if (res.ok) return { child, base: `http://127.0.0.1:${port}` };
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  child.kill();
  throw new Error('server did not become healthy within 10s');
}

async function get(path) {
  const res = await fetch(`${BASE}${path}`, { signal: AbortSignal.timeout(TIMEOUT) });
  return { status: res.status, headers: res.headers, body: await res.text() };
}

async function post(path, body, contentType = 'application/json') {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'content-type': contentType },
    body: contentType === 'application/json' ? JSON.stringify(body) : new URLSearchParams(body).toString(),
    signal: AbortSignal.timeout(TIMEOUT)
  });
  return { status: res.status, body: await res.text() };
}

async function json(res) {
  try {
    return JSON.parse(res.body);
  } catch {
    return { __unparsed: res.body?.slice(0, 200) };
  }
}

// MCP calls are stateless (sessionIdGenerator: undefined); responses may
// come back as SSE (data: lines) or plain JSON depending on negotiation.
async function mcpRpc(method, params, id) {
  const res = await fetch(`${BASE}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
    signal: AbortSignal.timeout(TIMEOUT)
  });
  const text = await res.text();
  if ((res.headers.get('content-type') || '').includes('text/event-stream')) {
    for (const line of text.split('\n')) {
      if (!line.startsWith('data:')) continue;
      const msg = JSON.parse(line.slice(5).trim());
      if (msg.id === id) return msg;
    }
    return { __no_matching_event: true };
  }
  try {
    return JSON.parse(text);
  } catch {
    return { __unparsed: text.slice(0, 200) };
  }
}

async function mcpTool(name, args, id) {
  return mcpRpc('tools/call', { name, arguments: args }, id);
}

async function runChecks() {
  // ---- health & discovery ----
  section('Health & discovery');
  const health = await json(await get('/api/health'));
  assert(health.ok === true && health.issuer, '/api/health ok with issuer');
  const issuer = health.issuer;

  const presets = (await json(await get('/api/presets'))).presets || [];
  assert(presets.length > 0 && presets.every((p) => p.id && p.name && p.claims), `/api/presets returns ${presets.length} well-formed presets`);

  const jwks = await json(await get('/.well-known/jwks.json'));
  const key = jwks.keys?.[0];
  assert(key?.kty === 'RSA' && key?.kid && key?.alg === 'RS256', 'JWKS publishes RSA key with kid + alg');

  const asMeta = await json(await get('/.well-known/oauth-authorization-server'));
  assert(asMeta.issuer === issuer, 'oauth metadata issuer consistent');
  assert(asMeta.jwks_uri === `${issuer}/.well-known/jwks.json`, 'oauth metadata jwks_uri points at issuer');
  assert((await json(await get('/.well-known/openid-configuration'))).issuer === issuer, 'openid-configuration issuer consistent');

  // ---- API token issuance ----
  section('API: /api/token');
  const first = presets[0];
  const minted = await json(await post('/api/token', { preset: first.id }));
  assert(minted.access_token?.split('.').length === 3, `mint with preset '${first.id}' returns 3-part JWT`);
  assert(minted.decoded?.header?.alg === 'RS256' && minted.decoded?.header?.kid, 'token header has alg RS256 + kid');
  assert(minted.issuer === minted.decoded?.payload?.iss, 'response issuer matches payload iss');
  assert(Number.isFinite(minted.expires_in) && minted.expires_in > 0, 'expires_in positive number');

  const everyPreset = await Promise.all(presets.map(async (p) => {
    const r = await post('/api/token', { preset: p.id });
    const parsed = await json(r);
    const ok = r.status === 200 && parsed.access_token;
    return ok ? true : `${p.id} (HTTP ${r.status}: ${JSON.stringify(parsed).slice(0, 120)})`;
  }));
  const badPresets = everyPreset.filter((v) => v !== true);
  assert(badPresets.length === 0, `mint succeeds for every preset (${presets.length})`, badPresets.length ? `failed: ${badPresets.join(' | ')}` : '');

  const typedPresets = presets.filter((p) => p.header?.typ);
  const typChecks = await Promise.all(typedPresets.map(async (p) => {
    const t = await json(await post('/api/token', { preset: p.id }));
    return t.decoded?.header?.typ === p.header.typ;
  }));
  assert(typedPresets.length === 0 || typChecks.every(Boolean), `presets with spec typ headers emit them (${typedPresets.length} checked)`);

  const txnPreset = presets.find((p) => p.options?.generateTxn);
  if (txnPreset) {
    const [t1, t2] = await Promise.all([0, 1].map(async () => json(await post('/api/token', { preset: txnPreset.id }))));
    assert(t1.decoded.payload.txn && t1.decoded.payload.txn !== t2.decoded.payload.txn, 'generateTxn mints a unique txn per token');
  }

  const expiredPresets = presets.filter((p) => Number(p.options?.expiresIn) < 0);
  const nbfPresets = presets.filter((p) => Number(p.options?.nbfOffset) > 0);
  if (expiredPresets.length === 0 && nbfPresets.length === 0) {
    console.log('  (no negative-time presets present — skipped exp/nbf checks)');
  } else {
    if (expiredPresets.length > 0) {
      const t = await json(await post('/api/token', { preset: expiredPresets[0].id }));
      assert(t.decoded.payload.exp < Date.now() / 1000, 'negative-TTL preset mints an already-expired token');
    }
    if (nbfPresets.length > 0) {
      const t = await json(await post('/api/token', { preset: nbfPresets[0].id }));
      assert(t.decoded.payload.nbf > Date.now() / 1000, 'nbfOffset preset mints a not-yet-valid token');
    }
  }

  const badReserved = await json(await post('/api/token', { claims: { iss: 'https://spoofed.example' } }));
  assert(badReserved.error === 'invalid_request' && /advanced/i.test(badReserved.error_description), 'reserved claim without advanced rejected with hint');
  const badReserved2 = await json(await post('/api/token', { claims: { iss: 'x', jti: 'y' } }));
  assert(/'iss', 'jti'/.test(badReserved2.error_description), 'multiple reserved claims all named in error');
  const advanced = await json(await post('/api/token', { advanced: true, claims: { iss: 'https://spoofed.example' } }));
  assert(advanced.decoded.payload.iss === 'https://spoofed.example' && advanced.issuer === advanced.decoded.payload.iss, 'advanced iss override mints and reports consistently');
  const unknownPreset = await json(await post('/api/token', { preset: 'no-such-preset' }));
  assert(unknownPreset.error === 'invalid_request' && /Unknown preset/.test(unknownPreset.error_description), 'unknown preset rejected');

  // ---- introspection ----
  section('API: /api/introspect');
  const roundTrip = await json(await post('/api/introspect', { token: minted.access_token }, 'application/x-www-form-urlencoded'));
  assert(roundTrip.active === true && roundTrip.iss === issuer, 'fresh token introspects active with matching iss');
  const tampered = `${minted.access_token.slice(0, -3)}abc`;
  assert((await json(await post('/api/introspect', { token: tampered }, 'application/x-www-form-urlencoded'))).active === false, 'tampered token introspects inactive');
  assert((await json(await post('/api/introspect', { token: 'not-a-jwt' }, 'application/x-www-form-urlencoded'))).active === false, 'garbage token introspects inactive');
  assert((await post('/api/introspect', {}, 'application/x-www-form-urlencoded')).status === 400, 'introspect without token returns 400');

  // ---- static & CORS ----
  section('Static & CORS');
  assert((await get('/')).status === 200, 'landing page serves');
  assert((await get('/app')).status === 200, 'lab UI serves');
  assert((await get('/docs')).status === 200, 'docs serve');
  const preflight = await fetch(`${BASE}/api/token`, { method: 'OPTIONS', signal: AbortSignal.timeout(TIMEOUT) });
  assert(preflight.status === 204, 'CORS preflight returns 204');

  // ---- MCP ----
  section('MCP: /mcp');
  const init = await mcpRpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'smoke-test', version: '1.0' } }, 1);
  assert(!!init.result?.protocolVersion && init.result?.serverInfo?.name === 'jwt-lab', 'initialize negotiates protocol and reports serverInfo');

  const tools = await mcpRpc('tools/list', {}, 2);
  const toolNames = (tools.result?.tools || []).map((t) => t.name);
  const expected = ['issue_token', 'introspect_token', 'list_presets', 'get_jwks', 'get_oauth_metadata'];
  assert(expected.every((t) => toolNames.includes(t)), `tools/list exposes all expected tools (${toolNames.length} total)`);

  const mcpMint = await mcpTool('issue_token', { preset: first.id }, 3);
  assert(mcpMint.result?.structuredContent?.access_token?.split('.').length === 3 && mcpMint.result.isError !== true, 'issue_token mints via MCP');
  const mcpBad = await mcpTool('issue_token', { claims: { iss: 'https://spoofed.example' } }, 4);
  assert(mcpBad.result?.isError === true && /advanced/i.test(mcpBad.result.content?.[0]?.text || ''), 'issue_token reserved-claim error surfaces as tool error');
  const mcpAdvanced = await mcpTool('issue_token', { advanced: true, claims: { iss: 'https://spoofed.example' } }, 5);
  assert(mcpAdvanced.result?.structuredContent?.decoded?.payload?.iss === 'https://spoofed.example', 'issue_token advanced override works via MCP');
  const mcpIntrospect = await mcpTool('introspect_token', { token: mcpMint.result.structuredContent.access_token }, 6);
  assert(mcpIntrospect.result?.structuredContent?.active === true, 'introspect_token round-trips via MCP');
  const mcpGarbage = await mcpTool('introspect_token', { token: 'not-a-jwt' }, 7);
  assert(mcpGarbage.result?.structuredContent?.active === false, 'introspect_token reports garbage as inactive');
  assert((await mcpTool('list_presets', {}, 8)).result?.structuredContent, 'list_presets returns data');
  assert((await mcpTool('get_jwks', {}, 9)).result?.structuredContent?.keys?.length > 0, 'get_jwks returns keys');
  const unknownTool = await mcpTool('definitely_not_a_tool', {}, 10);
  assert(unknownTool.error || unknownTool.result?.isError === true, 'unknown tool call is rejected');

  return results.filter((r) => !r.ok);
}

try {
  let child = null;
  if (!BASE) {
    const started = await startServer();
    child = started.child;
    BASE = started.base;
  }
  console.log(`JWT Lab smoke test — target: ${BASE}`);
  const failed = await runChecks();
  const passed = results.length - failed.length;
  console.log(`\n${passed}/${results.length} checks passed${failed.length === 0 ? ' — all good' : ''}`);
  if (failed.length > 0) {
    console.log('\nFailed checks:');
    for (const f of failed) console.log(`  ✗ ${f.name}${f.detail ? ` — ${f.detail}` : ''}`);
  }
  child?.kill();
  process.exitCode = failed.length === 0 ? 0 : 1;
} catch (error) {
  console.error(`smoke test failed to run: ${error.message}`);
  process.exitCode = 1;
}
