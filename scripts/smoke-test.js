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

  // ---- RFC 8693 token exchange ----
  section('API: /oauth/token (RFC 8693)');
  const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
  const JWT_URN = 'urn:ietf:params:oauth:token-type:jwt';
  const mintFor = async (claims) => (await json(await post('/api/token', { claims }))).access_token;
  const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  const unsigned = (claims) => `${b64url({ alg: 'RS256', typ: 'JWT' })}.${b64url(claims)}.`; // undecodable-signature JWT is fine: decoded, never verified

  const subjectClaims = {
    iss: 'https://id.example', sub: 'alice', aud: 'https://api.example.com',
    scope: 'profile.read', exp: Math.floor(Date.now() / 1000) + 60, may_act: { sub: 'agent-1' }
  };
  const actorClaims = { iss: 'https://id.example', sub: 'agent-1', aud: 'https://as.example', exp: Math.floor(Date.now() / 1000) + 60 };

  const exchangeForm = (params) => post('/oauth/token', new URLSearchParams(params).toString(), 'application/x-www-form-urlencoded');
  const ex = await json(await exchangeForm({
    grant_type: EXCHANGE,
    subject_token: unsigned(subjectClaims),
    subject_token_type: JWT_URN,
    actor_token: unsigned(actorClaims),
    actor_token_type: JWT_URN
  }));
  const exPayload = ex.decoded?.payload ?? {};
  assert(ex.access_token?.split('.').length === 3 && ex.issued_token_type === JWT_URN && ex.token_type === 'Bearer', 'exchange returns OAuth envelope with 3-part JWT');
  assert(exPayload.sub === 'alice' && exPayload.scope === 'profile.read', 'subject claims carried into issued token');
  assert(exPayload.act?.sub === 'agent-1' && exPayload.act?.exp === undefined && exPayload.act?.aud === undefined, 'act = actor identity claims; exp/aud stripped per §4.1');
  assert(exPayload.iss === issuer && exPayload.exp - exPayload.iat === 3600, 'iss/iat/exp re-stamped by the lab (fixed TTL, not inherited)');

  // Subject act chain preserved beneath the new actor (RFC 8693 Figure 6).
  const chained = await json(await exchangeForm({
    grant_type: EXCHANGE,
    subject_token: unsigned({ ...subjectClaims, act: { sub: 'orchestrator', act: { sub: 'oldest' } } }),
    subject_token_type: JWT_URN,
    actor_token: unsigned(actorClaims),
    actor_token_type: JWT_URN
  }));
  const act = chained.decoded?.payload?.act;
  assert(act?.sub === 'agent-1' && act?.act?.sub === 'orchestrator' && act?.act?.act?.sub === 'oldest', 'subject act chain nests beneath the new outermost actor');

  // audience/scope/resource params override embedded values (§2.1.1).
  const overridden = await json(await exchangeForm({
    grant_type: EXCHANGE,
    audience: 'urn:example:one',
    resource: 'https://backend.example/api',
    scope: 'payments.read',
    subject_token: unsigned(subjectClaims),
    subject_token_type: JWT_URN
  }));
  assert(Array.isArray(overridden.decoded?.payload?.aud) && overridden.decoded.payload.aud.join(',') === 'urn:example:one,https://backend.example/api', 'audience + resource params combine into aud array');
  assert(overridden.decoded?.payload?.scope === 'payments.read' && overridden.scope === 'payments.read', 'scope param overrides embedded scope and echoes in response');
  assert(overridden.decoded?.payload?.act === undefined, 'no act claim when no actor token and subject has none');

  // Fall back to embedded aud when no audience params (already covered by ex).
  assert(exPayload.aud === 'https://api.example.com', 'embedded aud kept when request has no audience/resource');

  const clientTagged = await json(await exchangeForm({
    grant_type: EXCHANGE,
    client_id: 'my-client',
    client_secret: 'whatever',
    subject_token: unsigned(subjectClaims),
    subject_token_type: JWT_URN
  }));
  assert(clientTagged.decoded?.payload?.client_id === 'my-client' && !JSON.stringify(clientTagged.decoded.payload).includes('whatever'), 'client_id becomes top-level claim; secret never appears');

  const noActorType = await json(await exchangeForm({
    grant_type: EXCHANGE,
    subject_token: unsigned(subjectClaims),
    subject_token_type: JWT_URN,
    actor_token: unsigned(actorClaims)
  }));
  assert(noActorType.error === 'invalid_request' && /actor_token_type/.test(noActorType.error_description), 'actor_token without actor_token_type rejected');

  const orphanType = await json(await exchangeForm({
    grant_type: EXCHANGE,
    subject_token: unsigned(subjectClaims),
    subject_token_type: JWT_URN,
    actor_token_type: JWT_URN
  }));
  assert(orphanType.error === 'invalid_request' && /must not/.test(orphanType.error_description), 'actor_token_type without actor_token rejected');

  const wrongGrant = await json(await exchangeForm({
    grant_type: 'client_credentials', subject_token: unsigned(subjectClaims), subject_token_type: JWT_URN
  }));
  assert(wrongGrant.error === 'unsupported_grant_type', 'wrong grant_type rejected with unsupported_grant_type');

  const missingGrant = await json(await post('/oauth/token', 'subject_token=x&subject_token_type=jwt', 'application/x-www-form-urlencoded'));
  assert(missingGrant.error === 'invalid_request' && /grant_type/.test(missingGrant.error_description), 'missing grant_type rejected with invalid_request');

  const garbage = await json(await exchangeForm({
    grant_type: EXCHANGE, subject_token: 'not-a-jwt', subject_token_type: JWT_URN
  }));
  assert(garbage.error === 'invalid_request' && /decodable/.test(garbage.error_description), 'undecodable subject_token rejected');

  const badResource = await json(await exchangeForm({
    grant_type: EXCHANGE, resource: 'https://backend.example/api#frag',
    subject_token: unsigned(subjectClaims), subject_token_type: JWT_URN
  }));
  assert(badResource.error === 'invalid_target', 'resource with fragment rejected with invalid_target');

  const basicAuth = await fetch(`${BASE}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: 'Basic ' + Buffer.from('my-client:secret').toString('base64') },
    body: new URLSearchParams({ grant_type: EXCHANGE, subject_token: unsigned(subjectClaims), subject_token_type: JWT_URN }),
    signal: AbortSignal.timeout(TIMEOUT)
  });
  assert(basicAuth.status === 200 && (await basicAuth.json()).access_token, 'HTTP Basic client auth accepted (unvalidated)');

  assert((await json(await post('/api/introspect', { token: ex.access_token }, 'application/x-www-form-urlencoded'))).active === true, 'exchanged token introspects active');

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

let spawned = null;
try {
  if (!BASE) {
    const { child, base } = await startServer();
    spawned = child;
    BASE = base;
  }
  console.log(`JWT Lab smoke test — target: ${BASE}`);
  const failed = await runChecks();
  const passed = results.length - failed.length;
  console.log(`\n${passed}/${results.length} checks passed${failed.length === 0 ? ' — all good' : ''}`);
  if (failed.length > 0) {
    console.log('\nFailed checks:');
    for (const f of failed) console.log(`  ✗ ${f.name}${f.detail ? ` — ${f.detail}` : ''}`);
  }
  process.exitCode = failed.length === 0 ? 0 : 1;
} catch (error) {
  console.error(`smoke test failed to run: ${error.message}`);
  process.exitCode = 1;
} finally {
  // Unconditional: a spawned server must never outlive the test run.
  spawned?.kill();
}
