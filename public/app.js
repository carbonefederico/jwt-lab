const state = { presets: [], active: null, token: null };
const el = (id) => document.getElementById(id);

async function loadPresets() {
  const response = await fetch('/api/presets');
  const data = await response.json();
  state.presets = data.presets;
  el('presetCount').textContent = `${state.presets.length} scenarios`;
  renderPresets();
  selectPreset('basic-user');
}

function renderPresets() {
  const root = el('presets');
  root.innerHTML = '';
  for (const preset of state.presets) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `chip ${state.active === preset.id ? 'active' : ''}`;
    button.dataset.id = preset.id;
    button.innerHTML = `${escapeHtml(preset.name)}<span class="tip"><strong>${escapeHtml(preset.category)}</strong>${escapeHtml(preset.description)}</span>`;
    button.addEventListener('click', () => selectPreset(preset.id));
    root.appendChild(button);
  }
}

function selectPreset(id) {
  const preset = state.presets.find((p) => p.id === id);
  if (!preset) return;
  state.active = id;
  el('presetId').value = id;
  el('claims').value = JSON.stringify(preset.claims, null, 2);
  el('ttl').value = preset.options?.expiresIn ?? 3600;
  renderPresets();
}

async function issue() {
  let claims;
  try { claims = JSON.parse(el('claims').value); }
  catch { return showError('Claims must be valid JSON.'); }

  const preset = state.presets.find((p) => p.id === state.active);
  const presetClaims = JSON.stringify(preset?.claims ?? {});
  // Claims the preset itself owns (e.g. iss in the wrong-issuer test) don't
  // need the advanced toggle; user-added reserved claims do.
  const needsAdvanced = Object.keys(claims).some((key) =>
    ['iss', 'iat', 'exp', 'nbf', 'jti'].includes(key) && !(preset && key in preset.claims)
  );

  el('issueBtn').disabled = true;
  el('issueBtn').textContent = 'Issuing…';
  try {
    const response = await fetch('/api/token', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        preset: state.active,
        claims,
        expiresIn: Number(el('ttl').value),
        advanced: el('advanced').checked || needsAdvanced
      })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error_description || 'Token issuance failed');
    state.token = data.access_token;
    renderResult(data);
  } catch (error) { showError(error.message); }
  finally { el('issueBtn').disabled = false; el('issueBtn').textContent = 'Issue token'; }
}

function renderResult(data) {
  el('copyBtn').disabled = false;
  el('result').innerHTML = `
    <div class="token-box">${escapeHtml(data.access_token)}</div>
    <div class="result-block"><h4>Protected header</h4><pre>${escapeHtml(JSON.stringify(data.decoded.header, null, 2))}</pre></div>
    <div class="result-block"><h4>Payload</h4><pre>${escapeHtml(JSON.stringify(data.decoded.payload, null, 2))}</pre></div>
    <div class="result-block"><h4>Validation</h4><pre>${escapeHtml(JSON.stringify({ issuer: data.issuer, jwks_uri: data.jwks_uri }, null, 2))}</pre></div>`;
}

function showError(message) {
  el('result').innerHTML = `<div class="notice">${escapeHtml(message)}</div>`;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
}

el('issueBtn').addEventListener('click', issue);
el('resetBtn').addEventListener('click', () => selectPreset(state.active || 'basic-user'));
el('copyBtn').addEventListener('click', async () => {
  if (!state.token) return;
  await navigator.clipboard.writeText(state.token);
  el('copyBtn').textContent = 'Copied'; setTimeout(() => el('copyBtn').textContent = 'Copy JWT', 900);
});
loadPresets().catch((e) => showError(e.message));
