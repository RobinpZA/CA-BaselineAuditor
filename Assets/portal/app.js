/* global document, window, fetch */
'use strict';

// ── State ─────────────────────────────────────────────────────────────────
const state = {
  context: null,      // last /api/context response
  auditResult: null,  // last /api/run-audit response
};

// ── Helpers ───────────────────────────────────────────────────────────────
function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function setLoading(on) {
  document.getElementById('loading-overlay').classList.toggle('hidden', !on);
}

function toast(msg, type = 'info', durationMs = 4000) {
  const ct  = document.getElementById('toast-container');
  const el  = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = msg;
  ct.appendChild(el);
  requestAnimationFrame(() => el.classList.add('show'));
  setTimeout(() => {
    el.classList.remove('show');
    setTimeout(() => el.remove(), 300);
  }, durationMs);
}

const api = {
  async get(path) {
    const r = await fetch(path);
    if (!r.ok) throw new Error(await r.text());
    return r.json();
  },
  async post(path, body = {}) {
    const r = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      let msg;
      try { msg = (await r.json()).error ?? await r.text(); } catch { msg = await r.text(); }
      throw new Error(msg);
    }
    return r.json();
  },
};

// ── View helpers ──────────────────────────────────────────────────────────
function showView(id) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  const el = document.getElementById(id);
  if (el) el.classList.add('active');
}

function showAuditState(state) {
  ['audit-config', 'audit-running', 'audit-results', 'audit-error'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
  });
  const target = document.getElementById(state);
  if (target) target.style.display = '';
}

// ── Header tenant info ────────────────────────────────────────────────────
function updateHeaderTenant(ctx) {
  const info  = document.getElementById('tenant-info');
  const name  = document.getElementById('tenant-name-text');
  const email = document.getElementById('connected-as-text');
  const disc  = document.getElementById('btn-disconnect');

  if (ctx && ctx.connected) {
    info.style.display  = 'flex';
    disc.style.display  = 'inline-flex';
    name.textContent    = ctx.tenantName  || 'Unknown tenant';
    email.textContent   = ctx.connectedAs || '';
  } else {
    info.style.display  = 'none';
    disc.style.display  = 'none';
  }
}

// ── Connect view ──────────────────────────────────────────────────────────
function showConnectError(msg) {
  const el = document.getElementById('connect-error');
  el.textContent = msg;
  el.style.display = msg ? '' : 'none';
}

function setConnectBusy(busy, progressText) {
  document.getElementById('connect-idle').style.display     = busy ? 'none' : '';
  document.getElementById('connect-progress').style.display = busy ? '' : 'none';
  if (progressText) document.getElementById('connect-progress-text').textContent = progressText;
  document.getElementById('btn-connect').disabled = busy;
}

async function doConnect() {
  showConnectError('');
  setConnectBusy(true, 'Opening sign-in window…');
  try {
    const result = await api.post('/api/connect');
    state.context = result;
    updateHeaderTenant(result);
    showView('view-audit');
    showAuditState('audit-config');
    toast('Connected to ' + (result.tenantName || 'tenant'), 'success');
  } catch (err) {
    showConnectError(err.message || 'Connection failed');
    toast('Connection failed', 'error');
  } finally {
    setConnectBusy(false, '');
  }
}

// ── Audit view ────────────────────────────────────────────────────────────
let runningInterval = null;
const runningMessages = [
  'Fetching Conditional Access policies…',
  'Resolving identities and groups…',
  'Checking named locations…',
  'Comparing against baseline…',
  'Analysing posture checks…',
  'Generating report…',
];

function startRunningAnimation() {
  let i = 0;
  const label = document.getElementById('running-label');
  if (label) label.textContent = runningMessages[0];
  runningInterval = setInterval(() => {
    i = (i + 1) % runningMessages.length;
    if (label) label.textContent = runningMessages[i];
  }, 4000);
}

function stopRunningAnimation() {
  if (runningInterval) { clearInterval(runningInterval); runningInterval = null; }
}

function renderSummaryCard(value, label, colorClass) {
  return `<div class="summary-card">
    <div class="value ${esc(colorClass)}">${esc(String(value))}</div>
    <div class="s-label">${esc(label)}</div>
  </div>`;
}

function renderResults(data) {
  stopRunningAnimation();

  const total     = data.totalBaseline  ?? 0;
  const matched   = data.matched        ?? 0;
  const partial   = data.partial        ?? 0;
  const missing   = data.missing        ?? 0;
  const na        = data.notApplicable  ?? 0;
  const pctRaw    = data.complianceScore ?? (total > 0 ? Math.round(((matched + partial * 0.5) / total) * 100) : 0);
  const pct       = Math.min(100, Math.max(0, pctRaw));

  // Score ring
  const circumference = 238.76;
  const offset        = circumference - (pct / 100) * circumference;
  const arc           = document.getElementById('score-arc');
  const pctEl         = document.getElementById('score-pct');

  requestAnimationFrame(() => {
    if (arc) {
      arc.style.strokeDashoffset = offset;
      arc.style.stroke = pct >= 75 ? 'var(--success)' : pct >= 50 ? 'var(--warning)' : 'var(--danger)';
    }
    if (pctEl) pctEl.textContent = pct + '%';
  });

  const headline  = document.getElementById('score-headline');
  const subtext   = document.getElementById('score-subtext');
  if (headline) headline.textContent = pct >= 75 ? 'Good compliance posture' : pct >= 50 ? 'Partial compliance' : 'Needs attention';
  if (subtext)  subtext.textContent  = `${matched} matched, ${partial} partial, ${missing} missing out of ${total} baseline controls`;

  // Summary grid
  const grid = document.getElementById('summary-grid');
  if (grid) {
    grid.innerHTML = [
      renderSummaryCard(matched,  'Matched',       'value-green'),
      renderSummaryCard(partial,  'Partial',       'value-yellow'),
      renderSummaryCard(missing,  'Missing',       'value-red'),
      renderSummaryCard(na,       'Not Applicable','value-blue'),
      renderSummaryCard(total,    'Total Controls',''),
      renderSummaryCard(data.policyCount ?? 0, 'CA Policies', ''),
    ].join('');
  }

  // Posture bar
  const postureWrap  = document.getElementById('posture-bar-wrap');
  const posturePass  = data.posturePass  ?? 0;
  const postureTotal = data.postureTotal ?? 0;
  if (postureTotal > 0 && postureWrap) {
    postureWrap.style.display = '';
    const pPct = Math.round((posturePass / postureTotal) * 100);
    const fill  = document.getElementById('posture-fill');
    const badge = document.getElementById('posture-badge');
    const desc  = document.getElementById('posture-desc');
    if (fill)  fill.style.width = pPct + '%';
    if (badge) badge.textContent = `${posturePass}/${postureTotal} passed`;
    if (desc)  desc.textContent = `${posturePass} of ${postureTotal} checks passed — baseline-independent tenant security checks`;
  } else if (postureWrap) {
    postureWrap.style.display = 'none';
  }

  // Badges
  const blBadge  = document.getElementById('result-baseline-badge');
  const dtBadge  = document.getElementById('result-date-badge');
  if (blBadge) blBadge.textContent = data.baseline ?? '';
  if (dtBadge) dtBadge.textContent = new Date().toLocaleString();

  showAuditState('audit-results');
}

async function doRunAudit() {
  const baseline        = document.getElementById('sel-baseline').value;
  const includeDisabled = document.getElementById('chk-include-disabled').checked;
  const skipDevices     = document.getElementById('chk-skip-devices').checked;
  const skipTemplates   = document.getElementById('chk-skip-templates').checked;

  showAuditState('audit-running');
  startRunningAnimation();

  try {
    const result = await api.post('/api/run-audit', {
      baseline,
      includeDisabled,
      skipDevices,
      skipTemplates,
    });
    state.auditResult = result;
    renderResults(result);
    toast('Audit complete', 'success');
  } catch (err) {
    stopRunningAnimation();
    const errorText = document.getElementById('audit-error-text');
    if (errorText) errorText.textContent = err.message || 'An unknown error occurred.';
    showAuditState('audit-error');
    toast('Audit failed: ' + (err.message || 'unknown error'), 'error');
  }
}

function doNewAudit() {
  state.auditResult = null;
  showAuditState('audit-config');
}

// ── Disconnect ────────────────────────────────────────────────────────────
async function doDisconnect() {
  try {
    setLoading(true);
    await api.post('/api/disconnect');
  } catch { /* swallow */ } finally {
    setLoading(false);
  }
  state.context     = null;
  state.auditResult = null;
  updateHeaderTenant(null);
  showView('view-connect');
  showConnectError('');
  toast('Disconnected', 'info');
}

// ── Close server ──────────────────────────────────────────────────────────
async function doCloseServer() {
  try {
    await api.post('/api/close');
  } catch { /* server closes, response may not arrive */ }
  document.body.innerHTML = `
    <div style="
      display:flex;align-items:center;justify-content:center;
      min-height:100vh;flex-direction:column;gap:16px;
      font-family:'Poppins',sans-serif;color:#8896b0;background:#0a0c0f;">
      <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#3b82f6"
           stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      <div style="font-size:14px;">Portal closed. You may close this tab.</div>
    </div>`;
}

// ── Init ──────────────────────────────────────────────────────────────────
async function init() {
  // Wire up static event listeners
  document.getElementById('btn-connect')?.addEventListener('click', doConnect);
  document.getElementById('btn-disconnect')?.addEventListener('click', doDisconnect);
  document.getElementById('btn-close-server')?.addEventListener('click', doCloseServer);
  document.getElementById('btn-run-audit')?.addEventListener('click', doRunAudit);
  document.getElementById('btn-new-audit')?.addEventListener('click', doNewAudit);
  document.getElementById('btn-retry-audit')?.addEventListener('click', doNewAudit);
  document.getElementById('btn-view-report')?.addEventListener('click', () => {
    window.open('/api/report', '_blank');
  });
  document.getElementById('btn-download-report')?.addEventListener('click', () => {
    const a = document.createElement('a');
    a.href = '/api/report?download=1';
    a.download = '';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  });

  // Poll current context
  try {
    setLoading(true);
    const ctx = await api.get('/api/context');
    state.context = ctx;
    updateHeaderTenant(ctx);

    if (ctx.connected) {
      showView('view-audit');
      // If an audit was already running/done before the page loaded, restore state
      if (ctx.auditStatus === 'done') {
        // No result data available without re-running; just show config
        showAuditState('audit-config');
      } else {
        showAuditState('audit-config');
      }
    } else {
      showView('view-connect');
    }
  } catch {
    showView('view-connect');
    toast('Could not reach the portal server', 'error');
  } finally {
    setLoading(false);
  }
}

document.addEventListener('DOMContentLoaded', init);
