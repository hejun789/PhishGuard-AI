/* PhishGuard AI — Frontend Logic */

// ─── Matrix Rain ──────────────────────────────────────────────────
(function initMatrixRain() {
  const canvas = document.getElementById('matrix-rain');
  const ctx    = canvas.getContext('2d');

  let cols, drops;

  function resize() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
    cols  = Math.floor(canvas.width / 18);
    drops = Array.from({ length: cols }, () => Math.random() * -50);
  }

  resize();
  window.addEventListener('resize', resize);

  const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノ';

  function draw() {
    ctx.fillStyle = 'rgba(10, 10, 15, 0.06)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#00ff41';
    ctx.font = '14px monospace';

    for (let i = 0; i < cols; i++) {
      const char = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(char, i * 18, drops[i] * 18);
      if (drops[i] * 18 > canvas.height && Math.random() > 0.97) drops[i] = 0;
      drops[i] += 0.35;
    }
  }

  setInterval(draw, 55);
})();

// ─── Typewriter ───────────────────────────────────────────────────
(function typewriter() {
  const el   = document.getElementById('subtitle-text');
  const text = 'ML-Powered Phishing URL Detection System';
  let i = 0;

  function tick() {
    el.textContent = text.slice(0, i) + (i < text.length ? '█' : '');
    if (i <= text.length) { i++; setTimeout(tick, 60); }
  }

  setTimeout(tick, 600);
})();

// ─── Core: scanURL ────────────────────────────────────────────────
async function scanURL() {
  const input  = document.getElementById('url-input');
  const url    = input.value.trim();
  const errEl  = document.getElementById('input-error');
  const btn    = document.getElementById('scan-btn');

  errEl.classList.add('hidden');
  document.getElementById('result-section').classList.add('hidden');

  if (!url) {
    showError('Please enter a URL to scan.');
    return;
  }

  // Basic URL-ish validation
  if (!url.includes('.') && !url.match(/^\d+\.\d+\.\d+\.\d+/)) {
    showError('Please enter a valid URL (e.g. https://example.com)');
    return;
  }

  setLoading(true, btn);

  try {
    const res  = await fetch('/api/predict', {
      method  : 'POST',
      headers : { 'Content-Type': 'application/json' },
      body    : JSON.stringify({ url }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || `Server error ${res.status}`);
    }

    const data = await res.json();
    renderResult(data);
  } catch (err) {
    showError('Error: ' + err.message);
  } finally {
    setLoading(false, btn);
  }
}

// ─── Render Result ────────────────────────────────────────────────
function renderResult(data) {
  const isPhish  = data.prediction === 'phishing';
  const pct      = Math.round(data.confidence * 100);

  // Banner
  const banner = document.getElementById('result-banner');
  banner.className = 'result-banner ' + (isPhish ? 'danger' : 'safe');

  document.getElementById('result-icon').textContent    = isPhish ? '☠' : '✓';
  const verdict = document.getElementById('result-verdict');
  verdict.textContent  = isPhish ? '⚠ PHISHING DETECTED' : '✔ LEGITIMATE';
  verdict.className    = 'result-verdict ' + (isPhish ? 'danger' : 'safe');

  const urlDisplay = document.getElementById('result-url-display');
  urlDisplay.textContent = data.url.length > 80 ? data.url.slice(0, 77) + '…' : data.url;

  document.getElementById('conf-value').textContent = pct + '%';

  // Confidence bar
  const fill = document.getElementById('conf-bar-fill');
  fill.className = 'conf-bar-fill ' + (isPhish ? 'danger' : '');
  setTimeout(() => { fill.style.width = pct + '%'; }, 50);

  // Risk score
  document.getElementById('risk-score').textContent = data.risk_score;

  // Model badge
  document.getElementById('model-badge').textContent = data.model;

  // Risk factors
  const rfList = document.getElementById('risk-factors-list');
  rfList.innerHTML = '';
  if (data.risk_factors.length === 0) {
    rfList.innerHTML = '<span class="no-risk">✓ No suspicious indicators found</span>';
  } else {
    data.risk_factors.forEach(rf => {
      const tag = document.createElement('span');
      tag.className   = 'risk-tag';
      tag.textContent = rf;
      rfList.appendChild(tag);
    });
  }

  // Feature grid
  const grid = document.getElementById('features-grid');
  grid.innerHTML = '';

  const flagged = new Set([
    'has_ip', 'suspicious_keywords', 'suspicious_tld', 'num_at', 'brand_in_path',
    'has_port', 'double_slash',
  ]);

  for (const [key, val] of Object.entries(data.features)) {
    const item = document.createElement('div');
    item.className = 'feat-item';

    const isFlagged = flagged.has(key) && val !== 0;
    item.innerHTML = `
      <span class="feat-name">${key}</span>
      <span class="feat-val ${isFlagged ? 'flagged' : ''}">${typeof val === 'number' && !Number.isInteger(val) ? val.toFixed(4) : val}</span>
    `;
    grid.appendChild(item);
  }

  document.getElementById('result-section').classList.remove('hidden');
  document.getElementById('result-section').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ─── Helpers ──────────────────────────────────────────────────────
function showError(msg) {
  const el = document.getElementById('input-error');
  el.textContent = msg;
  el.classList.remove('hidden');
}

function setLoading(on, btn) {
  const loader = document.getElementById('loader');
  const btnText = btn.querySelector('.btn-text');

  if (on) {
    loader.classList.remove('hidden');
    btn.disabled = true;
    btnText.textContent = 'SCANNING…';
  } else {
    loader.classList.add('hidden');
    btn.disabled = false;
    btnText.textContent = 'SCAN';
  }
}

function loadSample(url) {
  document.getElementById('url-input').value = url;
  document.getElementById('input-error').classList.add('hidden');
  document.getElementById('result-section').classList.add('hidden');
  document.getElementById('url-input').focus();
  scanURL();
}

// ─── Enter key support ────────────────────────────────────────────
document.getElementById('url-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') scanURL();
});
