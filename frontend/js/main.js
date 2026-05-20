// js/main.js

const EXAMPLE_HEADER = `From: sender@example.com
To: recipient@yourdomain.com
Subject: Test Email Analysis
Date: Mon, 18 May 2026 10:23:14 +0000
Message-ID: <abc123@mail.example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Received: from mail.example.com (mail.example.com [203.0.113.42])
        by mx.yourdomain.com with ESMTPS id x7si123456
        for <recipient@yourdomain.com>; Mon, 18 May 2026 10:23:16 +0000
Received: from [192.168.1.5] (unknown [203.0.113.42])
        by mail.example.com with ESMTP id abc789
        Mon, 18 May 2026 10:23:12 +0000
Authentication-Results: mx.yourdomain.com;
        dkim=pass header.i=@example.com;
        spf=pass (domain of sender@example.com designates 203.0.113.42);
        dmarc=pass (p=NONE) header.from=example.com
X-Spam-Status: No, score=-2.1
X-Mailer: Thunderbird 102.0`;

/* ── Estado de la UI ── */
function onInputChange() {
  const val   = document.getElementById('header-input').value;
  const lines = val.trim() ? val.split('\n').length : 0;

  document.getElementById('char-count').textContent =
    lines ? `${lines} líneas · ${val.length} ch` : '0 líneas';

  document.getElementById('analyze-btn').disabled = !val.trim();
}

function setStatus(msg) {
  const bar = document.getElementById('status-bar');
  document.getElementById('status-text').textContent = msg;
  bar.classList.add('visible');
}

function hideStatus() {
  document.getElementById('status-bar').classList.remove('visible');
}

function showError(msg) {
  const box = document.getElementById('error-box');
  box.textContent = '🚨 ' + msg;
  box.classList.add('visible');
}

function clearResults() {
  document.getElementById('results').classList.remove('visible');
  document.getElementById('error-box').classList.remove('visible');
  document.getElementById('status-bar').classList.remove('visible');
}

function toggleRaw() {
  const block  = document.getElementById('raw-block');
  const toggle = document.getElementById('raw-toggle');
  const isOpen = block.classList.toggle('visible');
  toggle.textContent = isOpen ? 'Ocultar ▴' : 'Mostrar ▾';
}

/* ── Acciones de botones ── */
function loadExample() {
  document.getElementById('header-input').value = EXAMPLE_HEADER;
  document.getElementById('file-pill-wrap').innerHTML = '';
  onInputChange();
  clearResults();
}

function clearAll() {
  document.getElementById('header-input').value = '';
  document.getElementById('file-pill-wrap').innerHTML = '';
  document.getElementById('file-input').value = '';
  onInputChange();
  clearResults();
}

/* ── Análisis principal ── */
async function analyze() {
  const raw = document.getElementById('header-input').value.trim();
  if (!raw) return;

  clearResults();
  setStatus('Analizando cabecera...');
  document.getElementById('analyze-btn').disabled = true;

  try {
    const data = await analyzeHeader(raw);

    renderVerdict(data);
    renderSignals(data);
    renderTimeline(data);
    renderMeta(data);

    document.getElementById('raw-block').textContent = raw;
    document.getElementById('results').classList.add('visible');

  } catch (err) {
    showError(err.message + ' — Asegúrate de que FastAPI está corriendo en localhost:8000');
  } finally {
    hideStatus();
    document.getElementById('analyze-btn').disabled = false;
  }
}

/* ── Inicialización ── */
document.addEventListener('DOMContentLoaded', () => {
  initUpload();

  document.getElementById('header-input').addEventListener('input', onInputChange);
  document.getElementById('analyze-btn').addEventListener('click', analyze);
  document.getElementById('example-btn').addEventListener('click', loadExample);
  document.getElementById('clear-btn').addEventListener('click', clearAll);
  document.getElementById('raw-toggle').addEventListener('click', toggleRaw);
});