/* ── Utilidades ── */
function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
 
function authClass(val) {
  if (!val || val === 'none') return 'none';
  val = val.toLowerCase();
  if (val === 'pass')     return 'ok';
  if (val === 'fail')     return 'bad';
  if (val === 'softfail') return 'warn';
  return 'none';
}

function urlFlagLabel(flag) {
  const flagLabels = {
    url_acortada:           'URL acortada',
    ip_directa:             'IP directa',
    numeros_en_dominio:     'Números en dominio',
    multiples_subdominios:  'Múltiples subdominios',
    tld_sospechoso:         'TLD sospechoso',
    http_sin_tls:           'HTTP sin TLS',
    usuario_en_url:         'Usuario en URL',
    puerto_no_estandar:     'Puerto no estándar',
    dominio_punycode:       'Dominio punycode',
    dominio_muy_largo:      'Dominio muy largo',
    path_sospechoso:        'Ruta sensible',
    resuelta:               'URL resuelta',
    vt_malicioso:           'VirusTotal: malicioso',
    vt_sospechoso:          'VirusTotal: sospechoso',
  };

  if (flag.startsWith('redireccion_en_params:')) {
    return `Redirección en parámetro ${flag.split(':')[1]}`;
  }

  return flagLabels[flag] || flag;
}
 
/* ── N1: Veredicto ── */
function renderVerdict(data) {
  const auth  = data.auth || {};
  const spf   = (auth.spf   || 'none').toLowerCase();
  const dkim  = (auth.dkim  || 'none').toLowerCase();
  const dmarc = (auth.dmarc || 'none').toLowerCase();
 
  const spamMatch = (data.spam_score || '').match(/-?[\d.]+/);
  const spamScore = spamMatch ? parseFloat(spamMatch[0]) : null;
  const isSpam    = spamScore !== null && spamScore > 3;
  const urls       = data.urls || [];
  const highUrls   = urls.filter(u => u.risk === 'high').length;
  const mediumUrls = urls.filter(u => u.risk === 'medium').length;
  const vtMaliciousUrls = urls.filter(u => (u.flags || []).includes('vt_malicioso')).length;
 
  const fails     = [spf, dkim, dmarc].filter(v => v === 'fail').length;
  const passes    = [spf, dkim, dmarc].filter(v => v === 'pass').length;
  const nones     = [spf, dkim, dmarc].filter(v => v === 'none').length;
  const softfails = [spf, dkim, dmarc].filter(v => v === 'softfail').length;
 
  let level, label, reasons = [];
 
  const severeUrlSignal = vtMaliciousUrls > 0 || highUrls >= 2 || (highUrls > 0 && (fails >= 1 || isSpam));

  if (fails >= 1 || isSpam || severeUrlSignal) {
    level = 'bad';  label = 'PELIGROSO';
  } else if (softfails >= 1 || nones >= 2 || highUrls > 0) {
    level = 'warn'; label = 'SOSPECHOSO';
  } else if (nones === 1) {
    level = 'warn'; label = 'INDETERMINADO';
  } else if (passes === 3) {
    level = 'ok';   label = 'LEGÍTIMO';
  } else {
    level = 'warn'; label = 'INDETERMINADO';
  }
 
  if (spf   === 'pass')     reasons.push('✓ SPF pass');
  if (dkim  === 'pass')     reasons.push('✓ DKIM pass');
  if (dmarc === 'pass')     reasons.push('✓ DMARC pass');
  if (spf   === 'fail')     reasons.push('✗ SPF fail');
  if (dkim  === 'fail')     reasons.push('✗ DKIM fail');
  if (dmarc === 'fail')     reasons.push('✗ DMARC fail');
  if (spf   === 'softfail') reasons.push('⚠ SPF softfail');
  if (dkim  === 'none')     reasons.push('⚠ DKIM no configurado');
  if (dmarc === 'none')     reasons.push('⚠ DMARC no configurado');
  if (spamScore !== null)   reasons.push(`Score spam: ${spamScore}`);
  if (highUrls > 0)         reasons.push(`${highUrls} enlace(s) de riesgo alto`);
  if (!highUrls && mediumUrls > 0) reasons.push(`${mediumUrls} enlace(s) de riesgo medio detectado(s)`);
 
  const card = document.getElementById('verdict-card');
  card.className = `verdict-card ${level}`;
  document.getElementById('verdict-label').textContent = label;
  document.getElementById('verdict-reasons').innerHTML =
    reasons.map(r => `<span>${esc(r)}</span>`).join('');
}
 
/* ── N2: Semáforo ── */
function renderSignals(data) {
  const auth   = data.auth || {};
  const protos = ['spf', 'dkim', 'dmarc'];
 
  const spamRaw   = data.spam_score || '';
  const spamMatch = spamRaw.match(/-?[\d.]+/);
  let spamHtml    = '';
 
  if (spamMatch) {
    const score = parseFloat(spamMatch[0]);
    const pct   = Math.min(100, Math.max(0, ((score + 5) / 15) * 100));
    const cls   = pct < 30 ? 'ok' : pct < 60 ? 'warn' : 'bad';
    const color = pct < 30 ? 'var(--ok)' : pct < 60 ? 'var(--warn)' : 'var(--bad)';
    spamHtml = `
      <div class="signal-item ${cls}">
        <div class="signal-proto">Spam Score</div>
        <div class="signal-val" style="font-size:15px">${score}</div>
        <div class="spam-track">
          <div class="spam-fill" style="width:${pct}%;background:${color}"></div>
        </div>
        <div class="signal-note">
          ${spamRaw.toLowerCase().startsWith('no') ? 'No spam' : 'Posible spam'}
        </div>
      </div>`;
  }
 
  const hopCount = (data.hops || []).length;
  const hopCls   = hopCount <= 3 ? 'ok' : hopCount <= 6 ? 'warn' : 'bad';
  const hopNote  = hopCount <= 3 ? 'Ruta normal' : hopCount <= 6 ? 'Ruta larga' : 'Ruta inusual';
  const urls      = data.urls || [];
  const highUrls  = urls.filter(u => u.risk === 'high').length;
  const mediumUrls = urls.filter(u => u.risk === 'medium').length;
  const urlCls    = highUrls > 0 ? 'bad' : mediumUrls > 0 ? 'warn' : urls.length ? 'ok' : 'none';
  const urlNote   = highUrls > 0
    ? `${highUrls} riesgo alto`
    : mediumUrls > 0
      ? `${mediumUrls} riesgo medio`
      : urls.length
        ? 'Sin señales críticas'
        : 'Sin enlaces';
 
  document.getElementById('signal-grid').innerHTML =
    protos.map(p => {
      const val = (auth[p] || 'none');
      const cls = authClass(val);
      return `
        <div class="signal-item ${cls}">
          <div class="signal-proto">${p.toUpperCase()}</div>
          <div class="signal-val">${val.toUpperCase()}</div>
        </div>`;
    }).join('') +
    spamHtml +
    `<div class="signal-item ${hopCls}">
      <div class="signal-proto">Hops</div>
      <div class="signal-val">${hopCount}</div>
      <div class="signal-note">${hopNote}</div>
    </div>` +
    `<div class="signal-item ${urlCls}">
      <div class="signal-proto">Enlaces</div>
      <div class="signal-val">${urls.length}</div>
      <div class="signal-note">${urlNote}</div>
    </div>`;
}
 
/* ── N2b: Reputación de IPs ── */
function renderReputation(data) {
  const reps = data.reputation || [];
 
  // Elimina card anterior si existe
  const existing = document.getElementById('reputation-card');
  if (existing) existing.remove();
 
  if (!reps.length) return;
 
  const card = document.createElement('div');
  card.className = 'card';
  card.id = 'reputation-card';
  card.innerHTML = `
    <div class="section-title">Reputación de IPs</div>
    <div class="reputation-grid">
      ${reps.map(r => {
        const abuse = r.abuseipdb || {};
        const vt    = r.virustotal || {};
        const score = abuse.score ?? 0;
        const cls   = score === 0 ? 'ok' : score < 25 ? 'warn' : 'bad';
        const vtMalicious = vt.malicious ?? 0;
        const vtCls = vtMalicious === 0 ? 'ok' : vtMalicious < 3 ? 'warn' : 'bad';
 
        return `
          <div class="rep-item">
            <div class="rep-head">
              <span class="rep-ip">${esc(r.ip)}</span>
              ${abuse.country ? `<span class="tl-tag">${esc(abuse.country)}</span>` : ''}
              ${abuse.is_tor  ? `<span class="tl-tag" style="color:var(--bad)">TOR</span>` : ''}
            </div>
            <div class="rep-isp">${esc(abuse.isp || '—')}</div>
            <div class="rep-scores">
              <div class="rep-score-item">
                <span class="rep-source">AbuseIPDB</span>
                <span class="rep-val ${cls}">${score}%</span>
                <span class="rep-sub">${abuse.reports ?? 0} reportes</span>
              </div>
              <div class="rep-score-item">
                <span class="rep-source">VirusTotal</span>
                <span class="rep-val ${vtCls}">${vtMalicious} maliciosos</span>
                <span class="rep-sub">${vt.harmless ?? 0} limpios</span>
              </div>
            </div>
          </div>`;
      }).join('')}
    </div>`;
 
  document.getElementById('signal-grid').closest('.card').after(card);
}
 
/* ── N3: Timeline ── */
function renderTimeline(data) {
  const hops = data.hops || [];
  const el   = document.getElementById('timeline');
 
  if (!hops.length) {
    el.innerHTML = '<span style="color:var(--dim);font-size:11px">No se encontraron saltos Received:</span>';
    return;
  }
 
  el.innerHTML = hops.map((h, i) => {
    const raw     = h.raw || '';
    const isFirst = i === 0;
    const isLast  = i === hops.length - 1;
 
    const isAnomaly = !isLast && (
      raw.toLowerCase().includes('unknown') ||
      (h.ip && (h.ip.startsWith('192.168.') || h.ip.startsWith('10.')))
    );
 
    const serverMatch = raw.match(/from\s+([^\s(]+)/i);
    const server      = serverMatch ? serverMatch[1] : 'servidor desconocido';
 
    const tsMatch = raw.match(/;\s*(.+)$/m);
    const ts      = tsMatch ? tsMatch[1].trim().slice(0, 32) : '';
 
    const label     = isFirst ? ' · ORIGEN' : isLast ? ' · DESTINO' : '';
    const connector = !isLast ? `<div class="tl-connector">↓</div>` : '';
 
    return `
      <div class="tl-hop${isAnomaly ? ' anomaly' : ''}">
        <div class="tl-dot"></div>
        <div class="tl-body">
          <div class="tl-head">
            <span class="tl-num">HOP ${i + 1}${label}</span>
            <span class="tl-server">${esc(server)}</span>
            ${ts ? `<span class="tl-ts">${esc(ts)}</span>` : ''}
          </div>
          <div class="tl-detail">${esc(raw.trim())}</div>
          <div class="tl-meta">
            ${h.ip ? `<span class="tl-tag ip">${esc(h.ip)}</span>` : ''}
            ${isAnomaly ? `<span class="tl-tag" style="color:var(--bad);border-color:#3d1209">⚠ servidor desconocido</span>` : ''}
          </div>
        </div>
      </div>${connector}`;
  }).join('');
}

/* ── URLs ── */
function renderUrls(data) {
  const urls = data.urls || [];

  const existing = document.getElementById('urls-card');
  if (existing) existing.remove();
  if (!urls.length) return;

  const riskLabel = { low: 'BAJO', medium: 'MEDIO', high: 'ALTO' };
  const riskClass = { low: 'ok', medium: 'warn', high: 'bad' };

  const card = document.createElement('div');
  card.className = 'card';
  card.id = 'urls-card';
  card.innerHTML = `
    <div class="section-title">Enlaces detectados (${urls.length})</div>
    <div class="urls-list">
      ${urls.map(u => {
        const cls = riskClass[u.risk] || 'none';
        const vt  = u.virustotal;
        const flags = u.flags || [];
        return `
          <div class="url-item ${cls}">
            <div class="url-head">
              <span class="url-risk ${cls}">${riskLabel[u.risk] || u.risk}</span>
              <span class="url-domain">${esc(u.domain || '—')}</span>
            </div>
            <div class="url-raw">${esc(u.url)}</div>
            ${u.resolved_url ? `<div class="url-resolved">→ ${esc(u.resolved_url)}</div>` : ''}
            ${flags.length ? `
              <div class="url-flags">
                ${flags.map(f => `
                  <span class="url-flag">${esc(urlFlagLabel(f))}</span>
                `).join('')}
              </div>` : ''}
            ${vt && !vt.error && vt.status !== 'not_found' ? `
              <div class="url-vt">
                <span class="rep-source">VirusTotal</span>
                <span class="rep-val ${vt.malicious > 0 ? 'bad' : 'ok'}">
                  ${vt.malicious} maliciosos
                </span>
                <span class="rep-sub">${vt.harmless ?? 0} limpios</span>
              </div>` : ''}
          </div>`;
      }).join('')}
    </div>`;

  document.getElementById('timeline').closest('.card').after(card);
}
 
/* ── N4: Metadata ── */
function renderMeta(data) {
  const fields = [
    ['De',         data.from       || '—'],
    ['Para',       data.to         || '—'],
    ['Asunto',     data.subject    || '—'],
    ['Fecha',      data.date       || '—'],
    ['Message-ID', data.message_id || '—'],
    ['Cliente',    data.mailer     || '—'],
  ];
 
  document.getElementById('meta-table').innerHTML =
    fields.map(([k, v]) => `<tr><td>${k}</td><td>${esc(v)}</td></tr>`).join('');
}
