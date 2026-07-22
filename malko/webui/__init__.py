"""Embedded single-page dashboard frontend (no build step, no CDNs).

The whole UI is one self-contained HTML document with inline CSS and
vanilla JS. UI language: Russian.
"""

PAGE = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mal-ko — панель защиты</title>
<style>
  :root {
    --bg: #0a0e14; --panel: #11161f; --panel2: #151c27; --border: #1f2a37;
    --text: #c9d1d9; --dim: #7d8590; --accent: #22d3ee; --green: #00e676;
    --critical: #ff4d5e; --high: #ff9f43; --medium: #ffd32a;
    --low: #4da3ff; --unknown: #8b949e;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg); color: var(--text);
    font: 14px/1.5 "Segoe UI", system-ui, sans-serif; padding: 24px;
  }
  code, .mono { font-family: "Cascadia Code", Consolas, monospace; font-size: 12px; }
  header { display: flex; align-items: center; gap: 14px; margin-bottom: 24px; }
  header h1 { font-size: 22px; letter-spacing: 2px; color: var(--green); }
  header .sub { color: var(--dim); font-size: 13px; }
  .grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); margin-bottom: 16px; }
  .card {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; padding: 16px;
  }
  .card h2 { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: var(--dim); margin-bottom: 8px; }
  .stat { font-size: 28px; font-weight: 700; color: var(--accent); }
  .stat.green { color: var(--green); }
  .stat.red { color: var(--critical); }
  .stat.yellow { color: var(--medium); }
  .card .note { color: var(--dim); font-size: 12px; margin-top: 4px; }
  .row { display: grid; gap: 16px; grid-template-columns: 1fr 1fr; margin-bottom: 16px; }
  @media (max-width: 900px) { .row { grid-template-columns: 1fr; } }
  .full { margin-bottom: 16px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { color: var(--dim); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
  .badge {
    display: inline-block; padding: 1px 8px; border-radius: 4px;
    font: 700 11px/1.6 "Cascadia Code", Consolas, monospace; letter-spacing: 1px;
  }
  .sev-CRITICAL { background: rgba(255,77,94,.15); color: var(--critical); border: 1px solid var(--critical); }
  .sev-HIGH     { background: rgba(255,159,67,.15); color: var(--high); border: 1px solid var(--high); }
  .sev-MEDIUM   { background: rgba(255,211,42,.12); color: var(--medium); border: 1px solid var(--medium); }
  .sev-SUSPICIOUS { background: rgba(192,132,252,.14); color: #c084fc; border: 1px solid #c084fc; }
  .sev-LOW      { background: rgba(77,163,255,.12); color: var(--low); border: 1px solid var(--low); }
  .sev-UNKNOWN  { background: rgba(139,148,158,.12); color: var(--unknown); border: 1px solid var(--unknown); }
  .kev { color: var(--critical); font-weight: 700; font-size: 11px; letter-spacing: 1px; }
  button {
    background: var(--panel2); color: var(--green); border: 1px solid var(--green);
    border-radius: 6px; padding: 7px 14px; cursor: pointer; font-size: 13px;
  }
  button:hover { background: rgba(0,230,118,.12); }
  button.secondary { color: var(--accent); border-color: var(--accent); }
  button.secondary:hover { background: rgba(34,211,238,.12); }
  input[type=text] {
    background: var(--panel2); border: 1px solid var(--border); color: var(--text);
    border-radius: 6px; padding: 7px 10px; width: 320px; font-family: Consolas, monospace;
  }
  .controls { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
  #events { max-height: 320px; overflow-y: auto; }
  .evt { padding: 3px 0; border-bottom: 1px solid var(--border); font-family: Consolas, monospace; font-size: 12px; }
  .evt .ts { color: var(--dim); margin-right: 8px; }
  .evt.critical { color: var(--critical); }
  .evt.warning { color: var(--medium); }
  .evt.info { color: var(--text); }
  .empty { color: var(--dim); padding: 8px 0; }
  .shield { filter: drop-shadow(0 0 6px rgba(0,230,118,.5)); }
</style>
</head>
<body>
<header>
  <svg class="shield" width="44" height="52" viewBox="0 0 44 52" fill="none">
    <path d="M22 2 L40 9 V24 C40 37 32 46 22 50 C12 46 4 37 4 24 V9 Z"
          stroke="#00e676" stroke-width="2.5" fill="rgba(0,230,118,.08)"/>
    <path d="M14 25 L20 31 L31 18" stroke="#22d3ee" stroke-width="3"
          fill="none" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>
  <div>
    <h1>MAL-KO</h1>
    <div class="sub">панель защиты &middot; threat intelligence console</div>
  </div>
</header>

<div class="grid">
  <div class="card"><h2>Блоклист</h2><div class="stat green" id="bl-count">—</div><div class="note" id="bl-updated">нет данных</div></div>
  <div class="card"><h2>Проверено файлов</h2><div class="stat" id="c-scanned">0</div><div class="note">монитор + scan-files</div></div>
  <div class="card"><h2>Угроз найдено</h2><div class="stat red" id="c-threats">0</div><div class="note" id="last-scan">сканирований не было</div></div>
  <div class="card"><h2>В карантине</h2><div class="stat yellow" id="c-quar">0</div><div class="note">всего перемещено</div></div>
</div>

<div class="card full">
  <h2>Действия</h2>
  <div class="controls">
    <input type="text" id="scan-path" placeholder="Абсолютный путь, напр. C:\Users\me\Downloads">
    <button data-scan="deps">Сканировать зависимости</button>
    <button data-scan="system">Сканировать систему</button>
    <button data-scan="files">Сканировать файлы</button>
    <button class="secondary" id="btn-bl">Обновить блоклист</button>
  </div>
</div>

<div class="row">
  <div class="card">
    <h2>Журнал событий</h2>
    <div id="events"><div class="empty">событий пока нет</div></div>
  </div>
  <div class="card">
    <h2>Карантин</h2>
    <div id="quarantine"><div class="empty">карантин пуст</div></div>
  </div>
</div>

<div class="card full">
  <h2>Находки</h2>
  <div id="findings"><div class="empty">находок нет</div></div>
</div>

<script>
const esc = s => String(s ?? '').replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const sevBadge = sev => {
  const s = String(sev || 'UNKNOWN').toUpperCase();
  return '<span class="badge sev-' + esc(s) + '">' + esc(s) + '</span>';
};
const getJSON = async url => (await fetch(url)).json();
const postJSON = async (url, body) => {
  const r = await fetch(url, {method: 'POST',
    headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body || {})});
  return {code: r.status, body: await r.json()};
};

function renderStatus(d) {
  const st = d.state || {};
  const bl = st.blocklist || {};
  document.getElementById('bl-count').textContent =
    (bl.hashes ?? 0).toLocaleString('ru-RU');
  document.getElementById('bl-updated').textContent =
    'обновлён: ' + (bl.updated || d.blocklist_mtime || 'никогда');
  const c = st.counters || {};
  document.getElementById('c-scanned').textContent = c.files_scanned ?? 0;
  document.getElementById('c-threats').textContent = c.threats_found ?? 0;
  document.getElementById('c-quar').textContent = c.quarantined ?? 0;
  document.getElementById('last-scan').textContent = st.last_scan
    ? st.last_scan.type + ': ' + st.last_scan.summary : 'сканирований не было';
}

function renderEvents(d) {
  const box = document.getElementById('events');
  const evts = (d.events || []).slice().reverse();
  if (!evts.length) { box.innerHTML = '<div class="empty">событий пока нет</div>'; return; }
  box.innerHTML = evts.map(e =>
    '<div class="evt ' + esc(e.level) + '"><span class="ts">' +
    esc((e.ts || '').replace('T', ' ').replace('+00:00', 'Z')) +
    '</span>' + esc(e.message) + '</div>').join('');
}

function renderFindings(d) {
  const box = document.getElementById('findings');
  const fs = (d.findings || []).slice().reverse();
  if (!fs.length) { box.innerHTML = '<div class="empty">находок нет</div>'; return; }
  box.innerHTML = '<table><tr><th>Время</th><th>Источник</th><th>Серьёзность</th>' +
    '<th>ID</th><th>Описание</th><th>KEV</th></tr>' + fs.map(f => {
      const kev = f.details && f.details.kev ? '<span class="kev">АКТИВНО ЭКСПЛУАТИРУЕТСЯ</span>' : '—';
      return '<tr><td class="mono">' + esc(f.ts || '') + '</td>' +
        '<td>' + esc(f.source || '') + '</td>' +
        '<td>' + sevBadge(f.severity) + '</td>' +
        '<td class="mono">' + esc(f.id || '') + '</td>' +
        '<td>' + esc(f.title || '') + '</td><td>' + kev + '</td></tr>';
    }).join('') + '</table>';
}

function renderQuarantine(d) {
  const box = document.getElementById('quarantine');
  const es = d.entries || [];
  if (!es.length) { box.innerHTML = '<div class="empty">карантин пуст</div>'; return; }
  box.innerHTML = '<table>' + es.map(e =>
    '<tr><td><div class="mono">' + esc(e.id) + '</div>' +
    '<div class="mono" style="color:var(--dim)">' + esc(e.original_path) + '</div>' +
    '<div class="mono" style="color:var(--dim)">' + esc(e.sha256) + '</div></td>' +
    '<td style="white-space:nowrap"><button onclick="restoreEntry(\'' + esc(e.id) +
    '\', \'' + esc(e.original_path).replace(/\\/g, '\\\\') + '\')">Восстановить</button></td></tr>'
  ).join('') + '</table>';
}

async function restoreEntry(id, originalPath) {
  if (!confirm('Восстановить файл?\n' + originalPath)) return;
  const r = await postJSON('/api/quarantine/restore', {id: id});
  if (r.code !== 200) alert('Ошибка: ' + (r.body.error || r.code));
  refresh();
}

async function refresh() {
  try {
    const [status, events, findings, quar] = await Promise.all(
      ['/api/status', '/api/events', '/api/findings', '/api/quarantine'].map(getJSON));
    renderStatus(status); renderEvents(events);
    renderFindings(findings); renderQuarantine(quar);
  } catch (e) { /* server restarting etc. — retry on next tick */ }
}

document.querySelectorAll('button[data-scan]').forEach(btn =>
  btn.addEventListener('click', async () => {
    const type = btn.dataset.scan;
    const path = document.getElementById('scan-path').value.trim();
    const r = await postJSON('/api/scan', {type: type, path: path});
    if (r.code !== 200) alert('Ошибка: ' + (r.body.error || r.code));
    refresh();
  }));
document.getElementById('btn-bl').addEventListener('click', async () => {
  const r = await postJSON('/api/update-blocklist', {});
  if (r.code !== 200) alert('Ошибка: ' + (r.body.error || r.code));
  refresh();
});

refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""
