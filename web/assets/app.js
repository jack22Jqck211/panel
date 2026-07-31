// Panel front-end. Plain DOM, no framework, no build step.

const $ = (id) => document.getElementById(id);
const msg = $('msg');

let state = { settings: {}, users: [], locations: 50, revision: '' };

function flash(text, kind) {
  msg.textContent = text;
  msg.className = 'notice show ' + (kind === 'ok' ? 'ok' : 'err');
  if (kind === 'ok') setTimeout(() => msg.classList.remove('show'), 4000);
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'content-type': 'application/json' },
    ...opts,
  });
  if (res.status === 401) {
    location.href = '/login';
    throw new Error('unauthorized');
  }
  const text = await res.text();
  let body = {};
  if (text) {
    try { body = JSON.parse(text); } catch { body = { raw: text }; }
  }
  if (!res.ok) throw new Error(body.error || ('HTTP ' + res.status));
  return body;
}

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[c]);
}

function fmtDate(iso) {
  if (!iso) return '—';
  const t = new Date(iso);
  if (isNaN(t) || t.getUTCFullYear() < 2000) return 'بی‌نهایت';
  return t.toLocaleDateString('fa-IR');
}

function fmtBytes(n) {
  if (!n || n <= 0) return 'بی‌نهایت';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = n, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return v.toFixed(v < 10 && i > 0 ? 1 : 0) + ' ' + u[i];
}

function subURL(u) {
  return location.origin + '/sub/' + u.subToken;
}

// ---------- rendering ----------

function renderSettings() {
  const s = state.settings;
  $('serverAddress').value = s.serverAddress || '';
  $('serverPort').value = s.serverPort || 443;
  $('pathPrefix').value = s.pathPrefix || '/ws';
  $('protocol').value = s.protocol || 'vless';
  $('defaultCleanIp').value = s.defaultCleanIp || '';
  $('subIntervalHours').value = s.subIntervalHours || 12;
  $('tls').checked = !!s.tls;
  $('noAddr').style.display = s.serverAddress ? 'none' : 'block';
}

function renderUsers() {
  const tb = $('rows');
  tb.innerHTML = '';
  $('emptyState').style.display = state.users.length ? 'none' : 'block';

  for (const u of state.users) {
    const tr = document.createElement('tr');
    const active = u.enabled && !u.expired;
    tr.innerHTML = `
      <td>
        <div style="font-weight:600">${esc(u.name)}</div>
        ${u.note ? `<div class="meta">${esc(u.note)}</div>` : ''}
      </td>
      <td><span class="badge ${active ? 'on' : 'off'}">${active ? 'فعال' : (u.expired ? 'منقضی' : 'غیرفعال')}</span></td>
      <td class="mono">${u.cleanIp ? esc(u.cleanIp) : '<span class="meta">پیش‌فرض</span>'}</td>
      <td>${fmtBytes(u.quotaBytes)}</td>
      <td>${fmtDate(u.expiresAt)}</td>
      <td>
        <div class="sub-cell">
          <input type="text" readonly value="${esc(subURL(u))}">
          <button class="ghost sm" data-copy="${esc(subURL(u))}">کپی</button>
          <a class="ghost sm" href="/sub/${esc(u.subToken)}/view" target="_blank"
             rel="noopener noreferrer" style="padding:5px 10px;border:1px solid var(--border);border-radius:8px;font-size:12.5px">دیدن</a>
        </div>
      </td>
      <td>
        <div class="row-actions">
          <button class="ghost sm" data-toggle="${esc(u.id)}">${u.enabled ? 'غیرفعال' : 'فعال'}</button>
          <button class="ghost sm" data-rotate="${esc(u.id)}">توکن نو</button>
          <button class="danger sm" data-del="${esc(u.id)}">حذف</button>
        </div>
      </td>`;
    tb.appendChild(tr);
  }
}

function render() {
  $('locCount').textContent = state.locations;
  $('locCount2').textContent = state.locations;
  $('revLabel').textContent = state.users.length + ' کاربر';
  renderSettings();
  renderUsers();
}

async function load() {
  try {
    state = await api('/api/state');
    render();
  } catch (e) {
    if (e.message !== 'unauthorized') flash('خطا در بارگذاری: ' + e.message);
  }
}

// ---------- events ----------

$('settingsForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('/api/settings', {
      method: 'POST',
      body: JSON.stringify({
        serverAddress: $('serverAddress').value.trim(),
        serverPort: Number($('serverPort').value) || 443,
        pathPrefix: $('pathPrefix').value.trim() || '/ws',
        protocol: $('protocol').value,
        defaultCleanIp: $('defaultCleanIp').value.trim(),
        subIntervalHours: Number($('subIntervalHours').value) || 12,
        tls: $('tls').checked,
      }),
    });
    flash('تنظیمات ذخیره شد.', 'ok');
    await load();
  } catch (e) {
    flash('ذخیره نشد: ' + e.message);
  }
});

$('addForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const gb = Number($('quotaGb').value) || 0;
  try {
    await api('/api/users', {
      method: 'POST',
      body: JSON.stringify({
        name: $('name').value.trim(),
        cleanIp: $('cleanIp').value.trim(),
        note: $('note').value.trim(),
        expiresInDays: Number($('expiresInDays').value) || 0,
        quotaBytes: gb > 0 ? gb * 1024 * 1024 * 1024 : 0,
      }),
    });
    $('addForm').reset();
    flash('کاربر ساخته شد. لینک ساب در جدول پایین است.', 'ok');
    await load();
  } catch (e) {
    flash('ساخته نشد: ' + e.message);
  }
});

document.addEventListener('click', async (e) => {
  const t = e.target;
  if (!(t instanceof HTMLElement)) return;

  const copy = t.getAttribute('data-copy');
  if (copy) {
    try {
      await navigator.clipboard.writeText(copy);
      t.textContent = 'کپی شد';
      setTimeout(() => { t.textContent = 'کپی'; }, 1500);
    } catch {
      flash('کپی نشد — دستی انتخاب کنید.');
    }
    return;
  }

  const toggle = t.getAttribute('data-toggle');
  if (toggle) {
    try { await api('/api/users/' + toggle + '/toggle', { method: 'POST' }); await load(); }
    catch (err) { flash(err.message); }
    return;
  }

  const rotate = t.getAttribute('data-rotate');
  if (rotate) {
    if (!confirm('توکن ساب عوض شود؟ لینک قبلی از کار می‌افتد.')) return;
    try { await api('/api/users/' + rotate + '/rotate', { method: 'POST' }); flash('توکن عوض شد.', 'ok'); await load(); }
    catch (err) { flash(err.message); }
    return;
  }

  const del = t.getAttribute('data-del');
  if (del) {
    if (!confirm('این کاربر حذف شود؟')) return;
    try { await api('/api/users/' + del, { method: 'DELETE' }); flash('حذف شد.', 'ok'); await load(); }
    catch (err) { flash(err.message); }
  }
});

$('dlXray').addEventListener('click', () => { window.location = '/api/generate/xray?download=1'; });
$('dlNginx').addEventListener('click', () => { window.location = '/api/generate/nginx?download=1'; });

$('logout').addEventListener('click', async () => {
  try { await api('/api/logout', { method: 'POST' }); } catch {}
  location.href = '/login';
});

load();
