const API = '';

const state = {
  accessToken: null,
  expiresAt: 0,
  user: null,
  route: 'acceso',
  panelLoaded: false,
};

const els = {
  apiBadge: document.getElementById('api-badge'),
  views: {
    acceso: document.getElementById('view-acceso'),
    panel: document.getElementById('view-panel'),
  },
  navLinks: Array.from(document.querySelectorAll('.nav a')),
  sessionState: document.getElementById('session-state'),
  sessionUser: document.getElementById('session-user'),
  sessionToken: document.getElementById('session-token'),
  sessionExp: document.getElementById('session-exp'),
  btnMe: document.getElementById('btn-me'),
  btnRefresh: document.getElementById('btn-refresh'),
  btnLogout: document.getElementById('btn-logout'),
  log: document.getElementById('log'),
  registerForm: document.getElementById('register-form'),
  loginForm: document.getElementById('login-form'),
  clearLog: document.getElementById('btn-clear-log'),
  panelNotice: document.getElementById('panel-notice'),
  panelContent: document.getElementById('panel-content'),
  panelStats: document.getElementById('panel-stats'),
  activeRows: document.getElementById('active-rows'),
  activeCount: document.getElementById('active-count'),
  eventsRows: document.getElementById('events-rows'),
  eventsType: document.getElementById('events-type'),
  eventsLimit: document.getElementById('events-limit'),
  btnPanelRefresh: document.getElementById('btn-panel-refresh'),
};

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function log(method, path, status, detail) {
  const li = document.createElement('li');
  const cls = status >= 200 && status < 300 ? 'ok' : 'err';
  li.appendChild(el('span', 'method', method));
  li.appendChild(el('span', 'path', path));
  li.appendChild(el('span', `status ${cls}`, String(status)));
  if (detail) li.appendChild(el('span', 'meta', detail));
  els.log.prepend(li);
}

function summarize(data) {
  const json = typeof data === 'string' ? data : JSON.stringify(data);
  return json.length > 220 ? `${json.slice(0, 220)}…` : json;
}

async function api(method, path, { body, auth, silent } = {}) {
  const headers = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (auth && state.accessToken) {
    headers.authorization = `Bearer ${state.accessToken}`;
  }

  let res;
  let data = null;
  try {
    res = await fetch(API + path, {
      method,
      headers,
      credentials: 'include',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = text;
      }
    }
  } catch (error) {
    if (!silent) log(method, path, 0, `fallo de red: ${error.message}`);
    return { ok: false, status: 0, data: null };
  }

  if (!silent) log(method, path, res.status, data === null ? '' : summarize(data));
  return { ok: res.ok, status: res.status, data };
}

/* ----------------------------- Sesión ----------------------------- */

function setSession({ accessToken, expiresIn, user }) {
  if (accessToken) {
    state.accessToken = accessToken;
    state.expiresAt = expiresIn ? Date.now() + expiresIn * 1000 : 0;
  }
  if (user) state.user = user;
  state.panelLoaded = false;
  renderSession();
}

function clearSession() {
  state.accessToken = null;
  state.expiresAt = 0;
  state.user = null;
  state.panelLoaded = false;
  renderSession();
}

function renderSession() {
  const active = Boolean(state.accessToken);
  els.sessionState.textContent = active ? 'sesión activa' : 'sin sesión';
  els.sessionState.classList.toggle('active', active);
  els.sessionUser.textContent = state.user?.email ?? '—';
  els.sessionToken.textContent = active
    ? `${state.accessToken.slice(0, 24)}…`
    : '—';
  els.btnMe.disabled = !active;
  els.btnRefresh.disabled = !active;
  els.btnLogout.disabled = !active;
  updateExpiry();
}

function updateExpiry() {
  if (!state.accessToken) {
    els.sessionExp.textContent = '—';
    return;
  }
  const remaining = Math.max(0, Math.round((state.expiresAt - Date.now()) / 1000));
  els.sessionExp.textContent =
    remaining === 0 ? 'expirado (renueva)' : `${remaining} s`;
}

function formBody(form) {
  const data = new FormData(form);
  return {
    email: String(data.get('email') ?? '').trim().toLowerCase(),
    password: String(data.get('password') ?? ''),
  };
}

/* ---------------------------- Enrutado ---------------------------- */

function route() {
  const hash = window.location.hash || '#/acceso';
  return hash === '#/panel' ? 'panel' : 'acceso';
}

function showView(view) {
  state.route = view;
  for (const [name, node] of Object.entries(els.views)) {
    node.hidden = name !== view;
  }
  for (const link of els.navLinks) {
    link.classList.toggle('active', link.dataset.view === view);
  }
  if (view === 'panel') loadPanel();
}

/* ------------------------ Vista: panel admin ---------------------- */

function panelNotice(message, kind = 'warn') {
  els.panelNotice.hidden = false;
  els.panelNotice.textContent = message;
  els.panelNotice.className = `notice ${kind}`;
  els.panelContent.hidden = true;
}

function eventClass(type) {
  if (['REUSE_DETECTED', 'LOGIN_BLOCKED', 'RATE_LIMITED', 'REFRESH_INVALID'].includes(type)) {
    return 'tag err';
  }
  if (['LOGIN_FAIL', 'REGISTER_FAIL'].includes(type)) return 'tag warn';
  if (type === 'ADMIN_VIEW') return 'tag info';
  return 'tag ok';
}

function fmtDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString('es-ES');
}

async function loadPanel() {
  if (!state.accessToken) {
    panelNotice('Inicia sesión como administrador en la pestaña Acceso para ver el panel.', 'warn');
    return;
  }

  els.panelNotice.hidden = true;
  els.panelContent.hidden = false;
  els.btnPanelRefresh.disabled = true;

  const [overview, users, events] = await Promise.all([
    api('GET', '/admin/overview', { auth: true }),
    api('GET', '/admin/active-users', { auth: true }),
    api('GET', `/admin/events?limit=${els.eventsLimit.value}&type=${encodeURIComponent(els.eventsType.value)}`, { auth: true }),
  ]);
  els.btnPanelRefresh.disabled = false;

  if (overview.status === 401 || users.status === 401) {
    panelNotice('La sesión expiró. Renueva el token o vuelve a iniciar sesión en la pestaña Acceso.', 'warn');
    return;
  }
  if (overview.status === 403 || users.status === 403) {
    panelNotice('Tu cuenta no tiene rol de administrador. Añade tu email a ADMIN_EMAILS y reinicia la API.', 'err');
    return;
  }
  if (!overview.ok || !users.ok || !events.ok) {
    panelNotice('No se pudo cargar el panel. Revisa el log de peticiones.', 'err');
    return;
  }

  state.panelLoaded = true;
  renderStats(overview.data);
  renderActiveUsers(users.data);
  renderEvents(events.data);
}

function renderStats(data) {
  const total24h = Object.values(data.eventsLast24h ?? {}).reduce(
    (sum, n) => sum + n,
    0,
  );
  const cards = [
    ['Usuarios totales', data.totalUsers],
    ['Usuarios activos', data.activeUsers],
    ['Cuentas bloqueadas', data.lockedAccounts],
    ['Eventos (24 h)', total24h],
  ];
  els.panelStats.replaceChildren(
    ...cards.map(([label, value]) => {
      const card = el('div', 'stat');
      card.appendChild(el('span', 'stat-value', String(value)));
      card.appendChild(el('span', 'stat-label', label));
      return card;
    }),
  );
}

function renderActiveUsers(users) {
  els.activeCount.textContent = `${users.length} activos`;
  if (users.length === 0) {
    els.activeRows.replaceChildren(emptyRow(5, 'Ningún usuario con sesión vigente.'));
    return;
  }
  els.activeRows.replaceChildren(
    ...users.map((user) => {
      const tr = document.createElement('tr');
      tr.appendChild(el('td', 'mono', user.email));
      tr.appendChild(el('td', null, String(user.sessions)));
      tr.appendChild(el('td', null, fmtDate(user.lastSessionAt)));
      const status = el('td');
      status.appendChild(el('span', user.locked ? 'tag err' : 'tag ok', user.locked ? 'bloqueada' : 'ok'));
      tr.appendChild(status);
      tr.appendChild(el('td', null, fmtDate(user.createdAt)));
      return tr;
    }),
  );
}

function renderEvents(events) {
  if (events.length === 0) {
    els.eventsRows.replaceChildren(emptyRow(5, 'Sin eventos para el filtro actual.'));
    return;
  }
  els.eventsRows.replaceChildren(
    ...events.map((event) => {
      const tr = document.createElement('tr');
      tr.appendChild(el('td', null, fmtDate(event.createdAt)));
      const type = el('td');
      type.appendChild(el('span', eventClass(event.type), event.type));
      tr.appendChild(type);
      tr.appendChild(el('td', 'mono', event.email ?? (event.userId ? '(usuario eliminado)' : '—')));
      tr.appendChild(el('td', 'mono', event.ip ?? '—'));
      tr.appendChild(el('td', 'mono small', event.meta ? summarize(event.meta) : '—'));
      return tr;
    }),
  );
}

function emptyRow(colspan, text) {
  const tr = document.createElement('tr');
  const td = el('td', 'empty', text);
  td.colSpan = colspan;
  tr.appendChild(td);
  return tr;
}

/* ----------------------------- Eventos ---------------------------- */

els.registerForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const { email, password } = formBody(els.registerForm);
  const res = await api('POST', '/auth/register', { body: { email, password } });
  if (res.ok) {
    els.loginForm.elements.email.value = email;
    els.registerForm.reset();
    els.loginForm.elements.password.focus();
  }
});

els.loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const { email, password } = formBody(els.loginForm);
  const res = await api('POST', '/auth/login', { body: { email, password } });
  if (res.ok) {
    setSession(res.data);
    els.loginForm.elements.password.value = '';
  }
});

els.btnMe.addEventListener('click', async () => {
  const res = await api('GET', '/users/me', { auth: true });
  if (res.ok && res.data) {
    state.user = res.data;
    renderSession();
  }
});

els.btnRefresh.addEventListener('click', async () => {
  const res = await api('POST', '/auth/refresh');
  if (res.ok) setSession(res.data);
});

els.btnLogout.addEventListener('click', async () => {
  await api('POST', '/auth/logout');
  clearSession();
});

els.clearLog.addEventListener('click', () => els.log.replaceChildren());

els.btnPanelRefresh.addEventListener('click', loadPanel);
els.eventsType.addEventListener('change', loadPanel);
els.eventsLimit.addEventListener('change', loadPanel);

window.addEventListener('hashchange', () => showView(route()));

async function checkHealth() {
  try {
    const res = await fetch('/health', { headers: { accept: 'application/json' } });
    els.apiBadge.textContent = res.ok ? 'API operativa' : `API sin salud (${res.status})`;
    els.apiBadge.classList.toggle('ok', res.ok);
    els.apiBadge.classList.toggle('err', !res.ok);
  } catch {
    els.apiBadge.textContent = 'API no accesible';
    els.apiBadge.classList.add('err');
  }
}

renderSession();
showView(route());
checkHealth();
setInterval(updateExpiry, 1000);
