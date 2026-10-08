const state = { user: null, mode: 'login', page: 'overview' };
const $ = (selector) => document.querySelector(selector);

function parseServerDate(value) {
  if (!value) return null;
  const normalized = value.includes('T') ? value : `${value.replace(' ', 'T')}Z`;
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? null : date;
}

function formatServerDate(value, includeTime = false) {
  const date = parseServerDate(value);
  if (!date) return 'Sin fecha';
  return new Intl.DateTimeFormat('es-MX', {
    dateStyle: 'medium',
    ...(includeTime ? { timeStyle: 'short' } : {}),
  }).format(date);
}

const api = async (url, options = {}) => {
  const response = await fetch(`/api${url}`, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });

  const data = response.status === 204 ? null : await response.json();
  if (!response.ok) throw new Error(data?.error || 'No fue posible completar la solicitud');
  return data;
};

const toast = (text) => {
  $('#toast').textContent = text;
  $('#toast').classList.add('show');
  setTimeout(() => $('#toast').classList.remove('show'), 2800);
};

function setMode(mode) {
  state.mode = mode;
  document.querySelectorAll('.tab').forEach((tab) => {
    const isActive = tab.dataset.mode === mode;
    tab.classList.toggle('active', isActive);
    tab.setAttribute('aria-selected', String(isActive));
  });

  $('#name-field').classList.toggle('hidden', mode === 'login');
  $('#submit-label').textContent = mode === 'login' ? 'Entrar al espacio' : 'Crear mi cuenta';
  $('#forgot').classList.toggle('hidden', mode !== 'login');
  $('#auth-message').textContent = '';
  $('#password-strength').classList.add('hidden');
  $('#password-strength span').style.width = '0%';
}

function setButtonLoading(isLoading) {
  const button = $('#submit-btn');
  const loader = button.querySelector('.button-loader');
  const label = $('#submit-label');
  button.disabled = isLoading;
  loader.classList.toggle('hidden', !isLoading);
  label.textContent = isLoading ? (state.mode === 'login' ? 'Accediendo...' : 'Creando cuenta...') : (state.mode === 'login' ? 'Entrar al espacio' : 'Crear mi cuenta');
}

function computePasswordStrength(password) {
  if (!password) return { value: 0, label: 'Fuerza de contraseña' };
  let score = 0;
  if (password.length >= 8) score += 25;
  if (password.length >= 12) score += 15;
  if (/[A-Z]/.test(password)) score += 15;
  if (/[0-9]/.test(password)) score += 15;
  if (/[^A-Za-z0-9]/.test(password)) score += 20;
  if (password.length >= 18) score += 10;

  const label = score < 35 ? 'Débil' : score < 60 ? 'Media' : score < 80 ? 'Buena' : 'Muy fuerte';
  return { value: Math.min(score, 100), label };
}

function updatePasswordStrength() {
  const passwordInput = $('#passwordInput');
  const strengthBox = $('#password-strength');
  const bar = strengthBox.querySelector('span');
  const label = $('#strength-label');

  if (!passwordInput || state.mode !== 'register') {
    strengthBox.classList.add('hidden');
    return;
  }

  const { value, label: strengthLabel } = computePasswordStrength(passwordInput.value);
  strengthBox.classList.toggle('hidden', !passwordInput.value);
  bar.style.width = `${value}%`;
  label.textContent = strengthLabel;
}

function togglePasswordVisibility(button) {
  const targetId = button.dataset.target;
  const input = document.getElementById(targetId);
  if (!input) return;
  const isHidden = input.type === 'password';
  input.type = isHidden ? 'text' : 'password';
  button.setAttribute('aria-label', isHidden ? 'Ocultar contraseña' : 'Mostrar contraseña');
}

function applyUserToShell(user) {
  $('#profile-name').textContent = user.name;
  $('#profile-role').textContent = user.roles.map((role) => role.name).join(' · ');
  $('#avatar').textContent = user.name[0].toUpperCase();
  document.querySelectorAll('[data-permission]').forEach((item) => {
    item.classList.toggle('hidden', !user.permissions.includes(item.dataset.permission));
  });
}

document.querySelectorAll('.tab').forEach((tab) => tab.addEventListener('click', () => setMode(tab.dataset.mode)));

document.querySelectorAll('.password-toggle').forEach((button) => button.addEventListener('click', () => togglePasswordVisibility(button)));

$('#passwordInput').addEventListener('input', updatePasswordStrength);

$('#auth-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const body = Object.fromEntries(new FormData(event.target));
  setButtonLoading(true);

  try {
    if (state.mode === 'register') {
      await api('/auth/register', { method: 'POST', body: JSON.stringify(body) });
      toast('Cuenta creada. Ya puedes iniciar sesión.');
      setMode('login');
      event.target.reset();
      updatePasswordStrength();
    } else {
      const data = await api('/auth/login', { method: 'POST', body: JSON.stringify(body) });
      enter(data.user);
    }
  } catch (error) {
    $('#auth-message').textContent = error.message;
  } finally {
    setButtonLoading(false);
  }
});

$('#forgot').addEventListener('click', () => {
  $('#reset-panel').classList.remove('hidden');
  $('#reset-message').textContent = '';
  $('#reset-email').focus();
});

$('#cancel-reset').addEventListener('click', () => {
  $('#reset-panel').classList.add('hidden');
  $('#reset-form').reset();
  $('#reset-message').textContent = '';
});

$('#reset-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const formData = new FormData(event.target);
  const email = formData.get('email');
  const tokenInput = $('#reset-token');
  const message = $('#reset-message');

  try {
    if (!tokenInput.value) {
      const data = await api('/auth/forgot-password', { method: 'POST', body: JSON.stringify({ email }) });
      if (data.resetToken) {
        tokenInput.value = data.resetToken;
        message.textContent = 'Código generado para este entorno local. Completa la nueva contraseña.';
      } else {
        message.textContent = data.message;
      }
      return;
    }

    const newPassword = formData.get('password');
    if (!newPassword || newPassword.length < 8) {
      message.textContent = 'La nueva contraseña debe tener al menos 8 caracteres.';
      $('#reset-password').focus();
      return;
    }

    const reset = await api('/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ token: tokenInput.value, password: newPassword }),
    });
    $('#reset-form').reset();
    $('#reset-panel').classList.add('hidden');
    toast(reset.message);
  } catch (error) {
    message.textContent = error.message;
  }
});

$('#logout').addEventListener('click', async () => {
  await api('/auth/logout', { method: 'POST' });
  location.reload();
});

function enter(user) {
  state.user = user;
  $('#auth-view').classList.add('hidden');
  $('#app-view').classList.remove('hidden');
  applyUserToShell(user);
  renderPage();
}

document.querySelectorAll('.nav-item').forEach((item) => item.addEventListener('click', () => {
  state.page = item.dataset.page;
  document.querySelectorAll('.nav-item').forEach((nav) => nav.classList.toggle('active', nav === item));
  renderPage();
}));

async function renderPage() {
  const pages = {
    overview: ['VISTA GENERAL', 'Tu espacio seguro'],
    content: ['BIBLIOTECA', 'Contenido protegido'],
    users: ['ADMINISTRACIÓN', 'Usuarios registrados'],
    roles: ['CONTROL DE ACCESO', 'Roles y permisos'],
    audit: ['TRAZABILIDAD', 'Registro de auditoría'],
  };

  try {
    const current = await api('/auth/me');
    state.user = current.user;
    applyUserToShell(state.user);
  } catch {
    return;
  }

  const pagePermissions = { users: 'users:manage', roles: 'roles:manage', audit: 'audit:read' };
  if (pagePermissions[state.page] && !state.user.permissions.includes(pagePermissions[state.page])) {
    state.page = 'overview';
  }

  $('#section-kicker').textContent = pages[state.page][0];
  $('#page-title').textContent = pages[state.page][1];

  const renderers = { overview, content, users, roles, audit };
  try {
    $('#page-content').innerHTML = await renderers[state.page]();
    bindPageActions();
  } catch (error) {
    toast(error.message);
  }
}

async function overview() {
  const canAdmin = state.user.permissions.includes('users:manage');
  let contentCount = 0;
  try {
    contentCount = (await api('/content')).items.length;
  } catch {
    contentCount = 0;
  }

  return `
    <div class="dashboard-grid">
      <div class="metric">
        <span class="eyebrow">Identidad</span>
        <div class="number">${state.user.roles.length}</div>
        <p>Rol(es) asignado(s)</p>
      </div>
      <div class="metric">
        <span class="eyebrow">Alcance</span>
        <div class="number">${state.user.permissions.length}</div>
        <p>Permisos activos</p>
      </div>
      <div class="metric">
        <span class="eyebrow">Recursos</span>
        <div class="number">${contentCount}</div>
        <p>Elementos disponibles</p>
      </div>
    </div>

    <div class="overview-grid">
      <div class="panel overview-panel">
        <span class="eyebrow">Estado de seguridad</span>
        <h3>Tu sesión está protegida</h3>
        <p>El backend valida la identidad, el rol y los permisos en cada petición. Las acciones administrativas quedan registradas con fecha, usuario e IP.</p>
        <div class="actions-row">
          ${canAdmin ? '<button class="action" data-page="audit">Revisar auditoría →</button>' : ''}
          <button class="action" data-action="change-password">Cambiar contraseña</button>
        </div>
      </div>

      <div class="panel overview-panel compact">
        <span class="eyebrow">Estado del entorno</span>
        <div class="status-list">
          <div class="status-item"><span class="status-dot ok"></span><div><strong>JWT activo</strong><small>Acceso con expiración corta</small></div></div>
          <div class="status-item"><span class="status-dot ok"></span><div><strong>Cookies seguras</strong><small>HttpOnly + SameSite</small></div></div>
          <div class="status-item"><span class="status-dot ok"></span><div><strong>Auditoría</strong><small>Seguimiento de acciones</small></div></div>
        </div>
      </div>
    </div>
  `;
}

async function content() {
  const data = await api('/content');
  const canWrite = state.user.permissions.includes('content:write');
  return `
    <div class="section-heading">
      <h3>Todos los contenidos</h3>
      ${canWrite ? '<button class="action" data-action="new-content">+ Nuevo contenido</button>' : ''}
    </div>

    <div class="content-grid">
      ${data.items.length ? data.items.map((item) => `
        <article class="content-card">
          <div class="card-head">
            <span class="eyebrow">${escapeHtml(item.author)} · ${formatServerDate(item.updated_at)}</span>
            ${state.user.permissions.includes('content:delete') ? `<button class="mini-button danger" data-delete="${item.id}">Eliminar</button>` : ''}
          </div>
          <h3>${escapeHtml(item.title)}</h3>
          <p>${escapeHtml(item.body)}</p>
        </article>
      `).join('') : '<p class="empty">Aún no hay contenido.</p>'}
    </div>

    <div id="content-form"></div>
  `;
}

async function users() {
  const data = await api('/admin/users');
  const roles = await api('/admin/roles');
  return `
    <div class="panel table-wrap">
      <div class="list-header">
        <h3>Usuarios registrados</h3>
      </div>
      <table>
        <thead>
          <tr><th>Usuario</th><th>Correo</th><th>Roles</th><th>Alta</th></tr>
        </thead>
        <tbody>
          ${data.users.map((user) => {
            const selected = new Set(user.roles.map((role) => role.id));
            const options = roles.roles.map((role) => `<option value="${role.id}" ${selected.has(role.id) ? 'selected' : ''}>${escapeHtml(role.name)}</option>`).join('');
            return `
              <tr>
                <td><strong>${escapeHtml(user.name)}</strong></td>
                <td>${escapeHtml(user.email)}</td>
                <td>
                  <select multiple data-user-role-select="${user.id}" size="${Math.min(roles.roles.length, 4)}">${options}</select>
                  <button class="action small" data-user-role-save="${user.id}">Guardar</button>
                </td>
                <td>${formatServerDate(user.created_at)}</td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    </div>
  `;
}

async function roles() {
  const data = await api('/admin/roles');
  return `
    <div class="section-heading">
      <h3>Permisos asignados dinámicamente</h3>
      <button class="action" data-action="new-role">+ Nuevo rol</button>
    </div>

    <div id="role-form-container"></div>

    <div class="panel table-wrap">
      <table>
        <thead>
          <tr><th>Rol</th><th>Descripción</th><th>Permisos</th></tr>
        </thead>
        <tbody>
          ${data.roles.map((role) => `
            <tr>
              <td><strong>${escapeHtml(role.name)}</strong></td>
              <td>${escapeHtml(role.description || 'Rol del sistema')}</td>
              <td>${role.permissions.map((permission) => `<span class="tag">${permission.code}</span>`).join('')}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

async function audit() {
  const data = await api('/admin/audit');
  return `
    <div class="panel table-wrap">
      <div class="list-header">
        <h3>Registro de auditoría</h3>
      </div>
      <table>
        <thead>
          <tr><th>Fecha</th><th>Usuario</th><th>Acción</th><th>IP</th></tr>
        </thead>
        <tbody>
          ${data.logs.map((log) => `
            <tr>
              <td>${formatServerDate(log.created_at, true)}</td>
              <td>${escapeHtml(log.email || 'sistema')}</td>
              <td>${escapeHtml(log.action)}</td>
              <td>${escapeHtml(log.ip || '-')}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

function bindPageActions() {
  document.querySelectorAll('[data-page]').forEach((item) => item.addEventListener('click', () => {
    state.page = item.dataset.page;
    document.querySelectorAll('.nav-item').forEach((nav) => nav.classList.toggle('active', nav === item));
    renderPage();
  }));

  document.querySelectorAll('[data-delete]').forEach((item) => item.addEventListener('click', async () => {
    if (confirm('¿Eliminar este contenido?')) {
      await api(`/content/${item.dataset.delete}`, { method: 'DELETE' });
      toast('Contenido eliminado');
      renderPage();
    }
  }));

  document.querySelectorAll('[data-user-role-save]').forEach((button) => button.addEventListener('click', async () => {
    const userId = Number(button.dataset.userRoleSave);
    const select = document.querySelector(`[data-user-role-select="${userId}"]`);
    const roleIds = Array.from(select.selectedOptions).map((option) => Number(option.value));
    await api(`/admin/users/${userId}/roles`, { method: 'PUT', body: JSON.stringify({ roleIds }) });
    toast('Roles actualizados');
    renderPage();
  }));

  document.querySelector('[data-action="new-content"]')?.addEventListener('click', () => {
    $('#content-form').innerHTML = '<div class="panel form-panel"><form id="new-content-form" class="stack-form"><label>Título<input name="title" required maxlength="150"></label><label>Contenido<textarea name="body" required maxlength="10000"></textarea></label><button class="action" type="submit">Publicar contenido</button></form></div>';
    $('#new-content-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      await api('/content', { method: 'POST', body: JSON.stringify(Object.fromEntries(new FormData(event.target))) });
      toast('Contenido publicado');
      renderPage();
    });
  });

  document.querySelector('[data-action="change-password"]')?.addEventListener('click', () => {
    $('#page-content').innerHTML = `
      <div class="panel form-panel">
        <form id="change-password-form" class="stack-form">
          <label>Contraseña actual<input name="currentPassword" type="password" required minlength="8"></label>
          <label>Nueva contraseña<input name="newPassword" type="password" required minlength="8"></label>
          <button class="action" type="submit" style="width:auto; margin-top:12px;">Actualizar contraseña</button>
        </form>
      </div>`;
    $('#change-password-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const formData = new FormData(event.target);
      const payload = { currentPassword: formData.get('currentPassword'), newPassword: formData.get('newPassword') };
      await api('/auth/password', { method: 'PUT', body: JSON.stringify(payload) });
      toast('Contraseña actualizada');
      renderPage();
    });
  });

  document.querySelector('[data-action="new-role"]')?.addEventListener('click', async () => {
    const roles = await api('/admin/roles');
    const form = `
      <div class="panel form-panel">
        <form id="new-role-form" class="stack-form">
          <label>Nombre del rol<input name="name" required maxlength="60"></label>
          <label>Descripción<textarea name="description" maxlength="200"></textarea></label>
          <div class="perm-grid">
            ${roles.permissions.map((permission) => `<label><input type="checkbox" name="permissionIds" value="${permission.id}">${escapeHtml(permission.label)}</label>`).join('')}
          </div>
          <button class="action" type="submit" style="width:auto; margin-top:20px;">Crear rol</button>
        </form>
      </div>`;
    $('#role-form-container').innerHTML = form;
    $('#new-role-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const formData = new FormData(event.target);
      const permissionIds = Array.from(formData.getAll('permissionIds')).map((value) => Number(value));
      const payload = { name: formData.get('name'), description: formData.get('description') || '', permissionIds };
      await api('/admin/roles', { method: 'POST', body: JSON.stringify(payload) });
      toast('Rol creado');
      renderPage();
    });
  });
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[char]));
}

api('/auth/me').then((data) => enter(data.user)).catch(() => {});
setMode('login');
updatePasswordStrength();
