require('dotenv').config();

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');

const app = express();
const port = Number(process.env.PORT || 3000);
const jwtSecret = process.env.JWT_SECRET || 'development-only-change-this-secret';
const db = new Database(path.join(__dirname, 'data.sqlite'));
db.pragma('foreign_keys = ON');

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', process.env.FRONTEND_ORIGIN || 'http://localhost:3000');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS roles (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '');
  CREATE TABLE IF NOT EXISTS permissions (id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT NOT NULL UNIQUE, label TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS user_roles (user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE, PRIMARY KEY(user_id, role_id));
  CREATE TABLE IF NOT EXISTS role_permissions (role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE, permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE, PRIMARY KEY(role_id, permission_id));
  CREATE TABLE IF NOT EXISTS contents (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, body TEXT NOT NULL, author_id INTEGER NOT NULL REFERENCES users(id), updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER REFERENCES users(id), email TEXT, action TEXT NOT NULL, ip TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS refresh_tokens (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS password_reset_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash TEXT NOT NULL UNIQUE, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at TEXT NOT NULL);
`);

const permissions = [
  ['content:read', 'Leer contenido'], ['content:write', 'Crear y editar contenido'],
  ['content:delete', 'Eliminar contenido'], ['users:manage', 'Gestionar usuarios'],
  ['roles:manage', 'Gestionar roles y permisos'], ['audit:read', 'Consultar auditoria']
];
const insertPermission = db.prepare('INSERT OR IGNORE INTO permissions (code, label) VALUES (?, ?)');
permissions.forEach((permission) => insertPermission.run(...permission));
['Administrador', 'Editor', 'Usuario Regular'].forEach((role) => db.prepare('INSERT OR IGNORE INTO roles (name) VALUES (?)').run(role));
const roleId = (name) => db.prepare('SELECT id FROM roles WHERE name = ?').get(name).id;
const permissionId = (code) => db.prepare('SELECT id FROM permissions WHERE code = ?').get(code).id;
const grant = db.prepare('INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)');
permissions.forEach(([code]) => grant.run(roleId('Administrador'), permissionId(code)));
['content:read', 'content:write', 'content:delete'].forEach((code) => grant.run(roleId('Editor'), permissionId(code)));
grant.run(roleId('Usuario Regular'), permissionId('content:read'));

const adminEmail = process.env.ADMIN_EMAIL;
const adminPassword = process.env.ADMIN_PASSWORD;
if (adminEmail && adminPassword && !db.prepare('SELECT id FROM users WHERE email = ?').get(adminEmail)) {
  const result = db.prepare('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)')
    .run('Administrador', adminEmail.toLowerCase(), bcrypt.hashSync(adminPassword, 12));
  db.prepare('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)').run(result.lastInsertRowid, roleId('Administrador'));
}

function audit(req, action, user = req.user) {
  db.prepare('INSERT INTO audit_logs (user_id, email, action, ip) VALUES (?, ?, ?, ?)')
    .run(user?.id || null, user?.email || null, action, req.ip);
}

function userDetails(id) {
  const user = db.prepare('SELECT id, name, email, active, created_at FROM users WHERE id = ?').get(id);
  if (!user) return null;
  user.roles = db.prepare('SELECT r.id, r.name FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ?').all(id);
  user.permissions = db.prepare('SELECT DISTINCT p.code FROM permissions p JOIN role_permissions rp ON rp.permission_id = p.id JOIN user_roles ur ON ur.role_id = rp.role_id WHERE ur.user_id = ?').all(id).map((row) => row.code);
  return user;
}

function issueTokens(user) {
  const details = userDetails(user.id);
  const accessToken = jwt.sign({ sub: user.id, email: user.email, roles: details.roles.map((role) => role.name), permissions: details.permissions }, jwtSecret, { expiresIn: process.env.JWT_EXPIRES_IN || '15m' });
  const refreshToken = crypto.randomBytes(48).toString('hex');
  const expires = new Date(Date.now() + Number(process.env.REFRESH_TOKEN_DAYS || 7) * 86400000).toISOString();
  db.prepare('INSERT INTO refresh_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(crypto.createHash('sha256').update(refreshToken).digest('hex'), user.id, expires);
  return { accessToken, refreshToken };
}

function setAuthCookies(res, tokens) {
  const secure = process.env.NODE_ENV === 'production';
  res.cookie('access_token', tokens.accessToken, { httpOnly: true, secure, sameSite: 'strict', maxAge: 900000 });
  res.cookie('refresh_token', tokens.refreshToken, { httpOnly: true, secure, sameSite: 'strict', maxAge: 604800000, path: '/api/auth' });
}

function createPasswordResetToken(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const expiresAt = new Date(Date.now() + 15 * 60000).toISOString();
  db.prepare('INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
    .run(tokenHash, userId, expiresAt);
  return token;
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : req.cookies.access_token;
  if (!token) return res.status(401).json({ error: 'Autenticacion requerida' });
  try {
    req.user = jwt.verify(token, jwtSecret);
    if (!userDetails(req.user.sub)?.active) return res.status(401).json({ error: 'Cuenta inactiva' });
    next();
  } catch {
    return res.status(401).json({ error: 'Sesion invalida o expirada' });
  }
}

const requirePermission = (permission) => (req, res, next) => {
  if (!req.user.permissions.includes(permission)) return res.status(403).json({ error: 'No tienes permiso para esta accion' });
  next();
};
const validate = (schema) => (req, res, next) => {
  const result = schema.safeParse(req.body);
  if (!result.success) return res.status(400).json({ error: 'Datos invalidos', fields: result.error.flatten().fieldErrors });
  req.body = result.data;
  next();
};
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, message: { error: 'Demasiados intentos. Espera unos minutos.' } });
const credentials = z.object({ email: z.string().email().max(150), password: z.string().min(8).max(128) });

app.post('/api/auth/register', authLimiter, validate(z.object({ name: z.string().trim().min(2).max(80), email: z.string().email().max(150), password: z.string().min(8).max(128) })), (req, res) => {
  try {
    const result = db.prepare('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)').run(req.body.name, req.body.email.toLowerCase(), bcrypt.hashSync(req.body.password, 12));
    db.prepare('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)').run(result.lastInsertRowid, roleId('Usuario Regular'));
    audit(req, 'Registro de nuevo usuario', { id: result.lastInsertRowid, email: req.body.email });
    res.status(201).json({ message: 'Cuenta creada correctamente' });
  } catch { res.status(409).json({ error: 'No fue posible crear la cuenta' }); }
});

app.post('/api/auth/login', authLimiter, validate(credentials), (req, res) => {
  const email = req.body.email.toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (user?.locked_until && new Date(user.locked_until) > new Date()) return res.status(429).json({ error: 'Cuenta bloqueada temporalmente' });
  if (!user || !user.active || !bcrypt.compareSync(req.body.password, user.password_hash)) {
    if (user) {
      const attempts = user.failed_attempts + 1;
      db.prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?').run(attempts, attempts >= 5 ? new Date(Date.now() + 15 * 60000).toISOString() : null, user.id);
    }
    return res.status(401).json({ error: 'Credenciales invalidas' });
  }
  db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?').run(user.id);
  const tokens = issueTokens(user); setAuthCookies(res, tokens); audit(req, 'Inicio de sesion', user);
  res.json({ user: userDetails(user.id), expiresIn: process.env.JWT_EXPIRES_IN || '15m' });
});

app.post('/api/auth/refresh', (req, res) => {
  const raw = req.cookies.refresh_token;
  const stored = raw && db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ? AND expires_at > ?').get(crypto.createHash('sha256').update(raw).digest('hex'), new Date().toISOString());
  if (!stored) return res.status(401).json({ error: 'Refresh token invalido' });
  db.prepare('DELETE FROM refresh_tokens WHERE token_hash = ?').run(crypto.createHash('sha256').update(raw).digest('hex'));
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(stored.user_id); const tokens = issueTokens(user); setAuthCookies(res, tokens); res.json({ ok: true });
});
app.post('/api/auth/logout', auth, (req, res) => { res.clearCookie('access_token'); res.clearCookie('refresh_token', { path: '/api/auth' }); audit(req, 'Cierre de sesion'); res.json({ ok: true }); });
app.get('/api/auth/me', auth, (req, res) => res.json({ user: userDetails(req.user.sub) }));
app.put('/api/auth/password', auth, validate(z.object({ currentPassword: z.string().min(8).max(128), newPassword: z.string().min(8).max(128) })), (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.sub);
  if (!user || !bcrypt.compareSync(req.body.currentPassword, user.password_hash)) {
    return res.status(400).json({ error: 'La contraseña actual no es correcta' });
  }
  db.prepare('UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?')
    .run(bcrypt.hashSync(req.body.newPassword, 12), req.user.sub);
  audit(req, 'Cambio de contraseña');
  res.json({ message: 'Contraseña actualizada' });
});
app.post('/api/auth/forgot-password', authLimiter, validate(z.object({ email: z.string().email() })), (req, res) => {
  const email = req.body.email.toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (user) {
    const token = createPasswordResetToken(user.id);
    if (process.env.NODE_ENV !== 'production') {
      return res.json({ message: 'Si la cuenta existe, recibiras instrucciones de recuperacion', resetToken: token });
    }
  }
  res.json({ message: 'Si la cuenta existe, recibiras instrucciones de recuperacion' });
});
app.post('/api/auth/reset-password', authLimiter, validate(z.object({ token: z.string().min(16).max(200), password: z.string().min(8).max(128) })), (req, res) => {
  const tokenHash = crypto.createHash('sha256').update(req.body.token).digest('hex');
  const entry = db.prepare('SELECT * FROM password_reset_tokens WHERE token_hash = ? AND expires_at > ?').get(tokenHash, new Date().toISOString());
  if (!entry) return res.status(400).json({ error: 'Token invalido o expirado' });

  db.transaction(() => {
    db.prepare('UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?')
      .run(bcrypt.hashSync(req.body.password, 12), entry.user_id);
    db.prepare('DELETE FROM password_reset_tokens WHERE token_hash = ?').run(tokenHash);
  })();

  audit(req, 'Restablecimiento de contraseña', { id: entry.user_id });
  res.json({ message: 'Contraseña restablecida correctamente' });
});

app.get('/api/content', auth, requirePermission('content:read'), (req, res) => res.json({ items: db.prepare('SELECT c.*, u.name AS author FROM contents c JOIN users u ON u.id = c.author_id ORDER BY c.updated_at DESC').all() }));
app.post('/api/content', auth, requirePermission('content:write'), validate(z.object({ title: z.string().trim().min(2).max(150), body: z.string().trim().min(1).max(10000) })), (req, res) => { const result = db.prepare('INSERT INTO contents (title, body, author_id) VALUES (?, ?, ?)').run(req.body.title, req.body.body, req.user.sub); audit(req, `Creacion de contenido #${result.lastInsertRowid}`); res.status(201).json({ id: result.lastInsertRowid }); });
app.put('/api/content/:id', auth, requirePermission('content:write'), validate(z.object({ title: z.string().trim().min(2).max(150), body: z.string().trim().min(1).max(10000) })), (req, res) => { db.prepare('UPDATE contents SET title = ?, body = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(req.body.title, req.body.body, req.params.id); audit(req, `Edicion de contenido #${req.params.id}`); res.json({ ok: true }); });
app.delete('/api/content/:id', auth, requirePermission('content:delete'), (req, res) => { db.prepare('DELETE FROM contents WHERE id = ?').run(req.params.id); audit(req, `Eliminacion de contenido #${req.params.id}`); res.status(204).end(); });

app.get('/api/admin/users', auth, requirePermission('users:manage'), (req, res) => res.json({ users: db.prepare('SELECT id, name, email, active, created_at FROM users ORDER BY created_at DESC').all().map((user) => ({ ...user, roles: userDetails(user.id).roles })) }));
app.put('/api/admin/users/:id/roles', auth, requirePermission('users:manage'), validate(z.object({ roleIds: z.array(z.number().int()).max(10) })), (req, res) => { const transaction = db.transaction(() => { db.prepare('DELETE FROM user_roles WHERE user_id = ?').run(req.params.id); req.body.roleIds.forEach((id) => db.prepare('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)').run(req.params.id, id)); }); transaction(); audit(req, `Actualizacion de roles del usuario #${req.params.id}`); res.json({ ok: true }); });
app.get('/api/admin/roles', auth, requirePermission('roles:manage'), (req, res) => res.json({ roles: db.prepare('SELECT * FROM roles ORDER BY name').all().map((role) => ({ ...role, permissions: db.prepare('SELECT p.id, p.code, p.label FROM permissions p JOIN role_permissions rp ON rp.permission_id = p.id WHERE rp.role_id = ?').all(role.id) })), permissions: db.prepare('SELECT * FROM permissions ORDER BY id').all() }));
app.post('/api/admin/roles', auth, requirePermission('roles:manage'), validate(z.object({ name: z.string().trim().min(2).max(60), description: z.string().trim().max(200).optional(), permissionIds: z.array(z.number().int()).max(20) })), (req, res) => { try { const result = db.prepare('INSERT INTO roles (name, description) VALUES (?, ?)').run(req.body.name, req.body.description || ''); req.body.permissionIds.forEach((id) => grant.run(result.lastInsertRowid, id)); audit(req, `Creacion del rol ${req.body.name}`); res.status(201).json({ id: result.lastInsertRowid }); } catch { res.status(409).json({ error: 'El rol ya existe' }); } });
app.get('/api/admin/audit', auth, requirePermission('audit:read'), (req, res) => res.json({ logs: db.prepare('SELECT id, email, action, ip, created_at FROM audit_logs ORDER BY id DESC LIMIT 200').all() }));

app.use('/api', (req, res) => res.status(404).json({ error: 'Recurso no encontrado' }));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Ocurrio un error interno' }); });
app.listen(port, () => console.log(`Aplicacion disponible en http://localhost:${port}`));