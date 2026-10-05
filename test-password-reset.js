require('dotenv').config();
const assert = require('node:assert/strict');

const adminEmail = process.env.ADMIN_EMAIL;
const adminPassword = process.env.ADMIN_PASSWORD;

if (!adminEmail || !adminPassword) {
  throw new Error('Define ADMIN_EMAIL y ADMIN_PASSWORD en .env para ejecutar esta prueba');
}

async function main() {
  const session = { headers: {} };
  const loginRes = await fetch('http://localhost:3000/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: adminEmail, password: adminPassword }),
  });
  const loginData = await loginRes.json();
  assert.equal(loginRes.status, 200, 'Debe iniciar sesión correctamente');
  const token = loginData.user ? 'ok' : 'missing';
  assert.equal(token, 'ok');

  const resetRes = await fetch('http://localhost:3000/api/auth/reset-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: 'demo-invalid-token', password: 'NuevaPass123!' }),
  });
  const resetData = await resetRes.json();
  assert.equal(resetRes.status, 400, 'La ruta de reset debe existir y rechazar token inválido');
  assert.ok(resetData?.error, 'Debe devolver un mensaje de error');
  console.log('ok');
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
