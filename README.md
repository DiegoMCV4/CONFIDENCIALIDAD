# Caso práctico: Seguridad en Cómputo

Aplicación web desarrollada para cumplir el caso práctico de confidencialidad, autenticación, roles, permisos y auditoría.

## Descripción general

La solución implementa una arquitectura cliente-servidor con:

- Frontend web en HTML/CSS/JavaScript
- Backend REST con Node.js y Express
- Base de datos SQLite para persistencia local
- Autenticación basada en JWT
- División por roles y permisos
- Registro de auditoría de acciones y accesos

## Requisitos cubiertos

- Gestión de usuarios con registro e inicio de sesión
- Roles predeterminados: Administrador, Editor y Usuario Regular
- Permisos dinámicos por acción y recurso
- Control de acceso basado en servidor
- Dashboard de administración
- Registro de auditoría con usuario, acción, fecha y dirección IP
- Cifrado de contraseñas con bcrypt
- Tokens JWT con expiración y refresh tokens
- Validación y sanitización de entradas
- Rate limiting y bloqueo temporal por intentos fallidos
- Interfaz web consumiendo la API REST únicamente

## Ejecución

```powershell
npm install
Copy-Item .env.example .env
# Edita .env y define ADMIN_EMAIL y ADMIN_PASSWORD antes de iniciar
npm start
```

Luego abrir:

```text
http://localhost:3000
```

## Cuenta administrativa

En un entorno compartido, crea el usuario administrador mediante el flujo de registro y asigna sus roles desde la base de datos de desarrollo. No se publican credenciales en este repositorio.

## Seguridad aplicada

- Contraseñas con hash + salt (`bcrypt`)
- Cookies `HttpOnly` para tokens
- JWT con expiración corta
- Refresh tokens con rotación
- Autorización validada en el backend, no solo en frontend
- Rate limiting en autenticación
- Validación de entradas con `zod`
- CORS y protección con Helmet

## API principal

| Método | Ruta | Uso |
| --- | --- | --- |
| POST | `/api/auth/register` | Registro |
| POST | `/api/auth/login` | Inicio de sesión |
| POST | `/api/auth/logout` | Cierre de sesión |
| GET | `/api/auth/me` | Perfil actual |
| PUT | `/api/auth/password` | Cambio de contraseña |
| POST | `/api/auth/forgot-password` | Recuperación |
| POST | `/api/auth/reset-password` | Restablecimiento |
| GET | `/api/content` | Consulta de contenido |
| POST | `/api/content` | Crear contenido |
| PUT | `/api/content/:id` | Editar contenido |
| DELETE | `/api/content/:id` | Eliminar contenido |
| GET | `/api/admin/users` | Usuarios del sistema |
| PUT | `/api/admin/users/:id/roles` | Asignar roles |
| GET | `/api/admin/roles` | Roles y permisos |
| POST | `/api/admin/roles` | Crear rol |
| GET | `/api/admin/audit` | Auditoría |

## Observaciones finales

La aplicación se encuentra en proceso de desarrollo y actualmente cuenta con una implementación funcional que cumple con la mayoría de los requisitos establecidos para el caso práctico. Se continúa trabajando en la mejora y optimización del sistema, así como en la implementación de medidas de seguridad adicionales. Como parte de las siguientes etapas, se contempla configurar HTTPS, establecer secretos seguros y habilitar un dominio con su respectivo certificado TLS, con el objetivo de preparar la aplicación para un futuro despliegue en un entorno de producción.
