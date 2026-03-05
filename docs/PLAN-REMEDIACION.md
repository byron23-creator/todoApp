# Plan de Remediación — todoApp

## Resumen ejecutivo

La **todoApp** es una API REST construida con Node.js, Express y MongoDB que permite gestionar tareas (crear, leer, actualizar y eliminar). Tras el análisis de seguridad realizado en la Tarea 1, se identificaron **12 vulnerabilidades** que abarcan desde la ausencia total de autenticación hasta la exposición de credenciales en el código fuente. En su estado actual, la aplicación no es apta para un entorno de producción. El objetivo de este plan es proporcionar soluciones concretas y accionables para cada hallazgo, priorizadas por severidad, de modo que cualquier desarrollador pueda implementarlas siguiendo únicamente este documento.

---

## Tabla de vulnerabilidades

| # | Vulnerabilidad | Severidad | OWASP | Principio violado | Solución | Clase |
|---|---|---|---|---|---|---|
| 1 | Sin autenticación en ningún endpoint | Crítica | A07 | Zero Trust | Implementar JWT con middleware `authenticate` en todas las rutas | Clase 6 |
| 2 | IDOR — modifica/borra tareas ajenas | Crítica | A01 | Menor Privilegio | Asociar tareas a `userId` y verificar propiedad antes de operar | Clase 6 |
| 3 | Acepta `<script>` como título (XSS) | Alta | A03 | Defensa en Profundidad | Validar con Joi: string 3-200 chars, rechazar HTML/JS | Clase 3 |
| 4 | `err.message` expuesto al cliente | Alta | A04 | Fail Secure | Retornar mensaje genérico; loguear el error real en servidor | Clase 3 |
| 5 | Sin rate limiting — DoS trivial | Alta | A04 | Economía de Mecanismo | Aplicar `express-rate-limit` (100 req/15 min por IP) | Clase 5 |
| 6 | MongoDB sin autenticación | Crítica | A05 | Menor Privilegio | Habilitar auth en MongoDB y usar usuario con permisos mínimos | Clase 4 |
| 7 | Mass assignment sin restricción | Alta | A04 | Seguro por Defecto | Desestructurar solo campos permitidos; nunca pasar `req.body` directo | Clase 3 |
| 8 | Sin CORS configurado | Media | A05 | Seguro por Defecto | Configurar `cors` con lista blanca de orígenes permitidos | Clase 5 |
| 9 | Sin headers de seguridad (Helmet) | Media | A05 | Defensa en Profundidad | Agregar `helmet()` como primer middleware en `app.js` | Clase 5 |
| 10 | Sin audit logs | Media | A09 | Separación de Responsabilidades | Registrar cada operación CRUD con usuario, timestamp y resultado | Clase 7 |
| 11 | Sin HTTPS | Alta | A02 | Defensa en Profundidad | Forzar TLS en producción; redirigir HTTP → HTTPS | Clase 2 |
| 12 | Connection string hardcodeada | Alta | A05 | Seguro por Defecto | Mover la URI a variable de entorno `MONGODB_URI` en `.env` | Clase 4 |

---

## Detalle de vulnerabilidades

### Vulnerabilidad #1: Sin autenticación en ningún endpoint

- **Severidad**: Crítica
- **OWASP**: A07 — Identification and Authentication Failures
- **Principio violado**: Zero Trust
- **Descripción**: Todos los endpoints (`GET`, `POST`, `PUT`, `DELETE`) de `/api/tareas` son accesibles sin ningún tipo de credencial. Cualquier persona con acceso a la red puede leer, crear, modificar o eliminar cualquier tarea sin identificarse. Esto viola el principio de Zero Trust, que exige verificar cada request independientemente de su origen.
- **Solución concreta**:
  1. Instalar dependencias: `npm install jsonwebtoken bcryptjs`.
  2. Crear `src/routes/auth.js` con endpoints `POST /api/auth/register` y `POST /api/auth/login` que generen un JWT firmado con `process.env.JWT_SECRET` y expiración de 1 hora (`expiresIn: '1h'`).
  3. Crear `src/middleware/authenticate.js`:
     ```js
     const jwt = require('jsonwebtoken');
     module.exports = (req, res, next) => {
       const token = req.headers.authorization?.split(' ')[1];
       if (!token) return res.status(401).json({ error: 'Token requerido' });
       try {
         req.user = jwt.verify(token, process.env.JWT_SECRET);
         next();
       } catch {
         return res.status(401).json({ error: 'Token inválido o expirado' });
       }
     };
     ```
  4. En `app.js`, aplicar el middleware antes del router de tareas:
     ```js
     const authenticate = require('./middleware/authenticate');
     app.use('/api/tareas', authenticate, tareasRouter);
     ```
- **Clase del curso**: Clase 6

---

### Vulnerabilidad #2: IDOR — modifica/borra tareas ajenas

- **Severidad**: Crítica
- **OWASP**: A01 — Broken Access Control
- **Principio violado**: Menor Privilegio
- **Descripción**: Los endpoints `PUT /api/tareas/:id` y `DELETE /api/tareas/:id` buscan la tarea únicamente por `_id` de MongoDB, sin verificar si pertenece al usuario autenticado. Un atacante que conozca el ObjectId de una tarea ajena puede modificarla o eliminarla libremente, ya que no existe ninguna verificación de propiedad.
- **Solución concreta**:
  1. Agregar campo `owner` al schema de Tarea en `src/models/tarea.model.js`:
     ```js
     owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
     ```
  2. En `POST /api/tareas`, asignar el owner desde el token: `const tarea = new Tarea({ title, completed, owner: req.user.id })`.
  3. En `PUT` y `DELETE`, filtrar por `_id` **y** `owner` simultáneamente:
     ```js
     const tarea = await Tarea.findOne({ _id: req.params.id, owner: req.user.id });
     if (!tarea) return res.status(404).json({ error: 'Not found' });
     ```
  4. En `GET /` (listar), filtrar solo las tareas del usuario: `Tarea.find({ owner: req.user.id }).lean()`.
  5. En `GET /:id`, aplicar la misma restricción de owner.
- **Clase del curso**: Clase 6

---

### Vulnerabilidad #3: Acepta `<script>` como título (XSS)

- **Severidad**: Alta
- **OWASP**: A03 — Injection (XSS)
- **Principio violado**: Defensa en Profundidad
- **Descripción**: El campo `title` no tiene ninguna validación de formato ni sanitización. Un atacante puede almacenar `<script>alert('XSS')</script>` como título de una tarea. Si algún cliente web renderiza este valor sin escaparlo, ejecutará código arbitrario en el navegador de la víctima (Stored XSS). El schema de Mongoose solo valida que sea `String` y `required`, pero no restringe el contenido.
- **Solución concreta**:
  1. Instalar Joi: `npm install joi`.
  2. Crear `src/middleware/validateTarea.js`:
     ```js
     const Joi = require('joi');
     const schema = Joi.object({
       title: Joi.string()
         .min(3).max(200)
         .pattern(/^[^<>{}()"'`]*$/)
         .required()
         .messages({ 'string.pattern.base': 'El título no puede contener caracteres HTML o JS' }),
       completed: Joi.boolean()
     });
     module.exports = (req, res, next) => {
       const { error } = schema.validate(req.body, { abortEarly: false, allowUnknown: false });
       if (error) return res.status(422).json({ errors: error.details.map(d => d.message) });
       next();
     };
     ```
  3. Aplicar el middleware en las rutas `POST` y `PUT` de `tareas.js`:
     ```js
     const validateTarea = require('../middleware/validateTarea');
     router.post('/', validateTarea, async (req, res) => { ... });
     router.put('/:id', validateTarea, async (req, res) => { ... });
     ```
- **Clase del curso**: Clase 3

---

### Vulnerabilidad #4: `err.message` expuesto al cliente

- **Severidad**: Alta
- **OWASP**: A04 — Insecure Design / Information Disclosure
- **Principio violado**: Fail Secure
- **Descripción**: En todos los bloques `catch` de `src/routes/tareas.js`, el código retorna `res.status(500).json({ error: err.message })`. Esto puede revelar rutas internas del sistema, nombres de colecciones de MongoDB, stack traces o mensajes de error de la base de datos que facilitan el reconocimiento del sistema por parte de un atacante (information disclosure).
- **Solución concreta**:
  1. Crear `src/middleware/errorHandler.js`:
     ```js
     module.exports = (err, req, res, next) => {
       console.error(`[ERROR] ${new Date().toISOString()} - ${req.method} ${req.path}:`, err);
       const status = err.status || 500;
       res.status(status).json({ error: 'Error interno del servidor' });
     };
     ```
  2. Registrar el middleware al **final** de `app.js` (después de todos los routers):
     ```js
     const errorHandler = require('./middleware/errorHandler');
     app.use(errorHandler);
     ```
  3. En cada bloque `catch` de las rutas, reemplazar `res.status(500).json({ error: err.message })` por `next(err)`.
- **Clase del curso**: Clase 3
---

### Vulnerabilidad #5: Sin rate limiting — DoS trivial

- **Severidad**: Alta
- **OWASP**: A04 — Insecure Design
- **Principio violado**: Economía de Mecanismo
- **Descripción**: La API no tiene ningún límite de peticiones por IP. Un atacante puede enviar miles de requests por segundo para saturar el servidor o la base de datos, causando una denegación de servicio (DoS) sin necesidad de autenticación ni herramientas sofisticadas. Basta con un script simple o herramientas como `ab` o `wrk`.
- **Solución concreta**:
  1. Instalar: `npm install express-rate-limit`.
  2. En `app.js`, antes de los routers, agregar:
     ```js
     const rateLimit = require('express-rate-limit');
     const limiter = rateLimit({
       windowMs: 15 * 60 * 1000, // ventana de 15 minutos
       max: 100,                  // máximo 100 requests por IP por ventana
       standardHeaders: true,
       legacyHeaders: false,
       message: { error: 'Demasiadas solicitudes, intenta más tarde' }
     });
     app.use(limiter);
     ```
  3. Para el endpoint de login (`POST /api/auth/login`), aplicar un limiter más estricto:
     ```js
     const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
     router.post('/login', loginLimiter, async (req, res) => { ... });
     ```
- **Clase del curso**: Clase 5

---

### Vulnerabilidad #6: MongoDB sin autenticación

- **Severidad**: Crítica
- **OWASP**: A05 — Security Misconfiguration
- **Principio violado**: Menor Privilegio
- **Descripción**: La instancia de MongoDB corre sin usuario ni contraseña (`mongodb://localhost:27017/todo_app`). Cualquier proceso o usuario con acceso a la máquina (o a la red si el puerto 27017 está expuesto) puede conectarse directamente a la base de datos, leer, modificar o eliminar todos los datos sin restricción alguna.
- **Solución concreta**:
  1. En el servidor, habilitar autenticación en MongoDB editando `/etc/mongod.conf`:
     ```yaml
     security:
       authorization: enabled
     ```
  2. Crear un usuario con permisos mínimos (solo `readWrite` sobre la base de datos de la app):
     ```js
     use todo_app
     db.createUser({
       user: "todoapp_user",
       pwd: "<contraseña-segura-generada>",
       roles: [{ role: "readWrite", db: "todo_app" }]
     })
     ```
  3. Actualizar la connection string en `.env`: `MONGODB_URI=mongodb://todoapp_user:<pwd>@localhost:27017/todo_app?authSource=todo_app`.
  4. En `docker-compose.yml`, configurar las variables de entorno del contenedor de Mongo:
     ```yaml
     environment:
       MONGO_INITDB_ROOT_USERNAME: root
       MONGO_INITDB_ROOT_PASSWORD: ${MONGO_ROOT_PASSWORD}
     ```
- **Clase del curso**: Clase 4
---

### Vulnerabilidad #7: Mass assignment sin restricción

- **Severidad**: Alta
- **OWASP**: A04 — Insecure Design
- **Principio violado**: Seguro por Defecto
- **Descripción**: Aunque en `PUT /api/tareas/:id` se desestructura `{ title, completed }`, no existe ningún mecanismo que rechace campos adicionales en el body. Si en el futuro se agrega un campo sensible como `owner` o `isAdmin` al modelo, un atacante podría sobreescribirlo enviando ese campo en el body. Además, el uso de `allowUnknown: true` (comportamiento por defecto sin Joi) permite que campos arbitrarios lleguen al modelo.
- **Solución concreta**:
  1. En el middleware `validateTarea.js` (ver Vuln #3), asegurarse de usar `allowUnknown: false` en las opciones de Joi para rechazar cualquier campo no declarado en el schema:
     ```js
     schema.validate(req.body, { abortEarly: false, allowUnknown: false })
     ```
  2. En las rutas, construir explícitamente el objeto de actualización con solo los campos permitidos:
     ```js
     const { title, completed } = req.body;
     const updateData = {};
     if (title !== undefined) updateData.title = title;
     if (completed !== undefined) updateData.completed = completed;
     const tarea = await Tarea.findOneAndUpdate(
       { _id: req.params.id, owner: req.user.id },
       { $set: updateData },
       { new: true, runValidators: true }
     );
     ```
  3. **Nunca** usar `$set: req.body` ni pasar `req.body` directamente a métodos de Mongoose.
- **Clase del curso**: Clase 3

---

### Vulnerabilidad #8: Sin CORS configurado

- **Severidad**: Media
- **OWASP**: A05 — Security Misconfiguration
- **Principio violado**: Seguro por Defecto
- **Descripción**: La aplicación no configura ninguna política CORS. Esto significa que cualquier origen puede hacer peticiones cross-origin a la API desde un navegador, facilitando ataques CSRF y el abuso de la API desde sitios maliciosos. Sin una lista blanca de orígenes, la API queda expuesta a cualquier dominio.
- **Solución concreta**:
  1. Instalar: `npm install cors`.
  2. En `app.js`, configurar CORS con lista blanca explícita:
     ```js
     const cors = require('cors');
     const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [];
     app.use(cors({
       origin: (origin, callback) => {
         if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
         callback(new Error('Origen no permitido por CORS'));
       },
       methods: ['GET', 'POST', 'PUT', 'DELETE'],
       allowedHeaders: ['Content-Type', 'Authorization'],
       credentials: true
     }));
     ```
  3. Agregar en `.env`: `ALLOWED_ORIGINS=https://mi-frontend.com,https://app.midominio.com`.
  4. **No usar** `cors()` sin opciones, ya que permite todos los orígenes (`*`).
- **Clase del curso**: Clase 5

---

### Vulnerabilidad #9: Sin headers de seguridad (Helmet)

- **Severidad**: Media
- **OWASP**: A05 — Security Misconfiguration
- **Principio violado**: Defensa en Profundidad
- **Descripción**: La API no envía headers de seguridad HTTP como `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy` ni `Strict-Transport-Security`. Sin estos headers, los navegadores son más vulnerables a ataques de clickjacking, MIME sniffing y otros vectores de ataque del lado del cliente.
- **Solución concreta**:
  1. Instalar: `npm install helmet`.
  2. En `app.js`, agregar `helmet()` como **primer** middleware (antes de cualquier router):
     ```js
     const helmet = require('helmet');
     app.use(helmet());
     ```
  3. Esto activa automáticamente los siguientes headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `X-XSS-Protection: 0`, `Strict-Transport-Security`, `Content-Security-Policy` (básico) y otros.
  4. Para una API REST pura (sin frontend propio), se puede personalizar CSP:
     ```js
     app.use(helmet({ contentSecurityPolicy: false }));
     ```
- **Clase del curso**: Clase 5
---

### Vulnerabilidad #10: Sin audit logs

- **Severidad**: Media
- **OWASP**: A09 — Security Logging and Monitoring Failures
- **Principio violado**: Separación de Responsabilidades
- **Descripción**: La aplicación no registra ningún evento de seguridad relevante: quién creó, modificó o eliminó una tarea, cuándo ocurrió, desde qué IP, ni si la operación fue exitosa o fallida. Sin audit logs, es imposible detectar actividad maliciosa, investigar incidentes o cumplir con requisitos de auditoría.
- **Solución concreta**:
  1. Instalar: `npm install winston`.
  2. Crear `src/utils/logger.js`:
     ```js
     const winston = require('winston');
     module.exports = winston.createLogger({
       level: 'info',
       format: winston.format.combine(
         winston.format.timestamp(),
         winston.format.json()
       ),
       transports: [
         new winston.transports.File({ filename: 'logs/audit.log' }),
         new winston.transports.Console()
       ]
     });
     ```
  3. En cada ruta de `tareas.js`, registrar la operación después de ejecutarla exitosamente:
     ```js
     const logger = require('../utils/logger');
     // Ejemplo en POST:
     logger.info({ action: 'CREATE_TAREA', userId: req.user.id, tareaId: tarea._id, ip: req.ip });
     // Ejemplo en DELETE:
     logger.info({ action: 'DELETE_TAREA', userId: req.user.id, tareaId: req.params.id, ip: req.ip });
     ```
  4. Registrar también los intentos fallidos de autenticación en `authenticate.js`.
- **Clase del curso**: Clase 7

---

### Vulnerabilidad #11: Sin HTTPS

- **Severidad**: Alta
- **OWASP**: A02 — Cryptographic Failures
- **Principio violado**: Defensa en Profundidad
- **Descripción**: La aplicación sirve tráfico en HTTP plano. Esto significa que los tokens JWT, credenciales y datos de las tareas viajan en texto claro por la red, expuestos a ataques de tipo Man-in-the-Middle (MitM). Cualquier actor en la misma red puede interceptar y leer o modificar el tráfico.
- **Solución concreta**:
  1. En producción, obtener un certificado TLS gratuito con Let's Encrypt usando Certbot:
     ```bash
     sudo certbot --nginx -d api.midominio.com
     ```
  2. Configurar un reverse proxy (Nginx) que termine TLS y reenvíe a la app en HTTP interno:
     ```nginx
     server {
       listen 443 ssl;
       server_name api.midominio.com;
       ssl_certificate /etc/letsencrypt/live/api.midominio.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/api.midominio.com/privkey.pem;
       location / { proxy_pass http://localhost:3000; }
     }
     server {
       listen 80;
       server_name api.midominio.com;
       return 301 https://$host$request_uri;
     }
     ```
  3. En `app.js`, agregar middleware para forzar HTTPS en producción:
     ```js
     if (process.env.NODE_ENV === 'production') {
       app.use((req, res, next) => {
         if (req.headers['x-forwarded-proto'] !== 'https')
           return res.redirect(301, `https://${req.headers.host}${req.url}`);
         next();
       });
     }
     ```
- **Clase del curso**: Clase 2

---

### Vulnerabilidad #12: Connection string hardcodeada

- **Severidad**: Alta
- **OWASP**: A05 — Security Misconfiguration
- **Principio violado**: Seguro por Defecto
- **Descripción**: En `src/server.js`, la cadena de conexión a MongoDB está escrita directamente en el código fuente: `mongoose.connect('mongodb://localhost:27017/todo_app')`. Si el repositorio es público o el código se filtra, cualquier persona conoce la dirección de la base de datos. Además, imposibilita tener configuraciones distintas para desarrollo, staging y producción sin modificar el código.
- **Solución concreta**:
  1. Instalar: `npm install dotenv`.
  2. En `src/server.js`, reemplazar la URI hardcodeada:
     ```js
     require('dotenv').config();
     mongoose.connect(process.env.MONGODB_URI)
     ```
  3. En `.env` (que ya existe en el proyecto como `.env.example`), definir:
     ```
     MONGODB_URI=mongodb://todoapp_user:<pwd>@localhost:27017/todo_app?authSource=todo_app
     JWT_SECRET=<cadena-aleatoria-de-al-menos-32-chars>
     PORT=3000
     NODE_ENV=development
     ALLOWED_ORIGINS=http://localhost:5173
     ```
  4. Verificar que `.env` esté en `.gitignore` (ya existe en el proyecto) y **nunca** commitear credenciales reales.
  5. En CI/CD (GitHub Actions), inyectar las variables como secrets del repositorio.
- **Clase del curso**: Clase 4

---

## Sección Impacto

### Vulnerabilidad más crítica: Sin autenticación en ningún endpoint (#1)

Esta vulnerabilidad es la más grave del sistema porque es la **raíz de todas las demás**. Sin autenticación, las vulnerabilidades #2 (IDOR), #7 (mass assignment) y #10 (sin audit logs) se vuelven trivialmente explotables por cualquier persona, no solo por atacantes sofisticados.

#### Escenario de ataque real (paso a paso)

1. **Reconocimiento**: El atacante descubre la API haciendo un simple `curl http://api.midominio.com/api/tareas`. Recibe un `200 OK` con todas las tareas de todos los usuarios en texto plano, sin necesidad de credenciales.
2. **Enumeración**: Itera sobre los IDs de MongoDB (`GET /api/tareas/:id`) para mapear todos los recursos existentes.
3. **Explotación**: Envía `DELETE /api/tareas/<id>` para eliminar cualquier tarea, o `PUT /api/tareas/<id>` con `{ "title": "<script>alert(1)</script>" }` para inyectar XSS en los datos.
4. **Persistencia**: Como no hay audit logs (#10), el ataque no deja rastro. La víctima no sabe que fue atacada.
5. **Escalada**: Si la API está en una red interna, el atacante puede automatizar la eliminación masiva de todas las tareas con un script de 5 líneas, causando pérdida total de datos.

#### Impacto por dimensión

| Dimensión | Impacto | Detalle |
|---|---|---|
| **Confidencialidad** | Alto | Cualquier persona puede leer todas las tareas de todos los usuarios |
| **Integridad** | Crítico | Cualquier persona puede modificar o eliminar cualquier tarea sin restricción |
| **Disponibilidad** | Alto | Sin rate limiting (#5), un atacante puede saturar la API o vaciar la BD |
| **Reputación** | Alto | Una brecha pública destruye la confianza de los usuarios |
| **Legal/Compliance** | Medio | Posible incumplimiento de GDPR/LGPD si se almacenan datos personales |

#### Puntuación CVSS v3.1 estimada

- **Vector**: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Score**: **9.8 (Crítico)**
- **Justificación**: Acceso por red (`AV:N`), sin complejidad (`AC:L`), sin privilegios requeridos (`PR:N`), sin interacción del usuario (`UI:N`), impacto alto en las tres dimensiones CIA.

#### Cadena de vulnerabilidades activada

```
#1 Sin autenticación
    ├── #2 IDOR (cualquiera modifica tareas ajenas)
    ├── #3 XSS (cualquiera inyecta scripts en títulos)
    ├── #7 Mass assignment (cualquiera sobreescribe campos)
    └── #10 Sin audit logs (el ataque no deja rastro)
```

#### Plan de mitigación inmediata (orden de implementación)

| Prioridad | Acción | Tiempo estimado |
|---|---|---|
| 1 | Implementar JWT + middleware `authenticate` (Vuln #1) | 2 horas |
| 2 | Agregar campo `owner` y verificación IDOR (Vuln #2) | 1 hora |
| 3 | Mover connection string a `.env` (Vuln #12) | 30 min |
| 4 | Habilitar autenticación en MongoDB (Vuln #6) | 1 hora |
| 5 | Agregar Helmet + CORS + rate limiting (Vuln #5, #8, #9) | 1 hora |
| 6 | Validación Joi + error handler (Vuln #3, #4, #7) | 2 horas |
| 7 | Configurar HTTPS con Nginx + Certbot (Vuln #11) | 2 horas |
| 8 | Implementar audit logs con Winston (Vuln #10) | 1 hora |

