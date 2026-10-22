const express = require('express');
const sqlite3 = require('sqlite3');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { applicationDefault, cert, initializeApp } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getStorage } = require('firebase-admin/storage');

// Carga backend/.env (KEY=VALUE) sin sobrescribir variables ya definidas en el entorno.
// Las credenciales de Firebase Admin se definen propiedad por propiedad (FIREBASE_*),
// sin necesidad de archivo JSON en el servidor de despliegue.
(function loadEnv() {
  try {
    const envPath = path.join(__dirname, '.env');
    if (!fs.existsSync(envPath)) return;
    for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
      const match = line.match(/^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$/);
      if (match && process.env[match[1]] === undefined) {
        process.env[match[1]] = match[2];
      }
    }
  } catch {
    // Si .env no se puede leer, el backend sigue arrancando con las variables del entorno.
  }
})();

const app = express();
const port = Number(process.env.PORT) || 3000;
app.use(bodyParser.json());

let db = null;
let firebaseAdminApp = null;

// Credencial de Firebase Admin construida a partir de variables de entorno (FIREBASE_*).
// Equivalente campo por campo al JSON del service account; no requiere archivo en producción.
// Si solo se define GOOGLE_APPLICATION_CREDENTIALS (o nada), hace fallback a applicationDefault().
function credencialFirebase() {
  if (process.env.FIREBASE_PRIVATE_KEY && process.env.FIREBASE_CLIENT_EMAIL) {
    // El PEM llega en una sola línea con los saltos de línea escapados como \n literales.
    const privateKey = process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');
    return cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey
    });
  }
  return applicationDefault();
}

// ==========================================
// SESIONES DE ADMIN CON COOKIE (después del login con Firebase)
// ==========================================
const COOKIE_SESSION = 'admin_session';
const SESION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 días
// Cookie Secure: activa en producción (NODE_ENV=production) o forzada con COOKIE_SECURE=true.
// Secure exige HTTPS: sin él el navegador no enviará/guardará la cookie de admin.
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production';
const sesiones = new Map(); // sesionId -> { uid, email, exp }
const SECRETO_FIRMA = crypto.randomBytes(32); // firma HMAC; invalida las cookies si el backend se reinicia

function firmarSesion(sesionId) {
  return `${sesionId}.${crypto.createHmac('sha256', SECRETO_FIRMA).update(sesionId).digest('hex')}`;
}

function crearSesion(uid, email) {
  const sesionId = crypto.randomBytes(24).toString('hex');
  sesiones.set(sesionId, { uid, email, exp: Date.now() + SESION_TTL_MS });
  return firmarSesion(sesionId);
}

function sesionValida(valorCookie) {
  if (typeof valorCookie !== 'string' || !valorCookie.includes('.')) return null;
  const [sesionId, firma] = valorCookie.split('.', 2);
  const tiempoFirma = crypto.createHmac('sha256', SECRETO_FIRMA).update(sesionId).digest('hex');
  // Comparación a tiempo constante para evitar filtrar con tiempos
  const esperado = Buffer.from(tiempoFirma);
  const recibido = Buffer.from(firma || '');
  if (esperado.length !== recibido.length || !crypto.timingSafeEqual(esperado, recibido)) return null;
  const sesion = sesiones.get(sesionId);
  if (!sesion) return null;
  if (sesion.exp < Date.now()) {
    sesiones.delete(sesionId);
    return null;
  }
  return { sesionId, ...sesion };
}

function leerCookie(req, nombreCookie) {
  const encabezado = req.headers.cookie;
  if (!encabezado) return null;
  for (const fragmento of encabezado.split(';')) {
    const [nombre, ...resto] = fragmento.trim().split('=');
    if (nombre === nombreCookie) return decodeURIComponent(resto.join('='));
  }
  return null;
}

function setCookieSession(res, valor, maxAgeSegundos) {
  const atributos = [
    `${COOKIE_SESSION}=${encodeURIComponent(valor)}`,
    'Path=/',
    'HttpOnly',
    `Max-Age=${maxAgeSegundos}`,
    'SameSite=None',
    ...(COOKIE_SECURE ? ['Secure'] : [])
  ];
  res.setHeader('Set-Cookie', atributos.join('; '));
}

// ==========================================
// MIDDLEWARE CORS
// ==========================================

function requireAdmin(req, res, next) {
  // 1) Sesión por cookie emitida tras el login con Firebase
  const sesion = sesionValida(leerCookie(req, COOKIE_SESSION));
  if (sesion) {
    req.adminUid = sesion.uid;
    return next();
  }

  // 2) Fallback: token Bearer de Firebase verificado en línea
  const authorization = req.headers.authorization || '';
  const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Se requiere iniciar sesión como administrador' });

  try {
    if (!firebaseAdminApp) {
      firebaseAdminApp = initializeApp({
        credential: credencialFirebase(),
        projectId: process.env.FIREBASE_PROJECT_ID
      }, 'rifa-api');
    }

    getAuth(firebaseAdminApp).verifyIdToken(token).then((decoded) => {
      if (decoded.admin !== true) {
        return res.status(403).json({ error: 'Solo el administrador puede marcar como pago' });
      }
      req.adminUid = decoded.uid;
      next();
    }).catch(() => {
      res.status(401).json({ error: 'La sesión de administrador no es válida' });
    });
  } catch {
    return res.status(401).json({ error: 'No se pudo validar la sesión de administrador' });
  }
}

// ==========================================
// MIDDLEWARE CORS
// ==========================================
const allowedOrigins = [
  'https://tejiendo-redes-a375d.web.app',
  'https://tejiendo-redes-a375d.firebaseapp.com',
  'https://console.cron-job.org/jobs/8701785'
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    // Necesario para que el frontend pueda enviar y recibir la cookie de sesión
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Forwarded-For');
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
});

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

// ==========================================
// BASE DE DATOS: ÚNICA TABLA sorteos CON JSON DE PUESTOS
// ==========================================
function puestosDisponibles() {
  // Todos los 100 puestos (00-99) con estado 0 = disponible
  const puestos = {};
  for (let i = 0; i <= 99; i++) {
    const num = i.toString().padStart(2, '0');
    puestos[num] = { duenio: null, estado: 0, chosen_by: null };
  }
  return puestos;
}

function initDb() {
  // Ruta de la base de datos: configurable con RIFA_DATABASE_PATH en .env (ideal para producción);
  // por defecto se usa rifa.db junto a server.js.
  const rutaBd = process.env.RIFA_DATABASE_PATH || path.join(__dirname, 'rifa.db');
  return new Promise((resolve, reject) => {
    try {
      // sqlite3 no crea directorios: si la ruta padre no existe, el arranque moriría
      // con SQLITE_CANTOPEN. Se crea el arbol completo de una vez.
      const dirBd = path.dirname(rutaBd);
      if (!fs.existsSync(dirBd)) fs.mkdirSync(dirBd, { recursive: true });
    } catch (error) {
      return reject(new Error(`No se pudo crear el directorio para la base de datos en "${rutaBd}": ${error.message}`));
    }
    db = new sqlite3.Database(rutaBd, (err) => {
      if (err) {
        return reject(new Error(`No se pudo abrir la base de datos "${rutaBd}" (revisar permisos del usuario que corre node): ${err.message}`));
      }
      db.serialize(() => {
        // Producción: NO se borra ni se siembra nada en el arranque.
        // Si no existen, se crean las tablas vacías la primera vez.
        // Los sorteos y sus 100 puestos se generan cuando el administrador crea un sorteo.
        db.run("CREATE TABLE IF NOT EXISTS premios (id INTEGER PRIMARY KEY AUTOINCREMENT, descripcion TEXT, url_imagen TEXT)", (premioError) => {
          if (premioError) return reject(premioError);
          db.run(
            "CREATE TABLE IF NOT EXISTS sorteos (id INTEGER PRIMARY KEY AUTOINCREMENT, fecha TEXT, descripcion TEXT, premio_id INTEGER, puestos_json TEXT, admin TEXT, FOREIGN KEY(premio_id) REFERENCES premios(id))",
            (createError) => {
              if (createError) return reject(createError);
              resolve(); // tablas listas, sin datos sembrados
            }
          );
        });
      });
    });
  });
}

// ==========================================
// HELPERS
// ==========================================
// Helper: Obtener un puesto del JSON del sorteo
function getPuestoFromSorteo(sorteo, numero) {
  if (!sorteo) return null;
  const key = numero.toString().padStart(2, '0');
  const puestos = JSON.parse(sorteo.puestos_json);
  return puestos[key] || null;
}

// Helper: Reglas de pares: 00-98, 01-97, ..., 47-51, y 48/49 intercambian pareja (48-99 y 49-50)
// Cache de emparejamientos: única fuente de verdad compartida por el endpoint y por esParValido
const EMPAREJAMIENTOS = (() => {
  const pares = [];
  // 00-98, 01-97, ..., 47-51
  for (let i = 0; i <= 47; i++) {
    const secondPosition = 98 - i;
    if (i.toString()?.at(-1)==='4') {
      pares.push([i, parseInt(secondPosition)-1])
    } else if (i.toString()?.at(-1)==='5') {
      pares.push([i, parseInt(secondPosition)+1]);
    } else {
      pares.push([i, parseInt(secondPosition)]);
    }
  }
  // 48 y 49 intercambian pareja: 48-99 y 49-50
  pares.push([48, 99]);
  pares.push([49, 50]);
  return pares;
})();

function esParValido(numero1, numero2) {
  const first = Math.min(numero1, numero2);
  const second = Math.max(numero1, numero2);
  return EMPAREJAMIENTOS.some(([a, b]) => a === first && b === second);
}

// Helper: Alternar un puesto dentro del JSON de un sorteo
function actualizarPuesto(sorteo, numero, nuevoEstado, callback) {
  const puestos = JSON.parse(sorteo.puestos_json);
  const key = numero.toString().padStart(2, '0');
  if (!puestos[key]) return callback(new Error('Puesto no encontrado'));
  puestos[key] = { ...puestos[key], ...nuevoEstado };
  db.run("UPDATE sorteos SET puestos_json = ? WHERE id = ?", [JSON.stringify(puestos), sorteo.id], callback);
}

const estadoTexto = (estado) => ({ 0: 'disponible', 1: 'asignado', 2: 'pago' }[estado] || 'desconocido');

function puestosComoLista(puestos) {
  return Object.entries(puestos).map(([key, value]) => ({
    numero: Number(key),
    duenio: value.duenio,
    estado: value.estado,
    estado_texto: estadoTexto(value.estado),
    chosen_by: value.chosen_by
  }));
}

// ==========================================
// ENDPOINTS
// ==========================================

const SORTEOS_CON_PREMIO = `
  SELECT s.id, s.fecha, s.descripcion, s.admin, s.premio_id,
         p.descripcion AS premio_descripcion,
         p.url_imagen AS url_imagen_del_premio
  FROM sorteos s
  LEFT JOIN premios p ON p.id = s.premio_id
`;

app.get('/api/sorteos', (req, res) => {
  db.all(`${SORTEOS_CON_PREMIO} ORDER BY s.id DESC`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/premios', (req, res) => {
  db.all('SELECT * FROM premios ORDER BY id DESC', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Crear sorteo (reutiliza premio existente o crea uno nuevo) — SOLO ADMIN
const crearSorteo = (req, res) => {
  const { fecha, descripcion, premio_id, premio_descripcion, url_imagen, admin } = req.body;

  const responder = (premioId) => {
    // Cada sorteo nuevo inicia con TODOS los puestos disponibles (estado 0)
    db.run(
      "INSERT INTO sorteos (fecha, descripcion, premio_id, puestos_json, admin) VALUES (?, ?, ?, ?, ?)",
      [fecha || null, descripcion || 'Nueva rifa', premioId, JSON.stringify(puestosDisponibles()), admin || 'admin'],
      function (err) {
        if (err) return res.status(500).json({ error: err.message });
        db.get(`${SORTEOS_CON_PREMIO} WHERE s.id = ?`, [this.lastID], (rowError, creado) => {
          if (rowError) return res.status(500).json({ error: rowError.message });
          res.json({ ...creado, mensaje: 'Sorteo creado exitosamente' });
        });
      }
    );
  };

  const crearPremioYVincular = () => {
    // El premio se crea aparte; si no la pasan, hereda la descripcion del sorteo
    const premioFinal = premio_descripcion || descripcion || 'Premio sin definir';
    db.run(
      "INSERT INTO premios (descripcion, url_imagen) VALUES (?, ?)",
      [premioFinal, url_imagen || null],
      function (premioError) {
        if (premioError) return res.status(500).json({ error: premioError.message });
        responder(this.lastID);
      }
    );
  };

  if (premio_id !== undefined && premio_id !== null) {
    if (!Number.isInteger(premio_id) || premio_id < 1) {
      return res.status(400).json({ error: 'premio_id debe ser un número entero positivo' });
    }
    db.get("SELECT id FROM premios WHERE id = ?", [premio_id], (premioError, premio) => {
      if (premioError) return res.status(500).json({ error: premioError.message });
      if (!premio) return res.status(404).json({ error: 'Premio no encontrado' });
      // Reutilizar un premio existente: muchos sorteos apuntan al mismo premio
      if (url_imagen) {
        db.run("UPDATE premios SET url_imagen = ? WHERE id = ?", [url_imagen, premio_id], (updError) => {
          if (updError) return res.status(500).json({ error: updError.message });
          responder(premio_id);
        });
      } else {
        responder(premio_id);
      }
    });
    return;
  }

  crearPremioYVincular();
};

// Rutas creacionales del administrador, protegidas por cookie de sesión (o Bearer como respaldo)
app.post('/api/crear-sorteo', requireAdmin, crearSorteo);
app.post('/api/sorteos', requireAdmin, crearSorteo);

app.post('/api/seleccionar-par', (req, res) => {
  const { numero1, numero2, nombre, rifa_id } = req.body;

  const num1Valid = Number.isInteger(numero1) && numero1 >= 0 && numero1 <= 99;
  const num2Valid = Number.isInteger(numero2) && numero2 >= 0 && numero2 <= 99;
  const nameValid = typeof nombre === 'string' && nombre.trim().length > 0;

  if (!num1Valid || !num2Valid || !nameValid) {
    return res.status(400).json({ error: 'Datos inválidos' });
  }
  if (rifa_id !== undefined && (!Number.isInteger(rifa_id) || rifa_id < 1)) {
    return res.status(400).json({ error: 'rifa_id debe ser un número entero positivo' });
  }

  if (numero1 === numero2) {
    return res.status(400).json({ error: 'No se pueden seleccionar el mismo puesto' });
  }

  const query = rifa_id
    ? { sql: 'SELECT * FROM sorteos WHERE id = ?', params: [rifa_id] }
    : { sql: 'SELECT * FROM sorteos ORDER BY id DESC LIMIT 1', params: [] };

  db.get(query.sql, query.params, (err, sorteo) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!sorteo) return res.status(404).json({ error: 'No hay sorteos activos' });

    const puestos = JSON.parse(sorteo.puestos_json);

    const key1 = numero1.toString().padStart(2, '0');
    const key2 = numero2.toString().padStart(2, '0');

    if (!puestos[key1]) return res.status(404).json({ error: 'Puesto ' + numero1 + ' no encontrado' });
    if (!puestos[key2]) return res.status(404).json({ error: 'Puesto ' + numero2 + ' no encontrado' });

    // Los puestos deben estar disponibles (estado 0)
    if (puestos[key1].estado !== 0) {
      return res.status(400).json({ error: 'Puesto ' + numero1 + ' no está disponible (estado actual: ' + estadoTexto(puestos[key1].estado) + ')' });
    }
    if (puestos[key2].estado !== 0) {
      return res.status(400).json({ error: 'Puesto ' + numero2 + ' no está disponible (estado actual: ' + estadoTexto(puestos[key2].estado) + ')' });
    }

    // Validar par según reglas: 00-98, ..., 47-51, 48-99, 49-50
    if (!esParValido(numero1, numero2)) {
      return res.status(400).json({ error: 'Combinación no válida. La lista de pares permitidos está en /api/emparejamientos' });
    }

    // Actualizar ambos puestos a estado "asignado" (1)
    puestos[key1] = { ...puestos[key1], estado: 1, chosen_by: nombre.trim() };
    puestos[key2] = { ...puestos[key2], estado: 1, chosen_by: nombre.trim() };

    db.run("UPDATE sorteos SET puestos_json = ? WHERE id = ?", [JSON.stringify(puestos), sorteo.id], (updateErr) => {
      if (updateErr) return res.status(500).json({ error: updateErr.message });
      res.json({
        mensaje: 'Par ' + numero1 + '-' + numero2 + ' asignado a ' + nombre.trim(),
        estado: 'asignado',
        puestos: { [numero1]: puestos[key1], [numero2]: puestos[key2] }
      });
    });
  });
});

app.post('/api/liberar-par', (req, res) => {
  const { numero1, numero2 } = req.body;
  if (numero1 === undefined || numero1 === null || numero2 === undefined || numero2 === null) {
    return res.status(400).json({ error: 'Números requeridos' });
  }

  db.get("SELECT * FROM sorteos ORDER BY id DESC LIMIT 1", (err, sorteo) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!sorteo) return res.status(404).json({ error: 'No hay sorteos activos' });

    const puestos = JSON.parse(sorteo.puestos_json);
    const key1 = numero1.toString().padStart(2, '0');
    const key2 = numero2.toString().padStart(2, '0');
    if (!puestos[key1] || !puestos[key2]) return res.status(404).json({ error: 'Puesto no encontrado' });

    // Resetear a estado disponible (0)
    puestos[key1] = { duenio: null, estado: 0, chosen_by: null };
    puestos[key2] = { duenio: null, estado: 0, chosen_by: null };

    db.run("UPDATE sorteos SET puestos_json = ? WHERE id = ?", [JSON.stringify(puestos), sorteo.id], (updateErr) => {
      if (updateErr) return res.status(500).json({ error: updateErr.message });
      res.json({ mensaje: 'Par liberado exitosamente' });
    });
  });
});

app.post('/api/marcar-pago', requireAdmin, (req, res) => {
  const { numero1, numero2, rifa_id } = req.body;
  const num1Valid = Number.isInteger(numero1) && numero1 >= 0 && numero1 <= 99;
  const num2Valid = Number.isInteger(numero2) && numero2 >= 0 && numero2 <= 99;
  if (!num1Valid || !num2Valid || numero1 === numero2) {
    return res.status(400).json({ error: 'Se requiere un par de puestos válido' });
  }
  if (rifa_id !== undefined && (!Number.isInteger(rifa_id) || rifa_id < 1)) {
    return res.status(400).json({ error: 'rifa_id debe ser un número entero positivo' });
  }
  if (!esParValido(numero1, numero2)) {
    return res.status(400).json({ error: 'La combinación de puestos no es válida' });
  }

  const query = rifa_id
    ? { sql: 'SELECT * FROM sorteos WHERE id = ?', params: [rifa_id] }
    : { sql: 'SELECT * FROM sorteos ORDER BY id DESC LIMIT 1', params: [] };

  db.get(query.sql, query.params, (err, sorteo) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!sorteo) return res.status(404).json({ error: 'No hay sorteos activos' });

    const puestos = JSON.parse(sorteo.puestos_json);
    const key1 = numero1.toString().padStart(2, '0');
    const key2 = numero2.toString().padStart(2, '0');

    if (!puestos[key1] || !puestos[key2]) return res.status(404).json({ error: 'Puesto no encontrado' });

    if (puestos[key1].estado !== 1 || puestos[key2].estado !== 1) {
      return res.status(400).json({ error: 'Solo se pueden marcar como pago los pares asignados' });
    }

    puestos[key1] = { ...puestos[key1], estado: 2 };
    puestos[key2] = { ...puestos[key2], estado: 2 };

    db.run("UPDATE sorteos SET puestos_json = ? WHERE id = ?", [JSON.stringify(puestos), sorteo.id], (updateErr) => {
      if (updateErr) return res.status(500).json({ error: updateErr.message });
      res.json({ mensaje: 'Par marcado como pago', estado: 'pago' });
    });
  });
});

app.get('/api/puestos', (req, res) => {
  const { rifa_id } = req.query;

  if (rifa_id && isNaN(Number(rifa_id))) {
    // rifa_id inválido: caer al sorteo más reciente en lugar de 404
    db.get("SELECT * FROM sorteos ORDER BY id DESC LIMIT 1", (err, sorteo) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!sorteo) return res.status(404).json({ error: 'No hay sorteos activos' });
      res.json(puestosComoLista(JSON.parse(sorteo.puestos_json)));
    });
    return;
  }

  const responder = (err, sorteo) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!sorteo) return res.status(404).json({ error: 'No hay sorteos activos' });
    res.json(puestosComoLista(JSON.parse(sorteo.puestos_json)));
  };

  // Si se pide un rifa_id que no existe, se hace fallback al sorteo más reciente
  if (rifa_id) {
    db.get("SELECT * FROM sorteos WHERE id = ?", [Number(rifa_id)], (err, sorteo) => {
      if (err) return res.status(500).json({ error: err.message });
      if (sorteo) return responder(null, sorteo);
      db.get("SELECT * FROM sorteos ORDER BY id DESC LIMIT 1", responder);
    });
    return;
  }

  db.get("SELECT * FROM sorteos ORDER BY id DESC LIMIT 1", responder);
});

// Consulta de un puesto individual (dos ortografías por compatibilidad)
const getPuestoIndividual = (req, res) => {
  const { numero } = req.params;
  db.get("SELECT * FROM sorteos ORDER BY id DESC LIMIT 1", (err, sorteo) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!sorteo) return res.status(404).json({ error: 'No hay sorteos activos' });
    const puesto = getPuestoFromSorteo(sorteo, Number(numero));
    if (!puesto) return res.status(404).json({ error: 'Puesto no encontrado' });
    res.json({
      numero: Number(numero),
      duenio: puesto.duenio,
      estado: puesto.estado,
      estado_texto: estadoTexto(puesto.estado),
      chosen_by: puesto.chosen_by
    });
  });
};

app.get('/api/puesto/:numero', getPuestoIndividual);

app.get('/api/emparejamientos', (req, res) => {
  res.json(EMPAREJAMIENTOS);
});

// ==========================================
// SESIÓN DE ADMIN: intercambio ID token de Firebase -> cookie HttpOnly
// ==========================================
app.post('/api/admin/iniciar-sesion', (req, res) => {
  const { id_token } = req.body;
  if (typeof id_token !== 'string' || !id_token) {
    return res.status(400).json({ error: 'Se requiere id_token' });
  }

  try {
    if (!firebaseAdminApp) {
      firebaseAdminApp = initializeApp({
        credential: credencialFirebase(),
        projectId: process.env.FIREBASE_PROJECT_ID
      }, 'rifa-api');
    }

    getAuth(firebaseAdminApp).verifyIdToken(id_token).then((decoded) => {
      if (decoded.admin !== true) {
        return res.status(403).json({ error: 'La cuenta no tiene el permiso de administrador' });
      }
      const valor = crearSesion(decoded.uid, decoded.email || null);
      setCookieSession(res, valor, SESION_TTL_MS / 1000);
      res.json({
        mensaje: 'Sesión de administrador iniciada',
        uid: decoded.uid,
        email: decoded.email || null
      });
    }).catch(() => {
      res.status(401).json({ error: 'El token no es válido' });
    });
  } catch (error) {
    res.status(500).json({ error: 'No se pudo validar el token: ' + error.message });
  }
});

app.post('/api/admin/cerrar-sesion', (req, res) => {
  const valor = leerCookie(req, COOKIE_SESSION);
  if (valor) {
    const sesionId = valor.split('.', 1)[0];
    sesiones.delete(sesionId);
  }
  setCookieSession(res, '', 0);
  // Pide al navegador borrar TODAS las cookies del sitio, incluyendo sesiones HttpOnly.
  // Navegadores sin soporte quedan cubiertos por el Set-Cookie expirado y el borrado del frontend.
  res.setHeader('Clear-Site-Data', '"cookies"');
  res.json({ mensaje: 'Sesión cerrada' });
});

// Consulta del estado de la sesión (para que el frontend sepa si hay cookie viva)
app.get('/api/admin/sesion', (req, res) => {
  const sesion = sesionValida(leerCookie(req, COOKIE_SESSION));
  if (!sesion) return res.status(401).json({ error: 'Sin sesión activa' });
  res.json({
    uid: sesion.uid,
    email: sesion.email,
    expira_en: Math.round((sesion.exp - Date.now()) / 1000)
  });
});

// ==========================================
// IMAGEN DEL PREMIO (PROTEGIDO): guarda el binario en Firebase Storage
// y vincula su URL pública a premios.url_imagen del sorteo
// ==========================================
const TIPOS_IMAGEN_VALIDOS = ['image/jpeg', 'image/png', 'image/webp'];

app.post('/api/sorteos/:id/imagen-premio', requireAdmin, express.raw({ type: '*/*', limit: '5mb' }), (req, res) => {
  const sorteoId = Number(req.params.id);
  if (!Number.isInteger(sorteoId) || sorteoId < 1) {
    return res.status(400).json({ error: 'id de sorteo inválido' });
  }
  const contentType = req.headers['content-type'] || '';
  if (!TIPOS_IMAGEN_VALIDOS.includes(contentType)) {
    return res.status(400).json({ error: 'Solo se aceptan imágenes JPEG, PNG o WebP' });
  }
  if (!req.body || req.body.length < 1) {
    return res.status(400).json({ error: 'Cuerpo vacío: envía los bytes de la imagen' });
  }

  db.get(`${SORTEOS_CON_PREMIO} WHERE s.id = ?`, [sorteoId], async (err, sorteo) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!sorteo) return res.status(404).json({ error: 'Sorteo no encontrado' });
    if (sorteo.premio_id === null || sorteo.premio_id === undefined) {
      return res.status(400).json({ error: 'El sorteo no tiene premio asociado' });
    }

    const bucketName = process.env.FIREBASE_STORAGE_BUCKET;
    if (!bucketName) return res.status(500).json({ error: 'FIREBASE_STORAGE_BUCKET no está configurado' });

    try {
      const bucket = getStorage(firebaseAdminApp || initializeApp({ credential: credencialFirebase(), projectId: process.env.FIREBASE_PROJECT_ID }, 'rifa-api')).bucket(bucketName);
      const extension = contentType === 'image/jpeg' ? 'jpg' : contentType === 'image/png' ? 'png' : 'webp';
      const rutaArchivo = `raffle-prize/${sorteoId}/${Date.now()}.${extension}`;
      const archivo = bucket.file(rutaArchivo);
      await archivo.save(req.body, { contentType, resumable: false });
      await archivo.makePublic();
      const urlPublica = `https://storage.googleapis.com/${bucketName}/${rutaArchivo}`;

      db.run("UPDATE premios SET url_imagen = ? WHERE id = ?", [urlPublica, sorteo.premio_id], (updError) => {
        if (updError) return res.status(500).json({ error: updError.message });
        db.get(`${SORTEOS_CON_PREMIO} WHERE s.id = ?`, [sorteoId], (rowError, actualizado) => {
          if (rowError) return res.status(500).json({ error: rowError.message });
          res.json(actualizado);
        });
      });
    } catch (error) {
      res.status(500).json({ error: 'No se pudo subir la imagen: ' + error.message });
    }
  });
});

initDb()
  .then(() => { app.listen(port, () => console.log('Backend listo en http://localhost:' + port)); })
  .catch((error) => { console.error('No se pudo inicializar la base de datos:', error); process.exitCode = 1; });
