// Verifica que las credenciales de Firebase Admin cargan y funcionan de verdad.
// Uso: node scripts/check-admin-credentials.js
// Credenciales por variables de entorno (FIREBASE_*, lo aporta backend/.env),
// con fallback opcional a GOOGLE_APPLICATION_CREDENTIALS si estuviera definido.
const fs = require('fs');
const path = require('path');

// Cargar backend/.env igual que server.js (sin dependencias)
(function loadEnv() {
  const envPath = path.join(__dirname, '..', '.env');
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  }
})();

const { applicationDefault, cert, initializeApp } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');

(async () => {
  let credential;
  if (process.env.FIREBASE_PRIVATE_KEY && process.env.FIREBASE_CLIENT_EMAIL) {
    const privateKey = process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');
    credential = cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey
    });
    console.log('Credenciales por variables de entorno:');
  } else {
    const credPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
    if (!credPath || !fs.existsSync(credPath)) {
      console.error('FALLO: define FIREBASE_PRIVATE_KEY + FIREBASE_CLIENT_EMAIL en .env (o GOOGLE_APPLICATION_CREDENTIALS):', credPath);
      process.exit(1);
    }
    try {
      const serviceAccount = JSON.parse(fs.readFileSync(credPath, 'utf8'));
      if (!serviceAccount.private_key || !serviceAccount.client_email) {
        throw new Error('El JSON no tiene las claves private_key / client_email');
      }
      credential = cert({
        projectId: serviceAccount.project_id,
        clientEmail: serviceAccount.client_email,
        privateKey: serviceAccount.private_key
      });
    } catch (error) {
      console.error('FALLO leyendo el JSON:', error.message);
      process.exit(1);
    }
  }

  initializeApp({ credential, projectId: process.env.FIREBASE_PROJECT_ID });

  try {
    // listUsers prueba de punta a punta: credenciales válidas + token OAuth2 + acceso a Auth
    const { users } = await getAuth().listUsers(1);
    console.log('OK: credenciales validadas. Usuarios Auth accesibles:', users.length >= 0 ? 'sí' : 'sí');
  } catch (error) {
    console.error('FALLO validando credenciales contra Firebase Auth:', error.message);
    process.exit(1);
  }
})();
