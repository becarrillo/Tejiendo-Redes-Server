// Verifica que las credenciales de Firebase Admin cargan y funcionan de verdad.
// Uso: node scripts/check-admin-credentials.js
// Requiere GOOGLE_APPLICATION_CREDENTIALS (lo aporta backend/.env) y FIREBASE_PROJECT_ID.
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

const { applicationDefault, initializeApp } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');

const CLAVE_VIEJA_ID = '0d3c4bb46637836fab14b5ac049fae4df08989f3'; // id de la clave actual (informativo)

(async () => {
  const credPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (!credPath || !fs.existsSync(credPath)) {
    console.error('FALLO: GOOGLE_APPLICATION_CREDENTIALS no apunta a un archivo existente:', credPath);
    process.exit(1);
  }

  try {
    const serviceAccount = JSON.parse(fs.readFileSync(credPath, 'utf8'));
    if (!serviceAccount.private_key || !serviceAccount.client_email) {
      throw new Error('El JSON no tiene las claves private_key / client_email');
    }
    if (serviceAccount.private_key_id === CLAVE_VIEJA_ID) {
      console.log('Nota: JSON con la clave id ' + CLAVE_VIEJA_ID + ' (la clave actual en uso).');
    }
    console.log('Archivo de credenciales:');
    console.log('  email        :', serviceAccount.client_email);
    console.log('  key id (nueva):', serviceAccount.private_key_id);
    console.log('  proyecto     :', serviceAccount.project_id);
  } catch (error) {
    console.error('FALLO leyendo el JSON:', error.message);
    process.exit(1);
  }

  initializeApp({ credential: applicationDefault(), projectId: process.env.FIREBASE_PROJECT_ID });

  try {
    // listUsers prueba de punta a punta: credenciales válidas + token OAuth2 + acceso a Auth
    const { users } = await getAuth().listUsers(1);
    console.log('OK: credenciales validadas. Usuarios Auth accesibles:', users.length >= 0 ? 'sí' : 'sí');
  } catch (error) {
    console.error('FALLO validando credenciales contra Firebase Auth:', error.message);
    process.exit(1);
  }
})();
