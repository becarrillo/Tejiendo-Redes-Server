const { applicationDefault, deleteApp, initializeApp } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');

async function setAdminClaim() {
  const uid = process.argv[2];
  const projectId = process.env.FIREBASE_PROJECT_ID;

  if (!uid || !projectId) {
    throw new Error('Usage: FIREBASE_PROJECT_ID=project-id node scripts/set-admin-claim.js <auth-user-uid>');
  }

  const app = initializeApp({
    credential: applicationDefault(),
    projectId
  });

  try {
    const auth = getAuth(app);
    const user = await auth.getUser(uid);
    await auth.setCustomUserClaims(uid, {
      ...user.customClaims,
      admin: true
    });
    await auth.revokeRefreshTokens(uid);

    console.log(`Admin claim granted to Firebase Authentication user ${uid}.`);
  } finally {
    await deleteApp(app);
  }
}

setAdminClaim().catch(error => {
  console.error('Failed to grant the admin claim:', error);
  process.exitCode = 1;
});
