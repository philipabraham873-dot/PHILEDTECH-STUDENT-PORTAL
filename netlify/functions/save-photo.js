// netlify/functions/save-photo.js
//
// Lets a signed-in student save their passport photo server-side. Needed
// because once the Firestore rules restrict writes to staff roles only, a
// student session can no longer write to "core" directly. Trust here comes
// from verifying the student's Firebase ID token itself (they're already
// signed in) rather than re-asking for a password, since there's no
// password involved in a photo upload.

const admin = require("firebase-admin");

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT))
  });
}
const db = admin.firestore();

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: CORS_HEADERS, body: "" };
  }
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, headers: CORS_HEADERS, body: JSON.stringify({ error: "Method not allowed." }) };
  }

  const authHeader = event.headers.authorization || event.headers.Authorization || "";
  const idToken = authHeader.replace(/^Bearer\s+/i, "");
  if (!idToken) {
    return { statusCode: 401, headers: CORS_HEADERS, body: JSON.stringify({ error: "Not signed in." }) };
  }

  let claims;
  try {
    claims = await admin.auth().verifyIdToken(idToken);
  } catch {
    return { statusCode: 401, headers: CORS_HEADERS, body: JSON.stringify({ error: "Session expired. Please log in again." }) };
  }
  if (claims.role !== "student" || !claims.schoolCode || !claims.studentId) {
    return { statusCode: 403, headers: CORS_HEADERS, body: JSON.stringify({ error: "Not authorized." }) };
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "Invalid request body." }) };
  }
  const { photoDataUrl } = body;
  if (!photoDataUrl || typeof photoDataUrl !== "string" || !photoDataUrl.startsWith("data:image/")) {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "Missing or invalid photo." }) };
  }
  // A generous but real ceiling — Firestore documents cap at 1MB total, and
  // this doc holds every student's data, so one photo shouldn't be able to
  // eat a meaningful chunk of that on its own.
  if (photoDataUrl.length > 400000) {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "Photo is too large. Please use a smaller image." }) };
  }

  try {
    const coreRef = db.collection("schools").doc(claims.schoolCode).collection("data").doc("core");
    await db.runTransaction(async (tx) => {
      const snap = await tx.get(coreRef);
      if (!snap.exists) throw new Error("School data not found.");
      const data = snap.data() || {};
      const students = data.students || [];
      const idx = students.findIndex(s => s.id === claims.studentId);
      if (idx === -1) throw new Error("Student record not found.");
      students[idx] = Object.assign({}, students[idx], { photo: photoDataUrl });
      tx.set(coreRef, { students }, { merge: true });
    });
    return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ success: true }) };
  } catch (err) {
    console.error(err);
    return { statusCode: 500, headers: CORS_HEADERS, body: JSON.stringify({ error: err.message || "Server error. Try again." }) };
  }
};
