// netlify/functions/save-photo.js
//
// Lets a signed-in student save their passport photo server-side. Needed
// because once the Firestore rules restrict writes to staff roles only, a
// student session can no longer write to "core" directly. Trust here comes
// from verifying the student's Firebase ID token itself (they're already
// signed in) rather than re-asking for a password, since there's no
// password involved in a photo upload.
//
// The photo itself is uploaded to Firebase Storage (not embedded in the
// Firestore document) — Firestore documents cap at 1MB total and hold every
// student's data for the whole school, so a handful of embedded photos
// could fill that cap on their own. Only a private download link gets saved
// into Firestore instead. That link carries a random access token (the same
// scheme Firebase's own client SDK uses) rather than being made publicly
// browsable, so a photo is only reachable by someone who already has the
// exact link — not discoverable or guessable.

const admin = require("firebase-admin");
const crypto = require("crypto");

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)),
    storageBucket: "school-software-c511c.firebasestorage.app"
  });
}
const db = admin.firestore();
const bucket = admin.storage().bucket();

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
  const match = typeof photoDataUrl === "string" && photoDataUrl.match(/^data:(image\/(png|jpeg));base64,(.+)$/);
  if (!match) {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "Missing or invalid photo." }) };
  }
  const contentType = match[1];
  const base64Data = match[3];
  const buffer = Buffer.from(base64Data, "base64");
  // No longer constrained by the 1MB Firestore document cap, but still a
  // sane ceiling — nothing here should legitimately need more than this.
  if (buffer.length > 3 * 1024 * 1024) {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "Photo is too large. Please use a smaller image." }) };
  }

  try {
    // Confirm the student record actually exists before uploading anything.
    const coreRef = db.collection("schools").doc(claims.schoolCode).collection("data").doc("core");
    const coreSnap = await coreRef.get();
    if (!coreSnap.exists) {
      return { statusCode: 404, headers: CORS_HEADERS, body: JSON.stringify({ error: "School data not found." }) };
    }
    const coreData = coreSnap.data() || {};
    const students = coreData.students || [];
    const idx = students.findIndex(s => s.id === claims.studentId);
    if (idx === -1) {
      return { statusCode: 404, headers: CORS_HEADERS, body: JSON.stringify({ error: "Student record not found." }) };
    }

    // Fixed path per student — re-uploading overwrites the previous photo
    // (and the new random token below invalidates any old cached link).
    const ext = contentType === "image/png" ? "png" : "jpg";
    const filePath = `schools/${claims.schoolCode}/studentPhotos/${claims.studentId}.${ext}`;
    const token = crypto.randomUUID();
    const file = bucket.file(filePath);
    await file.save(buffer, {
      metadata: {
        contentType,
        metadata: { firebaseStorageDownloadTokens: token }
      }
    });
    const photoUrl = `https://firebasestorage.googleapis.com/v0/b/${bucket.name}/o/${encodeURIComponent(filePath)}?alt=media&token=${token}`;

    await coreRef.set(
      { students: students.map((s, i) => i === idx ? Object.assign({}, s, { photo: photoUrl }) : s) },
      { merge: true }
    );

    return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ success: true, photoUrl }) };
  } catch (err) {
    console.error(err);
    return { statusCode: 500, headers: CORS_HEADERS, body: JSON.stringify({ error: err.message || "Server error. Try again." }) };
  }
};
