// netlify/functions/change-password.js
//
// Lets a student change their own password server-side. Needed because once
// the Firestore rules restrict writes to staff roles only, a student session
// can no longer write to "core" directly — this function does that write
// using the Firebase Admin SDK instead, after re-verifying the student's
// current password itself (so this endpoint can't be used to change someone
// else's password just by knowing their student ID).

const crypto = require("crypto");
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
  "Access-Control-Allow-Headers": "Content-Type"
};

function verifyPbkdf2(secret, saltHex, expectedHashHex) {
  if (!saltHex || !expectedHashHex) return false;
  const salt = Buffer.from(saltHex, "hex");
  const derived = crypto.pbkdf2Sync(String(secret), salt, 210000, 32, "sha256");
  return derived.toString("hex") === expectedHashHex;
}

function hashPbkdf2(secret) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.pbkdf2Sync(String(secret), salt, 210000, 32, "sha256");
  return { hash: derived.toString("hex"), salt: salt.toString("hex") };
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: CORS_HEADERS, body: "" };
  }
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, headers: CORS_HEADERS, body: JSON.stringify({ error: "Method not allowed." }) };
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "Invalid request body." }) };
  }

  const { syncCode, studentId, currentPassword, newPassword } = body;
  if (!syncCode || !studentId || !currentPassword || !newPassword) {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "Missing required fields." }) };
  }
  if (String(newPassword).length < 4) {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "New password must be at least 4 characters." }) };
  }

  try {
    const coreRef = db.collection("schools").doc(syncCode).collection("data").doc("core");

    const result = await db.runTransaction(async (tx) => {
      const snap = await tx.get(coreRef);
      if (!snap.exists) throw new Error("School data not found.");
      const data = snap.data() || {};
      const students = data.students || [];
      const idx = students.findIndex(s => s.id === studentId);
      if (idx === -1) throw new Error("Student record not found.");
      const student = students[idx];

      let currentOk = false;
      if (student.passwordHash && student.passwordSalt) {
        currentOk = verifyPbkdf2(currentPassword, student.passwordSalt, student.passwordHash);
      } else {
        currentOk = String(student.password) === String(currentPassword);
      }
      if (!currentOk) throw new Error("WRONG_CURRENT_PASSWORD");

      const { hash, salt } = hashPbkdf2(newPassword);
      const updated = Object.assign({}, student, { passwordHash: hash, passwordSalt: salt });
      delete updated.password;
      students[idx] = updated;
      tx.set(coreRef, { students }, { merge: true });
      return { hash, salt };
    });

    return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ success: true }) };
  } catch (err) {
    if (err.message === "WRONG_CURRENT_PASSWORD") {
      return { statusCode: 401, headers: CORS_HEADERS, body: JSON.stringify({ error: "Current password is incorrect." }) };
    }
    console.error(err);
    return { statusCode: 500, headers: CORS_HEADERS, body: JSON.stringify({ error: err.message || "Server error. Try again." }) };
  }
};
