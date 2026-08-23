// netlify/functions/change-teacher-pin.js
//
// Lets a teacher/leadership/bursar account change their own PIN. Built as a
// dedicated function rather than a direct client write because Firestore
// rules can only grant or deny write access to the whole teacherAccounts
// document — they can't restrict a write to "only this one array entry."
// This function enforces that narrower rule itself: it re-verifies the
// caller's current PIN and only ever modifies their own record, never
// anyone else's, regardless of what a tampered client request might ask for.

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

  const { syncCode, staffId, currentPin, newPin } = body;
  if (!syncCode || !staffId || !currentPin || !newPin) {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "Missing required fields." }) };
  }
  if (String(newPin).length < 4) {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "New PIN must be at least 4 characters." }) };
  }

  try {
    const acctRef = db.collection("schools").doc(syncCode).collection("data").doc("teacherAccounts");

    await db.runTransaction(async (tx) => {
      const snap = await tx.get(acctRef);
      if (!snap.exists) throw new Error("School data not found.");
      const data = snap.data() || {};
      const accounts = data.teacherAccounts || [];
      const idx = accounts.findIndex(t => t.id === staffId);
      if (idx === -1) throw new Error("Staff record not found.");
      const teacher = accounts[idx];

      let currentOk = false;
      if (teacher.pinHash && teacher.pinSalt) {
        currentOk = verifyPbkdf2(currentPin, teacher.pinSalt, teacher.pinHash);
      } else {
        currentOk = String(teacher.pin) === String(currentPin);
      }
      if (!currentOk) throw new Error("WRONG_CURRENT_PIN");

      const { hash, salt } = hashPbkdf2(newPin);
      const updated = Object.assign({}, teacher, { pinHash: hash, pinSalt: salt });
      delete updated.pin;
      accounts[idx] = updated;
      tx.set(acctRef, { teacherAccounts: accounts }, { merge: true });
    });

    return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ success: true }) };
  } catch (err) {
    if (err.message === "WRONG_CURRENT_PIN") {
      return { statusCode: 401, headers: CORS_HEADERS, body: JSON.stringify({ error: "Current PIN is incorrect." }) };
    }
    console.error(err);
    return { statusCode: 500, headers: CORS_HEADERS, body: JSON.stringify({ error: err.message || "Server error. Try again." }) };
  }
};
