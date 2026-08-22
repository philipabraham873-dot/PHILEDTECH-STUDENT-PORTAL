// netlify/functions/verify-login.js
//
// Verifies Staff ID+PIN / Student ID+password / admin Sync-Code login
// server-side, then mints a Firebase custom auth token carrying the
// school's syncCode and the caller's role as claims. The client signs in
// with that token instead of an anonymous session, so Firestore rules can
// finally check WHO is asking, not just "is this some authenticated user."
//
// Setup (one time):
//   1. In this Netlify site: npm install firebase-admin
//   2. Add env var FIREBASE_SERVICE_ACCOUNT = the full JSON content of your
//      Firebase service account key (Project settings > Service accounts).

const crypto = require("crypto");
const admin = require("firebase-admin");

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT))
  });
}
const db = admin.firestore();

// Allows this function to be called from your other portal domains (and from
// the Electron admin app's file:// origin). Not a security boundary by
// itself — the real protection is the PIN/password check below — this just
// lets legitimate cross-origin browser requests through.
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type"
};

// Must match the browser's Web Crypto PBKDF2 params exactly:
// PBKDF2-HMAC-SHA256, 210,000 iterations, 256-bit (32-byte) output.
function verifyPbkdf2(secret, saltHex, expectedHashHex) {
  if (!saltHex || !expectedHashHex) return false;
  const salt = Buffer.from(saltHex, "hex");
  const derived = crypto.pbkdf2Sync(String(secret), salt, 210000, 32, "sha256");
  return derived.toString("hex") === expectedHashHex;
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

  const { syncCode, actorType, id, secret } = body;
  if (!syncCode || !actorType || !secret) {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "Missing required fields." }) };
  }

  try {
    const dataRef = db.collection("schools").doc(syncCode).collection("data");

    // ---- Admin device: knowing the Sync Code is the credential, same as
    // today's behaviour — this just moves the check server-side so the
    // resulting session gets a real "admin" claim instead of a free
    // anonymous one that also happens to work for every other school.
    if (actorType === "admin") {
      const coreSnap = await dataRef.doc("core").get();
      if (!coreSnap.exists) {
        return { statusCode: 401, headers: CORS_HEADERS, body: JSON.stringify({ error: "Portal Code not found." }) };
      }
      if (String(secret) !== String(syncCode)) {
        return { statusCode: 401, headers: CORS_HEADERS, body: JSON.stringify({ error: "Incorrect Portal Code." }) };
      }
      const token = await admin.auth().createCustomToken("admin-" + syncCode, {
        schoolCode: syncCode,
        role: "admin"
      });
      return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ token }) };
    }

    // ---- Teacher / leadership / bursar: verified against the hashed PIN
    // already stored in teacherAccounts. Falls back to legacy plaintext PINs
    // (from before hashing was added) and migrates them to a hash right here
    // on success, so plaintext never lingers past this login.
    if (actorType === "teacher") {
      const acctRef = dataRef.doc("teacherAccounts");
      const acctSnap = await acctRef.get();
      const accounts = acctSnap.exists ? (acctSnap.data().teacherAccounts || []) : [];
      const teacher = accounts.find(t => t.id === id);
      if (!teacher) {
        return { statusCode: 401, headers: CORS_HEADERS, body: JSON.stringify({ error: "Incorrect Staff ID or PIN." }) };
      }
      let verified = false;
      if (teacher.pinHash && teacher.pinSalt) {
        verified = verifyPbkdf2(secret, teacher.pinSalt, teacher.pinHash);
      } else if (String(teacher.pin) === String(secret)) {
        verified = true;
        const salt = crypto.randomBytes(16).toString("hex");
        const derived = crypto.pbkdf2Sync(String(secret), Buffer.from(salt, "hex"), 210000, 32, "sha256").toString("hex");
        teacher.pinHash = derived;
        teacher.pinSalt = salt;
        delete teacher.pin;
        await acctRef.set({ teacherAccounts: accounts }, { merge: true });
      }
      if (!verified) {
        return { statusCode: 401, headers: CORS_HEADERS, body: JSON.stringify({ error: "Incorrect Staff ID or PIN." }) };
      }
      const token = await admin.auth().createCustomToken("teacher-" + syncCode + "-" + id, {
        schoolCode: syncCode,
        role: teacher.role || "teacher",
        staffId: id
      });
      return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ token }) };
    }

    // ---- Student: verified against the hashed password/RRR stored on
    // their record in core. Falls back to legacy plaintext passwords (from
    // before hashing was added) and migrates them to a hash right here on
    // success, so plaintext never lingers past this login.
    if (actorType === "student") {
      const coreRef = dataRef.doc("core");
      const coreSnap = await coreRef.get();
      const coreData = coreSnap.exists ? coreSnap.data() : {};
      const students = coreData.students || [];
      const student = students.find(s => s.id === id);
      if (!student) {
        return { statusCode: 401, headers: CORS_HEADERS, body: JSON.stringify({ error: "Incorrect Student ID or password." }) };
      }
      let verified = false;
      if (student.passwordHash && student.passwordSalt) {
        verified = verifyPbkdf2(secret, student.passwordSalt, student.passwordHash);
      } else if (String(student.password) === String(secret)) {
        verified = true;
        const salt = crypto.randomBytes(16).toString("hex");
        const derived = crypto.pbkdf2Sync(String(secret), Buffer.from(salt, "hex"), 210000, 32, "sha256").toString("hex");
        student.passwordHash = derived;
        student.passwordSalt = salt;
        delete student.password;
        await coreRef.set({ students }, { merge: true });
      }
      if (!verified) {
        return { statusCode: 401, headers: CORS_HEADERS, body: JSON.stringify({ error: "Incorrect Student ID or password." }) };
      }
      const token = await admin.auth().createCustomToken("student-" + syncCode + "-" + id, {
        schoolCode: syncCode,
        role: "student",
        studentId: id
      });
      return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ token }) };
    }

    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "Unknown login type." }) };
  } catch (err) {
    console.error(err);
    return { statusCode: 500, headers: CORS_HEADERS, body: JSON.stringify({ error: "Server error. Try again." }) };
  }
};
