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

// ===== Brute-force lockout =====
// Tracked per (syncCode + login type + ID) in a single small Firestore doc,
// the same "one document per category" pattern the rest of this app already
// uses. 5 wrong attempts within 15 minutes locks that specific account for
// 15 minutes — a stranger guessing PINs gets stopped fast; a real user who
// mistypes a couple of times is barely affected.
const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000;
const LOCK_MS = 15 * 60 * 1000;

function attemptsRef(syncCode) {
  return db.collection("schools").doc(syncCode).collection("data").doc("loginAttempts");
}

async function checkLockout(syncCode, key) {
  const snap = await attemptsRef(syncCode).get();
  const entry = snap.exists ? (snap.data().attempts || {})[key] : null;
  if (entry && entry.lockedUntil && Date.now() < entry.lockedUntil) {
    return Math.ceil((entry.lockedUntil - Date.now()) / 1000); // seconds remaining
  }
  return 0;
}

async function recordFailedAttempt(syncCode, key) {
  const ref = attemptsRef(syncCode);
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const data = snap.exists ? snap.data() : {};
    const attempts = data.attempts || {};
    const now = Date.now();
    let entry = attempts[key] || { count: 0, windowStart: now, lockedUntil: 0 };

    if (!entry.windowStart || now - entry.windowStart > WINDOW_MS) {
      entry = { count: 0, windowStart: now, lockedUntil: 0 };
    }
    entry.count += 1;
    if (entry.count >= MAX_ATTEMPTS) {
      entry.lockedUntil = now + LOCK_MS;
    }
    attempts[key] = entry;
    tx.set(ref, { attempts }, { merge: true });
  });
}

async function clearAttempts(syncCode, key) {
  try {
    const ref = attemptsRef(syncCode);
    await db.runTransaction(async (tx) => {
      const snap = await tx.get(ref);
      if (!snap.exists) return;
      const data = snap.data();
      const attempts = data.attempts || {};
      if (attempts[key]) {
        delete attempts[key];
        tx.set(ref, { attempts }, { merge: true });
      }
    });
  } catch (e) {
    console.error("clearAttempts failed (non-fatal):", e);
  }
}

function lockedResponse(seconds) {
  const minutes = Math.ceil(seconds / 60);
  return {
    statusCode: 429,
    headers: CORS_HEADERS,
    body: JSON.stringify({ error: `Too many incorrect attempts. Try again in about ${minutes} minute${minutes === 1 ? "" : "s"}.` })
  };
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
    // Works for brand-new Sync Codes too (setting up a new school for the
    // first time), not just reconnecting to an existing one — the code
    // matching itself is the actual credential here, nothing else to check.
    if (actorType === "admin") {
      const lockKey = "admin:" + syncCode;
      const lockedFor = await checkLockout(syncCode, lockKey);
      if (lockedFor > 0) return lockedResponse(lockedFor);

      if (String(secret) !== String(syncCode)) {
        await recordFailedAttempt(syncCode, lockKey);
        return { statusCode: 401, headers: CORS_HEADERS, body: JSON.stringify({ error: "Incorrect Portal/Sync Code." }) };
      }
      await clearAttempts(syncCode, lockKey);
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
      const lockKey = "teacher:" + id;
      const lockedFor = await checkLockout(syncCode, lockKey);
      if (lockedFor > 0) return lockedResponse(lockedFor);

      const acctRef = dataRef.doc("teacherAccounts");
      const acctSnap = await acctRef.get();
      const accounts = acctSnap.exists ? (acctSnap.data().teacherAccounts || []) : [];
      const teacher = accounts.find(t => t.id === id);
      if (!teacher) {
        await recordFailedAttempt(syncCode, lockKey);
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
        await recordFailedAttempt(syncCode, lockKey);
        return { statusCode: 401, headers: CORS_HEADERS, body: JSON.stringify({ error: "Incorrect Staff ID or PIN." }) };
      }
      await clearAttempts(syncCode, lockKey);
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
      const lockKey = "student:" + id;
      const lockedFor = await checkLockout(syncCode, lockKey);
      if (lockedFor > 0) return lockedResponse(lockedFor);

      const coreRef = dataRef.doc("core");
      const coreSnap = await coreRef.get();
      const coreData = coreSnap.exists ? coreSnap.data() : {};
      const students = coreData.students || [];
      const student = students.find(s => s.id === id);
      if (!student) {
        await recordFailedAttempt(syncCode, lockKey);
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
        await recordFailedAttempt(syncCode, lockKey);
        return { statusCode: 401, headers: CORS_HEADERS, body: JSON.stringify({ error: "Incorrect Student ID or password." }) };
      }
      await clearAttempts(syncCode, lockKey);
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
