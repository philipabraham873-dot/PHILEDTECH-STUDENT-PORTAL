// netlify/functions/save-scores.js
//
// Lets a teacher save scores, but only for a class/subject that's actually
// in their own "assignments" list — checked here server-side, since
// Firestore rules can only see "is this a teacher," not "is this teacher
// assigned to THIS class." A tampered request claiming a different class or
// subject is rejected before anything is written.

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

function sameTermSession(x, term, session) {
  return x.term === term && x.session === session;
}

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
  if (!claims.schoolCode || !claims.staffId) {
    return { statusCode: 403, headers: CORS_HEADERS, body: JSON.stringify({ error: "Not authorized." }) };
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "Invalid request body." }) };
  }
  const { className, stream, subject, term, session, entries } = body;
  if (!className || !subject || !term || !session || !Array.isArray(entries) || entries.length === 0) {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "Missing required fields." }) };
  }

  try {
    const dataRef = db.collection("schools").doc(claims.schoolCode).collection("data");

    // ---- Authorization: is this teacher actually assigned to this exact
    // class/stream/subject? Leadership (principal/VP) can save for any class.
    const acctSnap = await dataRef.doc("teacherAccounts").get();
    const accounts = acctSnap.exists ? (acctSnap.data().teacherAccounts || []) : [];
    const teacher = accounts.find(t => t.id === claims.staffId);
    if (!teacher) {
      return { statusCode: 403, headers: CORS_HEADERS, body: JSON.stringify({ error: "Staff record not found." }) };
    }
    const isLeadership = teacher.role === "principal" || teacher.role === "vice_principal";
    const isAssigned = (teacher.assignments || []).some(a =>
      a.className === className && (a.stream || "") === (stream || "") && a.subject === subject
    );
    if (!isLeadership && !isAssigned) {
      return { statusCode: 403, headers: CORS_HEADERS, body: JSON.stringify({ error: "You're not assigned to this class/subject." }) };
    }

    // ---- Extra safety: every student in this submission must actually
    // belong to the class being claimed.
    const coreRef = dataRef.doc("core");
    const coreSnap = await coreRef.get();
    const coreData = coreSnap.exists ? coreSnap.data() : {};
    const allStudents = coreData.students || [];
    const rosterIds = new Set(
      allStudents
        .filter(s => s.className === className && (!stream || s.stream === stream))
        .map(s => s.id)
    );
    const cleanEntries = entries.filter(e => rosterIds.has(e.studentId) && e.subject === subject);
    if (cleanEntries.length === 0) {
      return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "No valid student scores in this submission." }) };
    }

    let freshScores = coreData.scores || [];
    cleanEntries.forEach(entry => {
      const cleanEntry = {
        studentId: entry.studentId,
        subject,
        ca: Array.isArray(entry.ca) ? entry.ca.map(Number) : [],
        exam: Number(entry.exam) || 0,
        total: Number(entry.total) || 0,
        term,
        session
      };
      const idx = freshScores.findIndex(x => x.studentId === cleanEntry.studentId && x.subject === subject && sameTermSession(x, term, session));
      if (idx !== -1) {
        const merged = Object.assign({}, freshScores[idx], cleanEntry);
        delete merged.ca1; delete merged.ca2; delete merged.ca3;
        freshScores[idx] = merged;
      } else {
        freshScores.push(cleanEntry);
      }
    });

    await coreRef.set({
      scores: freshScores,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedBy: "teacher_" + claims.staffId
    }, { merge: true });

    return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ success: true, saved: cleanEntries.length, scores: freshScores }) };
  } catch (err) {
    console.error(err);
    return { statusCode: 500, headers: CORS_HEADERS, body: JSON.stringify({ error: "Server error. Try again." }) };
  }
};
