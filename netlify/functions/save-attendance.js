// netlify/functions/save-attendance.js
//
// Lets a teacher save attendance, but only for the class they're actually
// the Class Teacher of — checked here server-side, since Firestore rules
// can only see "is this a teacher," not "is this THEIR class." A tampered
// request claiming a different class is rejected before anything is written.

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
  if (!claims.schoolCode || !claims.staffId) {
    return { statusCode: 403, headers: CORS_HEADERS, body: JSON.stringify({ error: "Not authorized." }) };
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "Invalid request body." }) };
  }
  const { className, stream, date, marks, term, session } = body;
  if (!className || !date || !marks || typeof marks !== "object" || !term || !session) {
    return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "Missing required fields." }) };
  }

  try {
    const dataRef = db.collection("schools").doc(claims.schoolCode).collection("data");

    // ---- Authorization: is this teacher actually the Class Teacher of this
    // exact class/stream? Leadership (principal/VP) can save for any class.
    const acctSnap = await dataRef.doc("teacherAccounts").get();
    const accounts = acctSnap.exists ? (acctSnap.data().teacherAccounts || []) : [];
    const teacher = accounts.find(t => t.id === claims.staffId);
    if (!teacher) {
      return { statusCode: 403, headers: CORS_HEADERS, body: JSON.stringify({ error: "Staff record not found." }) };
    }
    const isLeadership = teacher.role === "principal" || teacher.role === "vice_principal";
    const isClassTeacher = teacher.classTeacherOf === className;
    if (!isLeadership && !isClassTeacher) {
      return { statusCode: 403, headers: CORS_HEADERS, body: JSON.stringify({ error: "You're not the Class Teacher of this class." }) };
    }

    // ---- Extra safety: only accept marks for students who actually belong
    // to this class.
    const coreSnap = await dataRef.doc("core").get();
    const coreData = coreSnap.exists ? coreSnap.data() : {};
    const allStudents = coreData.students || [];
    const rosterIds = new Set(
      allStudents
        .filter(s => s.className === className && (!stream || s.stream === stream))
        .map(s => s.id)
    );
    const cleanMarks = {};
    Object.keys(marks).forEach(studentId => {
      if (rosterIds.has(studentId) && ["Present", "Absent", "Late"].includes(marks[studentId])) {
        cleanMarks[studentId] = marks[studentId];
      }
    });
    if (Object.keys(cleanMarks).length === 0) {
      return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "No valid attendance marks in this submission." }) };
    }

    const attRef = dataRef.doc("attendance");
    const attSnap = await attRef.get();
    const attData = attSnap.exists ? attSnap.data() : {};
    let freshAttendance = attData.attendance || {};

    const existingRec = freshAttendance[date];
    const existingMarks = (existingRec && existingRec.marks) ? existingRec.marks : (existingRec || {});
    const mergedMarks = Object.assign({}, existingMarks, cleanMarks);

    freshAttendance[date] = {
      term: (existingRec && existingRec.term) || term,
      session: (existingRec && existingRec.session) || session,
      marks: mergedMarks
    };

    await attRef.set({
      attendance: freshAttendance,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedBy: "teacher_" + claims.staffId
    }, { merge: true });

    return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ success: true, saved: Object.keys(cleanMarks).length, attendance: freshAttendance }) };
  } catch (err) {
    console.error(err);
    return { statusCode: 500, headers: CORS_HEADERS, body: JSON.stringify({ error: "Server error. Try again." }) };
  }
};
