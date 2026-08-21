const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();
const { CURRICULUM, tagsForTopic } = require('./topics');
const { GRADE_STYLE_GUIDE } = require('./curriculum_style');

// --- Fail fast on missing/unsafe configuration ---
// These used to fall back to defaults, which meant a typo'd or forgotten environment variable
// on Render produced a site that *looked* like it was working while being wide open: the JWT
// fallback secret is published in this source file, so anyone who read it could mint a token
// for any account. Crashing at boot is much safer than serving a compromised app — Render
// shows the failed deploy and keeps the previous working version running.
const REQUIRED_ENV = ['JWT_SECRET', 'DATABASE_URL'];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length) {
  console.error(`FATAL: missing required environment variable(s): ${missingEnv.join(', ')}.`);
  console.error('Set them in the Render dashboard (Environment tab) and redeploy.');
  process.exit(1);
}
if (process.env.JWT_SECRET.length < 32) {
  console.error('FATAL: JWT_SECRET is too short — use at least 32 random characters.');
  console.error('Generate one with:  node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))"');
  process.exit(1);
}
if (!process.env.ADMIN_EMAIL) {
  console.warn('WARNING: ADMIN_EMAIL is not set — no account will be promoted to teacher/admin automatically.');
}

// Builds the "match real Lebanese exams" grounding block injected into Question Bank / Exam
// generation prompts for a given grade — see curriculum_style.js for where this came from and
// why type mix varies by grade (Grade 12 real exams never use tf/mcq, for example).
function styleGroundingFor(grade){
  const g = GRADE_STYLE_GUIDE[grade];
  if (!g) return '';
  return `Real Lebanese exam grounding for ${g.label} (match this, not a generic international textbook style):
- Actual topic scope/order at this grade: ${g.scope}
- Question types that actually appear in real ${g.label} physics exams: ${g.types.join(', ')}. Do not use any other type for this grade.
- Real format/phrasing conventions: ${g.conventions}
- Example of the real style (for calibration only — write NEW questions, never reuse this example): ${g.example}`;
}

const app = express();

// Render sits behind a reverse proxy — without this, req.ip returns the proxy's
// address for every request, which would make IP-based rate limiting below
// either block everyone at once or nobody at all.
app.set('trust proxy', 1);

// --- CORS: only allow the actual frontend(s) to call this API ---
// ALLOWED_ORIGINS can be set on Render as a comma-separated list to add more
// origins (e.g. a custom domain) without touching code. Defaults cover the
// live Netlify site plus localhost for local development/testing.
const DEFAULT_ALLOWED_ORIGINS = [
  'https://singular-mousse-2c988e.netlify.app',
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:5500',
  'http://127.0.0.1:5500'
];
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
  : DEFAULT_ALLOWED_ORIGINS;

app.use(cors({
  origin(origin, callback) {
    // Allow requests with no Origin header at all (server-to-server calls, curl, mobile
    // webviews), and the literal string "null" — browsers send that for local file:// pages
    // (e.g. double-clicking an .html file straight from disk, which is how test/diagnostic
    // pages get opened while debugging) and some sandboxed contexts. Neither of those is a
    // browser-enforced cross-origin request in the way a real website's Origin header is, so
    // there's no CORS protection being weakened by allowing them.
    if (!origin || origin === 'null' || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
}));
// Body size limits, scoped by route.
//
// Only two endpoints legitimately receive photos: Practice Exam grading (one photo per "big
// problem", up to 5 in a single submission) and the Solver (one photo of a problem). Those get
// a large ceiling. Everything else — login, register, bookings, admin actions — is small JSON,
// and applying a 25mb limit globally meant an attacker could tie up memory by POSTing 25mb to
// the login endpoint. Route-specific parsers run before the small global one below.
const largeJson = express.json({ limit: '25mb' });
app.use('/api/grade-exam', largeJson);
app.use('/api/solve', largeJson);
app.use(express.json({ limit: '200kb' }));

// --- Simple in-memory rate limiting (no external dependency needed) ---
// Keyed by IP address. Each limiter instance keeps its own bucket map and
// sweeps expired entries periodically so memory doesn't grow unbounded.
// This is process-local (fine for a single free-tier Render instance) —
// if the app is ever scaled to multiple instances, swap this for a
// shared store (e.g. Redis) instead.
function makeRateLimiter({ windowMs, max, message, keyBy }) {
  const hits = new Map(); // key -> { count, resetAt }
  const sweeper = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of hits) {
      if (now > entry.resetAt) hits.delete(key);
    }
  }, windowMs);
  sweeper.unref();

  return (req, res, next) => {
    const key = (keyBy && keyBy(req)) || req.ip || 'unknown';
    const now = Date.now();
    let entry = hits.get(key);
    if (!entry || now > entry.resetAt) {
      entry = { count: 0, resetAt: now + windowMs };
      hits.set(key, entry);
    }
    entry.count++;
    if (entry.count > max) {
      res.set('Retry-After', String(Math.ceil((entry.resetAt - now) / 1000)));
      return res.status(429).json({ error: message || 'Too many requests — please slow down and try again in a bit.' });
    }
    next();
  };
}

// Generous general safety net across the whole API.
const generalLimiter = makeRateLimiter({
  windowMs: 60 * 1000, max: 120,
  message: 'Too many requests from this device — please slow down.'
});
app.use('/api/', generalLimiter);

// Tighter limit specifically on endpoints that call Groq/Gemini — these run on
// free-tier API quotas shared across every visitor, so a handful of accidental
// or abusive rapid-fire requests from one device can exhaust the daily quota
// for everyone else using the site.
//
// Keyed by ACCOUNT, not IP. A whole class sitting in one room shares a single public IP through
// the school's router, so an IP-keyed limit of 8/minute would be spent by the first two or
// three students and lock out everyone else — the exact situation this site is built for.
// requireAuth runs before this in the aiGuard chain, so req.user is always available here;
// the IP fallback only applies if that ever changes.
const aiLimiter = makeRateLimiter({
  windowMs: 60 * 1000, max: 12,
  message: 'You are sending requests very quickly — please wait a minute before trying again.',
  keyBy: (req) => (req.user && req.user.userId ? 'u' + req.user.userId : null),
});

// Slow down brute-force login/registration attempts.
const authLimiter = makeRateLimiter({
  windowMs: 15 * 60 * 1000, max: 10,
  message: 'Too many attempts — please wait a few minutes before trying again.'
});

// --- Per-student daily AI budget ---
// The per-IP limiter above stops rapid-fire bursts, but not a single account working steadily
// through the day, and it can be sidestepped by changing network. Groq/Gemini run on shared
// free-tier quotas, so one heavy user can exhaust the day's allowance for the whole class.
// This caps how many AI calls one *account* can make per day. The limit is deliberately
// generous — a student doing a full exam plus a long solver session lands nowhere near it —
// so in practice it only ever trips on automated abuse.
//
// Counted in the DATABASE, not in memory. Two reasons that matters:
//   1. Render restarts free instances often. An in-memory counter reset the limit every time,
//      so the cap was largely decorative.
//   2. It doubles as the only record of what the AI actually costs. Every call the site makes
//      draws on a shared free quota; without a count there is no way to answer "can this
//      survive a whole class?" until the day it stops working for everyone at once.
// One tiny indexed upsert per AI call, immediately before a request that takes several
// seconds — the added latency is not measurable.
const AI_DAILY_LIMIT = Number(process.env.AI_DAILY_LIMIT || 120);

async function aiQuota(req, res, next){
  if (!req.user) return next(); // requireAuth runs first and will already have rejected this
  if (!pool) return next();     // never block practice just because counting isn't available
  try {
    // LEAST(..., limit + 1) stops the counter climbing once the cap is passed. Without it, a
    // student mashing a blocked button kept incrementing on every rejected request, and those
    // phantom calls went straight into the admin usage panel — the one screen whose entire job
    // is to give a trustworthy number for quota planning.
    const result = await pool.query(
      `INSERT INTO ai_usage (user_id, day, calls) VALUES ($1, CURRENT_DATE, 1)
       ON CONFLICT (user_id, day)
       DO UPDATE SET calls = LEAST(ai_usage.calls + 1, $2::int + 1)
       RETURNING calls`,
      [req.user.userId, AI_DAILY_LIMIT]
    );
    const used = result.rows[0] ? result.rows[0].calls : 0;
    if (used > AI_DAILY_LIMIT) {
      console.warn(`AI daily limit reached by user ${req.user.userId} (${req.user.email}) — ${used} calls today.`);
      return res.status(429).json({
        error: "You've reached today's limit for AI help. It resets tomorrow — if you need more, message your teacher."
      });
    }
    next();
  } catch (err) {
    // Counting is bookkeeping, not a gate. If it fails, let the student work.
    console.error('AI usage counting failed (allowing the request):', err.message);
    next();
  }
}

// Convenience: the full middleware chain every AI endpoint should use.
const aiGuard = [requireAuth, aiLimiter, aiQuota];

// --- Database setup ---
// DATABASE_URL is provided automatically by Render when you attach a Postgres database.
const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      // Render's managed Postgres allows a limited number of concurrent connections, and it
      // closes idle ones from its side. Keeping the pool small and recycling idle clients
      // ourselves avoids hitting that ceiling and reduces how often we hold a dead socket.
      max: 5,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    })
  : null;

// Without this handler, when Postgres drops an idle connection the `pg` pool emits an 'error'
// event with no listener — and an unhandled 'error' event takes down the entire Node process.
// This was the most likely cause of unexplained restarts. Logging it is enough: the pool
// discards the bad client and opens a fresh one on the next query.
if (pool) {
  pool.on('error', (err) => {
    console.error('Idle Postgres client error (connection will be recycled):', err.message);
  });
}

// Runs one migration statement, isolating its failure from every other statement.
//
// These are all `IF NOT EXISTS`-style, additive and independent, so if one cannot be applied
// the right response is to log it and carry on — not to abandon the remaining migrations (and
// certainly not to take the server down). `migrate` is used for the additive/optional
// statements; the handful of statements that everything else depends on are still awaited
// directly so a genuinely broken database is obvious in the logs.
async function migrate(label, sql, params){
  try {
    await pool.query(sql, params);
    return true;
  } catch (err) {
    console.error(`Migration step failed (continuing): ${label} — ${err.message}`);
    return false;
  }
}

async function setupDatabase(){
  if (!pool) {
    console.warn('No DATABASE_URL set — accounts and history will not work until a database is connected.');
    return;
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  // Additive migration: every account is locked to one grade at signup (a student picks
  // their real grade once and can't switch freely — see the register endpoint below).
  // Nullable so accounts created before this existed (and the admin account) don't break.
  await migrate('users.grade', `ALTER TABLE users ADD COLUMN IF NOT EXISTS grade TEXT;`);
  // Additive migration: lets the teacher mark an account as a demo/test account (e.g. to
  // show the site to someone) without it ever showing up in class analytics, the weekly
  // digest, the teacher dashboard, or the "what to teach next" recommendation — every one of
  // those aggregate queries excludes users flagged here. Defaults to false so every existing
  // real student is unaffected.
  await migrate('users.is_demo', `ALTER TABLE users ADD COLUMN IF NOT EXISTS is_demo BOOLEAN DEFAULT false;`);
  // Additive migration: real role stored on the account instead of inferring "is this the
  // teacher?" from a matching email address. The old email-based check was fragile — email is
  // never verified at signup, so if ADMIN_EMAIL ever pointed at an address with no account
  // yet, a student could register it and inherit admin access. It also could not be revoked,
  // because the email was baked into a 30-day token.
  await migrate('users.role', `ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'student';`);
  // Promote the configured admin email once, if that account exists. Safe to re-run.
  if (process.env.ADMIN_EMAIL) {
    const promoted = await pool.query(
      `UPDATE users SET role = 'teacher' WHERE LOWER(email) = LOWER($1) AND role <> 'teacher' RETURNING id`,
      [process.env.ADMIN_EMAIL.trim()]
    );
    if (promoted.rows.length) console.log(`Promoted ${process.env.ADMIN_EMAIL} to role=teacher.`);
  }
  // Additive migration: optional parent contact, used for the monthly progress report.
  await migrate('users.parent_email', `ALTER TABLE users ADD COLUMN IF NOT EXISTS parent_email TEXT;`);
  // Additive migration: lets us invalidate tokens issued before a password change. Without it,
  // resetting a student's password did not actually cut off anyone already holding their old
  // 30-day token. Defaults to NULL, which means "no reset has happened" — existing tokens for
  // accounts that never reset stay valid, so nobody is logged out by this upgrade.
  await migrate('users.password_changed_at', `ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP;`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS exam_results (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      grade TEXT,
      score INTEGER,
      total INTEGER,
      questions JSONB,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS study_plans (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      grade TEXT,
      exam_date TEXT,
      plan TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS solver_history (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      problem TEXT,
      solution TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // --- Unified data model: Student -> Topic -> Skill -> Attempt -> Result -> Mistake -> Mastery ---
  // See the design doc ("Unified Data Model & Teacher Dashboard Design") for the full rationale.
  // Mastery is intentionally NOT a stored table — it's computed on read from `attempts`.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS topics (
      id SERIAL PRIMARY KEY,
      grade TEXT NOT NULL,
      title TEXT NOT NULL,
      order_index INTEGER,
      UNIQUE (grade, title)
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS skills (
      id SERIAL PRIMARY KEY,
      topic_id INTEGER REFERENCES topics(id) ON DELETE CASCADE,
      title TEXT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS attempts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      source TEXT NOT NULL,
      topic_id INTEGER REFERENCES topics(id),
      skill_id INTEGER REFERENCES skills(id),
      difficulty TEXT,
      question_text TEXT,
      student_answer TEXT,
      correct BOOLEAN,
      mistake_tag TEXT,
      time_spent_seconds INTEGER,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await migrate('idx_attempts_user_topic', `CREATE INDEX IF NOT EXISTS idx_attempts_user_topic ON attempts (user_id, topic_id);`);
  await migrate('idx_attempts_topic', `CREATE INDEX IF NOT EXISTS idx_attempts_topic ON attempts (topic_id);`);
  // Used by the weekly digest and every "recent activity" window. This index used to be
  // created at module load time, outside this function — on a fresh database that ran before
  // the `attempts` table existed, and the failure was swallowed by an empty .catch().
  await migrate('idx_attempts_created_at', `CREATE INDEX IF NOT EXISTS idx_attempts_created_at ON attempts (created_at);`);
  // Supports the per-student mistake lookup that now feeds question/exam generation.
  await migrate('idx_attempts_user_correct', `CREATE INDEX IF NOT EXISTS idx_attempts_user_correct ON attempts (user_id, correct);`);

  // Every /api/my/* page and the per-user counts on the admin users list filter by user_id.
  // Without these, each one is a sequential scan over the whole table.
  await migrate('idx_exam_results_user', `CREATE INDEX IF NOT EXISTS idx_exam_results_user ON exam_results (user_id);`);
  await migrate('idx_study_plans_user', `CREATE INDEX IF NOT EXISTS idx_study_plans_user ON study_plans (user_id);`);
  await migrate('idx_solver_history_user', `CREATE INDEX IF NOT EXISTS idx_solver_history_user ON solver_history (user_id);`);

  // Teacher Intervention Log — lets a teacher note "I taught/reviewed X" so the dashboard
  // can later show before/after mastery around that moment. topic_id is nullable: an
  // intervention can be tied to one specific topic (shows on that topic's trend) or be a
  // grade-wide note (e.g. "reviewed exam technique with the whole class").
  await pool.query(`
    CREATE TABLE IF NOT EXISTS interventions (
      id SERIAL PRIMARY KEY,
      admin_user_id INTEGER REFERENCES users(id),
      grade TEXT NOT NULL,
      topic_id INTEGER REFERENCES topics(id) ON DELETE SET NULL,
      note TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await migrate('idx_interventions_grade', `CREATE INDEX IF NOT EXISTS idx_interventions_grade ON interventions (grade);`);
  await migrate('idx_interventions_topic', `CREATE INDEX IF NOT EXISTS idx_interventions_topic ON interventions (topic_id);`);

  // Booking — a student requests a session (grade/topic/private-or-group/duration/preferred
  // time), the teacher confirms or cancels it from the admin side. status starts 'pending'
  // and moves to 'confirmed' or 'cancelled'; preferred_time is stored as free text (the
  // student's own wording, e.g. "Tuesday evening" or a picked date/time) rather than a
  // strict timestamp, since this is a request to be confirmed by a human, not an instant
  // auto-scheduled slot.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS bookings (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      grade TEXT,
      topic TEXT,
      session_type TEXT,
      duration_minutes INTEGER,
      preferred_time TEXT,
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await migrate('idx_bookings_user', `CREATE INDEX IF NOT EXISTS idx_bookings_user ON bookings (user_id);`);
  await migrate('idx_bookings_status', `CREATE INDEX IF NOT EXISTS idx_bookings_status ON bookings (status);`);

  // --- Spaced review queue ---
  // Getting a question wrong once and never seeing it again is the biggest thing the app was
  // missing pedagogically: the forgetting curve means a misconception corrected today is
  // usually gone within a week unless it comes back. Every wrong answer now schedules itself
  // for review, and each successful review pushes it further out (a Leitner-style box system):
  //   box 0 -> due in 1 day, box 1 -> 3 days, box 2 -> 7 days, box 3 -> 21 days, box 4 -> done.
  // Getting it wrong again on review knocks it back to box 0, so it returns tomorrow.
  //
  // One row per (student, topic, mistake_tag) rather than per individual question — the thing
  // worth re-testing is the misconception, not the exact wording, and new questions targeting
  // it are generated fresh at review time.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS review_queue (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      topic_id INTEGER REFERENCES topics(id) ON DELETE CASCADE,
      mistake_tag TEXT,
      box INTEGER NOT NULL DEFAULT 0,
      due_at TIMESTAMP NOT NULL DEFAULT NOW(),
      times_reviewed INTEGER NOT NULL DEFAULT 0,
      times_correct INTEGER NOT NULL DEFAULT 0,
      retired BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW(),
      UNIQUE (user_id, topic_id, mistake_tag)
    );
  `);
  await migrate('idx_review_due', `CREATE INDEX IF NOT EXISTS idx_review_due ON review_queue (user_id, retired, due_at);`);

  // --- Homework assignments ---
  // The teacher sets work for a whole grade; each student gets their OWN generated question set
  // for it. Two reasons that matters: copying a friend's answers is pointless when the numbers
  // and scenarios differ, and every submission still flows through the normal grading path, so
  // it feeds mastery, the mistake tags and the spaced-review queue like any other practice.
  //
  // Assignments target a grade rather than a hand-picked student list — that matches how this
  // is actually used (a class is a grade here) and keeps the teacher's flow to a few clicks.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS assignments (
      id SERIAL PRIMARY KEY,
      teacher_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      grade TEXT NOT NULL,
      topic_id INTEGER REFERENCES topics(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      instructions TEXT,
      question_count INTEGER NOT NULL DEFAULT 6,
      difficulty TEXT NOT NULL DEFAULT 'medium',
      due_at TIMESTAMPTZ,
      archived BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await migrate('idx_assignments_grade', `CREATE INDEX IF NOT EXISTS idx_assignments_grade ON assignments (grade, archived, due_at);`);

  // One row per student per assignment. Created when the student opens it (status
  // 'in_progress', questions stored so a refresh doesn't reshuffle their paper) and completed
  // on submit. UNIQUE stops a student generating themselves an easier second set.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS assignment_submissions (
      id SERIAL PRIMARY KEY,
      assignment_id INTEGER NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'in_progress',
      questions JSONB,
      score INTEGER,
      total INTEGER,
      started_at TIMESTAMPTZ DEFAULT NOW(),
      submitted_at TIMESTAMPTZ,
      UNIQUE (assignment_id, user_id)
    );
  `);
  await migrate('idx_submissions_assignment', `CREATE INDEX IF NOT EXISTS idx_submissions_assignment ON assignment_submissions (assignment_id);`);
  // Ties an attempt to the exact homework it came from. Without it, the teacher's "what did the
  // class get wrong" panel had to guess by (topic + created after the assignment), which meant
  // a second assignment on the same topic later in the year got folded into the first one's
  // breakdown — permanently over-reporting it.
  await migrate('attempts.assignment_id', `ALTER TABLE attempts ADD COLUMN IF NOT EXISTS assignment_id INTEGER REFERENCES assignments(id) ON DELETE SET NULL;`);
  await migrate('idx_attempts_assignment', `CREATE INDEX IF NOT EXISTS idx_attempts_assignment ON attempts (assignment_id);`);
  await migrate('idx_submissions_user', `CREATE INDEX IF NOT EXISTS idx_submissions_user ON assignment_submissions (user_id, status);`);

  // --- Method-first answering ---
  // Did the student reach for the RIGHT physics, regardless of whether the final number came
  // out right? NULL means this question never asked for a method.
  //
  // This is the most useful column in the table for teaching. "Used the wrong law" and "used
  // the right law but slipped in the arithmetic" produce an identical score, need completely
  // different lessons, and until now were indistinguishable in the data.
  // One row per student per day. Backs the daily cap AND answers "what is this costing me?"
  // before the free quota runs out mid-lesson.
  // Uses migrate() like its neighbours: a bare pool.query here would reject the whole
  // setupDatabase() promise on failure, skipping every migration after it — including the
  // attempts columns below, after which every attempt INSERT would fail silently into a
  // .catch while students carried on seeing normal scores.
  await migrate('ai_usage table', `
    CREATE TABLE IF NOT EXISTS ai_usage (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      day DATE NOT NULL,
      calls INTEGER NOT NULL DEFAULT 0,
      UNIQUE (user_id, day)
    );
  `);
  await migrate('idx_ai_usage_day', `CREATE INDEX IF NOT EXISTS idx_ai_usage_day ON ai_usage (day);`);

  await migrate('attempts.method_correct', `ALTER TABLE attempts ADD COLUMN IF NOT EXISTS method_correct BOOLEAN;`);
  await migrate('attempts.stated_method', `ALTER TABLE attempts ADD COLUMN IF NOT EXISTS stated_method TEXT;`);
  await migrate('idx_attempts_method', `CREATE INDEX IF NOT EXISTS idx_attempts_method ON attempts (user_id, method_correct);`);

  // Seed `topics` from the CURRICULUM in topics.js — safe to re-run, ON CONFLICT skips
  // anything already there. Keeps the canonical topic list in one place server-side.
  for (const grade of Object.keys(CURRICULUM)) {
    const titles = CURRICULUM[grade];
    for (let i = 0; i < titles.length; i++) {
      await pool.query(
        'INSERT INTO topics (grade, title, order_index) VALUES ($1, $2, $3) ON CONFLICT (grade, title) DO NOTHING',
        [grade, titles[i], i]
      );
    }
  }

  console.log('Database tables ready.');
}

// Looks up a topic's id by grade + exact title. Returns null if the AI returned a topic
// string that doesn't match the seeded curriculum (logged so it can be reconciled by hand —
// either the taxonomy needs updating or the AI drifted from the given lesson list).
async function resolveTopicId(grade, title){
  if (!pool || !title) return null;
  try {
    const result = await pool.query('SELECT id FROM topics WHERE grade = $1 AND title = $2', [grade, title]);
    if (result.rows.length) return result.rows[0].id;
    console.warn(`No matching topic for grade="${grade}" title="${title}" — attempt will be saved with topic_id = null.`);
    return null;
  } catch (err) {
    console.error('Topic lookup failed:', err);
    return null;
  }
}
// Startup migrations run in the background and must NEVER take the site down.
//
// An earlier version of this exited the process when setupDatabase() rejected. That was the
// wrong trade: a single failing ALTER — an index that couldn't be built, a column added by a
// newer deploy, a transient connection drop during startup — killed the whole server, so
// students couldn't even log in over a migration that had nothing to do with logging in.
// Logging loudly and continuing is far safer: the routes that depend on a missing column fail
// individually and visibly, while everything else keeps working.
setupDatabase().catch(err => {
  console.error('WARNING: database setup did not finish cleanly. The server is still running,');
  console.error('but any feature relying on a migration that failed may not work:', err);
});

// --- Auth helpers ---
// Validated at boot above, so no insecure fallback is needed here.
const JWT_SECRET = process.env.JWT_SECRET;

function signToken(user){
  return jwt.sign({ userId: user.id, name: user.name, email: user.email, grade: user.grade || null }, JWT_SECRET, { expiresIn: '30d' });
}

// Attaches req.user if a valid token is present; does NOT block the request if absent (optional auth)
function optionalAuth(req, res, next){
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) {
    try {
      req.user = jwt.verify(header.slice(7), JWT_SECRET);
    } catch (e) { /* invalid/expired token — treat as logged out */ }
  }
  next();
}
app.use(optionalAuth);

// Blocks the request unless a valid token is present, AND confirms the account still exists
// and the token was issued after the last password reset. Loading the account row here means
// requireAdmin (below) can reuse it instead of running a second query on admin routes.
async function requireAuth(req, res, next){
  if (!req.user) return res.status(401).json({ error: 'Please log in first.' });
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  try {
    // The "token is older than the last password reset" comparison is done in SQL, against the
    // token's own `iat` claim. Doing it in JavaScript would compare a naive TIMESTAMP (which
    // node-pg parses in the server's LOCAL timezone) against a UTC epoch — on a server set to
    // anything other than UTC that silently shifts the cutoff by the offset, either leaving old
    // tokens valid after a reset or rejecting freshly-issued ones and locking students out.
    const result = await pool.query(
      `SELECT id, name, email, grade, role, parent_email,
              (password_changed_at IS NOT NULL AND $2::bigint IS NOT NULL
               AND password_changed_at > to_timestamp($2::bigint)) AS token_is_stale
         FROM users WHERE id = $1`,
      [req.user.userId, req.user.iat || null]
    );
    const account = result.rows[0];
    // The account was deleted while a valid token was still in circulation.
    if (!account) return res.status(401).json({ error: 'This account no longer exists. Please log in again.' });
    // The password was reset after this token was issued — force a fresh login.
    if (account.token_is_stale) {
      return res.status(401).json({ error: 'Your password was changed. Please log in again.' });
    }

    // Lazy admin promotion. The boot-time promotion in setupDatabase() only runs once, and only
    // if ADMIN_EMAIL was already set AND the account already existed at that moment. Without
    // this fallback, setting ADMIN_EMAIL after first deploy — or creating the teacher account
    // after the server started — would leave NOBODY with role='teacher', permanently locking
    // the admin and teacher dashboards behind a 403 until the next redeploy.
    const adminEmail = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
    if (adminEmail && account.role !== 'teacher' && (account.email || '').toLowerCase() === adminEmail) {
      await pool.query(`UPDATE users SET role = 'teacher' WHERE id = $1`, [account.id]);
      account.role = 'teacher';
      console.log(`Promoted ${account.email} to role=teacher (lazy promotion).`);
    }

    req.account = account;
    // Keep the token's grade in sync with the database, so an admin grade correction takes
    // effect immediately instead of after the student's 30-day token expires.
    req.user.grade = account.grade;
    next();
  } catch (err) {
    console.error('Auth check failed:', err);
    res.status(500).json({ error: 'Could not verify your session.' });
  }
}

// Basic shape check only — deliberately permissive, since the goal is to catch typos like a
// missing "@", not to police which addresses are valid.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

app.post('/api/register', authLimiter, async (req, res) => {
  const { name, email, password, grade, parentEmail } = req.body;
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, and password are all required.' });
  if (typeof name !== 'string' || name.trim().length < 2 || name.length > 80) {
    return res.status(400).json({ error: 'Please enter your real name.' });
  }
  if (typeof email !== 'string' || !EMAIL_RE.test(email.trim())) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }
  if (password.length > 200) return res.status(400).json({ error: 'That password is too long.' });
  if (parentEmail && !EMAIL_RE.test(String(parentEmail).trim())) {
    return res.status(400).json({ error: "Please enter a valid parent email, or leave it empty." });
  }
  // Every student account is locked to one grade for good, chosen once at signup — see the
  // design note above the `grade` column migration. Validate against the real curriculum
  // grade keys so a typo or tampered request can't create an account with a bogus grade.
  if (!grade || !CURRICULUM[grade]) {
    return res.status(400).json({ error: 'Please choose your grade — it cannot be changed later, so pick carefully.' });
  }

  try {
    // No check-then-insert: two rapid submissions could both pass the check and the second
    // would fail with a raw duplicate-key 500. Let the UNIQUE constraint decide, and translate
    // its error code into the correct 409.
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash, grade, parent_email) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, grade',
      [name.trim(), email.trim().toLowerCase(), hash, grade, parentEmail ? String(parentEmail).trim().toLowerCase() : null]
    );
    const user = result.rows[0];
    res.json({ token: signToken(user), name: user.name, email: user.email, grade: user.grade });
  } catch (err) {
    if (err && err.code === '23505') {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }
    console.error('Register error:', err);
    res.status(500).json({ error: 'Something went wrong creating the account.' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  // Type checks, not just truthiness: a non-string email reached email.toLowerCase() and threw,
  // returning a confusing 500 instead of a plain 400.
  if (typeof email !== 'string' || typeof password !== 'string' || !email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Incorrect email or password.' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Incorrect email or password.' });

    res.json({ token: signToken(user), name: user.name, email: user.email, grade: user.grade });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Something went wrong logging in.' });
  }
});

app.get('/api/my/history', requireAuth, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  try {
    const exams = await pool.query(
      'SELECT id, grade, score, total, created_at FROM exam_results WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20',
      [req.user.userId]
    );
    const plans = await pool.query(
      'SELECT id, grade, exam_date, created_at FROM study_plans WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20',
      [req.user.userId]
    );
    const solves = await pool.query(
      'SELECT id, problem, created_at FROM solver_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20',
      [req.user.userId]
    );
    res.json({ exams: exams.rows, plans: plans.rows, solves: solves.rows });
  } catch (err) {
    console.error('History fetch error:', err);
    res.status(500).json({ error: 'Could not load your history.' });
  }
});

// Review one past exam in full.
//
// Every graded exam already stored its complete question list, the student's per-part results
// and the AI's feedback in exam_results.questions (JSONB) — but nothing ever read it back, so
// a student could see "12/20" in their history and had no way to find out which parts they got
// wrong or why. Reviewing a past mistake is one of the highest-value things a student can do,
// and the data was sitting there the whole time.
//
// Scoped to the requesting user: the WHERE clause matches on user_id as well as id, so a
// student cannot read another student's exam by guessing an id.
app.get('/api/my/exams/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  const examId = Number(req.params.id);
  if (!Number.isInteger(examId) || examId <= 0) return res.status(400).json({ error: 'Invalid exam id.' });
  try {
    const result = await pool.query(
      `SELECT id, grade, score, total, questions, created_at
         FROM exam_results
        WHERE id = $1 AND user_id = $2`,
      [examId, req.user.userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Exam not found.' });
    const exam = result.rows[0];
    const scorePct = exam.total ? Math.round((exam.score / exam.total) * 1000) / 10 : null;

    // Exams graded before per-part results were stored have questions but no correct/feedback
    // fields. Flag that explicitly so the review screen can say "detailed review isn't
    // available for this one" instead of rendering a page of blank, apparently-ungraded parts.
    const problems = Array.isArray(exam.questions) ? exam.questions : [];
    const hasPartResults = problems.some(p =>
      p && Array.isArray(p.parts) && p.parts.some(part => part && typeof part.correct === 'boolean')
    );

    res.json({ exam: { ...exam, scorePct, hasPartResults } });
  } catch (err) {
    console.error('Exam review fetch error:', err);
    res.status(500).json({ error: 'Could not load this exam.' });
  }
});

// --- Homework assignments (student side) ---

// GET /api/my/assignments — what this student has been set, newest first.
// Scoped to their own grade, so a student can only ever see work meant for them.
app.get('/api/my/assignments', requireAuth, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  const grade = req.account && req.account.grade;
  if (!grade) return res.json({ assignments: [], pendingCount: 0 });

  try {
    const result = await pool.query(
      `SELECT a.id, a.title, a.instructions, a.question_count, a.difficulty, a.due_at, a.created_at,
              t.title AS topic,
              COALESCE(s.status, 'not_started') AS status,
              s.score, s.total, s.submitted_at
         FROM assignments a
         JOIN topics t ON t.id = a.topic_id
         LEFT JOIN assignment_submissions s ON s.assignment_id = a.id AND s.user_id = $1
        WHERE a.grade = $2 AND a.archived = false
        ORDER BY (COALESCE(s.status, 'not_started') = 'completed'),
                 a.due_at ASC NULLS LAST, a.created_at DESC
        LIMIT 30`,
      [req.user.userId, grade]
    );
    const rows = result.rows.map(r => ({
      ...r,
      overdue: !!(r.due_at && r.status !== 'completed' && new Date(r.due_at).getTime() < Date.now()),
    }));
    res.json({
      assignments: rows,
      pendingCount: rows.filter(r => r.status !== 'completed').length,
    });
  } catch (err) {
    console.error('My assignments error:', err);
    res.status(500).json({ error: 'Could not load your assignments.' });
  }
});

// POST /api/my/assignments/:id/start — get this student's own question set for an assignment.
//
// Questions are generated per student and then STORED. Two consequences that matter: two
// students sitting together get different numbers and scenarios, so copying an answer across
// is useless; and refreshing the page returns the same paper rather than rerolling until an
// easier one appears.
app.post('/api/my/assignments/:id/start', aiGuard, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  if (!process.env.GROQ_API_KEY) return res.status(500).json({ error: 'Server is missing its API key. Set GROQ_API_KEY in the environment.' });
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid assignment id.' });
  const { lang } = req.body || {};

  try {
    const meta = await pool.query(
      `SELECT a.id, a.grade, a.title, a.instructions, a.question_count, a.difficulty, a.due_at,
              t.title AS topic
         FROM assignments a JOIN topics t ON t.id = a.topic_id
        WHERE a.id = $1 AND a.archived = false`,
      [id]
    );
    if (!meta.rows.length) return res.status(404).json({ error: 'Assignment not found.' });
    const a = meta.rows[0];
    if (a.grade !== (req.account && req.account.grade)) {
      return res.status(403).json({ error: 'This assignment is not for your grade.' });
    }

    // Already started or finished? Return what's on file rather than generating again.
    const existing = await pool.query(
      `SELECT status, questions, score, total FROM assignment_submissions
        WHERE assignment_id = $1 AND user_id = $2`,
      [id, req.user.userId]
    );
    if (existing.rows.length) {
      const sub = existing.rows[0];
      if (sub.status === 'completed') {
        return res.status(409).json({ error: 'You have already submitted this assignment.', score: sub.score, total: sub.total });
      }
      if (Array.isArray(sub.questions) && sub.questions.length) {
        return res.json({ assignment: a, grade: a.grade, topic: a.topic, questions: sub.questions, resumed: true });
      }
    }

    const grounding = styleGroundingFor(a.grade);
    const personal = await mistakeGroundingFor(req.user.userId, a.grade, a.topic);
    const n = a.question_count;
    const userMessage = `Grade/branch: ${GRADE_LABELS[a.grade] || a.grade}\nTopic: ${a.topic}\nDifficulty/style: ${a.difficulty}\nNumber of questions: ${n}${grounding ? `\n\n${grounding}` : ''}${personal ? `\n\n${personal}` : ''}`;
    const text = await callGroq(withLanguage(QUESTION_BANK_GEN_SYSTEM_PROMPT, lang), userMessage, Math.min(6000, 400 + n * tokensPerQuestion(a.grade)));

    let questions;
    try {
      questions = extractJson(text);
    } catch (e) {
      console.error(`Failed to parse assignment questions (id=${id}, grade=${a.grade}):`, e.message, '\nRAW:', text);
      return res.status(502).json({ error: 'Could not build your questions. Please try again.' });
    }
    const allowedTypes = (GRADE_STYLE_GUIDE[a.grade] && GRADE_STYLE_GUIDE[a.grade].types) || ['tf', 'mcq', 'problem'];
    const usable = questions.filter(Boolean);
    const filtered = usable.filter(q => allowedTypes.includes(q.type || 'problem'));
    questions = filtered.length ? filtered : usable;
    if (!questions.length) return res.status(502).json({ error: 'Could not build your questions. Please try again.' });

    questions.forEach(q => { q.topic = a.topic; if (!q.difficulty) q.difficulty = a.difficulty; });

    // Upsert so a retry after a transient failure doesn't collide on the unique constraint.
    await pool.query(
      `INSERT INTO assignment_submissions (assignment_id, user_id, status, questions)
       VALUES ($1, $2, 'in_progress', $3)
       ON CONFLICT (assignment_id, user_id)
       DO UPDATE SET questions = EXCLUDED.questions, status = 'in_progress', started_at = NOW()`,
      [id, req.user.userId, JSON.stringify(questions)]
    );

    res.json({ assignment: a, grade: a.grade, topic: a.topic, questions, resumed: false });
  } catch (err) {
    if (err.message === 'groq_timeout') return res.status(504).json({ error: 'The AI service took too long to respond. Please try again in a moment.' });
    if (err.message === 'groq_error') return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    console.error('Assignment start error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

// --- Spaced review: what's due today ---
// Cheap enough to call on every page load — it powers the "Review (N due)" badge.
app.get('/api/my/review/due', requireAuth, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  try {
    // The count is a separate query, NOT result.rows.length — the listing is capped at 20, so
    // a student with 35 items due would see the badge stuck at "20" and it would not move as
    // they cleared the first 15, making review look broken.
    const [countRes, result] = await Promise.all([
      pool.query(
        `SELECT COUNT(*)::int AS n FROM review_queue
          WHERE user_id = $1 AND retired = false AND due_at <= NOW()`,
        [req.user.userId]
      ),
      pool.query(
        `SELECT rq.id, rq.mistake_tag, rq.box, rq.due_at, t.title AS topic, t.grade
           FROM review_queue rq
           JOIN topics t ON t.id = rq.topic_id
          WHERE rq.user_id = $1 AND rq.retired = false AND rq.due_at <= NOW()
          ORDER BY rq.due_at ASC
          LIMIT 20`,
        [req.user.userId]
      ),
    ]);
    // Group by topic so the UI can offer "review Energy (3 things)" rather than 3 separate items.
    const byTopic = {};
    result.rows.forEach(r => {
      if (!byTopic[r.topic]) byTopic[r.topic] = { topic: r.topic, grade: r.grade, tags: [] };
      byTopic[r.topic].tags.push(shortTagLabel(r.mistake_tag));
    });
    res.json({ dueCount: countRes.rows[0].n, topics: Object.values(byTopic) });
  } catch (err) {
    console.error('Review due fetch error:', err);
    res.status(500).json({ error: 'Could not load your review queue.' });
  }
});

// --- Spaced review: build today's review session ---
// Generates NEW questions aimed squarely at the misconceptions that are due for this student on
// this topic, rather than replaying the original wording — re-testing the understanding, not
// the memory of one specific question. The returned questions carry `reviewTag` so that
// /api/question-bank/grade (called with isReview: true) can update the right queue rows.
app.post('/api/my/review/start', aiGuard, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  if (!process.env.GROQ_API_KEY) return res.status(500).json({ error: 'Server is missing its API key. Set GROQ_API_KEY in the environment.' });
  const { topic, lang } = req.body;

  try {
    // Filter on topic_id, not on the title. 14 topic titles are shared between grades
    // ("Energy" is in both bacls and bacgs; "Radioactivity" is in three), so matching by title
    // alone could pull in another grade's queue rows. The grading call later resolves a single
    // topic_id from (grade, title) — if that resolved to the other grade's row, the update
    // matched nothing and the item stayed due forever with the badge stuck on.
    const topicId = req.body.topicId ? Number(req.body.topicId) : null;
    const due = await pool.query(
      `SELECT rq.topic_id, rq.mistake_tag, rq.box, t.title AS topic, t.grade
         FROM review_queue rq
         JOIN topics t ON t.id = rq.topic_id
        WHERE rq.user_id = $1 AND rq.retired = false AND rq.due_at <= NOW()
          ${topicId ? 'AND rq.topic_id = $2' : (topic ? 'AND t.title = $2' : '')}
        ORDER BY rq.due_at ASC
        LIMIT 20`,
      topicId ? [req.user.userId, topicId] : (topic ? [req.user.userId, topic] : [req.user.userId])
    );
    if (!due.rows.length) {
      return res.json({ questions: [], message: 'Nothing due for review right now — well done.' });
    }

    // Work on ONE topic per session — the first one due — and take its tags by topic_id so a
    // same-titled topic from another grade can never be mixed in.
    const first = due.rows[0];
    const grade = first.grade;
    const topicTitle = first.topic;
    const sessionTopicId = first.topic_id;
    const tags = [...new Set(
      due.rows.filter(r => r.topic_id === sessionTopicId).map(r => shortTagLabel(r.mistake_tag))
    )].slice(0, 5);
    const n = Math.min(5, Math.max(2, tags.length + 1));

    const grounding = styleGroundingFor(grade);
    const userMessage = `Grade/branch: ${GRADE_LABELS[grade] || grade}
Topic: ${topicTitle}
Difficulty/style: medium
Number of questions: ${n}${grounding ? `\n\n${grounding}` : ''}

This is a SPACED REVIEW session. The student previously got these specific things wrong on this topic:
${tags.map(t => `- ${t}`).join('\n')}
Write questions that each re-test one of those specific weak points in a NEW situation — different numbers, different scenario, same underlying idea. Do not reuse the original wording, and do not mention that this is a review.`;

    const reviewMaxTokens = Math.min(6000, 400 + n * tokensPerQuestion(grade));
    const text = await callGroq(withLanguage(QUESTION_BANK_GEN_SYSTEM_PROMPT, lang), userMessage, reviewMaxTokens);
    let questions;
    try {
      questions = extractJson(text);
    } catch (e) {
      console.error(`Failed to parse review questions (grade=${grade}, maxTokens=${reviewMaxTokens}):`, e.message, '\nRAW:', text);
      return res.status(502).json({ error: 'Could not build your review session. Please try again.' });
    }
    if (!Array.isArray(questions)) questions = [];
    const allowedTypes = (GRADE_STYLE_GUIDE[grade] && GRADE_STYLE_GUIDE[grade].types) || ['tf', 'mcq', 'problem'];
    questions = questions.filter(q => q && allowedTypes.includes(q.type || 'problem'));
    if (!questions.length) return res.status(502).json({ error: 'Could not build your review session. Try again.' });

    // Tag each question with the misconception it is meant to re-test, cycling through the due
    // list so every due item gets covered even if the model returned fewer questions than tags.
    questions.forEach((q, i) => {
      q.topic = topicTitle;
      q.difficulty = 'medium';
      q.reviewTag = tags[i % tags.length];
    });
    res.json({ grade, topic: topicTitle, questions, reviewing: tags });
  } catch (err) {
    if (err.message === 'groq_timeout') return res.status(504).json({ error: 'The AI service took too long to respond. Please try again in a moment.' });
    if (err.message === 'groq_error') return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    console.error('Review start error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

// --- Student Dashboard + Error Analysis ---
// Student-facing mirrors of the teacher dashboard queries above, scoped to req.user.userId
// instead of an admin-supplied :userId. Same mastery rule: a topic needs >=3 attempts before
// its mastery % is shown (fewer than that comes back as null, "not enough data yet").

// GET /api/my/dashboard — per-topic mastery for this student, overall stats, coverage of
// their own grade's curriculum, and a recent-activity feed. This is the data behind the
// Student Dashboard page.
app.get('/api/my/dashboard', requireAuth, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  try {
    const userId = req.user.userId;
    const grade = req.user.grade;

    const topics = await pool.query(
      `SELECT t.id AS topic_id, t.title AS topic_title, t.grade,
              COUNT(*) AS attempts,
              SUM(CASE WHEN a.correct THEN 1 ELSE 0 END) AS correct_count,
              MAX(a.created_at) AS last_attempt_at,
              CASE WHEN COUNT(*) >= 3 THEN ROUND(100.0 * SUM(CASE WHEN a.correct THEN 1 ELSE 0 END) / COUNT(*), 1) ELSE NULL END AS mastery_pct
       FROM attempts a JOIN topics t ON t.id = a.topic_id
       WHERE a.user_id = $1
       GROUP BY t.id, t.title, t.grade
       ORDER BY mastery_pct ASC NULLS LAST, t.title`,
      [userId]
    );

    const overall = await pool.query(
      `SELECT COUNT(*) AS total_attempts, SUM(CASE WHEN correct THEN 1 ELSE 0 END) AS total_correct
       FROM attempts WHERE user_id = $1`,
      [userId]
    );
    const totalAttempts = Number(overall.rows[0].total_attempts) || 0;
    const totalCorrect = Number(overall.rows[0].total_correct) || 0;
    const overallMastery = totalAttempts > 0 ? Math.round((totalCorrect / totalAttempts) * 1000) / 10 : null;

    const examStats = await pool.query(
      `SELECT COUNT(*) AS exam_count, AVG(score::float / NULLIF(total, 0)) AS avg_ratio, MAX(created_at) AS last_exam_at
       FROM exam_results WHERE user_id = $1`,
      [userId]
    );

    const recent = await pool.query(
      `SELECT a.source, t.title AS topic_title, a.question_text, a.correct, a.mistake_tag, a.created_at
       FROM attempts a LEFT JOIN topics t ON t.id = a.topic_id
       WHERE a.user_id = $1
       ORDER BY a.created_at DESC
       LIMIT 15`,
      [userId]
    );

    const gradeTopicCount = (grade && CURRICULUM[grade]) ? CURRICULUM[grade].length : null;
    const topicsPracticed = topics.rows.filter(r => r.grade === grade).length;

    res.json({
      overallMastery,
      totalAttempts,
      weakTopicCount: topics.rows.filter(r => r.mastery_pct !== null && Number(r.mastery_pct) < 60).length,
      coverage: gradeTopicCount ? { practiced: topicsPracticed, total: gradeTopicCount } : null,
      examStats: {
        examCount: Number(examStats.rows[0].exam_count) || 0,
        avgScorePct: examStats.rows[0].avg_ratio !== null ? Math.round(Number(examStats.rows[0].avg_ratio) * 1000) / 10 : null,
        lastExamAt: examStats.rows[0].last_exam_at,
      },
      topics: topics.rows.map(r => ({
        topicId: r.topic_id,
        topic: r.topic_title,
        grade: r.grade,
        attempts: Number(r.attempts),
        masteryPct: r.mastery_pct === null ? null : Number(r.mastery_pct),
        lastAttemptAt: r.last_attempt_at,
      })),
      recentActivity: recent.rows.map(r => ({
        source: r.source,
        topic: r.topic_title,
        question: r.question_text,
        correct: r.correct,
        mistakeTag: r.mistake_tag,
        createdAt: r.created_at,
      })),
    });
  } catch (err) {
    console.error('My dashboard error:', err);
    res.status(500).json({ error: 'Could not load your dashboard.' });
  }
});

// GET /api/my/mistakes — Error Analysis: this student's mistake-tag breakdown (overall and
// per topic), plus their most recent incorrect attempts. Powers the "where you're losing
// points" view.
app.get('/api/my/mistakes', requireAuth, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  try {
    const userId = req.user.userId;

    const distribution = await pool.query(
      `SELECT mistake_tag, COUNT(*) AS cnt, COUNT(DISTINCT topic_id) AS topic_count
       FROM attempts
       WHERE user_id = $1 AND correct = false AND mistake_tag IS NOT NULL
       GROUP BY mistake_tag ORDER BY cnt DESC, mistake_tag`,
      [userId]
    );

    const byTopic = await pool.query(
      `SELECT t.id AS topic_id, t.title AS topic_title, t.grade AS topic_grade, a.mistake_tag, COUNT(*) AS cnt
       FROM attempts a JOIN topics t ON t.id = a.topic_id
       WHERE a.user_id = $1 AND a.correct = false AND a.mistake_tag IS NOT NULL
       GROUP BY t.id, t.title, t.grade, a.mistake_tag
       ORDER BY t.title, cnt DESC`,
      [userId]
    );

    const recentMistakes = await pool.query(
      `SELECT a.source, t.title AS topic_title, a.question_text, a.student_answer, a.mistake_tag, a.created_at
       FROM attempts a LEFT JOIN topics t ON t.id = a.topic_id
       WHERE a.user_id = $1 AND a.correct = false
       ORDER BY a.created_at DESC
       LIMIT 20`,
      [userId]
    );

    const topicMap = {};
    byTopic.rows.forEach(r => {
      const key = r.topic_id;
      if (!topicMap[key]) topicMap[key] = { topicId: r.topic_id, topic: r.topic_title, grade: r.topic_grade, mistakes: [] };
      topicMap[key].mistakes.push({ tag: r.mistake_tag, count: Number(r.cnt) });
    });

    res.json({
      mistakeDistribution: distribution.rows.map(r => ({ tag: r.mistake_tag, count: Number(r.cnt), topicCount: Number(r.topic_count) })),
      byTopic: Object.values(topicMap),
      recentMistakes: recentMistakes.rows.map(r => ({
        source: r.source,
        topic: r.topic_title,
        question: r.question_text,
        studentAnswer: r.student_answer,
        mistakeTag: r.mistake_tag,
        createdAt: r.created_at,
      })),
    });
  } catch (err) {
    console.error('My mistakes error:', err);
    res.status(500).json({ error: 'Could not load your mistakes.' });
  }
});

// --- Gamification (simple, not childish) ---
// A coarse keyword categorizer for badges like "Mechanics Master" — the curriculum tracks
// individual topics (91 of them across 9 grades), not broad chapter categories, so this maps
// topic titles into a handful of physics areas by keyword match. It's a heuristic for
// grouping badge progress, not a claim about official curriculum structure.
function categorizeTopic(title){
  const t = (title || '').toLowerCase();
  if (/force|motion|newton|momentum|gravity|projectile|circular|work|power|pressure|archimedes|hooke|elastic|kinematic|dynamic|equilibrium|friction|energy/.test(t)) return 'Mechanics';
  if (/circuit|current|resistance|voltage|charge|capacitor|induction|magnet|electr|ohm|coulomb|diode|semiconductor/.test(t)) return 'Electricity & Magnetism';
  if (/wave|light|reflection|refraction|diffraction|interference|lens|mirror|photoelectric|optic|sound/.test(t)) return 'Waves & Light';
  if (/heat|temperature|thermo|calorimetry/.test(t)) return 'Thermodynamics';
  if (/atom|nucleus|nuclear|radioactiv|quantum|photon|relativity/.test(t)) return 'Modern Physics';
  return 'General Physics';
}

// GET /api/my/progress — streak, activity counts, curriculum coverage, and a handful of
// rule-based badges. Powers the Dashboard's "Physics Progress" panel.
app.get('/api/my/progress', requireAuth, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  try {
    const userId = req.user.userId;
    const grade = req.user.grade;

    const [streakRows, countRow, labRow, examRow, topicRows] = await Promise.all([
      pool.query(`SELECT DISTINCT date_trunc('day', created_at) AS day FROM attempts WHERE user_id = $1 ORDER BY day DESC LIMIT 60`, [userId]),
      pool.query(`SELECT COUNT(*) AS cnt FROM attempts WHERE user_id = $1`, [userId]),
      pool.query(`SELECT COUNT(DISTINCT topic_id) AS cnt FROM attempts WHERE user_id = $1 AND source = 'lab' AND topic_id IS NOT NULL`, [userId]),
      pool.query(`SELECT COUNT(*) AS cnt, COUNT(*) FILTER (WHERE score = total) AS perfect_cnt FROM exam_results WHERE user_id = $1`, [userId]),
      pool.query(
        `SELECT t.title, COUNT(*) AS attempts, SUM(CASE WHEN a.correct THEN 1 ELSE 0 END) AS correct_count
         FROM attempts a JOIN topics t ON t.id = a.topic_id
         WHERE a.user_id = $1 GROUP BY t.title`,
        [userId]
      ),
    ]);

    // Streak: consecutive days with any activity, counting back from today — or from
    // yesterday if nothing's logged yet today, so the streak doesn't look broken before
    // the student has had a chance to do anything today.
    const dayStrings = streakRows.rows.map(r => new Date(r.day).toISOString().slice(0, 10));
    let streakDays = 0;
    if (dayStrings.length) {
      const daySet = new Set(dayStrings);
      const oneDayMs = 86400000;
      const todayStr = new Date().toISOString().slice(0, 10);
      let cursor = new Date(todayStr + 'T00:00:00Z');
      if (!daySet.has(todayStr)) {
        cursor = new Date(cursor.getTime() - oneDayMs);
        if (!daySet.has(cursor.toISOString().slice(0, 10))) cursor = null;
      }
      while (cursor && daySet.has(cursor.toISOString().slice(0, 10))) {
        streakDays++;
        cursor = new Date(cursor.getTime() - oneDayMs);
      }
    }

    const questionsSolved = Number(countRow.rows[0].cnt) || 0;
    const labsCompleted = Number(labRow.rows[0].cnt) || 0;
    const examsCompleted = Number(examRow.rows[0].cnt) || 0;
    const perfectExams = Number(examRow.rows[0].perfect_cnt) || 0;

    const gradeTopicCount = (grade && CURRICULUM[grade]) ? CURRICULUM[grade].length : null;
    const topicsPracticedThisGrade = topicRows.rows.length; // approximate; category grouping below is grade-agnostic
    const coverage = gradeTopicCount ? { practiced: Math.min(topicsPracticedThisGrade, gradeTopicCount), total: gradeTopicCount } : null;
    const progressPct = coverage ? Math.round((coverage.practiced / coverage.total) * 100) : null;

    // Category rollup for "<Category> Master/Pro" badges — needs a real sample size (>=5
    // attempts in that category) before it means anything.
    const categoryAgg = {};
    topicRows.rows.forEach(r => {
      const cat = categorizeTopic(r.title);
      if (!categoryAgg[cat]) categoryAgg[cat] = { attempts: 0, correct: 0 };
      categoryAgg[cat].attempts += Number(r.attempts);
      categoryAgg[cat].correct += Number(r.correct_count);
    });

    const badges = [];
    if (streakDays >= 7) badges.push({ id: 'streak7', label: '7-Day Streak' });
    const volumeTiers = [[100, '100 Questions Solved'], [50, '50 Questions Solved'], [10, 'Getting Started']];
    const volumeBadge = volumeTiers.find(([n]) => questionsSolved >= n);
    if (volumeBadge) badges.push({ id: 'volume' + volumeBadge[0], label: volumeBadge[1] });
    if (labsCompleted >= 5) badges.push({ id: 'labexplorer', label: 'Lab Explorer' });
    if (examsCompleted >= 1) badges.push({ id: 'firstexam', label: 'First Exam Complete' });
    if (perfectExams >= 1) badges.push({ id: 'perfectscore', label: 'Perfect Score' });
    Object.keys(categoryAgg).forEach(cat => {
      const c = categoryAgg[cat];
      if (c.attempts < 5) return;
      const pct = (c.correct / c.attempts) * 100;
      if (pct >= 85) badges.push({ id: 'cat-' + cat, label: `${cat} Master` });
      else if (pct >= 65) badges.push({ id: 'cat-' + cat, label: `${cat} Pro` });
    });

    res.json({ progressPct, coverage, streakDays, questionsSolved, labsCompleted, examsCompleted, badges });
  } catch (err) {
    console.error('My progress error:', err);
    res.status(500).json({ error: 'Could not load your progress.' });
  }
});

// --- Booking ---
// A student requests a session; the teacher confirms or cancels it from admin.html. This is
// a request-and-confirm flow, not instant auto-scheduling — nothing here touches a calendar.
const BOOKING_SESSION_TYPES = ['private', 'group'];

app.post('/api/bookings', requireAuth, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  const { grade, topic, sessionType, duration, preferredTime } = req.body;
  if (!grade || !CURRICULUM[grade]) return res.status(400).json({ error: 'Please choose a valid grade.' });
  if (!BOOKING_SESSION_TYPES.includes(sessionType)) return res.status(400).json({ error: 'Please choose Private or Group.' });
  const durationMinutes = Number(duration);
  if (!durationMinutes || durationMinutes <= 0) return res.status(400).json({ error: 'Please choose a session duration.' });
  if (!preferredTime || !String(preferredTime).trim()) return res.status(400).json({ error: 'Please tell me your preferred time.' });

  try {
    const result = await pool.query(
      `INSERT INTO bookings (user_id, grade, topic, session_type, duration_minutes, preferred_time, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'pending')
       RETURNING id, grade, topic, session_type, duration_minutes, preferred_time, status, created_at`,
      [req.user.userId, grade, topic || null, sessionType, durationMinutes, String(preferredTime).trim()]
    );
    res.json({ booking: result.rows[0] });
  } catch (err) {
    console.error('Create booking error:', err);
    res.status(500).json({ error: 'Could not submit your booking request.' });
  }
});

// GET /api/my/bookings — this student's requests, most recent first. Powers the Dashboard's
// "Upcoming session" panel (pending/confirmed only are shown as "upcoming" on the frontend).
app.get('/api/my/bookings', requireAuth, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  try {
    const result = await pool.query(
      `SELECT id, grade, topic, session_type, duration_minutes, preferred_time, status, created_at
       FROM bookings WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20`,
      [req.user.userId]
    );
    res.json({ bookings: result.rows });
  } catch (err) {
    console.error('My bookings error:', err);
    res.status(500).json({ error: 'Could not load your bookings.' });
  }
});

// PATCH /api/my/bookings/:id/cancel — a student can cancel their own request (ownership
// enforced — this is NOT admin-only, so it must check user_id itself).
app.patch('/api/my/bookings/:id/cancel', requireAuth, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  try {
    const result = await pool.query(
      `UPDATE bookings SET status = 'cancelled' WHERE id = $1 AND user_id = $2 RETURNING id, status`,
      [req.params.id, req.user.userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Booking not found.' });
    res.json({ booking: result.rows[0] });
  } catch (err) {
    console.error('Cancel booking error:', err);
    res.status(500).json({ error: 'Could not cancel this booking.' });
  }
});

// --- Admin ---
// Admin access is decided by the `role` column on the account, read fresh from the database on
// every admin request — NOT by comparing against an email baked into the token.
//
// Why the change: email is never verified at signup, so the old check could be satisfied by
// simply registering with the configured ADMIN_EMAIL if no account held it yet. And because
// the email lived inside a 30-day token, admin access could not be revoked before it expired.
// Reading the role live means demoting an account takes effect on the very next request.
// The extra lookup is one indexed primary-key read, only on admin/teacher routes.
// Always mount this AFTER requireAuth, which loads req.account.
function requireAdmin(req, res, next){
  if (!req.account) return res.status(401).json({ error: 'Please log in first.' });
  const role = req.account.role;
  if (role !== 'teacher' && role !== 'admin') {
    return res.status(403).json({ error: 'You do not have admin access.' });
  }
  next();
}

app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  try {
    const result = await pool.query(`
      SELECT
        u.id, u.name, u.email, u.grade, u.created_at, COALESCE(u.is_demo, false) AS is_demo,
        (SELECT COUNT(*) FROM exam_results WHERE user_id = u.id) AS exam_count,
        (SELECT COUNT(*) FROM study_plans WHERE user_id = u.id) AS plan_count,
        (SELECT COUNT(*) FROM solver_history WHERE user_id = u.id) AS solve_count
      FROM users u
      ORDER BY u.created_at DESC
    `);
    res.json({ users: result.rows });
  } catch (err) {
    console.error('Admin users fetch error:', err);
    res.status(500).json({ error: 'Could not load users.' });
  }
});

// Students are locked to the grade they picked at signup and can't change it themselves —
// this is the one escape hatch, for the rare real cases (typo at signup, a student moving up
// a grade next year). Admin/teacher only.
app.patch('/api/admin/users/:id/grade', requireAuth, requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  const { grade } = req.body;
  if (!grade || !CURRICULUM[grade]) return res.status(400).json({ error: 'Not a valid grade.' });
  try {
    const result = await pool.query(
      'UPDATE users SET grade = $1 WHERE id = $2 RETURNING id, name, email, grade',
      [grade, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Student not found.' });
    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error('Admin grade update error:', err);
    res.status(500).json({ error: 'Could not update this student\'s grade.' });
  }
});

// Mark/unmark an account as a demo/test account. Use this for any account you make just to
// show the site to someone — once flagged, nothing that account does (exams, question bank,
// solver, etc.) is counted in Class Analytics, the Weekly Digest, the Teacher Dashboard, or
// the "what to teach next" recommendation, so demo activity never distorts real class data.
app.patch('/api/admin/users/:id/demo', requireAuth, requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  const { isDemo } = req.body;
  try {
    const result = await pool.query(
      'UPDATE users SET is_demo = $1 WHERE id = $2 RETURNING id, name, email, is_demo',
      [!!isDemo, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Student not found.' });
    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error('Admin demo-flag update error:', err);
    res.status(500).json({ error: 'Could not update this account.' });
  }
});

// There's no email-based "forgot password" flow (the site has no email sending set up, and
// adding one is real infrastructure for a small classroom deployment). Instead: the teacher
// generates a fresh temporary password for a student right in the admin panel and tells them
// in person/in class. The plaintext password is returned ONCE in this response and never
// stored or logged anywhere — only its hash is saved.
app.post('/api/admin/users/:id/reset-password', requireAuth, requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  try {
    // Short, readable temporary password (avoids visually ambiguous characters like 0/O/1/l).
    // Uses crypto.randomInt, not Math.random — Math.random is predictable, and a password
    // that grants access to a student's account should not be guessable from prior output.
    const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    let tempPassword = '';
    for (let i = 0; i < 10; i++) tempPassword += chars[crypto.randomInt(0, chars.length)];

    const hash = await bcrypt.hash(tempPassword, 10);
    // password_changed_at invalidates any token issued before this reset — otherwise a student
    // (or anyone holding their old 30-day token) keeps access even after the password changes.
    const result = await pool.query(
      'UPDATE users SET password_hash = $1, password_changed_at = NOW() WHERE id = $2 RETURNING id, name, email',
      [hash, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Student not found.' });
    res.json({ user: result.rows[0], tempPassword });
  } catch (err) {
    console.error('Admin password reset error:', err);
    res.status(500).json({ error: 'Could not reset this student\'s password.' });
  }
});

app.delete('/api/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Admin delete user error:', err);
    res.status(500).json({ error: 'Could not delete this user.' });
  }
});

// GET /api/admin/bookings — every booking request with the student's name/email joined in,
// pending ones first so the teacher sees what needs a response.
app.get('/api/admin/bookings', requireAuth, requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  try {
    const result = await pool.query(
      `SELECT b.id, b.grade, b.topic, b.session_type, b.duration_minutes, b.preferred_time, b.status, b.created_at,
              u.id AS student_id, u.name AS student_name, u.email AS student_email
       FROM bookings b JOIN users u ON u.id = b.user_id
       ORDER BY (b.status = 'pending') DESC, b.created_at DESC`
    );
    res.json({ bookings: result.rows });
  } catch (err) {
    console.error('Admin bookings fetch error:', err);
    res.status(500).json({ error: 'Could not load bookings.' });
  }
});

// PATCH /api/admin/bookings/:id — teacher confirms or cancels a request.
app.patch('/api/admin/bookings/:id', requireAuth, requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  const { status } = req.body;
  if (!['confirmed', 'cancelled', 'pending'].includes(status)) return res.status(400).json({ error: 'Invalid status.' });
  try {
    const result = await pool.query(
      'UPDATE bookings SET status = $1 WHERE id = $2 RETURNING id, status',
      [status, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Booking not found.' });
    res.json({ booking: result.rows[0] });
  } catch (err) {
    console.error('Admin booking update error:', err);
    res.status(500).json({ error: 'Could not update this booking.' });
  }
});

// GET /api/admin/analytics — a class-wide (not per-student) view: how each grade is doing on
// average, the most common mistake types per grade, and each grade's weakest topics. This is
// the teacher-facing counterpart to the student Dashboard, which only ever shows one student
// at a time. Every query is grouped by grade — no single-student drill-down here, that's what
// /api/admin/users is for.
// GET /api/admin/ai-usage — what the AI is actually being used for, and by whom.
//
// The point of this screen is to answer one question before it becomes urgent: "if I put a
// whole class on this, does the free quota survive?" Both providers cut off silently when their
// allowance runs out, and it stops working for everyone at once, mid-lesson.
app.get('/api/admin/ai-usage', requireAuth, requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  try {
    // Every figure below excludes demo accounts, and the per-student average is computed from a
    // dedicated COUNT — not from the length of the top-30 list, which would peg the divisor at
    // 30 once the class grew past that and inflate the projection without limit.
    const [today, month, perStudent, daily, activeCount] = await Promise.all([
      pool.query(
        `SELECT COALESCE(SUM(a.calls), 0)::int AS n
           FROM ai_usage a JOIN users u ON u.id = a.user_id
          WHERE a.day = CURRENT_DATE AND COALESCE(u.is_demo, false) = false`
      ),
      pool.query(
        `SELECT COALESCE(SUM(a.calls), 0)::int AS n
           FROM ai_usage a JOIN users u ON u.id = a.user_id
          WHERE a.day >= CURRENT_DATE - INTERVAL '30 days' AND COALESCE(u.is_demo, false) = false`
      ),
      pool.query(
        `SELECT u.id, u.name, u.grade,
                COALESCE(SUM(a.calls), 0)::int AS calls_30d,
                COALESCE(SUM(a.calls) FILTER (WHERE a.day = CURRENT_DATE), 0)::int AS calls_today
           FROM users u
           LEFT JOIN ai_usage a ON a.user_id = u.id AND a.day >= CURRENT_DATE - INTERVAL '30 days'
          WHERE COALESCE(u.is_demo, false) = false
          GROUP BY u.id, u.name, u.grade
         HAVING COALESCE(SUM(a.calls), 0) > 0
          ORDER BY calls_30d DESC
          LIMIT 30`
      ),
      pool.query(
        `SELECT a.day, SUM(a.calls)::int AS calls
           FROM ai_usage a JOIN users u ON u.id = a.user_id
          WHERE a.day >= CURRENT_DATE - INTERVAL '14 days' AND COALESCE(u.is_demo, false) = false
          GROUP BY a.day ORDER BY a.day ASC`
      ),
      // Counts EVERY active student, not just the 30 listed below.
      pool.query(
        `SELECT COUNT(DISTINCT a.user_id)::int AS n
           FROM ai_usage a JOIN users u ON u.id = a.user_id
          WHERE a.day >= CURRENT_DATE - INTERVAL '30 days' AND COALESCE(u.is_demo, false) = false`
      ),
    ]);

    const students = perStudent.rows;          // top 30, for the table
    const activeStudents = activeCount.rows[0].n;  // all of them, for the maths
    const monthTotal = month.rows[0].n;
    // The number that actually matters for planning: what one student costs per month.
    const perStudentPerMonth = activeStudents ? Math.round((monthTotal / activeStudents) * 10) / 10 : 0;

    res.json({
      today: today.rows[0].n,
      last30Days: monthTotal,
      activeStudents,
      perStudentPerMonth,
      dailyLimit: AI_DAILY_LIMIT,
      students,
      daily: daily.rows,
    });
  } catch (err) {
    console.error('AI usage error:', err);
    res.status(500).json({ error: 'Could not load AI usage.' });
  }
});

app.get('/api/admin/analytics', requireAuth, requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  try {
    const [examStats, mistakeStats, topicStats, overall] = await Promise.all([
      // Average Practice Exam score per grade. Note: `grade` here is whatever was stored on
      // exam_results at submit time — student-facing routes always send the raw curriculum
      // key (e.g. "g9") going forward, but a handful of very old rows (from before that was
      // fixed) may carry a human label instead. Shown as-is; harmless, just an odd label.
      // Demo/test accounts (see /api/admin/users/:id/demo) are excluded from every query
      // below — a "show the site to someone" account should never distort real class data.
      pool.query(`
        SELECT er.grade, COUNT(*) AS exam_count,
          ROUND(AVG(CASE WHEN er.total > 0 THEN er.score::float / er.total * 100 END)::numeric, 1) AS avg_score_pct
        FROM exam_results er JOIN users u ON u.id = er.user_id
        WHERE er.grade IS NOT NULL AND COALESCE(u.is_demo, false) = false
        GROUP BY er.grade
        ORDER BY er.grade
      `),
      // Every incorrect, tagged attempt across every source (exam/question_bank/lab/diagnostic),
      // grouped by grade + mistake tag — the raw material for "top mistakes per grade" below.
      pool.query(`
        SELECT t.grade, a.mistake_tag, COUNT(*) AS cnt
        FROM attempts a JOIN topics t ON t.id = a.topic_id JOIN users u ON u.id = a.user_id
        WHERE a.correct = false AND a.mistake_tag IS NOT NULL AND COALESCE(u.is_demo, false) = false
        GROUP BY t.grade, a.mistake_tag
        ORDER BY t.grade, cnt DESC
      `),
      // Per-topic mastery averaged across the WHOLE grade (not one student) — same >=3-attempt
      // minimum-sample-size rule used everywhere else in the unified attempts model.
      pool.query(`
        SELECT t.grade, t.title AS topic, COUNT(*) AS attempts,
          ROUND(AVG(CASE WHEN a.correct THEN 100 ELSE 0 END)::numeric, 1) AS mastery_pct
        FROM attempts a JOIN topics t ON t.id = a.topic_id JOIN users u ON u.id = a.user_id
        WHERE COALESCE(u.is_demo, false) = false
        GROUP BY t.grade, t.title
        HAVING COUNT(*) >= 3
        ORDER BY t.grade, mastery_pct ASC
      `),
      pool.query(`
        SELECT
          (SELECT COUNT(*) FROM users WHERE COALESCE(is_demo, false) = false) AS student_count,
          (SELECT COUNT(*) FROM attempts a JOIN users u ON u.id = a.user_id WHERE COALESCE(u.is_demo, false) = false) AS attempt_count,
          (SELECT COUNT(*) FROM exam_results er JOIN users u ON u.id = er.user_id WHERE COALESCE(u.is_demo, false) = false) AS exam_count,
          (SELECT ROUND(AVG(CASE WHEN a.correct THEN 100 ELSE 0 END)::numeric, 1) FROM attempts a JOIN users u ON u.id = a.user_id WHERE a.correct IS NOT NULL AND COALESCE(u.is_demo, false) = false) AS overall_correct_pct
      `),
    ]);

    // Top 5 mistake tags per grade, already ordered by count from the query above.
    const mistakesByGrade = {};
    mistakeStats.rows.forEach(r => {
      const grade = r.grade;
      mistakesByGrade[grade] = mistakesByGrade[grade] || [];
      if (mistakesByGrade[grade].length < 5) {
        mistakesByGrade[grade].push({ tag: shortTagLabel(r.mistake_tag), count: Number(r.cnt) });
      }
    });

    // Weakest 3 topics per grade (lowest mastery first, already ordered by the query above).
    const weakTopicsByGrade = {};
    topicStats.rows.forEach(r => {
      const grade = r.grade;
      weakTopicsByGrade[grade] = weakTopicsByGrade[grade] || [];
      if (weakTopicsByGrade[grade].length < 3) {
        weakTopicsByGrade[grade].push({ topic: r.topic, masteryPct: Number(r.mastery_pct), attempts: Number(r.attempts) });
      }
    });

    const overallRow = overall.rows[0] || {};
    res.json({
      overall: {
        studentCount: Number(overallRow.student_count) || 0,
        attemptCount: Number(overallRow.attempt_count) || 0,
        examCount: Number(overallRow.exam_count) || 0,
        overallCorrectPct: overallRow.overall_correct_pct !== null && overallRow.overall_correct_pct !== undefined ? Number(overallRow.overall_correct_pct) : null,
      },
      examStatsByGrade: examStats.rows.map(r => ({
        grade: r.grade,
        examCount: Number(r.exam_count),
        avgScorePct: r.avg_score_pct !== null ? Number(r.avg_score_pct) : null,
      })),
      mistakesByGrade,
      weakTopicsByGrade,
    });
  } catch (err) {
    console.error('Admin analytics fetch error:', err);
    res.status(500).json({ error: 'Could not load analytics.' });
  }
});

// Weekly Digest: unlike /api/admin/analytics (all-time totals), this is scoped to the last 7
// days and named-student-level — the teacher asked for a way to see WHICH students are
// struggling and on WHAT each week, not just class-wide averages, so she can check in on them
// early instead of finding out at the next exam. No email/cron pipeline exists on this
// project (would need SMTP credentials + a scheduled job service) so this is served on-demand
// whenever the Admin page is opened; the frontend adds a "copy as text" button so it can be
// pasted into WhatsApp/email by hand if the teacher wants to send it somewhere.
app.get('/api/admin/weekly-digest', requireAuth, requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  try {
    const [weekOverall, strugglingStudents, studentMistakes, gradeMistakes] = await Promise.all([
      // Demo/test accounts are excluded everywhere below — see /api/admin/users/:id/demo.
      pool.query(`
        SELECT COUNT(DISTINCT a.user_id) AS active_students, COUNT(*) AS attempts_7d,
          ROUND(AVG(CASE WHEN a.correct THEN 100 ELSE 0 END)::numeric, 1) AS overall_correct_pct_7d
        FROM attempts a JOIN users u ON u.id = a.user_id
        WHERE a.created_at >= NOW() - INTERVAL '7 days' AND a.correct IS NOT NULL AND COALESCE(u.is_demo, false) = false
      `),
      // Students with at least 3 graded attempts this week, worst correctness rate first —
      // the "check in on these students" list.
      pool.query(`
        SELECT u.id, u.name, u.grade, COUNT(*) AS attempts_7d,
          ROUND(AVG(CASE WHEN a.correct THEN 100 ELSE 0 END)::numeric, 1) AS correct_pct_7d
        FROM attempts a JOIN users u ON u.id = a.user_id
        WHERE a.created_at >= NOW() - INTERVAL '7 days' AND a.correct IS NOT NULL AND COALESCE(u.is_demo, false) = false
        GROUP BY u.id, u.name, u.grade
        HAVING COUNT(*) >= 3
        ORDER BY correct_pct_7d ASC
        LIMIT 15
      `),
      // Each struggling student's single most common mistake tag this week (rows arrive
      // ordered by count per user, descending — the JS below keeps only the first per user).
      // No demo filter needed here — this is only ever looked up by the ids already returned
      // in the (already-filtered) strugglingStudents query above.
      pool.query(`
        SELECT a.user_id, a.mistake_tag, COUNT(*) AS cnt
        FROM attempts a
        WHERE a.created_at >= NOW() - INTERVAL '7 days' AND a.correct = false AND a.mistake_tag IS NOT NULL
        GROUP BY a.user_id, a.mistake_tag
        ORDER BY a.user_id, cnt DESC
      `),
      pool.query(`
        SELECT t.grade, a.mistake_tag, COUNT(*) AS cnt
        FROM attempts a JOIN topics t ON t.id = a.topic_id JOIN users u ON u.id = a.user_id
        WHERE a.created_at >= NOW() - INTERVAL '7 days' AND a.correct = false AND a.mistake_tag IS NOT NULL AND COALESCE(u.is_demo, false) = false
        GROUP BY t.grade, a.mistake_tag
        ORDER BY t.grade, cnt DESC
      `),
    ]);

    const topMistakeByUser = {};
    studentMistakes.rows.forEach(r => {
      if (!topMistakeByUser[r.user_id]) topMistakeByUser[r.user_id] = shortTagLabel(r.mistake_tag);
    });

    const mistakesByGradeThisWeek = {};
    gradeMistakes.rows.forEach(r => {
      const grade = r.grade;
      mistakesByGradeThisWeek[grade] = mistakesByGradeThisWeek[grade] || [];
      if (mistakesByGradeThisWeek[grade].length < 5) {
        mistakesByGradeThisWeek[grade].push({ tag: shortTagLabel(r.mistake_tag), count: Number(r.cnt) });
      }
    });

    const overallRow = weekOverall.rows[0] || {};
    res.json({
      weekOverall: {
        activeStudents: Number(overallRow.active_students) || 0,
        attempts7d: Number(overallRow.attempts_7d) || 0,
        overallCorrectPct7d: overallRow.overall_correct_pct_7d !== null && overallRow.overall_correct_pct_7d !== undefined ? Number(overallRow.overall_correct_pct_7d) : null,
      },
      strugglingStudents: strugglingStudents.rows.map(r => ({
        name: r.name,
        grade: r.grade,
        attempts7d: Number(r.attempts_7d),
        correctPct7d: Number(r.correct_pct_7d),
        topMistake: topMistakeByUser[r.id] || null,
      })),
      mistakesByGradeThisWeek,
    });
  } catch (err) {
    console.error('Admin weekly digest fetch error:', err);
    res.status(500).json({ error: 'Could not load the weekly digest.' });
  }
});

// --- AI (Groq / Llama 3.1 for text; Gemini for the solver, since it can read photos) ---
// Set GROQ_API_KEY and GEMINI_API_KEY in the environment. Both have generous free tiers.
// llama-3.1-8b-instant was deprecated and shut down by Groq on Aug 16, 2026 — every route
// calling it (exam/question-bank/formula generation, study plan, grading, topic
// classification) started failing with a "model_not_found" error at that point. Switched to
// Groq's own recommended replacement.
const GROQ_MODEL = 'openai/gpt-oss-20b';
const GEMINI_MODEL = 'gemini-2.5-flash';

// How long to wait on an AI provider before giving up. Without a timeout, a hung socket holds
// the student's request open forever — they sit watching "Solving..." with no error, and on the
// image-grading route it also holds a database connection out of a pool of five.
const AI_TIMEOUT_MS = Number(process.env.AI_TIMEOUT_MS || 45000);

async function callGroq(systemPrompt, userMessage, maxTokens){
  let response;
  try {
    response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      signal: AbortSignal.timeout(AI_TIMEOUT_MS),
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + process.env.GROQ_API_KEY,
      },
      body: JSON.stringify({
        model: GROQ_MODEL,
        max_tokens: maxTokens,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userMessage },
        ],
      }),
    });
  } catch (err) {
    if (err.name === 'TimeoutError' || err.name === 'AbortError') {
      console.error(`Groq request timed out after ${AI_TIMEOUT_MS}ms`);
      throw new Error('groq_timeout');
    }
    console.error('Groq request failed:', err.message);
    throw new Error('groq_error');
  }

  if (!response.ok) {
    const errText = await response.text();
    console.error('Groq API error:', errText);
    throw new Error('groq_error');
  }

  const data = await response.json();
  return (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || '';
}

// Calls Gemini with text, and optionally an image (for the photo solver).
async function callGemini(systemPrompt, userText, image){
  const parts = [];
  if (image && image.data && image.media_type) {
    parts.push({ inline_data: { mime_type: image.media_type, data: image.data } });
  }
  parts.push({ text: userText || 'Solve the physics problem shown in this photo, step by step.' });

  let response;
  try {
    response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`,
      {
        method: 'POST',
        signal: AbortSignal.timeout(AI_TIMEOUT_MS),
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': process.env.GEMINI_API_KEY,
        },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: systemPrompt }] },
          contents: [{ parts }],
        }),
      }
    );
  } catch (err) {
    if (err.name === 'TimeoutError' || err.name === 'AbortError') {
      console.error(`Gemini request timed out after ${AI_TIMEOUT_MS}ms`);
      throw new Error('gemini_timeout');
    }
    console.error('Gemini request failed:', err.message);
    throw new Error('gemini_error');
  }

  if (!response.ok) {
    const errText = await response.text();
    console.error('Gemini API error:', errText);
    throw new Error('gemini_error');
  }

  const data = await response.json();
  const candidateParts = (data.candidates && data.candidates[0] && data.candidates[0].content && data.candidates[0].content.parts) || [];
  return candidateParts.map(p => p.text || '').join('\n');
}

// If the site is set to French, tell the AI to answer in French.
// Pins the output language explicitly, in BOTH directions.
//
// This used to add an instruction only for French and nothing at all otherwise, on the
// assumption that the model would default to English. It does not — and the prompts around it
// pull hard the other way: the exam prompts are steeped in "Lebanese Baccalaureate/Brevet"
// framing, and two Grade 9 topic names literally carry their French originals ("DC Voltage
// (Tension continue)", "Resistors (Conducteurs ohmiques)"). With no instruction to the
// contrary the model reads all that as a French-language context and writes the whole exam in
// French, for a student who set the site to English.
//
// So English is now stated as deliberately as French is. Never rely on a default.
function withLanguage(prompt, lang){
  if (lang === 'fr') {
    return prompt + `

LANGUAGE — this overrides any language cue elsewhere in this prompt:
Write your ENTIRE response in French: every question, explanation, heading, label and piece of feedback.
Physics symbols and units stay standard (U, I, R, m/s²), but all prose is French.`;
  }
  return prompt + `

LANGUAGE — this overrides any language cue elsewhere in this prompt:
Write your ENTIRE response in ENGLISH: every question, explanation, heading, label and piece of feedback.
This matters because the surrounding context is Lebanese and may mention French curriculum terms, French topic names, or the Baccalaureate — none of that changes the output language. Even where a topic name is given with its French original in brackets, write in English and use the English name.
Physics symbols and units stay standard (U, I, R, m/s²). Do not mix languages, and do not add French translations in brackets.`;
}

// This tool is used for homework help, so the #1 rule is: NEVER hand the student the finished
// answer in one shot. The response is a ladder of steps — a short "hint" for each step (a
// guiding question, no numbers/results) that the student sees first, and a "detail" (the full
// worked reasoning + calculation for that step) that is only revealed when the student asks
// for it, one step at a time. Only the LAST step's detail states the final answer.
const SYSTEM_PROMPT = `You are a physics tutor for Lebanese high school students (Lebanese national curriculum, grades 9-12 / Brevet-Bac), used as a HOMEWORK HELP tool. Your most important rule: never give the finished answer immediately. Students must work through guided steps themselves, not be handed a completed solution to copy.

When given a physics problem (as text, or shown in a photo), break the solution into a sequence of steps (usually 3-6 — as many as the problem genuinely needs, no more). Each step is an object with:
- "hint": a short guiding question or nudge for THIS step only (e.g. "What law relates pressure and depth here?" / "What two forces are acting on the object?"). It must contain NO numbers, results, or the answer to this step — it should make the student think, not tell them what to write.
- "detail": the full worked explanation for THIS step only — the reasoning, the relevant formula, and the calculation — revealed only after the student asks to see it. The "detail" of the LAST step must clearly state the final answer, with correct units.

If a photo of the student's OWN attempt is included alongside the problem, also include a top-level "feedback" string: briefly and gently note whether their attempt was on the right track and, if not, which step number they went wrong at — do not restate the full solution inside it, just point them back toward the right step. If no student attempt was included, set "feedback" to null.

The message may also contain a line beginning "The student's own first move:" — what they said they would try BEFORE any help appeared, written without seeing your steps. When that line is present, include a top-level "attemptResponse" string answering it directly: say whether that opening move was the right one. If it was, say so plainly before the steps begin ("Yes — energy conservation is exactly the right tool here"). If it wasn't, name what they reached for, say why it doesn't fit this problem, and point at what does — without solving it for them. Two or three sentences, addressed to the student as "you". Choosing the right first move is a real success and should be named as one; choosing the wrong one is the most useful thing they can learn from this problem. If there is no such line, set "attemptResponse" to null.

Keep language clear, concise, and appropriate for a high school student.

Respond with ONLY a single JSON object, nothing else — no markdown fences, no preamble, no text outside the JSON. Format:
{"steps": [{"hint": "...", "detail": "..."}, {"hint": "...", "detail": "..."}], "feedback": null, "attemptResponse": null}`;

// --- Solver topic classification ---
// The solver UI doesn't ask the student which topic/grade a problem is (that would add
// friction to a one-box "paste your problem" flow), so instead of a picker we classify the
// problem after the fact, using the same curriculum topics.js already seeds into the DB.
// This is a separate, cheap Groq text call (not another Gemini vision call) so it doesn't
// slow down or add cost to the actual solving.
const CLASSIFY_SYSTEM_PROMPT = `You classify a Lebanese high-school physics problem into the single best-matching grade and topic from a fixed curriculum list. You will be given the curriculum as "grade: topic1, topic2, ..." lines, and a physics problem (plus its worked solution).
Pick the ONE grade and ONE topic that best match, copying both EXACTLY (character-for-character) from the given list — never invent or paraphrase either one. If a grade was already told to you, only choose a topic from within that grade's list.
If you genuinely cannot match it to anything in the list, respond with {"grade": null, "topic": null}.
Respond with ONLY a single JSON object, nothing else — no markdown, no preamble. Format: {"grade": "g10", "topic": "Refraction of Light"}`;

function curriculumReference(onlyGrade){
  const grades = onlyGrade ? [onlyGrade] : Object.keys(CURRICULUM);
  return grades
    .filter(g => CURRICULUM[g])
    .map(g => `${g}: ${CURRICULUM[g].join(', ')}`)
    .join('\n');
}

// Best-effort — a classification failure should never break the actual solve response.
async function classifySolverTopic(problemText, solutionText, knownGrade){
  if (!process.env.GROQ_API_KEY) return null;
  try {
    const userMessage = `Curriculum:\n${curriculumReference(knownGrade)}\n\n${knownGrade ? `Grade: ${knownGrade}\n` : ''}Problem: ${problemText || '(submitted as a photo, see solution for context)'}\nSolution: ${solutionText}`;
    const text = await callGroq(withLanguage(CLASSIFY_SYSTEM_PROMPT, 'en'), userMessage, 100);
    const parsed = extractJsonObject(text);
    if (!parsed || !parsed.grade || !parsed.topic) return null;
    return { grade: parsed.grade, topic: parsed.topic };
  } catch (err) {
    console.error('Solver topic classification failed (non-fatal):', err.message || err);
    return null;
  }
}

app.get('/', (req, res) => {
  res.send('Physics tutor backend is running.');
});

// Some students are weaker in English than in the subject itself, and can get stuck on a
// question purely on VOCABULARY, not physics. This does NOT translate the whole question and
// does NOT solve anything — it picks out just the handful of English words/phrases in a
// question that a weak-English student might not know and explains them briefly in Arabic, so
// they understand what's being ASKED. Used as an optional per-question button in Question
// Bank / Practice Exam — never shown automatically, never affects grading or scoring.
const KEY_TERMS_HELPER_SYSTEM_PROMPT = `You help Lebanese physics students who are weaker in English understand a physics question written in English. You are NOT translating the whole question and NOT solving it — you are only explaining the handful of English words/phrases in the question that a weak-English (but not weak-physics) student might not recognize, so they understand what is being asked.

Rules:
- Pick only the important physics/technical/instructional words or short phrases (e.g. "terminal velocity", "at rest", "coefficient of friction", "increases", "in the opposite direction", "negligible") — usually 2-6 items. Do not list ordinary simple words.
- For each item, give the exact English word/phrase as it appears in the question, and a short Arabic (Lebanese colloquial is fine) explanation of what it means — a few words, not a full sentence essay.
- NEVER translate or reveal any numbers, the physics answer, or solve any part of the question. Do not explain the physics concept's solution — only the vocabulary/meaning.
- If the question has no real vocabulary barrier for a physics student, return an empty array — don't force it.

Respond with ONLY a single JSON array, nothing else — no markdown, no preamble. Format:
[{"term": "terminal velocity", "meaning": "السرعة النهائية يلي بيوصلها الجسم وما بتزيد بعدها"}]`;

app.post('/api/explain-terms', aiGuard, async (req, res) => {
  const { text } = req.body;
  if (!text || typeof text !== 'string' || !text.trim()) {
    return res.status(400).json({ error: 'Please provide the question text.' });
  }
  if (!process.env.GROQ_API_KEY) {
    return res.status(500).json({ error: 'Server is missing its API key. Set GROQ_API_KEY in the environment.' });
  }
  try {
    const raw = await callGroq(KEY_TERMS_HELPER_SYSTEM_PROMPT, `Question: ${text.trim()}`, 300);
    let terms = [];
    try {
      const parsed = extractJson(raw);
      if (Array.isArray(parsed)) terms = parsed;
    } catch (e) {
      // Non-fatal: the model sometimes answers "no hard vocabulary here" in plain text
      // instead of returning `[]` when a question has no real vocabulary barrier. Treat any
      // unparseable response as "no terms" rather than showing the student an error for what
      // is, functionally, a harmless empty result.
      console.warn('Key-terms response was not valid JSON, defaulting to empty list:', raw);
    }
    res.json({ terms });
  } catch (err) {
    if (err.message === 'groq_timeout') return res.status(504).json({ error: 'The AI service took too long to respond. Please try again in a moment.' });
    if (err.message === 'groq_error') {
      return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    }
    console.error('Explain-terms error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

app.post('/api/solve', aiGuard, async (req, res) => {
  // `grade` is optional and not sent by the UI today — if present (future UI change) it
  // narrows classification to that grade's topic list; if absent, classification searches
  // the whole curriculum and also guesses the grade.
  // `firstStep` is what the student said they would try before any help was shown. It turns the
  // solver from something that explains at them into something that answers their actual
  // thinking — "yes, energy conservation is the right tool" or "you reached for kinematics, but
  // the acceleration isn't constant here".
  const { problem, image, lang, grade, firstStep } = req.body;

  if ((!problem || typeof problem !== 'string' || !problem.trim()) && !image) {
    return res.status(400).json({ error: 'Please send a physics problem in the "problem" field, or attach an image.' });
  }

  if (!process.env.GEMINI_API_KEY) {
    return res.status(500).json({ error: 'Server is missing its API key. Set GEMINI_API_KEY in the environment.' });
  }

  try {
    const attempt = typeof firstStep === 'string' && firstStep.trim()
      ? firstStep.trim().slice(0, 600)
      : '';
    const userText = attempt
      ? `${problem || ''}\n\nThe student's own first move: ${attempt}`
      : problem;
    const raw = await callGemini(withLanguage(SYSTEM_PROMPT, lang), userText, image);

    let parsed;
    try {
      parsed = extractJsonObject(raw);
    } catch (e) {
      console.error('Failed to parse solver steps JSON:', raw);
      return res.status(502).json({ error: 'Could not generate a valid solution. Try again.' });
    }
    const steps = Array.isArray(parsed.steps)
      ? parsed.steps.filter(s => s && typeof s.hint === 'string' && typeof s.detail === 'string')
      : [];
    if (!steps.length) {
      console.error('Solver returned no usable steps:', raw);
      return res.status(502).json({ error: 'Could not generate a valid solution. Try again.' });
    }
    const feedback = typeof parsed.feedback === 'string' && parsed.feedback.trim() ? parsed.feedback.trim() : null;
    // Only surfaced when the student actually stated a first move — never invented for someone
    // who skipped the prompt.
    const attemptResponse = attempt && typeof parsed.attemptResponse === 'string' && parsed.attemptResponse.trim()
      ? parsed.attemptResponse.trim()
      : null;

    // Flatten to plain text for storage/classification. solver_history's `solution` column is
    // never displayed back in a list (/api/my/history only selects id, problem, created_at),
    // so restructuring what lives in it here is safe.
    const flatSolution = steps.map((s, i) => `Step ${i + 1}: ${s.hint}\n${s.detail}`).join('\n\n')
      + (feedback ? `\n\nFeedback on your attempt: ${feedback}` : '');

    if (pool && req.user) {
      pool.query(
        'INSERT INTO solver_history (user_id, problem, solution) VALUES ($1, $2, $3)',
        [req.user.userId, problem || '(photo)', flatSolution]
      ).catch(err => console.error('Failed to save solver history:', err));

      // Unified data model: log this as an ungraded attempt (source='solver'). `correct` is
      // left null — the solver isn't testing the student, it's solving for them, so
      // correctness doesn't apply unless/until the UI asks for the student's own attempt too.
      classifySolverTopic(problem, flatSolution, grade).then(match => {
        if (!match) return;
        resolveTopicId(match.grade, match.topic).then(topicId => {
          if (!topicId) return;
          pool.query(
            `INSERT INTO attempts (user_id, source, topic_id, question_text) VALUES ($1, 'solver', $2, $3)`,
            [req.user.userId, topicId, problem || '(photo)']
          ).catch(err => console.error('Failed to save solver attempt:', err));
        }).catch(err => console.error('Solver topic resolution failed:', err));
      }).catch(err => console.error('Solver topic classification failed:', err));
    }

    res.json({ steps, feedback, attemptResponse });
  } catch (err) {
    if (err.message === 'gemini_timeout') return res.status(504).json({ error: 'The AI service took too long to respond. Please try again in a moment.' });
    if (err.message === 'gemini_error') {
      return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    }
    console.error('Server error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

const STUDY_PLAN_SYSTEM_PROMPT = `You are a physics tutor for a Lebanese high school student, helping them prepare for their physics exam.
You will be given: the student's grade/branch, how many days are left until the exam, the specific lessons/topics they still need to cover (by name), and (optionally) other exams they have around the same time.
Build a clear, realistic day-by-day (or every-2-3-days if there are many days) study plan for the PHYSICS exam only:
- Use the actual lesson names given, in an order that makes sense for that grade level (foundational topics before topics that build on them).
- Spread the named lessons across the available days, front-loading harder or foundational topics.
- Leave 1-2 light review days right before the exam, not new material.
- If other exams are listed close to the physics exam date, lighten the physics workload on and right before those days so the student isn't overloaded, and mention this adjustment briefly.
- If the number of days is very tight relative to the number of lessons, say so honestly and prioritize the most important topics first, rather than pretending everything fits comfortably.
Keep the tone encouraging but realistic. Format as a simple day-by-day list.`;

app.post('/api/study-plan', aiGuard, async (req, res) => {
  const { grade, examDate, daysLeft, lessons, otherExams, lang } = req.body;

  if (!grade || daysLeft === undefined || !lessons) {
    return res.status(400).json({ error: 'Please provide the grade, exam date, and lessons left.' });
  }

  if (!process.env.GROQ_API_KEY) {
    return res.status(500).json({ error: 'Server is missing its API key. Set GROQ_API_KEY in the environment.' });
  }

  // If this student has taken any Diagnostic Tests (see /api/diagnostic/grade), pull their
  // weakest misconceptions per topic so the plan can lean on them directly instead of
  // treating every topic as a blank slate. Best-effort — a lookup failure never blocks
  // plan generation, it just falls back to the plan not knowing about diagnostic history.
  let diagnosticContext = '';
  if (pool && req.user) {
    try {
      const weak = await pool.query(
        `SELECT t.title AS topic_title, a.mistake_tag, COUNT(*) AS cnt
         FROM attempts a JOIN topics t ON t.id = a.topic_id
         WHERE a.user_id = $1 AND a.source = 'diagnostic' AND a.correct = false AND a.mistake_tag IS NOT NULL AND t.grade = $2
         GROUP BY t.title, a.mistake_tag
         ORDER BY t.title, cnt DESC`,
        [req.user.userId, grade]
      );
      if (weak.rows.length) {
        const byTopic = {};
        weak.rows.forEach(r => { (byTopic[r.topic_title] = byTopic[r.topic_title] || []).push(r.mistake_tag.split(':')[0].trim()); });
        diagnosticContext = '\n\nThis student took a diagnostic quiz before some of these topics and already showed these specific misconceptions — prioritize time on them and mention them by name in the plan:\n' +
          Object.keys(byTopic).map(t => `- ${t}: ${byTopic[t].join(', ')}`).join('\n');
      }
    } catch (err) {
      console.error('Diagnostic context lookup failed (non-blocking):', err);
    }
  }

  const userMessage = `Grade/branch: ${GRADE_LABELS[grade] || grade}
Exam date: ${examDate}
Days left until the exam: ${daysLeft}
Physics lessons/topics still to cover:
${lessons}

Other exams around the same time: ${typeof otherExams === 'string' && otherExams.trim() ? otherExams : 'None mentioned'}${diagnosticContext}

Build my physics study plan.`;

  try {
    const plan = await callGroq(withLanguage(STUDY_PLAN_SYSTEM_PROMPT, lang), userMessage, 2500);

    if (pool && req.user) {
      pool.query(
        'INSERT INTO study_plans (user_id, grade, exam_date, plan) VALUES ($1, $2, $3, $4)',
        [req.user.userId, grade, examDate, plan]
      ).catch(err => console.error('Failed to save study plan:', err));
    }

    res.json({ plan: plan || 'No plan returned.' });
  } catch (err) {
    if (err.message === 'groq_timeout') return res.status(504).json({ error: 'The AI service took too long to respond. Please try again in a moment.' });
    if (err.message === 'groq_error') {
      return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    }
    console.error('Server error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

// Practice Exam: the student picks a grade + lessons, gets a small set of FULL, multi-part
// "big problems" (scenario + lettered sub-questions), the way an official Lebanese
// Baccalaureate/Brevet physics exam is actually structured — not a pile of isolated
// tf/mcq/short-answer questions (that format lives on in Question Bank, unchanged).
// How many problems to generate is sized to how long a practice sitting for that grade is
// meant to represent: grades 7-10, Grade 11 Literary, and Grade 12 SE/Literature are treated
// as the 1-hour set; Grade 11 Scientific and Grade 12 Life Sciences/General Sciences are the
// 2-hour set. (Grade 11 Literary isn't explicitly split by the teacher's own duration split —
// grouped with the 1-hour set as the non-science-heavy stream at that level; easy to move to
// the other bucket if that's wrong.)
const EXAM_PROBLEM_COUNT = {
  g7: 3, g8: 3, g9: 3, g10: 3, g11lit: 3, bacse: 3,
  g11sci: 5, bacls: 5, bacgs: 5,
};

// How many output tokens to allow per generated question, by grade.
//
// This used to be inferred from whether a grade's allowed-type list contained "tf", which was
// wrong for exactly the grades that matter most: Grade 9, 10 and 11-Scientific are
// ["tf","problem"], so they were budgeted like short True/False grades while actually producing
// long scaffolded problems. Truncation is what corrupts a whole generation or grading run, so
// this is now set explicitly per grade — junior grades really do write short items, but from
// Grade 10 up a single question carries a "Given:" block and lettered sub-parts.
const TOKENS_PER_QUESTION = {
  g7: 220, g8: 240, g9: 300,
  g10: 380, g11lit: 380, g11sci: 420,
  bacse: 380, bacls: 440, bacgs: 440,
};
function tokensPerQuestion(grade){
  return TOKENS_PER_QUESTION[grade] || 380;
}

function examProblemCountFor(grade){
  return EXAM_PROBLEM_COUNT[grade] || 3;
}

// Friendlier label for the AI prompt only — `grade` itself stays the raw curriculum key
// (e.g. "g9") everywhere else (DB lookups, topic resolution), matching Question Bank/Lab/etc.
const GRADE_LABELS = {
  g7: 'Grade 7', g8: 'Grade 8', g9: 'Grade 9 — Brevet', g10: 'Grade 10',
  g11sci: 'Grade 11 — Scientific', g11lit: 'Grade 11 — Literary',
  bacse: 'Grade 12 — SE / Literature', bacls: 'Grade 12 — Life Sciences', bacgs: 'Grade 12 — General Sciences',
};

const EXAM_GEN_SYSTEM_PROMPT = `You are a physics exam writer for a Lebanese high school student, writing a FULL-LENGTH practice exam in the style of an official Lebanese Baccalaureate/Brevet physics exam — not a set of short isolated questions.
You will also be given a "Real Lebanese exam grounding" block for the exact grade — follow its phrasing/format conventions closely (command verbs like "Determine/Deduce/Justify/Show that", given-value conventions like g=10 N/kg or 10 m/s² stated explicitly, named local characters, realistic non-round numeric values) so the exam reads like a real Lebanese paper, not a generic international-textbook one.
Given a grade/branch, a specific list of lesson/chapter names the student chose to be tested on, and how many big problems to write, write exactly that many comprehensive multi-part problems, ordered from easiest to hardest overall.
Each problem should:
- Present a realistic physical scenario/setup (1-3 sentences — concrete numbers, objects, a situation), then walk the student through it via several lettered sub-questions ("parts"), the way real exam problems are structured (e.g. a) find X, b) use your answer to (a) to find Y, c) explain/interpret the result...).
- Have 3-5 parts, building logically where it makes sense (later parts may depend on earlier answers), mixing calculation parts with at least one short conceptual/explanation part.
- Be based on ONE of the given lessons (pick the best-fitting one). If asked for more than one problem, spread them across different lessons from the list rather than repeating the same lesson.
Respond with ONLY a JSON array, nothing else — no markdown, no preamble. Each object must have:
- "topic": the EXACT lesson name (copied verbatim, character-for-character) from the given lesson list that this problem is primarily about — never invent or paraphrase a topic name
- "difficulty": one of "easy", "medium", "hard"
- "scenario": the shared context/setup text for this problem
- "parts": an array of objects, each with "label" (a single letter — "a", "b", "c", ...) and "question" (that part's question text)
Example (note g=10 m/s², the Lebanese convention — not 9.8):
[{"topic":"Motion of a Particle in a Plane","difficulty":"easy","scenario":"A ball is launched from ground level at 20 m/s at 30° above the horizontal (g = 10 m/s²).","parts":[{"label":"a","question":"Determine the time it takes the ball to reach its maximum height."},{"label":"b","question":"Deduce the maximum height reached."},{"label":"c","question":"Determine the total horizontal range."}]}]`;

// Used by /api/question-bank/grade (unchanged format there: a list of small tf/mcq/problem
// questions, graded together in one text-only Groq call). Practice Exam grading now uses its
// own vision-based prompt below (EXAM_PROBLEM_GRADE_SYSTEM_PROMPT) — kept separate so the two
// features don't fight over one shared prompt/format.
const EXAM_GRADE_SYSTEM_PROMPT = `You are a physics teacher grading a Lebanese high school student's exam.
You will be given a list of questions (each with a type: "tf", "mcq", or "problem"; mcq ones include their choices; each question also lists its topic and, if the topic is a known one, the exact set of allowed mistake tags for that topic) and the student's answers, in the same order.
For each question, decide if the student's answer is correct — for "tf" and "mcq" compare against the correct option; for "problem" allow reasonable equivalent phrasing/units, don't require exact wording. Write short (1-2 sentence) feedback explaining why, and the correct answer if they got it wrong.
If the answer is INCORRECT, also pick exactly one "mistake_tag" from that question's allowed list that best describes the kind of error — use "other" only if none of the specific tags fit. If the answer is correct, omit "mistake_tag" (or set it to null).

SOME questions also include a line starting with "Student's stated method:" — this is what the student said they would use BEFORE working out the answer (which law, principle or formula applies). When that line is present you must ALSO judge the method itself:
- "method_correct": true if the stated law/principle/formula is the right one for this question, even if their final number is wrong. False if they reached for the wrong physics.
- "method_feedback": one short sentence on the method specifically — if it was wrong, name the correct law/formula and say briefly why it applies here.
Judge the method on physics, not on wording: "v squared equals 2 g h", "energy conservation" and "mgh = half m v squared" are all the same correct method. Accept a method stated in the student's own words, and accept it in French or Arabic.
This distinction matters more than the final mark: a student who picked the right law and slipped in the arithmetic needs completely different help from one who reached for the wrong law entirely. When the method is right but the answer is wrong, prefer a mistake_tag describing the execution error (a calculation or unit slip) rather than a conceptual one; when the method itself is wrong, prefer the conceptual tag.
Respond with ONLY a JSON array of objects, nothing else — no markdown, no preamble. Format:
[{"correct": true, "feedback": "short explanation"}, {"correct": false, "feedback": "short explanation with the correct answer", "mistake_tag": "one-of-the-allowed-tags", "method_correct": false, "method_feedback": "short note on the method"}]
Include "method_correct" and "method_feedback" ONLY for questions that had a stated method. The array must have exactly as many objects as there are questions, in the same order.`;

// Practice Exam grading is now per-problem and vision-based: the student photographs their
// handwritten work for one whole problem (all its parts together) instead of typing answers,
// so this prompt grades ONE problem at a time from a photo, matching a single Gemini vision call.
const EXAM_PROBLEM_GRADE_SYSTEM_PROMPT = `You are a physics teacher grading ONE problem from a Lebanese high school student's practice exam. You will be given the problem (its topic, scenario, and lettered parts) and a PHOTO of the student's handwritten solution to this problem. The photo may show messy handwriting, crossed-out work, and work for multiple parts together — read it carefully and match each piece of the student's work to the corresponding lettered part of the problem.
For EACH part, decide if the student's answer/reasoning for that part is correct — allow reasonable equivalent phrasing, rounding, and units, don't require exact wording or exact decimal precision. Write short (1-2 sentence) feedback per part explaining why, and the correct answer/approach if they got it wrong. If a part was left blank or is illegible, mark it incorrect and say so plainly.
If a part is INCORRECT, also pick exactly one "mistake_tag" from the allowed list for this problem's topic that best describes the kind of error — use "other" only if none of the specific tags fit. If a part is correct, omit "mistake_tag" (or set it to null).
Respond with ONLY a single JSON object, nothing else — no markdown, no preamble. Format:
{"parts": [{"label": "a", "correct": true, "feedback": "short explanation"}, {"label": "b", "correct": false, "feedback": "short explanation with the correct approach/answer", "mistake_tag": "one-of-the-allowed-tags"}], "overall_feedback": "one short encouraging sentence about this problem as a whole"}
The "parts" array must have exactly as many objects as the problem has parts, in the same order, matching each "label".`;

// Pulls a JSON array out of a model response.
//
// The old version was one greedy regex plus a straight JSON.parse, which threw on the single
// most common real failure: a TRUNCATED response. When the model hits its max_tokens limit
// mid-array there is no closing "]", the regex finds nothing, the raw parse throws, and the
// student just sees "Could not generate practice questions" — even though nine perfectly good
// questions arrived before the cut-off. Grade 11/12 questions are long multi-part problems, so
// this happens far more often at the higher grades than at Grade 7.
//
// Strategy, in order: parse as-is, strip markdown fences, then repair a truncated array by
// dropping the incomplete trailing object and closing the bracket.
function extractJson(text){
  if (typeof text !== 'string') throw new Error('extractJson: expected a string');
  // Callers all index, .map and .filter the result. Returning a bare object because the model
  // wrapped the array ({"questions":[...]}) used to blow up later as "results.filter is not a
  // function" — a 500 with no useful message. Enforce the contract here, once, and unwrap the
  // common wrapper shapes instead of failing on them.
  const asArray = (v) => {
    if (Array.isArray(v)) return v;
    if (v && typeof v === 'object') {
      for (const key of ['questions', 'problems', 'results', 'items', 'data']) {
        if (Array.isArray(v[key])) return v[key];
      }
    }
    throw new Error('extractJson: response was not a JSON array');
  };

  let s = text.trim();

  // Strip ```json ... ``` fences if present.
  s = s.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '').trim();

  // Fast path: the whole thing is valid JSON.
  try { return asArray(JSON.parse(s)); } catch (e) {
    if (/not a JSON array/.test(e.message)) throw e;
    /* otherwise fall through to extraction */
  }

  // Find where the array actually starts. Taking the FIRST "[" is wrong when the model writes a
  // preamble that itself contains a bracket ("use [brackets] like this:") — that locks onto the
  // prose and discards a perfectly good array further down. Only accept a "[" followed by
  // something a JSON array can legally begin with.
  const candidates = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== '[') continue;
    const next = s.slice(i + 1).match(/^\s*(.)/);
    if (next && (next[1] === '{' || next[1] === '"' || next[1] === '[' || next[1] === ']' || /[0-9tfn-]/.test(next[1]))) {
      candidates.push(i);
    }
  }
  if (!candidates.length) throw new Error('extractJson: no JSON array found');

  let body = null;
  for (const start of candidates) {
    const attempt = s.slice(start);
    const complete = attempt.match(/\[[\s\S]*\]/);
    if (complete) {
      try { return asArray(JSON.parse(complete[0])); } catch (e) { /* try the next candidate */ }
    }
    if (body === null) body = attempt;
  }
  body = body || s.slice(candidates[0]);

  // Repair a truncated array: keep everything up to the last complete top-level object.
  // Walk the string tracking string literals/escapes so a "]" or "}" inside a question's text
  // can't fool the depth count.
  let depth = 0, inStr = false, esc = false, lastGoodEnd = -1;
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (esc) { esc = false; continue; }
    if (c === '\\') { esc = true; continue; }
    if (c === '"') { inStr = !inStr; continue; }
    if (inStr) continue;
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) lastGoodEnd = i; }
  }
  if (lastGoodEnd !== -1) {
    const repaired = body.slice(0, lastGoodEnd + 1) + ']';
    const parsed = asArray(JSON.parse(repaired)); // if this throws, the caller's catch reports it
    console.warn(`extractJson: response was truncated — recovered ${parsed.length} complete item(s).`);
    return parsed;
  }
  throw new Error('extractJson: could not parse or repair the response');
}

// Object counterpart of extractJson, for the routes that expect a single JSON object rather
// than an array (formula explanations, exam-part grading, the solver, key terms, lab grading).
// Those all used a bare `text.match(/\{[\s\S]*\}/)` + JSON.parse, which has the same truncation
// weakness: one missing closing brace and the whole response is discarded.
//
// Repair strategy: close any string still open, then add the braces/brackets needed to balance
// what was opened. A trailing incomplete key/value is trimmed first. This recovers the fields
// that did arrive instead of losing the entire explanation.
function extractJsonObject(text){
  if (typeof text !== 'string') throw new Error('extractJsonObject: expected a string');
  // Callers dereference fields on the result. A bare array, a string, or literal `null` all
  // parse successfully and then throw further down as "cannot read property of null" — a 500
  // instead of a clean "try again". Enforce the shape here.
  const asObject = (v) => {
    if (v && typeof v === 'object' && !Array.isArray(v)) return v;
    throw new Error('extractJsonObject: response was not a JSON object');
  };

  let s = text.trim().replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '').trim();

  try { return asObject(JSON.parse(s)); } catch (e) {
    if (/not a JSON object/.test(e.message)) throw e;
    /* otherwise fall through to extraction */
  }

  const start = s.indexOf('{');
  if (start === -1) throw new Error('extractJsonObject: no JSON object found');
  let body = s.slice(start);

  const complete = body.match(/\{[\s\S]*\}/);
  if (complete) {
    try { return asObject(JSON.parse(complete[0])); } catch (e) { /* fall through to repair */ }
  }

  // Find the last point where a complete key/value pair had just finished — that is, the last
  // comma or closing bracket that was NOT inside a string literal. Everything after it is a
  // half-written pair (a truncated value, or a key with no value) and gets dropped wholesale.
  let inStr = false, esc = false, lastComplete = -1;
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (esc) { esc = false; continue; }
    if (c === '\\') { esc = true; continue; }
    if (c === '"') { inStr = !inStr; continue; }
    if (inStr) continue;
    if (c === ',' || c === '}' || c === ']') lastComplete = i;
  }
  if (lastComplete === -1) throw new Error('extractJsonObject: nothing recoverable');

  // Cut before a trailing comma; keep a closing bracket.
  let repaired = body[lastComplete] === ','
    ? body.slice(0, lastComplete)
    : body.slice(0, lastComplete + 1);

  // Close whatever structures are still open, innermost first.
  const open = [];
  let inStr2 = false, esc2 = false;
  for (let i = 0; i < repaired.length; i++) {
    const c = repaired[i];
    if (esc2) { esc2 = false; continue; }
    if (c === '\\') { esc2 = true; continue; }
    if (c === '"') { inStr2 = !inStr2; continue; }
    if (inStr2) continue;
    if (c === '{') open.push('}');
    else if (c === '[') open.push(']');
    else if (c === '}' || c === ']') open.pop();
  }
  while (open.length) repaired += open.pop();

  const parsed = asObject(JSON.parse(repaired));
  console.warn('extractJsonObject: response was truncated — recovered the fields that arrived.');
  return parsed;
}

app.post('/api/generate-exam', aiGuard, async (req, res) => {
  const { grade, lessons, lang } = req.body;

  if (!grade) {
    return res.status(400).json({ error: 'Please provide the grade.' });
  }
  if (!process.env.GROQ_API_KEY) {
    return res.status(500).json({ error: 'Server is missing its API key. Set GROQ_API_KEY in the environment.' });
  }

  // Fall back to the full curriculum list for this grade so the AI always has real, exact
  // topic names to copy into "topic" — never a vague "general topics" placeholder.
  const chosenLessons = Array.isArray(lessons) && lessons.length ? lessons : CURRICULUM[grade];
  const lessonList = chosenLessons && chosenLessons.length ? chosenLessons.join(', ') : 'general physics topics for this grade';
  const problemCount = examProblemCountFor(grade);
  const grounding = styleGroundingFor(grade);

  try {
    // Personalised to this student's recorded misconceptions across the grade — a practice exam
    // that quietly revisits what they keep getting wrong is worth far more than a random one.
    const personal = await mistakeGroundingFor(req.user && req.user.userId, grade, null);
    const userMessage = `Grade/branch: ${GRADE_LABELS[grade] || grade}\nLessons to draw problems from (use these EXACT names for "topic"): ${lessonList}\nNumber of big problems to write: ${problemCount}${grounding ? `\n\n${grounding}` : ''}${personal ? `\n\n${personal}` : ''}`;
    // Each "big problem" carries a scenario, a Given: block and several lettered sub-parts —
    // and at Grade 11/12 those are long. 550 tokens per problem (old ceiling 3500) was cutting
    // the array off partway through, which used to discard the entire exam.
    const examMaxTokens = Math.min(8000, 600 + problemCount * 1100);
    const text = await callGroq(withLanguage(EXAM_GEN_SYSTEM_PROMPT, lang), userMessage, examMaxTokens);
    let problems;
    try {
      problems = extractJson(text);
    } catch (e) {
      console.error(`Failed to parse exam problems (grade=${grade}, count=${problemCount}, maxTokens=${examMaxTokens}, len=${text.length}):`, e.message, '\nRAW:', text);
      return res.status(502).json({ error: 'The exam came back in an unreadable format. Please try again.' });
    }
    // A truncated response can still yield a usable, shorter exam — but not an empty one.
    problems = (Array.isArray(problems) ? problems : []).filter(p => p && Array.isArray(p.parts) && p.parts.length);
    if (!problems.length) {
      console.error(`No complete problems survived parsing (grade=${grade}). RAW:`, text);
      return res.status(502).json({ error: 'Could not generate a valid exam. Please try again.' });
    }
    res.json({ problems });
  } catch (err) {
    if (err.message === 'groq_timeout') return res.status(504).json({ error: 'The AI service took too long to respond. Please try again in a moment.' });
    if (err.message === 'groq_error') {
      return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    }
    console.error('Server error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

app.post('/api/grade-exam', aiGuard, async (req, res) => {
  // timeSpent is optional — an array of seconds per PROBLEM (not per part), same order as
  // `problems`. When absent every attempt is saved with time_spent_seconds = null.
  const { grade, problems, lang, timeSpent } = req.body;

  if (!grade || !Array.isArray(problems) || !problems.length) {
    return res.status(400).json({ error: 'Please provide the grade and at least one problem.' });
  }
  if (problems.some(p => !p || !Array.isArray(p.parts) || !p.parts.length)) {
    return res.status(400).json({ error: 'Each problem must include its parts.' });
  }
  if (problems.some(p => !p.image || !p.image.data)) {
    return res.status(400).json({ error: 'Please attach a photo of your work for every problem before submitting.' });
  }
  if (!process.env.GEMINI_API_KEY) {
    return res.status(500).json({ error: 'Server is missing its API key. Set GEMINI_API_KEY in the environment.' });
  }

  try {
    // One Gemini vision call per problem (each has its own photo), run concurrently so a
    // 5-problem exam doesn't grade 5x slower than a 1-problem one.
    const gradedProblems = await Promise.all(problems.map(async (p) => {
      const partsText = p.parts.map(part => `(${part.label}) ${part.question}`).join('\n');
      const allowedTags = tagsForTopic(p.topic).join(', ');
      const userText = `Topic: ${p.topic || 'Unknown'}\nScenario: ${p.scenario || ''}\nParts:\n${partsText}\nAllowed mistake tags if a part is incorrect: ${allowedTags}`;
      try {
        const text = await callGemini(withLanguage(EXAM_PROBLEM_GRADE_SYSTEM_PROMPT, lang), userText, p.image);
        const parsed = extractJsonObject(text);

        // Only accept a result that actually grades EVERY part with a real true/false verdict.
        //
        // Two ways this used to go wrong, both producing wrong answers the student never gave:
        //   1. The model returns valid JSON with no `parts` array at all (a refusal, or "the
        //      photo is unreadable"). The old fallback turned that into every part marked wrong
        //      — and, unlike the catch branch, it was recorded as a SUCCESSFUL grade.
        //   2. The response is truncated. extractJsonObject now repairs it, which means a
        //      partial `parts` array parses cleanly — the last entry has no `correct` key at
        //      all, and `!!undefined` scored it as wrong.
        // Both are grading failures, not student failures, so they must throw into the catch
        // below and be excluded from the score, the database and the review queue.
        if (!Array.isArray(parsed.parts)) {
          throw new Error('grader returned no parts array');
        }
        if (parsed.parts.length !== p.parts.length) {
          throw new Error(`grader returned ${parsed.parts.length} part(s) for a ${p.parts.length}-part problem`);
        }
        if (!parsed.parts.every(r => r && typeof r.correct === 'boolean')) {
          throw new Error('grader returned a part with no true/false verdict');
        }
        return {
          graded: true,
          parts: parsed.parts,
          overall_feedback: parsed.overall_feedback || '',
        };
      } catch (err) {
        // A grading FAILURE is not the same as the student being wrong. This used to return
        // every part as correct:false, which then flowed into the score, a permanent
        // exam_results row, one attempts row per part, and the spaced-review queue — so a
        // single API timeout fabricated a 0/12 in the student's history, dragged down their
        // mastery, the class analytics and the weekly digest, and scheduled reviews for
        // misconceptions they never had. `graded: false` marks it as "no result" instead, and
        // everything downstream skips it.
        console.error('Failed to grade a problem (excluded from scoring):', err.message || err);
        return {
          graded: false,
          parts: p.parts.map(part => ({ label: part.label, correct: null, feedback: 'This problem could not be graded — please resubmit it.' })),
          overall_feedback: 'Grading failed for this problem, so it has been left out of your score. Try submitting it again.',
        };
      }
    }));

    const ungradedCount = gradedProblems.filter(g => g.graded === false).length;
    // If nothing could be graded at all, this is a service failure, not a 0% result — say so
    // rather than handing the student a fake zero.
    if (ungradedCount === gradedProblems.length) {
      return res.status(502).json({
        error: 'Your answers could not be graded right now — the AI service did not respond. Nothing was saved; please try submitting again in a moment.'
      });
    }

    // Score is counted at the PART level (a "big problem" is really several mini-questions),
    // which also keeps individual mistakes granular for the mistake-tag breakdown below.
    // Problems that failed to grade are skipped entirely so they can't distort the score.
    let correctParts = 0, totalParts = 0;
    const mistakeCounts = {};
    const topicMissCounts = {};
    gradedProblems.forEach((g, pi) => {
      if (g.graded === false) return;
      const topic = problems[pi].topic;
      g.parts.forEach(part => {
        totalParts++;
        if (part.correct) { correctParts++; return; }
        const label = shortTagLabel(part.mistake_tag || 'other');
        mistakeCounts[label] = (mistakeCounts[label] || 0) + 1;
        if (topic) topicMissCounts[topic] = (topicMissCounts[topic] || 0) + 1;
      });
    });
    const scorePct = totalParts > 0 ? Math.round((correctParts / totalParts) * 1000) / 10 : 0;

    let recommendedTopic = null;
    let maxMisses = 0;
    Object.keys(topicMissCounts).forEach(t => {
      if (topicMissCounts[t] > maxMisses) { maxMisses = topicMissCounts[t]; recommendedTopic = t; }
    });
    const recommendedRevision = recommendedTopic
      ? `${recommendedTopic} Revision`
      : (scorePct >= 85 ? 'Great job — no major gaps this time.' : 'Keep practicing — review your incorrect parts above.');

    if (pool && req.user) {
      // Store the grading outcome alongside each part, not just the question text. Previously
      // only the questions were saved, which meant a past exam could show a score but never
      // "here is the part you got wrong, and why" — the single most useful thing to revisit.
      // Only problems that actually graded are stored. `schemaVersion` lets the review screen
      // tell this shape apart from rows written before per-part results were saved.
      const reviewSnapshot = problems.map((p, pi) => {
        const g = gradedProblems[pi] || {};
        if (g.graded === false) return null;
        return {
          topic: p.topic,
          difficulty: p.difficulty,
          scenario: p.scenario,
          parts: p.parts.map((part, parti) => {
            const r = (g.parts && g.parts[parti]) || {};
            return {
              label: part.label,
              question: part.question,
              correct: !!r.correct,
              feedback: r.feedback || null,
              mistakeTag: r.correct ? null : (r.mistake_tag || null),
            };
          }),
        };
      }).filter(Boolean);
      pool.query(
        'INSERT INTO exam_results (user_id, grade, score, total, questions) VALUES ($1, $2, $3, $4, $5)',
        [req.user.userId, grade, correctParts, totalParts, JSON.stringify(reviewSnapshot)]
      ).catch(err => console.error('Failed to save exam result:', err));

      // Unified data model: one `attempts` row per PART (not per photo/problem), fire-and-forget
      // so a slow/failed insert never blocks the response the student is waiting on.
      problems.forEach((p, pi) => {
        const g = gradedProblems[pi];
        // A problem that failed to grade has no real result — recording it would invent a
        // wrong answer the student never gave, and poison mastery and the review queue.
        if (!g || g.graded === false) return;
        const spent = Array.isArray(timeSpent) ? (Number(timeSpent[pi]) || null) : null;
        resolveTopicId(grade, p.topic).then(topicId => {
          p.parts.forEach((part, parti) => {
            const r = g.parts[parti] || {};
            pool.query(
              `INSERT INTO attempts
                (user_id, source, topic_id, difficulty, question_text, student_answer, correct, mistake_tag, time_spent_seconds)
               VALUES ($1, 'exam', $2, $3, $4, $5, $6, $7, $8)`,
              [req.user.userId, topicId, p.difficulty || null, `(${part.label}) ${part.question}`, '(photo submission)', !!r.correct, r.correct ? null : (r.mistake_tag || 'other'), spent]
            ).catch(err => console.error('Failed to save exam attempt:', err));
            // Every wrong part schedules its misconception for spaced review.
            if (!r.correct) scheduleReview(req.user.userId, topicId, r.mistake_tag || 'other');
          });
        }).catch(err => console.error('Exam topic resolution failed:', err));
      });
    }

    res.json({
      results: gradedProblems,
      score: correctParts,
      total: totalParts,
      scorePct,
      mistakeCounts,
      recommendedTopic,
      recommendedRevision,
      // Lets the exam page tell the student which problems still need resubmitting, instead of
      // showing them a silently-deflated score.
      ungradedCount,
      partiallyGraded: ungradedCount > 0,
    });
  } catch (err) {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

// --- Question Bank ---
// Unlike Practice Exam (multi-lesson, fixed at 5 questions), this is focused, repeatable
// practice on ONE topic at a time, with a chosen difficulty/style and question count —
// Grade -> Topic -> Easy/Medium/Hard/Exam-style/Past-paper-style -> N questions -> score +
// mistakes + a recommended next step. Attempts are logged with source='question_bank' (kept
// separate from source='exam' so the Dashboard's "exam average" stat keeps meaning full
// practice exams only) but still feed the same unified mastery/mistake data everywhere else.
const QUESTION_BANK_GEN_SYSTEM_PROMPT = `You are a physics question writer for a Lebanese high school student practicing ONE specific topic in a focused, repeatable set (not a full multi-topic exam).
You will be given: grade/branch, ONE topic name, a difficulty/style, how many questions to write, and a "Real Lebanese exam grounding" block for this exact grade — READ IT CAREFULLY and follow it closely. Real Lebanese exams have a distinct house style (specific command verbs, True/False items that require correcting the false statement, explicit given-value conventions like g=10 N/kg, and — critically — different grades use different question TYPES in real exams, e.g. Grade 12 never uses true/false or multiple-choice at all). Writing generic international-textbook-style questions instead of matching this grounding is exactly the mistake to avoid.
Write EXACTLY that many questions, ALL about the given topic only, using ONLY the question types listed as real for this grade in the grounding block.
Difficulty/style meanings:
- "easy": simple recall or single-step questions.
- "medium": typical homework-level questions, may need two steps.
- "hard": multi-step or conceptually tricky questions.
- "examstyle": formal, rigorous exam-style questions on this one topic, similar to how it would be tested in an official Lebanese exam.
- "pastpaper": written in the phrasing/structure typical of official Lebanese Baccalaureate/Brevet past exam papers for this topic — write entirely NEW questions in that style, never claim to reproduce or recall a real past question.
Respond with ONLY a JSON array, nothing else — no markdown, no preamble. Each object must have:
- "type": one of "tf", "mcq", "problem" (only types present in the grounding block's allowed list for this grade)
- "question": the question text
- "choices": an array of 3-4 answer options (ONLY for "mcq"; omit for "tf" and "problem")
The array must have exactly the requested number of objects.`;

const QUESTION_BANK_DIFFICULTIES = ['easy', 'medium', 'hard', 'examstyle', 'pastpaper'];

// --- Mistake-aware generation ---
// The `attempts` table has been recording a mistake_tag for every wrong answer since the
// unified data model went in, but until now nothing read it back when generating new practice.
// A student could get the same misconception wrong ten times and keep being served questions
// picked purely from a difficulty dropdown.
//
// This looks up what this specific student actually gets wrong — first within the topic they
// asked for, then (if there's nothing there yet) across their whole grade — and returns a short
// instruction block for the generation prompt telling the model to target those misconceptions.
// Returns '' when there's no history, so a brand-new student's experience is unchanged.
async function mistakeGroundingFor(userId, grade, topicTitle){
  if (!pool || !userId) return '';
  try {
    // Prefer mistakes on the exact topic; fall back to the student's grade-wide pattern so a
    // first visit to a new topic still benefits from what we know about them.
    const scoped = topicTitle ? await pool.query(
      `SELECT a.mistake_tag, COUNT(*) AS cnt
         FROM attempts a
         JOIN topics t ON t.id = a.topic_id
        WHERE a.user_id = $1 AND a.correct = false AND a.mistake_tag IS NOT NULL
          AND t.grade = $2 AND t.title = $3
          AND a.created_at > NOW() - INTERVAL '120 days'
        GROUP BY a.mistake_tag ORDER BY cnt DESC LIMIT 3`,
      [userId, grade, topicTitle]
    ) : { rows: [] };

    let rows = scoped.rows;
    let scopeLabel = `on "${topicTitle}"`;
    if (!rows.length) {
      const wide = await pool.query(
        `SELECT a.mistake_tag, COUNT(*) AS cnt
           FROM attempts a
           JOIN topics t ON t.id = a.topic_id
          WHERE a.user_id = $1 AND a.correct = false AND a.mistake_tag IS NOT NULL
            AND t.grade = $2
            AND a.created_at > NOW() - INTERVAL '120 days'
          GROUP BY a.mistake_tag ORDER BY cnt DESC LIMIT 3`,
        [userId, grade]
      );
      rows = wide.rows;
      scopeLabel = 'across this grade';
    }
    if (!rows.length) return '';

    const list = rows.map(r => `- ${shortTagLabel(r.mistake_tag)} (got this wrong ${r.cnt} time${Number(r.cnt) === 1 ? '' : 's'})`).join('\n');
    return `This student's recorded weak points ${scopeLabel}:
${list}
Deliberately include at least one question that targets the first weak point above, and where it fits naturally, a second targeting another. Do NOT mention this list, the student's history, or that any question is "targeted" — the questions must read exactly like ordinary practice questions.`;
  } catch (err) {
    // Personalisation is a bonus, never a requirement — a failure here must not block practice.
    console.error('Mistake grounding lookup failed (continuing without it):', err.message);
    return '';
  }
}

// --- Worksheet answer key ---
// For paper lessons: the same generated question set, plus model answers for the teacher.
// This is the one place in the app where full worked answers are produced on purpose — it is
// gated behind requireAdmin, so it is only ever the teacher's copy, never a student's.
const ANSWER_KEY_SYSTEM_PROMPT = `You are a Lebanese physics teacher writing the ANSWER KEY for a worksheet you are about to hand out.
You will be given a grade, a topic, and a numbered list of questions.
For each question write the model answer a teacher would put on their own copy: the final answer, and the key steps or reasoning in the way it should be marked. Keep each one tight — a few lines, not a full essay. Use the Lebanese conventions for this grade (g = 10 m/s² or N/kg, U for voltage from Grade 9 up, P = F/S for pressure, SI units throughout).
Where a question could be marked on method as well as the final number, say briefly what earns the marks.
Respond with ONLY a JSON array of strings, nothing else — no markdown, no preamble. One string per question, in the same order:
["Answer to Q1 with the key steps.", "Answer to Q2 ..."]
The array must have exactly as many strings as there are questions.`;

// One short guiding hint for a student who's stuck on a practice question and hasn't
// answered yet — same "never give the answer away" philosophy as the Solver, applied here so
// a stuck student has somewhere to go besides leaving it blank or guessing.
const QUESTION_BANK_HINT_SYSTEM_PROMPT = `You are a physics teacher giving ONE short hint to a Lebanese high school student who is stuck on a practice question and has NOT answered it yet. You will be given the topic and the question text.
Give ONE short guiding hint (1-2 sentences) — remind them which law/formula/concept applies here, or what to look at or consider first.
Do NOT give the final answer, any numeric result, or the full solution. Do not solve any part of the problem for them.
Respond with ONLY the hint text, nothing else — no JSON, no markdown, no preamble.`;

app.post('/api/question-bank/generate', aiGuard, async (req, res) => {
  const { grade, topic, difficulty, count, lang } = req.body;
  if (!grade || !CURRICULUM[grade]) return res.status(400).json({ error: 'Please provide a valid grade.' });
  if (!topic || !CURRICULUM[grade].includes(topic)) return res.status(400).json({ error: 'Unknown topic for this grade.' });
  if (!process.env.GROQ_API_KEY) return res.status(500).json({ error: 'Server is missing its API key. Set GROQ_API_KEY in the environment.' });

  const diff = QUESTION_BANK_DIFFICULTIES.includes(difficulty) ? difficulty : 'medium';
  const n = Math.min(15, Math.max(3, Number(count) || 10));

  try {
    const grounding = styleGroundingFor(grade);
    const personal = await mistakeGroundingFor(req.user && req.user.userId, grade, topic);
    const userMessage = `Grade/branch: ${GRADE_LABELS[grade] || grade}\nTopic: ${topic}\nDifficulty/style: ${diff}\nNumber of questions: ${n}${grounding ? `\n\n${grounding}` : ''}${personal ? `\n\n${personal}` : ''}`;
    const maxTokens = Math.min(6000, 400 + n * tokensPerQuestion(grade));
    const text = await callGroq(withLanguage(QUESTION_BANK_GEN_SYSTEM_PROMPT, lang), userMessage, maxTokens);
    let questions;
    try {
      questions = extractJson(text);
    } catch (e) {
      console.error(`Failed to parse question bank JSON (grade=${grade}, topic="${topic}", maxTokens=${maxTokens}, len=${text.length}):`, e.message, '\nRAW:', text);
      return res.status(502).json({ error: 'The practice questions came back in an unreadable format. Please try again.' });
    }
    if (!Array.isArray(questions)) {
      console.error(`Question bank response was not an array (grade=${grade}):`, text);
      return res.status(502).json({ error: 'The practice questions came back in an unexpected shape. Please try again.' });
    }
    // Defensive filter: keep only the types real exams actually use at this grade, in case the
    // model drifts (e.g. slips in an MCQ for Grade 12, which never uses one in practice).
    const allowedTypes = (GRADE_STYLE_GUIDE[grade] && GRADE_STYLE_GUIDE[grade].types) || ['tf', 'mcq', 'problem'];
    const beforeFilter = questions.filter(Boolean);
    const filtered = beforeFilter.filter(q => allowedTypes.includes(q.type || 'problem'));
    if (filtered.length) {
      questions = filtered;
    } else if (beforeFilter.length) {
      // The model returned usable questions, but all in a type this grade doesn't normally use.
      // Showing slightly off-style questions is much better than showing the student an error
      // and nothing to practise with — so fall back to the unfiltered set and log it loudly so
      // the grade's type list in curriculum_style.js can be corrected.
      console.warn(`Type filter emptied the set for grade "${grade}" (allowed: ${allowedTypes.join(', ')}; got: ${[...new Set(beforeFilter.map(q => q.type || 'problem'))].join(', ')}). Serving unfiltered.`);
      questions = beforeFilter;
    } else {
      console.error('No usable questions returned for grade', grade, '- raw:', text);
      return res.status(502).json({ error: 'Could not generate practice questions. Try again.' });
    }
    // Stamp topic (and difficulty, as a fallback) on every question so grading/mistake-tagging
    // can resolve it the same way generate-exam's questions carry their topic.
    questions.forEach(q => { q.topic = topic; if (!q.difficulty) q.difficulty = diff; });
    res.json({ topic, difficulty: diff, questions });
  } catch (err) {
    if (err.message === 'groq_timeout') return res.status(504).json({ error: 'The AI service took too long to respond. Please try again in a moment.' });
    if (err.message === 'groq_error') {
      return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    }
    console.error('Question bank generate error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

app.post('/api/question-bank/hint', aiGuard, async (req, res) => {
  const { grade, topic, question, lang } = req.body;
  if (!question || typeof question !== 'string' || !question.trim()) {
    return res.status(400).json({ error: 'Please provide the question text.' });
  }
  if (!process.env.GROQ_API_KEY) {
    return res.status(500).json({ error: 'Server is missing its API key. Set GROQ_API_KEY in the environment.' });
  }
  try {
    const userMessage = `Grade/branch: ${GRADE_LABELS[grade] || grade || 'Unknown'}\nTopic: ${topic || 'Unknown'}\nQuestion: ${question}`;
    const hint = await callGroq(withLanguage(QUESTION_BANK_HINT_SYSTEM_PROMPT, lang), userMessage, 120);
    res.json({ hint: (hint || '').trim() || 'Think about which law or formula applies here.' });
  } catch (err) {
    if (err.message === 'groq_timeout') return res.status(504).json({ error: 'The AI service took too long to respond. Please try again in a moment.' });
    if (err.message === 'groq_error') {
      return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    }
    console.error('Question bank hint error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

app.post('/api/question-bank/grade', aiGuard, async (req, res) => {
  // assignmentId marks this as a homework submission. It reuses this whole route rather than
  // duplicating the grading pipeline — the only difference is that the result is also recorded
  // against the assignment, and the attempts are tagged source='assignment' so the teacher's
  // per-assignment mistake breakdown can find them.
  // `methods` is optional and parallel to `answers`: what the student said they would USE to
  // solve each problem, committed before they were allowed to type a final answer. It is what
  // separates "doesn't understand the physics" from "understands it but slipped in the
  // arithmetic" — the distinction the teacher actually needs to know what to reteach.
  const { answers, methods, lang, isReview, assignmentId } = req.body;
  let { grade, topic, questions } = req.body;
  if (!process.env.GROQ_API_KEY) {
    return res.status(500).json({ error: 'Server is missing its API key. Set GROQ_API_KEY in the environment.' });
  }

  // --- Homework: grade the paper we issued, never the one the browser sends back ---
  //
  // Without this, marking homework was trivially cheatable: a student could call this endpoint
  // with their real assignmentId but one easy question of their own ("Is 1+1=2?"), and the
  // teacher's gradebook would record 1/1 = 100%. Everything that decides the grade — the
  // questions, the topic and the grade key — is therefore re-read from the stored submission
  // and overrides whatever arrived in the body. The client's `answers` are the only thing it
  // is trusted to supply.
  //
  // Loading the row first also lets an already-submitted or never-started assignment be
  // rejected BEFORE any AI call, which stops a resubmit from double-writing attempts, mastery
  // and the review queue (and from spending another unit of the student's daily AI budget).
  let assignmentRow = null;
  if (assignmentId !== undefined && assignmentId !== null) {
    const aId = Number(assignmentId);
    if (!Number.isInteger(aId) || aId <= 0) return res.status(400).json({ error: 'Invalid assignment id.' });
    if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
    try {
      const found = await pool.query(
        `SELECT s.questions, s.status, a.id AS assignment_id, a.grade, a.archived, t.title AS topic
           FROM assignment_submissions s
           JOIN assignments a ON a.id = s.assignment_id
           JOIN topics t ON t.id = a.topic_id
          WHERE s.assignment_id = $1 AND s.user_id = $2`,
        [aId, req.user.userId]
      );
      if (!found.rows.length) {
        return res.status(404).json({ error: "You haven't started this homework yet. Open it from your dashboard first." });
      }
      assignmentRow = found.rows[0];
      if (assignmentRow.status === 'completed') {
        return res.status(409).json({ error: 'You have already handed this homework in.', alreadySubmitted: true });
      }
      if (!Array.isArray(assignmentRow.questions) || !assignmentRow.questions.length) {
        return res.status(409).json({ error: 'Your question set could not be found. Please open the homework again from your dashboard.' });
      }
      // Authoritative values, replacing anything the client sent.
      questions = assignmentRow.questions;
      grade = assignmentRow.grade;
      topic = assignmentRow.topic;
    } catch (err) {
      console.error('Assignment lookup failed:', err);
      return res.status(500).json({ error: 'Could not check this homework. Please try again.' });
    }
  }

  if (!grade || !CURRICULUM[grade]) return res.status(400).json({ error: 'Please provide a valid grade.' });
  if (!topic || !CURRICULUM[grade].includes(topic)) return res.status(400).json({ error: 'Unknown topic for this grade.' });
  if (!Array.isArray(questions) || !Array.isArray(answers) || questions.length !== answers.length || !questions.length) {
    return res.status(400).json({ error: 'Please provide matching questions and answers.' });
  }

  // Every element must be usable before we build the prompt. This used to run OUTSIDE the try
  // block below, so a null entry threw a TypeError that Express could not catch — the request
  // then hung with no response at all until the browser gave up.
  if (!questions.every(q => typeof q === 'string' || (q && typeof q.question === 'string'))) {
    return res.status(400).json({ error: 'One of the questions was malformed. Please regenerate the set.' });
  }

  try {
    const statedMethods = Array.isArray(methods) ? methods : [];
    const pairs = questions.map((q, i) => {
      const qText = typeof q === 'string' ? q : q.question;
      const qType = typeof q === 'string' ? 'problem' : (q.type || 'problem');
      const choicesLine = (qType === 'mcq' && Array.isArray(q.choices)) ? `\nChoices: ${q.choices.join(', ')}` : '';
      const m = typeof statedMethods[i] === 'string' ? statedMethods[i].trim() : '';
      const methodLine = m ? `\nStudent's stated method: ${m}` : '';
      return `Q${i + 1} (${qType}): ${qText}${choicesLine}\nAllowed mistake tags if incorrect: ${tagsForTopic(topic).join(', ')}${methodLine}\nStudent's answer: ${answers[i]}`;
    }).join('\n\n');
    const userMessage = `Grade/branch: ${grade}\nTopic: ${topic}\n\n${pairs}`;

    // A method judgement adds a sentence per question to the response.
    const gradeMaxTokens = Math.min(5000, 300 + questions.length * (statedMethods.length ? 260 : 180));
    const text = await callGroq(withLanguage(EXAM_GRADE_SYSTEM_PROMPT, lang), userMessage, gradeMaxTokens);
    let results;
    try {
      results = extractJson(text);
    } catch (e) {
      console.error(`Failed to parse question bank grading (grade=${grade}, topic="${topic}", n=${questions.length}):`, e.message, '\nRAW:', text);
      return res.status(502).json({ error: 'Could not grade this set. Please try again.' });
    }

    // The grader must return one verdict per question. A short array (truncated response) used
    // to be padded silently with `results[i] || {}`, which recorded every ungraded question as
    // WRONG in the database while showing the student no badge for it at all — an invented
    // mistake that then fed mastery, the teacher dashboard and the spaced-review queue.
    if (results.length !== questions.length) {
      console.error(`Grader returned ${results.length} result(s) for ${questions.length} question(s) — rejecting rather than guessing.`);
      return res.status(502).json({ error: 'Grading came back incomplete. Please submit again.' });
    }
    if (!results.every(r => r && typeof r.correct === 'boolean')) {
      console.error('Grader returned an entry with no true/false verdict — rejecting.');
      return res.status(502).json({ error: 'Grading came back incomplete. Please submit again.' });
    }

    const score = results.filter(r => r.correct).length;

    // Mistake-tag breakdown for this one session — powers the "you lost N marks because of..."
    // summary, using the same short labels as everywhere else (colon-suffix stripped).
    const mistakeCounts = {};
    results.forEach(r => {
      if (!r.correct) {
        const label = shortTagLabel(r.mistake_tag || 'other');
        mistakeCounts[label] = (mistakeCounts[label] || 0) + 1;
      }
    });

    // Split the wrong answers into the two kinds that need different teaching. This is the
    // headline the student sees now instead of a bare score: getting three questions wrong
    // because of arithmetic is a completely different situation from getting three wrong
    // because the wrong law was used, and a percentage hides that entirely.
    // A method verdict only counts when the student ACTUALLY stated a method. The model is told
    // to emit method_correct only for those questions, but it isn't a contract we can rely on —
    // and an unprompted verdict would put a "✕ Wrong method" badge on a True/False question the
    // student was never asked a method for, and write method_correct with stated_method NULL,
    // which then feeds the teacher's reteach columns as if it were real evidence.
    const hasStatedMethod = (i) => typeof statedMethods[i] === 'string' && statedMethods[i].trim().length > 0;
    results.forEach((r, i) => {
      if (!hasStatedMethod(i)) {
        // Drop anything the model volunteered here so it can't reach the student or the DB.
        delete r.method_correct;
        delete r.method_feedback;
      }
    });

    let methodRight = 0, methodWrong = 0, slips = 0;
    results.forEach((r, i) => {
      if (typeof r.method_correct !== 'boolean') return;
      if (r.method_correct) {
        methodRight++;
        if (!r.correct) slips++;   // right physics, wrong number
      } else {
        methodWrong++;
      }
    });
    const methodSummary = (methodRight + methodWrong) > 0
      ? { asked: methodRight + methodWrong, methodRight, methodWrong, slips }
      : null;

    // Only tag as homework once the submission row has actually been verified above — otherwise
    // any student could post a made-up assignmentId and inject rows into the teacher's
    // per-assignment mistake breakdown without ever being set that homework.
    const attemptSource = assignmentRow ? 'assignment' : 'question_bank';
    const attemptAssignmentId = assignmentRow ? assignmentRow.assignment_id : null;

    if (pool && req.user) {
      resolveTopicId(grade, topic).then(topicId => {
        questions.forEach((q, i) => {
          const qText = typeof q === 'string' ? q : q.question;
          const r = results[i] || {};
          const statedMethod = typeof statedMethods[i] === 'string' && statedMethods[i].trim()
            ? statedMethods[i].trim().slice(0, 500)
            : null;
          pool.query(
            `INSERT INTO attempts (user_id, source, topic_id, difficulty, question_text, student_answer, correct, mistake_tag, assignment_id, method_correct, stated_method)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
            [req.user.userId, attemptSource, topicId, (q && q.difficulty) || null, qText, answers[i],
             !!r.correct, r.correct ? null : (r.mistake_tag || 'other'), attemptAssignmentId,
             typeof r.method_correct === 'boolean' ? r.method_correct : null, statedMethod]
          ).catch(err => console.error('Failed to save question bank attempt:', err));
        });
        // Spaced review bookkeeping. When this set was served as a review session
        // (isReview=true), the result updates the existing queue entry — right answers push the
        // misconception further out, wrong ones bring it back tomorrow. Otherwise a wrong
        // answer schedules it fresh.
        if (isReview) {
          // A review set deliberately contains MORE questions than due tags (see
          // /api/my/review/start), so the same tag usually appears more than once. Aggregate
          // per tag before deciding: the misconception only counts as re-learned if EVERY
          // question testing it was right. Taking just the first result would let a student
          // who got one right and one wrong keep advancing the box until it retired.
          const byTag = new Map();
          results.forEach((r, i) => {
            const q = questions[i];
            const tag = shortTagLabel((q && q.reviewTag) || r.mistake_tag || 'other');
            byTag.set(tag, (byTag.get(tag) !== false) && !!r.correct);
          });
          byTag.forEach((allCorrect, tag) => {
            recordReviewResult(req.user.userId, topicId, tag, allCorrect);
          });
        } else {
          results.forEach(r => {
            if (!r.correct) scheduleReview(req.user.userId, topicId, r.mistake_tag || 'other');
          });
        }
      }).catch(err => console.error('Question bank topic resolution failed:', err));
    }

    const scorePct = Math.round((score / results.length) * 1000) / 10;
    const recommendedRevision = scorePct < 60
      ? `Revise ${topic} before moving on — the fundamentals here still need work.`
      : (scorePct < 85
        ? `Solid on ${topic}, but a bit more practice would help before your exam.`
        : `Strong work on ${topic} — you're ready to move on to the next topic.`);

    // Mark the homework submitted. Awaited, not fire-and-forget: if this write fails the
    // student must NOT be told their homework is in, or it would show as missing on the
    // teacher's list while they believe they handed it in.
    let assignmentSaved = false;
    if (pool && req.user && assignmentId) {
      const aId = Number(assignmentId);
      if (Number.isInteger(aId) && aId > 0) {
        try {
          const upd = await pool.query(
            `UPDATE assignment_submissions
                SET status = 'completed', score = $3, total = $4, submitted_at = NOW()
              WHERE assignment_id = $1 AND user_id = $2 AND status <> 'completed'
              RETURNING id`,
            [aId, req.user.userId, score, results.length]
          );
          assignmentSaved = upd.rows.length > 0;
          if (!assignmentSaved) {
            console.warn(`Assignment ${aId} submission for user ${req.user.userId} was already completed or missing.`);
          }
        } catch (err) {
          console.error('Failed to record assignment submission:', err);
        }
      }
    }

    res.json({
      results, score, total: results.length, scorePct, mistakeCounts, recommendedRevision,
      methodSummary,
      ...(assignmentId ? { assignmentSaved } : {}),
    });
  } catch (err) {
    if (err.message === 'groq_timeout') return res.status(504).json({ error: 'The AI service took too long to respond. Please try again in a moment.' });
    if (err.message === 'groq_error') {
      return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    }
    console.error('Question bank grade error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

// --- Diagnostic Test ---
// A short quiz (one question per known misconception for the topic) shown automatically
// the first time a student opens a lesson, BEFORE the lesson content. The point isn't a
// score — it's finding out which specific misconceptions the student already has, so the
// teacher sees it and the next study plan the student generates leans on it. Reuses the
// same MISTAKE_TAXONOMY tags as everywhere else in the app, so results plug straight into
// the Teacher Dashboard's existing mistake tracking with no separate system to maintain.
const DIAGNOSTIC_START_SYSTEM_PROMPT = `You are writing a short diagnostic quiz for a Lebanese physics student who is about to start a new topic, to reveal what they already know before they begin.
You will be given the topic name and a list of specific misconception/mistake types for that topic. Write EXACTLY one question per mistake type given — each question must be specifically designed so that a WRONG answer reveals that exact misconception. Use a mix of question types across the set (true/false, multiple-choice, short problem). Keep every question short and focused — this is a quick check, not a full exam, and the student hasn't been taught the topic yet, so ask about intuition/prior knowledge, not material only taught in class.
Respond with ONLY a JSON array, nothing else — no markdown, no preamble. Each object must have:
- "type": one of "tf", "mcq", "problem"
- "question": the question text
- "choices": an array of 3-4 answer options (ONLY include this field for "mcq" type; omit it for "tf" and "problem")
- "targetTag": copied EXACTLY, character-for-character (including everything after any colon), from the given mistake-type list — this is how the answer gets matched back to the misconception it probes, so it must match one of the given strings exactly.
The array must have exactly as many objects as there are mistake types given.`;

const DIAGNOSTIC_GRADE_SYSTEM_PROMPT = `You are a physics teacher grading a short diagnostic quiz for a Lebanese student who has not been taught this topic yet.
You will be given, for each question: its type, the question text, its choices (if multiple-choice), and the student's answer. Decide if the answer is correct — for "tf"/"mcq" compare against the right option, for "problem" allow reasonable equivalent phrasing/units. Be lenient: this is testing prior intuition, not taught material, so partial/reasonable reasoning counts as correct. Write short (1 sentence) feedback.
Respond with ONLY a JSON array of objects, nothing else — no markdown, no preamble. Format:
[{"correct": true, "feedback": "short explanation"}, {"correct": false, "feedback": "short explanation"}]
The array must have exactly as many objects as there are questions, in the same order.`;

// POST /api/diagnostic/start — { grade, topicId } -> { topic, questions }. One question per
// taxonomy tag for that topic (excluding the catch-all "other"), so a topic with few known
// misconceptions gets a short quiz and one with many gets a longer one — no fixed count.
app.post('/api/diagnostic/start', aiGuard, async (req, res) => {
  // Keyed by topic TITLE (not the DB-generated topic id) — the frontend's lesson list only
  // knows titles from CURRICULUM/GRADE_CONTENT, never the auto-assigned topics.id, so this
  // avoids making it fetch/resolve an id first just to start a diagnostic.
  const { grade, topic, lang } = req.body;
  if (!grade || !CURRICULUM[grade]) return res.status(400).json({ error: 'Please provide a valid grade.' });
  if (!topic || !CURRICULUM[grade].includes(topic)) return res.status(400).json({ error: 'Unknown topic for this grade.' });
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  if (!process.env.GROQ_API_KEY) return res.status(500).json({ error: 'Server is missing its API key. Set GROQ_API_KEY in the environment.' });
  try {
    const topicTitle = topic;
    const tags = tagsForTopic(topicTitle).filter(t => t !== 'other');
    if (!tags.length) return res.status(200).json({ topic: topicTitle, questions: [] });

    const userMessage = `Topic: ${topicTitle} (grade: ${grade})\nMistake types to probe (write exactly one question per type, in this order):\n${tags.map(t => '- ' + t).join('\n')}`;
    const text = await callGroq(withLanguage(DIAGNOSTIC_START_SYSTEM_PROMPT, lang), userMessage, 2000);
    let questions;
    try {
      questions = extractJson(text);
    } catch (e) {
      console.error('Failed to parse diagnostic questions JSON:', text);
      return res.status(502).json({ error: 'Could not build the diagnostic quiz. Try again.' });
    }
    res.json({ topic: topicTitle, questions });
  } catch (err) {
    if (err.message === 'groq_timeout') return res.status(504).json({ error: 'The AI service took too long to respond. Please try again in a moment.' });
    if (err.message === 'groq_error') return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    console.error('Diagnostic start error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

// POST /api/diagnostic/grade — { grade, topic, questions, answers } -> strengths /
// needsReview / possibleMisconceptions, and saves one `attempts` row per question
// (source='diagnostic') so it shows up in the Teacher Dashboard and future study plans
// exactly like exam/lab attempts do.
app.post('/api/diagnostic/grade', aiGuard, async (req, res) => {
  const { grade, topic, questions, answers, lang } = req.body;
  if (!grade || !CURRICULUM[grade]) return res.status(400).json({ error: 'Please provide a valid grade.' });
  if (!topic || !CURRICULUM[grade].includes(topic)) return res.status(400).json({ error: 'Unknown topic for this grade.' });
  if (!Array.isArray(questions) || !Array.isArray(answers) || questions.length !== answers.length || !questions.length) {
    return res.status(400).json({ error: 'Please provide matching questions and answers.' });
  }
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  if (!process.env.GROQ_API_KEY) return res.status(500).json({ error: 'Server is missing its API key. Set GROQ_API_KEY in the environment.' });

  try {
    const topicTitle = topic;
    const pairs = questions.map((q, i) => {
      const choicesLine = (q.type === 'mcq' && Array.isArray(q.choices)) ? `\nChoices: ${q.choices.join(', ')}` : '';
      return `Q${i + 1} (${q.type}): ${q.question}${choicesLine}\nStudent's answer: ${answers[i]}`;
    }).join('\n\n');
    const userMessage = `Topic: ${topicTitle} (grade: ${grade})\n\n${pairs}`;

    const text = await callGroq(withLanguage(DIAGNOSTIC_GRADE_SYSTEM_PROMPT, lang), userMessage, 1600);
    let results;
    try {
      results = extractJson(text);
    } catch (e) {
      console.error('Failed to parse diagnostic grading JSON:', e.message, '\nRAW:', text);
      return res.status(502).json({ error: 'Could not grade the diagnostic quiz. Please try again.' });
    }
    // One verdict per question, or nothing. A short/garbled array used to fall through to
    // `results[i] || {}`, which marked every unanswered-for question as WRONG — writing
    // misconceptions the student never demonstrated into their profile, and from there into
    // the study plan and the teacher dashboard.
    if (results.length !== questions.length || !results.every(r => r && typeof r.correct === 'boolean')) {
      console.error(`Diagnostic grading incomplete: ${results.length} result(s) for ${questions.length} question(s).`);
      return res.status(502).json({ error: 'Grading came back incomplete. Please try the quiz again.' });
    }

    const strengths = [];
    const needsReview = [];
    questions.forEach((q, i) => {
      const r = results[i] || {};
      if (r.correct) strengths.push(q.targetTag);
      else needsReview.push(q.targetTag);
    });

    // Save one attempt per question — fire-and-forget so the response isn't held up.
    resolveTopicId(grade, topicTitle).then(resolvedTopicId => {
      questions.forEach((q, i) => {
        const r = results[i] || {};
        pool.query(
          `INSERT INTO attempts (user_id, source, topic_id, question_text, student_answer, correct, mistake_tag)
           VALUES ($1, 'diagnostic', $2, $3, $4, $5, $6)`,
          [req.user.userId, resolvedTopicId, q.question, answers[i], !!r.correct, r.correct ? null : (q.targetTag || 'other')]
        ).catch(err => console.error('Failed to save diagnostic attempt:', err));
      });
    }).catch(err => console.error('Diagnostic topic resolution failed:', err));

    res.json({
      topic: topicTitle,
      strengths: strengths.map(shortTagLabel),
      needsReview: needsReview.map(shortTagLabel),
      possibleMisconceptions: needsReview,
      results: questions.map((q, i) => ({ question: q.question, targetTag: q.targetTag, correct: !!(results[i] && results[i].correct), feedback: results[i] && results[i].feedback })),
    });
  } catch (err) {
    if (err.message === 'groq_timeout') return res.status(504).json({ error: 'The AI service took too long to respond. Please try again in a moment.' });
    if (err.message === 'groq_error') return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    console.error('Diagnostic grade error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

// Strips the ": longer description" suffix some taxonomy tags carry, for short display labels.
function shortTagLabel(tag){ return (tag || '').split(':')[0].trim(); }

// --- Spaced review scheduling ---
// Leitner intervals in days, indexed by box. Reaching the end retires the item: the student has
// now got this misconception right four times across three weeks, which is a reasonable bar for
// "learned" — and leaving retired rows in place (rather than deleting) keeps the history.
const REVIEW_INTERVALS_DAYS = [1, 3, 7, 21];

// Called fire-and-forget after grading. Upserts one row per (student, topic, misconception):
// a repeat of the same mistake resets it to box 0 so it comes back tomorrow, rather than
// creating a duplicate row.
function scheduleReview(userId, topicId, mistakeTag){
  if (!pool || !userId || !topicId) return Promise.resolve();
  const tag = shortTagLabel(mistakeTag) || 'other';
  return pool.query(
    `INSERT INTO review_queue (user_id, topic_id, mistake_tag, box, due_at, updated_at)
     VALUES ($1, $2, $3, 0, NOW() + INTERVAL '1 day', NOW())
     ON CONFLICT (user_id, topic_id, mistake_tag)
     DO UPDATE SET box = 0,
                   due_at = NOW() + INTERVAL '1 day',
                   retired = false,
                   updated_at = NOW()`,
    [userId, topicId, tag]
  ).catch(err => console.error('Failed to schedule review:', err.message));
}

// Called after a review attempt. Correct -> advance a box (or retire); wrong -> back to box 0.
function recordReviewResult(userId, topicId, mistakeTag, wasCorrect){
  if (!pool || !userId || !topicId) return Promise.resolve();
  const tag = shortTagLabel(mistakeTag) || 'other';
  if (!wasCorrect) {
    return pool.query(
      `UPDATE review_queue
          SET box = 0, due_at = NOW() + INTERVAL '1 day', retired = false,
              times_reviewed = times_reviewed + 1, updated_at = NOW()
        WHERE user_id = $1 AND topic_id = $2 AND mistake_tag = $3`,
      [userId, topicId, tag]
    ).catch(err => console.error('Failed to record review miss:', err.message));
  }
  // Correct: advance one box, and set the next due date from the box being moved INTO.
  // The CASE mirrors REVIEW_INTERVALS_DAYS above (box 1 -> 3d, box 2 -> 7d, box 3 -> 21d);
  // box 4 retires the item, so its interval never actually matters.
  return pool.query(
    `UPDATE review_queue
        SET box = LEAST(box + 1, 4),
            times_reviewed = times_reviewed + 1,
            times_correct = times_correct + 1,
            retired = (box + 1 >= 4),
            due_at = NOW() + ((CASE box + 1
                                 WHEN 1 THEN 3
                                 WHEN 2 THEN 7
                                 WHEN 3 THEN 21
                                 ELSE 21
                               END) * INTERVAL '1 day'),
            updated_at = NOW()
      WHERE user_id = $1 AND topic_id = $2 AND mistake_tag = $3`,
    [userId, topicId, tag]
  ).catch(err => console.error('Failed to record review hit:', err.message));
}

// --- Formula Library ---
// The formulas themselves (plain strings, e.g. "F = ma") live in the frontend's curriculum.js
// per lesson — this endpoint doesn't re-store them, it explains ONE formula the frontend
// already knows about: symbol meanings, units, when to reach for it, a worked example, and a
// practice question. Generated live via Groq (like the Solver/Study Plan), not pre-baked,
// since doing this for every formula across all 91 topics up front would be a separate,
// much larger content project — this keeps it grounded in the real formula the student is
// looking at instead of guessing/inventing new ones.
const FORMULA_EXPLAIN_SYSTEM_PROMPT = `You are a physics teacher explaining ONE specific formula/law to a Lebanese high school student — the goal is for them to learn not just the formula, but when and why to reach for it.
You will be given: grade/branch, the topic/chapter it belongs to, the exact formula as written in the curriculum, and a grounding block describing how real Lebanese exams at this grade phrase things (units, constants, command verbs, given-value conventions). Do not change or "correct" the formula — explain it exactly as given.
The "example" and "practiceQuestion"/"practiceAnswer" fields MUST follow the real Lebanese conventions in the grounding block (e.g. g = 10 m/s² or N/kg, not 9.8; a "Given:" style value list; command verbs like "Determine"/"Deduce"/"Calculate" rather than casual phrasing) — write these as if they were lifted from a real Lebanese exam at this grade, not a generic international textbook.
Respond with ONLY a single JSON object, nothing else — no markdown, no preamble. Format:
{
  "formula": "<the formula, copied exactly as given>",
  "symbols": [{"symbol": "F", "meaning": "net force acting on the object"}],
  "units": "<the SI units of each quantity, briefly, e.g. 'F in newtons (N), m in kilograms (kg), a in m/s²'>",
  "whenToUse": "<1-2 sentences: what situation or clue in a problem tells you to use this formula>",
  "example": "<a short worked example with real numbers, 2-4 sentences, ending in the final numeric answer with units>",
  "practiceQuestion": "<one NEW practice question a student could try, testing this same formula>",
  "practiceAnswer": "<the correct final answer/approach to that practice question, 1-2 sentences>"
}
List every distinct symbol that appears in the formula (skip universal constants like π unless central to it) in "symbols", in the order they appear. Keep everything concise and pitched at this grade level.`;

app.post('/api/formula/explain', aiGuard, async (req, res) => {
  const { grade, topic, formula, lang } = req.body;
  if (!grade || !CURRICULUM[grade]) return res.status(400).json({ error: 'Please provide a valid grade.' });
  if (!topic || !CURRICULUM[grade].includes(topic)) return res.status(400).json({ error: 'Unknown topic for this grade.' });
  if (!formula || typeof formula !== 'string' || !formula.trim()) return res.status(400).json({ error: 'Please provide a formula.' });
  if (!process.env.GROQ_API_KEY) return res.status(500).json({ error: 'Server is missing its API key. Set GROQ_API_KEY in the environment.' });

  try {
    const userMessage = `Grade/branch: ${grade}\nTopic: ${topic}\nFormula: ${formula}\n\n${styleGroundingFor(grade)}`;
    // 700 tokens was sized for the original short explanation. This response now carries a
    // symbols list, units, when-to-use, a worked example AND a practice question with its
    // answer — all written in full Lebanese exam style since the grounding block was added.
    // At 700 it was being cut off mid-sentence, which the old parser treated as total failure.
    const text = await callGroq(withLanguage(FORMULA_EXPLAIN_SYSTEM_PROMPT, lang), userMessage, 1800);
    let explanation;
    try {
      explanation = extractJsonObject(text);
    } catch (e) {
      console.error(`Failed to parse formula explanation (grade=${grade}, formula="${formula}", len=${text.length}):`, e.message, '\nRAW:', text);
      return res.status(502).json({ error: 'The explanation came back unreadable. Please try again.' });
    }
    res.json({ explanation });
  } catch (err) {
    if (err.message === 'groq_timeout') return res.status(504).json({ error: 'The AI service took too long to respond. Please try again in a moment.' });
    if (err.message === 'groq_error') {
      return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    }
    console.error('Formula explain error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

// --- Virtual Lab ---
// Two ways a lab attempt reaches this endpoint:
// 1. Pre-graded (numeric "quick challenge" predictions) — the frontend already knows the
//    right answer (it's computed from the same formula as the live simulation) and just
//    needs this logged. Pass `pregraded: true` with `correct` (and optionally `feedback`)
//    to skip the AI call entirely — instant, free, no Groq round-trip.
// 2. AI-graded (open-ended "why" reasoning questions) — same shape as /api/grade-exam:
//    the answer is free text, so it's graded by Groq against the topic's allowed mistake tags.
const LAB_GRADE_SYSTEM_PROMPT = `You are a physics teacher grading a Lebanese high school student's answer to a virtual-lab reflection question.
You will be given the topic, the question, the exact set of allowed mistake tags for that topic, and the student's answer.
Decide if the answer is correct — allow reasonable equivalent phrasing/units, don't require exact wording. Write short (1-2 sentence) feedback explaining why, and the correct answer if they got it wrong.
If incorrect, pick exactly one "mistake_tag" from the allowed list that best fits (use "other" only if nothing specific fits). If correct, omit "mistake_tag".
Respond with ONLY a single JSON object, nothing else — no markdown, no preamble. Format:
{"correct": false, "feedback": "short explanation with the correct answer", "mistake_tag": "one-of-the-allowed-tags"}`;

app.post('/api/lab-attempt', aiGuard, async (req, res) => {
  const { grade, topic, question, answer, lang, timeSpent, pregraded, correct, feedback } = req.body;

  if (!grade || !topic || !question) {
    return res.status(400).json({ error: 'Please provide grade, topic, and question.' });
  }

  const spent = Number(timeSpent) || null;

  // --- Path 1: pre-graded numeric prediction, no AI call needed ---
  if (pregraded) {
    if (typeof correct !== 'boolean') {
      return res.status(400).json({ error: 'pregraded submissions must include a boolean "correct".' });
    }
    if (pool) {
      const topicId = await resolveTopicId(grade, topic);
      pool.query(
        `INSERT INTO attempts
          (user_id, source, topic_id, question_text, student_answer, correct, mistake_tag, time_spent_seconds)
         VALUES ($1, 'lab', $2, $3, $4, $5, $6, $7)`,
        [req.user.userId, topicId, question, (answer !== undefined ? String(answer) : null), correct, correct ? null : 'other', spent]
      ).catch(err => console.error('Failed to save lab attempt:', err));
    }
    return res.json({ result: { correct, feedback: feedback || null } });
  }

  // --- Path 2: open-ended answer, AI-graded ---
  if (typeof answer !== 'string' || !answer.trim()) {
    return res.status(400).json({ error: 'Please provide an answer.' });
  }
  if (!process.env.GROQ_API_KEY) {
    return res.status(500).json({ error: 'Server is missing its API key. Set GROQ_API_KEY in the environment.' });
  }

  const allowedTags = tagsForTopic(topic);
  const userMessage = `Topic: ${topic}\nQuestion: ${question}\nAllowed mistake tags if incorrect: ${allowedTags.join(', ')}\nStudent's answer: ${answer}`;

  try {
    // 300 tokens is tight for a verdict plus written feedback, so truncation is likely here —
    // this was the last call site still using the old fragile parser.
    const text = await callGroq(withLanguage(LAB_GRADE_SYSTEM_PROMPT, lang), userMessage, 600);
    let result;
    try {
      result = extractJsonObject(text);
    } catch (e) {
      console.error('Failed to parse lab grading JSON:', e.message, '\nRAW:', text);
      return res.status(502).json({ error: 'Could not grade this answer. Please try again.' });
    }

    if (pool) {
      const topicId = await resolveTopicId(grade, topic);
      pool.query(
        `INSERT INTO attempts
          (user_id, source, topic_id, question_text, student_answer, correct, mistake_tag, time_spent_seconds)
         VALUES ($1, 'lab', $2, $3, $4, $5, $6, $7)`,
        [req.user.userId, topicId, question, answer, !!result.correct, result.correct ? null : (result.mistake_tag || 'other'), spent]
      ).catch(err => console.error('Failed to save lab attempt:', err));
    }

    res.json({ result });
  } catch (err) {
    if (err.message === 'groq_timeout') return res.status(504).json({ error: 'The AI service took too long to respond. Please try again in a moment.' });
    if (err.message === 'groq_error') {
      return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    }
    console.error('Server error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

// --- Teacher Dashboard ---
// Three read views (Class / Student / Topic) over the unified `attempts` table, plus an
// AI "what should I teach next" recommendation. All reuse `requireAdmin` — no new auth
// model. Mastery follows the section-4 rule: needs >=3 attempts before it's shown as a
// number (fewer than that comes back as `null`, meaning "not enough data yet"), so a single
// unlucky guess never reads as 0% mastery.
// (The idx_attempts_created_at index this section used to create at module load now lives in
// setupDatabase(), where the `attempts` table is guaranteed to exist first.)

// GET /api/teacher/class/:grade — per-topic breakdown for a whole grade.
app.get('/api/teacher/class/:grade', requireAuth, requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  const { grade } = req.params;
  try {
    const overall = await pool.query(
      `SELECT COUNT(*) AS total_attempts, SUM(CASE WHEN a.correct THEN 1 ELSE 0 END) AS total_correct
       FROM attempts a JOIN topics t ON t.id = a.topic_id JOIN users u ON u.id = a.user_id
       WHERE t.grade = $1 AND COALESCE(u.is_demo, false) = false`,
      [grade]
    );
    const totalAttempts = Number(overall.rows[0].total_attempts) || 0;
    const totalCorrect = Number(overall.rows[0].total_correct) || 0;
    const overallMastery = totalAttempts > 0 ? Math.round((totalCorrect / totalAttempts) * 1000) / 10 : null;

    // Start from ALL topics defined for this grade (not just ones with attempts) so
    // topics nobody has practiced yet still show up in the dashboard — a teacher
    // needs to see "0 attempts, nothing here yet" just as much as low-mastery topics.
    // Demo/test accounts (see /api/admin/users/:id/demo) are excluded here too.
    const topics = await pool.query(
      `WITH grade_topics AS (
         SELECT id AS topic_id, title AS topic_title FROM topics WHERE grade = $1
       ),
       topic_attempts AS (
         SELECT a.user_id, a.correct, a.mistake_tag, a.question_text, gt.topic_id
         FROM attempts a JOIN grade_topics gt ON gt.topic_id = a.topic_id JOIN users u ON u.id = a.user_id
         WHERE COALESCE(u.is_demo, false) = false
       ),
       per_student_topic AS (
         SELECT topic_id, user_id, COUNT(*) AS attempts,
                SUM(CASE WHEN correct THEN 1 ELSE 0 END) AS correct_count
         FROM topic_attempts GROUP BY topic_id, user_id
       ),
       topic_agg AS (
         SELECT topic_id,
                COUNT(DISTINCT user_id) AS student_count,
                SUM(attempts) AS total_attempts,
                SUM(correct_count) AS total_correct,
                COUNT(*) FILTER (WHERE attempts >= 3 AND correct_count::float / attempts < 0.6) AS struggling_count
         FROM per_student_topic GROUP BY topic_id
       ),
       mistake_counts AS (
         -- Counted by DISTINCT student, not raw attempts, so one student retrying the
         -- same question 5 times doesn't inflate "X% of the class has this misconception".
         SELECT topic_id, mistake_tag, COUNT(DISTINCT user_id) AS student_cnt,
                ROW_NUMBER() OVER (PARTITION BY topic_id ORDER BY COUNT(DISTINCT user_id) DESC, mistake_tag) AS rn
         FROM topic_attempts WHERE correct = false AND mistake_tag IS NOT NULL
         GROUP BY topic_id, mistake_tag
       ),
       missed_questions AS (
         SELECT topic_id, question_text, COUNT(*) AS cnt,
                ROW_NUMBER() OVER (PARTITION BY topic_id ORDER BY COUNT(*) DESC, question_text) AS rn
         FROM topic_attempts WHERE correct = false
         GROUP BY topic_id, question_text
       )
       SELECT
         gt.topic_id,
         gt.topic_title,
         COALESCE(ta.student_count, 0) AS student_count,
         COALESCE(ta.total_attempts, 0) AS total_attempts,
         COALESCE(ta.total_correct, 0) AS total_correct,
         CASE WHEN COALESCE(ta.total_attempts, 0) >= 3 THEN ROUND(100.0 * ta.total_correct / ta.total_attempts, 1) ELSE NULL END AS mastery_pct,
         COALESCE(ta.struggling_count, 0) AS struggling_count,
         mc.mistake_tag AS top_mistake_tag,
         mc.student_cnt AS top_mistake_student_count,
         mq.question_text AS most_missed_question
       FROM grade_topics gt
       LEFT JOIN topic_agg ta ON ta.topic_id = gt.topic_id
       LEFT JOIN mistake_counts mc ON mc.topic_id = gt.topic_id AND mc.rn = 1
       LEFT JOIN missed_questions mq ON mq.topic_id = gt.topic_id AND mq.rn = 1
       ORDER BY mastery_pct ASC NULLS LAST, gt.topic_title`,
      [grade]
    );

    res.json({
      grade,
      overallMastery,
      totalAttempts,
      topics: topics.rows.map(r => ({
        topicId: r.topic_id,
        topic: r.topic_title,
        studentCount: Number(r.student_count),
        totalAttempts: Number(r.total_attempts),
        masteryPct: r.mastery_pct === null ? null : Number(r.mastery_pct),
        strugglingCount: Number(r.struggling_count),
        topMistakeTag: r.top_mistake_tag,
        topMistakeStudentCount: r.top_mistake_student_count === null ? 0 : Number(r.top_mistake_student_count),
        mostMissedQuestion: r.most_missed_question,
      })),
    });
  } catch (err) {
    console.error('Teacher class-view error:', err);
    res.status(500).json({ error: 'Could not load class data.' });
  }
});

// GET /api/teacher/student/:userId — one student's per-topic mastery + recent activity feed.
app.get('/api/teacher/student/:userId', requireAuth, requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  const userId = Number(req.params.userId);
  if (!Number.isInteger(userId)) return res.status(400).json({ error: 'Invalid student id.' });
  try {
    const student = await pool.query('SELECT id, name, email FROM users WHERE id = $1', [userId]);
    if (!student.rows.length) return res.status(404).json({ error: 'Student not found.' });

    const topics = await pool.query(
      `SELECT t.id AS topic_id, t.title AS topic_title, t.grade,
              COUNT(*) AS attempts,
              SUM(CASE WHEN a.correct THEN 1 ELSE 0 END) AS correct_count,
              CASE WHEN COUNT(*) >= 3 THEN ROUND(100.0 * SUM(CASE WHEN a.correct THEN 1 ELSE 0 END) / COUNT(*), 1) ELSE NULL END AS mastery_pct
       FROM attempts a JOIN topics t ON t.id = a.topic_id
       WHERE a.user_id = $1
       GROUP BY t.id, t.title, t.grade
       ORDER BY mastery_pct ASC NULLS LAST, t.title`,
      [userId]
    );

    const recent = await pool.query(
      `SELECT a.source, t.title AS topic_title, a.question_text, a.correct, a.mistake_tag, a.time_spent_seconds, a.created_at
       FROM attempts a LEFT JOIN topics t ON t.id = a.topic_id
       WHERE a.user_id = $1
       ORDER BY a.created_at DESC
       LIMIT 20`,
      [userId]
    );

    res.json({
      student: student.rows[0],
      topics: topics.rows.map(r => ({
        topicId: r.topic_id,
        topic: r.topic_title,
        grade: r.grade,
        attempts: Number(r.attempts),
        masteryPct: r.mastery_pct === null ? null : Number(r.mastery_pct),
      })),
      recentActivity: recent.rows.map(r => ({
        source: r.source,
        topic: r.topic_title,
        question: r.question_text,
        correct: r.correct,
        mistakeTag: r.mistake_tag,
        timeSpentSeconds: r.time_spent_seconds,
        createdAt: r.created_at,
      })),
    });
  } catch (err) {
    console.error('Teacher student-view error:', err);
    res.status(500).json({ error: 'Could not load student data.' });
  }
});

// GET /api/teacher/topic/:grade/:topicId — every student's mastery for one topic, weakest first.
app.get('/api/teacher/topic/:grade/:topicId', requireAuth, requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  const { grade } = req.params;
  const topicId = Number(req.params.topicId);
  if (!Number.isInteger(topicId)) return res.status(400).json({ error: 'Invalid topic id.' });
  try {
    const topic = await pool.query('SELECT id, title, grade FROM topics WHERE id = $1 AND grade = $2', [topicId, grade]);
    if (!topic.rows.length) return res.status(404).json({ error: 'Topic not found for this grade.' });

    // Demo/test accounts (see /api/admin/users/:id/demo) are excluded from all four queries
    // below — a demo account's clicking around shouldn't show up as a "student" here at all.
    const students = await pool.query(
      `SELECT u.id, u.name, u.email,
              COUNT(*) AS attempts,
              SUM(CASE WHEN a.correct THEN 1 ELSE 0 END) AS correct_count,
              CASE WHEN COUNT(*) >= 3 THEN ROUND(100.0 * SUM(CASE WHEN a.correct THEN 1 ELSE 0 END) / COUNT(*), 1) ELSE NULL END AS mastery_pct
       FROM attempts a JOIN users u ON u.id = a.user_id
       WHERE a.topic_id = $1 AND COALESCE(u.is_demo, false) = false
       GROUP BY u.id, u.name, u.email
       ORDER BY mastery_pct ASC NULLS LAST, u.name`,
      [topicId]
    );

    const mistakes = await pool.query(
      `SELECT a.mistake_tag, COUNT(*) AS cnt, COUNT(DISTINCT a.user_id) AS student_cnt
       FROM attempts a JOIN users u ON u.id = a.user_id
       WHERE a.topic_id = $1 AND a.correct = false AND a.mistake_tag IS NOT NULL AND COALESCE(u.is_demo, false) = false
       GROUP BY a.mistake_tag ORDER BY cnt DESC, a.mistake_tag`,
      [topicId]
    );

    const missedQuestions = await pool.query(
      `SELECT a.question_text, COUNT(*) AS cnt
       FROM attempts a JOIN users u ON u.id = a.user_id
       WHERE a.topic_id = $1 AND a.correct = false AND COALESCE(u.is_demo, false) = false
       GROUP BY a.question_text ORDER BY cnt DESC, a.question_text LIMIT 3`,
      [topicId]
    );

    // Progression over time: mastery % per day this topic had any attempts, so a teacher
    // can see e.g. 42% -> 61% -> 78% across the days they've been teaching/practicing it.
    // Only days with attempts appear (no padding for silent days) to keep it readable.
    const trend = await pool.query(
      `SELECT date_trunc('day', a.created_at) AS day,
              COUNT(*) AS attempts,
              SUM(CASE WHEN a.correct THEN 1 ELSE 0 END) AS correct_count
       FROM attempts a JOIN users u ON u.id = a.user_id
       WHERE a.topic_id = $1 AND COALESCE(u.is_demo, false) = false
       GROUP BY day ORDER BY day`,
      [topicId]
    );

    // Interventions logged specifically against this topic (see POST /api/teacher/intervention).
    const interventions = await pool.query(
      `SELECT i.id, i.note, i.created_at, u.name AS teacher_name
       FROM interventions i LEFT JOIN users u ON u.id = i.admin_user_id
       WHERE i.topic_id = $1 ORDER BY i.created_at DESC LIMIT 20`,
      [topicId]
    );

    res.json({
      topic: topic.rows[0],
      students: students.rows.map(r => ({
        id: r.id, name: r.name, email: r.email,
        attempts: Number(r.attempts),
        masteryPct: r.mastery_pct === null ? null : Number(r.mastery_pct),
      })),
      mistakeDistribution: mistakes.rows.map(r => ({ tag: r.mistake_tag, count: Number(r.cnt), studentCount: Number(r.student_cnt) })),
      mostMissedQuestions: missedQuestions.rows.map(r => ({ question: r.question_text, count: Number(r.cnt) })),
      trend: trend.rows.map(r => ({
        date: r.day,
        attempts: Number(r.attempts),
        masteryPct: Number(r.attempts) >= 3 ? Math.round((Number(r.correct_count) / Number(r.attempts)) * 1000) / 10 : null,
      })),
      interventions: interventions.rows.map(r => ({ id: r.id, note: r.note, createdAt: r.created_at, teacherName: r.teacher_name })),
    });
  } catch (err) {
    console.error('Teacher topic-view error:', err);
    res.status(500).json({ error: 'Could not load topic data.' });
  }
});

// GET /api/topics/:grade — the full curriculum topic list for a grade.
// The teacher dashboard needs every topic to choose from when setting homework, not just the
// ones that already have attempt data (which is all the class view returns). Serving it from
// here avoids pulling the 280KB curriculum.js into the dashboard just for a list of titles.
app.get('/api/topics/:grade', requireAuth, (req, res) => {
  const { grade } = req.params;
  if (!CURRICULUM[grade]) return res.status(400).json({ error: 'Unknown grade.' });
  res.json({ grade, topics: CURRICULUM[grade] });
});

// --- Homework assignments (teacher side) ---

// POST /api/teacher/assignments — set work for a grade.
app.post('/api/teacher/assignments', requireAuth, requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  const { grade, topic, title, instructions, questionCount, difficulty, dueAt } = req.body;

  if (!grade || !CURRICULUM[grade]) return res.status(400).json({ error: 'Please choose a valid grade.' });
  if (typeof topic !== 'string' || !CURRICULUM[grade].includes(topic)) {
    return res.status(400).json({ error: 'Please choose a topic from this grade.' });
  }
  if (typeof title !== 'string' || !title.trim()) return res.status(400).json({ error: 'Please give the assignment a title.' });
  if (title.length > 140) return res.status(400).json({ error: 'That title is too long.' });
  if (instructions && typeof instructions !== 'string') return res.status(400).json({ error: 'Instructions must be text.' });

  const count = Math.min(15, Math.max(3, Number(questionCount) || 6));
  const diff = QUESTION_BANK_DIFFICULTIES.includes(difficulty) ? difficulty : 'medium';

  // Accept a plain date ("2026-09-14") or a full timestamp; reject anything unparseable rather
  // than storing a silent null that would make the assignment look like it has no deadline.
  let due = null;
  if (dueAt) {
    const parsed = new Date(dueAt);
    if (isNaN(parsed.getTime())) return res.status(400).json({ error: 'That due date is not valid.' });
    due = parsed.toISOString();
  }

  try {
    const topicId = await resolveTopicId(grade, topic);
    if (!topicId) return res.status(400).json({ error: 'Could not find that topic. Try another one.' });

    const result = await pool.query(
      `INSERT INTO assignments (teacher_id, grade, topic_id, title, instructions, question_count, difficulty, due_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id, grade, title, instructions, question_count, difficulty, due_at, created_at`,
      [req.user.userId, grade, topicId, title.trim(), (instructions || '').trim() || null, count, diff, due]
    );
    res.json({ assignment: { ...result.rows[0], topic } });
  } catch (err) {
    console.error('Create assignment error:', err);
    res.status(500).json({ error: 'Could not create the assignment.' });
  }
});

// GET /api/teacher/assignments?grade=g9 — every assignment with its completion counts.
// The class size is "students in this grade, excluding demo accounts", so "8 / 21 done" means
// something real at a glance.
app.get('/api/teacher/assignments', requireAuth, requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  const { grade } = req.query;
  if (grade && !CURRICULUM[grade]) return res.status(400).json({ error: 'Unknown grade.' });

  try {
    const result = await pool.query(
      `SELECT a.id, a.grade, a.title, a.instructions, a.question_count, a.difficulty,
              a.due_at, a.archived, a.created_at, t.title AS topic,
              (SELECT COUNT(*) FROM users u
                WHERE u.grade = a.grade AND COALESCE(u.is_demo, false) = false)::int AS class_size,
              (SELECT COUNT(*) FROM assignment_submissions s
                WHERE s.assignment_id = a.id AND s.status = 'completed')::int AS completed_count,
              (SELECT COUNT(*) FROM assignment_submissions s
                WHERE s.assignment_id = a.id AND s.status = 'in_progress')::int AS started_count,
              (SELECT ROUND(AVG(s.score::numeric / NULLIF(s.total, 0)) * 100, 1)
                 FROM assignment_submissions s
                WHERE s.assignment_id = a.id AND s.status = 'completed') AS avg_pct
         FROM assignments a
         JOIN topics t ON t.id = a.topic_id
        WHERE a.archived = false ${grade ? 'AND a.grade = $1' : ''}
        ORDER BY a.created_at DESC
        LIMIT 50`,
      grade ? [grade] : []
    );
    res.json({ assignments: result.rows });
  } catch (err) {
    console.error('List assignments error:', err);
    res.status(500).json({ error: 'Could not load assignments.' });
  }
});

// GET /api/teacher/assignments/:id — who has done it, what they scored, and what the class as a
// whole got wrong on it. The mistake breakdown is the point: it turns one homework into a
// answer to "what do I need to reteach on Monday?".
app.get('/api/teacher/assignments/:id', requireAuth, requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid assignment id.' });

  try {
    const meta = await pool.query(
      `SELECT a.id, a.grade, a.title, a.instructions, a.question_count, a.difficulty,
              a.due_at, a.archived, a.created_at, a.topic_id, t.title AS topic
         FROM assignments a JOIN topics t ON t.id = a.topic_id
        WHERE a.id = $1`,
      [id]
    );
    if (!meta.rows.length) return res.status(404).json({ error: 'Assignment not found.' });
    const assignment = meta.rows[0];

    // Every student in the grade, whether or not they've started — the ones who haven't are
    // exactly who the teacher is looking for.
    const [students, mistakes] = await Promise.all([
      pool.query(
        `SELECT u.id, u.name,
                COALESCE(s.status, 'not_started') AS status,
                s.score, s.total, s.submitted_at
           FROM users u
           LEFT JOIN assignment_submissions s ON s.user_id = u.id AND s.assignment_id = $1
          WHERE u.grade = $2 AND COALESCE(u.is_demo, false) = false
          ORDER BY (COALESCE(s.status, 'not_started') = 'completed'), u.name`,
        [id, assignment.grade]
      ),
      // Scoped by assignment_id, so a later assignment on the same topic can't leak into this
      // one's numbers.
      pool.query(
        `SELECT a.mistake_tag, COUNT(*)::int AS cnt
           FROM attempts a
           JOIN users u ON u.id = a.user_id
          WHERE a.assignment_id = $1
            AND a.correct = false AND a.mistake_tag IS NOT NULL
            AND COALESCE(u.is_demo, false) = false
          GROUP BY a.mistake_tag ORDER BY cnt DESC LIMIT 6`,
        [id]
      ),
    ]);

    res.json({
      assignment,
      students: students.rows,
      commonMistakes: mistakes.rows.map(r => ({ tag: shortTagLabel(r.mistake_tag), count: r.cnt })),
    });
  } catch (err) {
    console.error('Assignment detail error:', err);
    res.status(500).json({ error: 'Could not load this assignment.' });
  }
});

// PATCH /api/teacher/assignments/:id — extend the deadline, or archive it (soft delete, so the
// submissions and their attempt history stay intact).
app.patch('/api/teacher/assignments/:id', requireAuth, requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid assignment id.' });
  const { dueAt, archived } = req.body;

  const sets = [], params = [];
  if (dueAt !== undefined) {
    if (dueAt === null) { sets.push(`due_at = NULL`); }
    else {
      const parsed = new Date(dueAt);
      if (isNaN(parsed.getTime())) return res.status(400).json({ error: 'That due date is not valid.' });
      params.push(parsed.toISOString());
      sets.push(`due_at = $${params.length}`);
    }
  }
  if (archived !== undefined) {
    params.push(!!archived);
    sets.push(`archived = $${params.length}`);
  }
  if (!sets.length) return res.status(400).json({ error: 'Nothing to update.' });

  params.push(id);
  try {
    const result = await pool.query(
      `UPDATE assignments SET ${sets.join(', ')} WHERE id = $${params.length} RETURNING id, title, due_at, archived`,
      params
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Assignment not found.' });
    res.json({ assignment: result.rows[0] });
  } catch (err) {
    console.error('Update assignment error:', err);
    res.status(500).json({ error: 'Could not update this assignment.' });
  }
});

// POST /api/teacher/intervention — log a teaching action ("reviewed Newton's 3rd Law with
// a force-pair activity") so the dashboard can later show mastery before/after it. topicId
// is optional: tie it to one topic to see it on that topic's trend, or omit for a
// grade-wide note (e.g. "went over exam technique with the whole class").
app.post('/api/teacher/intervention', requireAuth, requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  const { grade, topicId, note } = req.body;
  if (!grade || !CURRICULUM[grade]) return res.status(400).json({ error: 'Please provide a valid grade.' });
  if (!note || !note.trim()) return res.status(400).json({ error: 'Please write what you did.' });
  try {
    let resolvedTopicId = null;
    if (topicId !== undefined && topicId !== null && topicId !== '') {
      const t = await pool.query('SELECT id FROM topics WHERE id = $1 AND grade = $2', [topicId, grade]);
      if (!t.rows.length) return res.status(400).json({ error: 'That topic does not belong to this grade.' });
      resolvedTopicId = t.rows[0].id;
    }
    const result = await pool.query(
      'INSERT INTO interventions (admin_user_id, grade, topic_id, note) VALUES ($1, $2, $3, $4) RETURNING id, grade, topic_id, note, created_at',
      [req.user.userId, grade, resolvedTopicId, note.trim()]
    );
    res.json({ intervention: result.rows[0] });
  } catch (err) {
    console.error('Log intervention error:', err);
    res.status(500).json({ error: 'Could not save this note.' });
  }
});

// GET /api/teacher/interventions/:grade — recent teaching-log entries for a grade (both
// grade-wide notes and ones tied to a specific topic), newest first. Used by the Class View
// so a teacher can see their own log without opening each topic individually.
app.get('/api/teacher/interventions/:grade', requireAuth, requireAdmin, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  const { grade } = req.params;
  try {
    const result = await pool.query(
      `SELECT i.id, i.note, i.created_at, i.topic_id, t.title AS topic_title, u.name AS teacher_name
       FROM interventions i
       LEFT JOIN topics t ON t.id = i.topic_id
       LEFT JOIN users u ON u.id = i.admin_user_id
       WHERE i.grade = $1
       ORDER BY i.created_at DESC LIMIT 30`,
      [grade]
    );
    res.json({
      interventions: result.rows.map(r => ({
        id: r.id, note: r.note, createdAt: r.created_at,
        topicId: r.topic_id, topicTitle: r.topic_title, teacherName: r.teacher_name,
      })),
    });
  } catch (err) {
    console.error('List interventions error:', err);
    res.status(500).json({ error: 'Could not load the teaching log.' });
  }
});

// POST /api/teacher/recommend — "What should I teach next?" Sends only AGGREGATED
// per-topic stats (mastery %, mistake-tag distribution) to Groq — never raw student
// answers or names — so the prompt stays small/cheap and no student-identifiable data
// leaves the server.
// --- The weekly reteach list ---
// The dashboard already shows WHAT the class got wrong. This turns that into what to actually
// do about it on Monday: for each of the top misconceptions, a short explanation of why
// students fall into it and a concrete way to address it in a few minutes of class time.
// Aimed at being usable as-is, not as a starting point that still needs an hour of prep.
const RETEACH_SYSTEM_PROMPT = `You are an experienced Lebanese physics teacher planning what to reteach.
You will be given: a grade, and a list of the misconceptions this class actually showed over the past week — each with how many times it occurred, on which topic, and how many separate students showed it. Some entries also report how often students chose the WRONG METHOD (the wrong law/principle) versus getting the method right and slipping in the calculation. That distinction should drive your advice: a wrong-method problem needs the concept retaught, a calculation-slip problem needs practice and care, not reteaching.
For each misconception, write a short plan the teacher can use in 5 minutes of class time.
Respond with ONLY a JSON array, nothing else — no markdown, no preamble. At most 3 objects, most important first. Format:
[{
  "misconception": "<the misconception, in plain teacher language>",
  "topic": "<the topic it sits in>",
  "whyItHappens": "<1-2 sentences on the thinking error behind it — what the student believes that isn't true>",
  "howToFix": "<2-3 sentences: a concrete 5-minute approach — a specific demonstration, a counter-example, a question to pose to the class, or a contrast to draw. Name real physics, not generic teaching advice.>",
  "checkQuestion": "<one short question the teacher can ask afterwards to check it landed, written in Lebanese exam phrasing>"
}]
Be specific to the physics and to the Lebanese curriculum at this grade. Never give generic advice like "review the basics" or "encourage students to practice more".`;

const TEACH_NEXT_SYSTEM_PROMPT = `You are an experienced physics teacher's assistant. You will be given aggregated class performance stats: for each topic, mastery percentage, number of students struggling, and the most common mistake types.
Give ONE short, specific, actionable recommendation (2-4 sentences) about what to teach or review next, in the style of: "Before moving to friction, review net force and free-body diagrams. 38% of students are still showing the same misconception."
Be concrete — name the actual topic and the actual mistake pattern from the data, don't give generic teaching advice. If mastery is broadly high everywhere, say it's fine to move on and suggest the next logical topic.`;

// POST /api/teacher/worksheet — a printable question sheet plus a separate answer key.
//
// Teacher-only, deliberately. This is the single route in the app that returns fully worked
// answers, which is exactly what a student must never be handed — requireAdmin is what keeps
// the Socratic promise of the rest of the site intact.
app.post('/api/teacher/worksheet', requireAuth, requireAdmin, aiLimiter, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  if (!process.env.GROQ_API_KEY) return res.status(500).json({ error: 'Server is missing its API key. Set GROQ_API_KEY in the environment.' });
  const { grade, topic, count, difficulty, lang } = req.body;

  if (!grade || !CURRICULUM[grade]) return res.status(400).json({ error: 'Please choose a valid grade.' });
  if (typeof topic !== 'string' || !CURRICULUM[grade].includes(topic)) {
    return res.status(400).json({ error: 'Please choose a topic from this grade.' });
  }
  const n = Math.min(15, Math.max(3, Number(count) || 8));
  const diff = QUESTION_BANK_DIFFICULTIES.includes(difficulty) ? difficulty : 'medium';

  try {
    const grounding = styleGroundingFor(grade);
    const userMessage = `Grade/branch: ${GRADE_LABELS[grade] || grade}\nTopic: ${topic}\nDifficulty/style: ${diff}\nNumber of questions: ${n}${grounding ? `\n\n${grounding}` : ''}`;
    const text = await callGroq(withLanguage(QUESTION_BANK_GEN_SYSTEM_PROMPT, lang), userMessage, Math.min(6000, 400 + n * tokensPerQuestion(grade)));

    let questions;
    try {
      questions = extractJson(text);
    } catch (e) {
      console.error(`Failed to parse worksheet questions (grade=${grade}, topic="${topic}"):`, e.message, '\nRAW:', text);
      return res.status(502).json({ error: 'Could not build the worksheet. Please try again.' });
    }
    const allowedTypes = (GRADE_STYLE_GUIDE[grade] && GRADE_STYLE_GUIDE[grade].types) || ['tf', 'mcq', 'problem'];
    const usable = questions.filter(Boolean);
    const filtered = usable.filter(q => allowedTypes.includes(q.type || 'problem'));
    questions = filtered.length ? filtered : usable;
    if (!questions.length) return res.status(502).json({ error: 'Could not build the worksheet. Please try again.' });

    // The answer key is a second call. If it fails the worksheet is still worth having, so the
    // questions are returned either way rather than failing the whole request.
    let answers = [];
    try {
      const listed = questions.map((q, i) => {
        const choices = (q.type === 'mcq' && Array.isArray(q.choices)) ? `\n   Choices: ${q.choices.join(' / ')}` : '';
        return `${i + 1}. ${q.question}${choices}`;
      }).join('\n');
      const keyText = await callGroq(
        withLanguage(ANSWER_KEY_SYSTEM_PROMPT, lang),
        `Grade/branch: ${GRADE_LABELS[grade] || grade}\nTopic: ${topic}\n\n${listed}`,
        Math.min(5000, 400 + questions.length * 260)
      );
      const parsed = extractJson(keyText);
      if (Array.isArray(parsed)) answers = parsed.map(a => typeof a === 'string' ? a : String(a || ''));
    } catch (err) {
      console.error('Answer key generation failed (worksheet still returned):', err.message);
    }

    res.json({
      grade, gradeLabel: GRADE_LABELS[grade] || grade, topic, difficulty: diff,
      questions, answers,
      answerKeyAvailable: answers.length === questions.length,
    });
  } catch (err) {
    if (err.message === 'groq_timeout') return res.status(504).json({ error: 'The AI service took too long to respond. Please try again in a moment.' });
    if (err.message === 'groq_error') return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    console.error('Worksheet error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

// GET /api/teacher/reteach/:grade — the week's misconceptions, turned into a lesson plan.
// Read-only and cheap to look at: the raw list comes from the database, and the AI is only
// asked to turn the top few into teaching moves.
app.get('/api/teacher/reteach/:grade', requireAuth, requireAdmin, aiLimiter, async (req, res) => {
  const { grade } = req.params;
  const days = Math.min(30, Math.max(1, Number(req.query.days) || 7));
  if (!grade || !CURRICULUM[grade]) return res.status(400).json({ error: 'Please provide a valid grade.' });
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });

  try {
    // What went wrong, per misconception, with the method/calculation split alongside it.
    const rows = await pool.query(
      `SELECT t.title AS topic,
              a.mistake_tag,
              COUNT(*)::int AS occurrences,
              COUNT(DISTINCT a.user_id)::int AS students,
              COUNT(*) FILTER (WHERE a.method_correct = false)::int AS wrong_method,
              COUNT(*) FILTER (WHERE a.method_correct = true)::int AS right_method_wrong_answer
         FROM attempts a
         JOIN users u ON u.id = a.user_id
         JOIN topics t ON t.id = a.topic_id
        WHERE u.grade = $1
          AND COALESCE(u.is_demo, false) = false
          AND a.correct = false
          AND a.mistake_tag IS NOT NULL
          AND a.created_at >= NOW() - ($2 * INTERVAL '1 day')
        GROUP BY t.title, a.mistake_tag
        ORDER BY COUNT(DISTINCT a.user_id) DESC, COUNT(*) DESC
        LIMIT 8`,
      [grade, days]
    );

    const findings = rows.rows.map(r => ({
      topic: r.topic,
      misconception: shortTagLabel(r.mistake_tag),
      occurrences: r.occurrences,
      students: r.students,
      wrongMethod: r.wrong_method,
      rightMethodWrongAnswer: r.right_method_wrong_answer,
    }));

    if (!findings.length) {
      return res.json({
        grade, days, findings: [], plans: [],
        message: `No mistakes recorded for this grade in the last ${days} days — either they are doing well, or they have not been practising.`,
      });
    }

    // The list itself is useful even if the AI part fails, so it is returned either way.
    let plans = [];
    if (process.env.GROQ_API_KEY) {
      const summary = findings.slice(0, 5).map(f =>
        `- "${f.misconception}" on ${f.topic}: ${f.occurrences} time(s) across ${f.students} student(s)` +
        (f.wrongMethod || f.rightMethodWrongAnswer
          ? ` (wrong method ${f.wrongMethod}, right method but wrong answer ${f.rightMethodWrongAnswer})`
          : '')
      ).join('\n');
      try {
        const text = await callGroq(
          withLanguage(RETEACH_SYSTEM_PROMPT, 'en'),
          `Grade/branch: ${GRADE_LABELS[grade] || grade}\nPeriod: last ${days} days\n\nWhat this class got wrong:\n${summary}`,
          2000
        );
        plans = extractJson(text);
        if (!Array.isArray(plans)) plans = [];
      } catch (err) {
        console.error('Reteach plan generation failed (returning raw findings):', err.message);
      }
    }

    res.json({ grade, days, findings, plans });
  } catch (err) {
    console.error('Reteach list error:', err);
    res.status(500).json({ error: 'Could not build the reteach list.' });
  }
});

app.post('/api/teacher/recommend', requireAuth, requireAdmin, aiLimiter, async (req, res) => {
  const { grade } = req.body;
  if (!grade) return res.status(400).json({ error: 'Please provide a grade.' });
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  if (!process.env.GROQ_API_KEY) {
    return res.status(500).json({ error: 'Server is missing its API key. Set GROQ_API_KEY in the environment.' });
  }

  try {
    // Demo/test accounts (see /api/admin/users/:id/demo) are excluded here — a demo account's
    // clicking around should never nudge what the AI recommends teaching next.
    const topics = await pool.query(
      `WITH topic_attempts AS (
         SELECT a.*, t.title AS topic_title, t.order_index
         FROM attempts a JOIN topics t ON t.id = a.topic_id JOIN users u ON u.id = a.user_id
         WHERE t.grade = $1 AND COALESCE(u.is_demo, false) = false
       ),
       per_student_topic AS (
         SELECT topic_title, order_index, user_id, COUNT(*) AS attempts,
                SUM(CASE WHEN correct THEN 1 ELSE 0 END) AS correct_count
         FROM topic_attempts GROUP BY topic_title, order_index, user_id
       ),
       topic_summary AS (
         SELECT topic_title, order_index,
                SUM(attempts) AS total_attempts, SUM(correct_count) AS total_correct,
                COUNT(*) FILTER (WHERE attempts >= 3 AND correct_count::float / attempts < 0.6) AS struggling_count
         FROM per_student_topic GROUP BY topic_title, order_index
       ),
       mistake_counts AS (
         SELECT topic_title, mistake_tag, COUNT(*) AS cnt,
                ROW_NUMBER() OVER (PARTITION BY topic_title ORDER BY COUNT(*) DESC) AS rn
         FROM topic_attempts WHERE correct = false AND mistake_tag IS NOT NULL
         GROUP BY topic_title, mistake_tag
       )
       SELECT ts.topic_title, ts.order_index, ts.total_attempts, ts.total_correct, ts.struggling_count, mc.mistake_tag
       FROM topic_summary ts
       LEFT JOIN mistake_counts mc ON mc.topic_title = ts.topic_title AND mc.rn = 1
       ORDER BY ts.order_index NULLS LAST, ts.topic_title`,
      [grade]
    );

    if (!topics.rows.length) {
      return res.json({ recommendation: 'Not enough attempt data yet for this grade to make a recommendation.' });
    }

    const summaryLines = topics.rows.map(r => {
      const mastery = r.total_attempts >= 3 ? Math.round((r.total_correct / r.total_attempts) * 100) + '%' : 'not enough data';
      return `${r.topic_title}: mastery ${mastery}, ${r.struggling_count} students struggling, top mistake: ${r.mistake_tag || 'none recorded'}`;
    }).join('\n');

    const recommendation = await callGroq(withLanguage(TEACH_NEXT_SYSTEM_PROMPT, 'en'), `Grade: ${grade}\n\n${summaryLines}`, 300);
    res.json({ recommendation: recommendation || 'No recommendation returned.' });
  } catch (err) {
    if (err.message === 'groq_timeout') return res.status(504).json({ error: 'The AI service took too long to respond. Please try again in a moment.' });
    if (err.message === 'groq_error') {
      return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    }
    console.error('Teacher recommend error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

// --- 404 for unknown API routes ---
// Without this, a typo'd API path falls through to Express's default handler and returns an
// HTML error page, which the frontend then fails to parse as JSON and reports as a confusing
// "unexpected token <" error instead of a clear "not found".
app.use('/api/', (req, res) => {
  res.status(404).json({ error: `Unknown API endpoint: ${req.method} ${req.originalUrl}` });
});

// --- Global error handler ---
// Must be registered last, and must take four arguments for Express to recognise it as an
// error handler. Anything thrown synchronously in a route, or passed to next(err), lands here
// instead of returning an HTML stack trace. Notably this catches the CORS rejection above,
// which previously produced an HTML response the frontend couldn't read.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err && err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'This origin is not allowed to use the API.' });
  }
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'That upload is too large. Try a smaller or more compressed photo.' });
  }
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'The request body was not valid JSON.' });
  }
  console.error('Unhandled route error:', err);
  res.status(500).json({ error: 'Something went wrong on the server.' });
});

// A rejected promise with no .catch() terminates the process on modern Node. Several places in
// this file intentionally fire off "save this attempt" writes without awaiting them, so a
// transient database blip should be logged rather than take the whole site down.
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled promise rejection (ignored, but should be investigated):', reason);
});
// An uncaught exception leaves the process in an undefined state — Node's own documentation is
// explicit that resuming is unsafe. Logging and carrying on would keep a half-broken server
// answering students while Render's health check still passes, so nobody would notice. Exiting
// lets Render restart it cleanly.
process.on('uncaughtException', (err) => {
  console.error('FATAL uncaught exception — exiting so the platform can restart cleanly:', err);
  process.exit(1);
});

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => console.log(`Physics tutor backend running on port ${PORT}`));

// --- Graceful shutdown ---
// Render sends SIGTERM before replacing an instance. Without this, in-flight exam grading is
// killed mid-request and the student sees a network error. Stop accepting new connections, let
// current requests finish, then close the database pool.
let shuttingDown = false;
function shutdown(signal){
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`${signal} received — shutting down gracefully.`);

  server.close(() => {
    if (pool) pool.end().catch(() => {});
    console.log('Closed out remaining connections.');
    process.exit(0);
  });

  // server.close() waits for every open socket, and browsers hold keep-alive connections idle
  // for minutes. Without this the close callback would essentially never fire and every deploy
  // would fall through to the force path below. This drops idle sockets immediately while
  // letting in-flight requests finish.
  if (typeof server.closeIdleConnections === 'function') server.closeIdleConnections();

  setTimeout(() => {
    console.warn('Requests still in flight after 15s — closing remaining connections.');
    if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
    if (pool) pool.end().catch(() => {});
    process.exit(0);
  }, 15000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
