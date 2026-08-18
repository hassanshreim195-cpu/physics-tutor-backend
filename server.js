const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const { CURRICULUM, tagsForTopic } = require('./topics');
const { GRADE_STYLE_GUIDE } = require('./curriculum_style');

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
// Raised from 10mb: Practice Exam now sends one photo per "big problem" (up to 5 problems
// in one grading request), so a single submission can carry several MB of images at once.
app.use(express.json({ limit: '25mb' }));

// --- Simple in-memory rate limiting (no external dependency needed) ---
// Keyed by IP address. Each limiter instance keeps its own bucket map and
// sweeps expired entries periodically so memory doesn't grow unbounded.
// This is process-local (fine for a single free-tier Render instance) —
// if the app is ever scaled to multiple instances, swap this for a
// shared store (e.g. Redis) instead.
function makeRateLimiter({ windowMs, max, message }) {
  const hits = new Map(); // ip -> { count, resetAt }
  const sweeper = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of hits) {
      if (now > entry.resetAt) hits.delete(key);
    }
  }, windowMs);
  sweeper.unref();

  return (req, res, next) => {
    const key = req.ip || 'unknown';
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
const aiLimiter = makeRateLimiter({
  windowMs: 60 * 1000, max: 8,
  message: 'Too many AI requests from this device — please wait a minute before trying again.'
});

// Slow down brute-force login/registration attempts.
const authLimiter = makeRateLimiter({
  windowMs: 15 * 60 * 1000, max: 20,
  message: 'Too many attempts — please wait a few minutes before trying again.'
});

// --- Database setup ---
// DATABASE_URL is provided automatically by Render when you attach a Postgres database.
const pool = process.env.DATABASE_URL
  ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } })
  : null;

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
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS grade TEXT;`);
  // Additive migration: lets the teacher mark an account as a demo/test account (e.g. to
  // show the site to someone) without it ever showing up in class analytics, the weekly
  // digest, the teacher dashboard, or the "what to teach next" recommendation — every one of
  // those aggregate queries excludes users flagged here. Defaults to false so every existing
  // real student is unaffected.
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_demo BOOLEAN DEFAULT false;`);
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
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_attempts_user_topic ON attempts (user_id, topic_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_attempts_topic ON attempts (topic_id);`);

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
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_interventions_grade ON interventions (grade);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_interventions_topic ON interventions (topic_id);`);

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
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_bookings_user ON bookings (user_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_bookings_status ON bookings (status);`);

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
setupDatabase().catch(err => console.error('Database setup failed:', err));

// --- Auth helpers ---
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

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

// Blocks the request unless a valid token is present
function requireAuth(req, res, next){
  if (!req.user) return res.status(401).json({ error: 'Please log in first.' });
  next();
}

app.post('/api/register', authLimiter, async (req, res) => {
  const { name, email, password, grade } = req.body;
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, and password are all required.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  // Every student account is locked to one grade for good, chosen once at signup — see the
  // design note above the `grade` column migration. Validate against the real curriculum
  // grade keys so a typo or tampered request can't create an account with a bogus grade.
  if (!grade || !CURRICULUM[grade]) {
    return res.status(400).json({ error: 'Please choose your grade — it cannot be changed later, so pick carefully.' });
  }

  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length) return res.status(409).json({ error: 'An account with this email already exists.' });

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash, grade) VALUES ($1, $2, $3, $4) RETURNING id, name, email, grade',
      [name, email.toLowerCase(), hash, grade]
    );
    const user = result.rows[0];
    res.json({ token: signToken(user), name: user.name, email: user.email, grade: user.grade });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Something went wrong creating the account.' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

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
// Set ADMIN_EMAIL in the environment to the email of the account that should have admin access.
function requireAdmin(req, res, next){
  if (!req.user) return res.status(401).json({ error: 'Please log in first.' });
  const adminEmail = (process.env.ADMIN_EMAIL || '').toLowerCase();
  if (!adminEmail || req.user.email.toLowerCase() !== adminEmail) {
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
    const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    let tempPassword = '';
    for (let i = 0; i < 8; i++) tempPassword += chars[Math.floor(Math.random() * chars.length)];

    const hash = await bcrypt.hash(tempPassword, 10);
    const result = await pool.query(
      'UPDATE users SET password_hash = $1 WHERE id = $2 RETURNING id, name, email',
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

async function callGroq(systemPrompt, userMessage, maxTokens){
  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
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

  const response = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`,
    {
      method: 'POST',
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
function withLanguage(prompt, lang){
  if (lang === 'fr') {
    return prompt + '\n\nIMPORTANT: Respond entirely in French, including all explanations, headings, and labels.';
  }
  return prompt;
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

Keep language clear, concise, and appropriate for a high school student.

Respond with ONLY a single JSON object, nothing else — no markdown fences, no preamble, no text outside the JSON. Format:
{"steps": [{"hint": "...", "detail": "..."}, {"hint": "...", "detail": "..."}], "feedback": null}`;

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
    const text = await callGroq(CLASSIFY_SYSTEM_PROMPT, userMessage, 100);
    const match = text.match(/\{[\s\S]*\}/);
    const parsed = JSON.parse(match ? match[0] : text);
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

app.post('/api/explain-terms', aiLimiter, async (req, res) => {
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
    if (err.message === 'groq_error') {
      return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    }
    console.error('Explain-terms error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

app.post('/api/solve', aiLimiter, async (req, res) => {
  // `grade` is optional and not sent by the UI today — if present (future UI change) it
  // narrows classification to that grade's topic list; if absent, classification searches
  // the whole curriculum and also guesses the grade.
  const { problem, image, lang, grade } = req.body;

  if ((!problem || typeof problem !== 'string' || !problem.trim()) && !image) {
    return res.status(400).json({ error: 'Please send a physics problem in the "problem" field, or attach an image.' });
  }

  if (!process.env.GEMINI_API_KEY) {
    return res.status(500).json({ error: 'Server is missing its API key. Set GEMINI_API_KEY in the environment.' });
  }

  try {
    const raw = await callGemini(withLanguage(SYSTEM_PROMPT, lang), problem, image);

    let parsed;
    try {
      const match = raw.match(/\{[\s\S]*\}/);
      parsed = JSON.parse(match ? match[0] : raw);
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
        });
      });
    }

    res.json({ steps, feedback });
  } catch (err) {
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

app.post('/api/study-plan', aiLimiter, async (req, res) => {
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

Other exams around the same time: ${otherExams && otherExams.trim() ? otherExams : 'None mentioned'}${diagnosticContext}

Build my physics study plan.`;

  try {
    const plan = await callGroq(withLanguage(STUDY_PLAN_SYSTEM_PROMPT, lang), userMessage, 900);

    if (pool && req.user) {
      pool.query(
        'INSERT INTO study_plans (user_id, grade, exam_date, plan) VALUES ($1, $2, $3, $4)',
        [req.user.userId, grade, examDate, plan]
      ).catch(err => console.error('Failed to save study plan:', err));
    }

    res.json({ plan: plan || 'No plan returned.' });
  } catch (err) {
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
Respond with ONLY a JSON array of objects, nothing else — no markdown, no preamble. Format:
[{"correct": true, "feedback": "short explanation"}, {"correct": false, "feedback": "short explanation with the correct answer", "mistake_tag": "one-of-the-allowed-tags"}]
The array must have exactly as many objects as there are questions, in the same order.`;

// Practice Exam grading is now per-problem and vision-based: the student photographs their
// handwritten work for one whole problem (all its parts together) instead of typing answers,
// so this prompt grades ONE problem at a time from a photo, matching a single Gemini vision call.
const EXAM_PROBLEM_GRADE_SYSTEM_PROMPT = `You are a physics teacher grading ONE problem from a Lebanese high school student's practice exam. You will be given the problem (its topic, scenario, and lettered parts) and a PHOTO of the student's handwritten solution to this problem. The photo may show messy handwriting, crossed-out work, and work for multiple parts together — read it carefully and match each piece of the student's work to the corresponding lettered part of the problem.
For EACH part, decide if the student's answer/reasoning for that part is correct — allow reasonable equivalent phrasing, rounding, and units, don't require exact wording or exact decimal precision. Write short (1-2 sentence) feedback per part explaining why, and the correct answer/approach if they got it wrong. If a part was left blank or is illegible, mark it incorrect and say so plainly.
If a part is INCORRECT, also pick exactly one "mistake_tag" from the allowed list for this problem's topic that best describes the kind of error — use "other" only if none of the specific tags fit. If a part is correct, omit "mistake_tag" (or set it to null).
Respond with ONLY a single JSON object, nothing else — no markdown, no preamble. Format:
{"parts": [{"label": "a", "correct": true, "feedback": "short explanation"}, {"label": "b", "correct": false, "feedback": "short explanation with the correct approach/answer", "mistake_tag": "one-of-the-allowed-tags"}], "overall_feedback": "one short encouraging sentence about this problem as a whole"}
The "parts" array must have exactly as many objects as the problem has parts, in the same order, matching each "label".`;

function extractJson(text){
  const match = text.match(/\[[\s\S]*\]/);
  return match ? JSON.parse(match[0]) : JSON.parse(text);
}

app.post('/api/generate-exam', aiLimiter, async (req, res) => {
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
  const userMessage = `Grade/branch: ${GRADE_LABELS[grade] || grade}\nLessons to draw problems from (use these EXACT names for "topic"): ${lessonList}\nNumber of big problems to write: ${problemCount}${grounding ? `\n\n${grounding}` : ''}`;

  try {
    const text = await callGroq(withLanguage(EXAM_GEN_SYSTEM_PROMPT, lang), userMessage, Math.min(3500, 500 + problemCount * 550));
    let problems;
    try {
      problems = extractJson(text);
    } catch (e) {
      console.error('Failed to parse exam problems JSON:', text);
      return res.status(502).json({ error: 'Could not generate a valid exam. Try again.' });
    }
    res.json({ problems });
  } catch (err) {
    if (err.message === 'groq_error') {
      return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    }
    console.error('Server error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

app.post('/api/grade-exam', aiLimiter, async (req, res) => {
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
        const match = text.match(/\{[\s\S]*\}/);
        const parsed = JSON.parse(match ? match[0] : text);
        return {
          parts: Array.isArray(parsed.parts) ? parsed.parts : p.parts.map(part => ({ label: part.label, correct: false, feedback: 'Could not read a result for this part.' })),
          overall_feedback: parsed.overall_feedback || '',
        };
      } catch (err) {
        console.error('Failed to grade a problem (non-fatal, marked incorrect):', err.message || err);
        return {
          parts: p.parts.map(part => ({ label: part.label, correct: false, feedback: 'Could not grade this part — try resubmitting.' })),
          overall_feedback: 'Grading failed for this problem — try again.',
        };
      }
    }));

    // Score is counted at the PART level (a "big problem" is really several mini-questions),
    // which also keeps individual mistakes granular for the mistake-tag breakdown below.
    let correctParts = 0, totalParts = 0;
    const mistakeCounts = {};
    const topicMissCounts = {};
    gradedProblems.forEach((g, pi) => {
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
      pool.query(
        'INSERT INTO exam_results (user_id, grade, score, total, questions) VALUES ($1, $2, $3, $4, $5)',
        [req.user.userId, grade, correctParts, totalParts, JSON.stringify(problems.map(p => ({ topic: p.topic, difficulty: p.difficulty, scenario: p.scenario, parts: p.parts })))]
      ).catch(err => console.error('Failed to save exam result:', err));

      // Unified data model: one `attempts` row per PART (not per photo/problem), fire-and-forget
      // so a slow/failed insert never blocks the response the student is waiting on.
      problems.forEach((p, pi) => {
        const g = gradedProblems[pi];
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
          });
        });
      });
    }

    res.json({ results: gradedProblems, score: correctParts, total: totalParts, scorePct, mistakeCounts, recommendedTopic, recommendedRevision });
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

// One short guiding hint for a student who's stuck on a practice question and hasn't
// answered yet — same "never give the answer away" philosophy as the Solver, applied here so
// a stuck student has somewhere to go besides leaving it blank or guessing.
const QUESTION_BANK_HINT_SYSTEM_PROMPT = `You are a physics teacher giving ONE short hint to a Lebanese high school student who is stuck on a practice question and has NOT answered it yet. You will be given the topic and the question text.
Give ONE short guiding hint (1-2 sentences) — remind them which law/formula/concept applies here, or what to look at or consider first.
Do NOT give the final answer, any numeric result, or the full solution. Do not solve any part of the problem for them.
Respond with ONLY the hint text, nothing else — no JSON, no markdown, no preamble.`;

app.post('/api/question-bank/generate', aiLimiter, async (req, res) => {
  const { grade, topic, difficulty, count, lang } = req.body;
  if (!grade || !CURRICULUM[grade]) return res.status(400).json({ error: 'Please provide a valid grade.' });
  if (!topic || !CURRICULUM[grade].includes(topic)) return res.status(400).json({ error: 'Unknown topic for this grade.' });
  if (!process.env.GROQ_API_KEY) return res.status(500).json({ error: 'Server is missing its API key. Set GROQ_API_KEY in the environment.' });

  const diff = QUESTION_BANK_DIFFICULTIES.includes(difficulty) ? difficulty : 'medium';
  const n = Math.min(15, Math.max(3, Number(count) || 10));

  try {
    const grounding = styleGroundingFor(grade);
    const userMessage = `Grade/branch: ${GRADE_LABELS[grade] || grade}\nTopic: ${topic}\nDifficulty/style: ${diff}\nNumber of questions: ${n}${grounding ? `\n\n${grounding}` : ''}`;
    const text = await callGroq(withLanguage(QUESTION_BANK_GEN_SYSTEM_PROMPT, lang), userMessage, Math.min(1500, 200 + n * 120));
    let questions;
    try {
      questions = extractJson(text);
    } catch (e) {
      console.error('Failed to parse question bank JSON:', text);
      return res.status(502).json({ error: 'Could not generate practice questions. Try again.' });
    }
    // Defensive filter: keep only the types real exams actually use at this grade, in case the
    // model drifts (e.g. slips in an MCQ for Grade 12, which never uses one in practice).
    const allowedTypes = (GRADE_STYLE_GUIDE[grade] && GRADE_STYLE_GUIDE[grade].types) || ['tf', 'mcq', 'problem'];
    questions = questions.filter(q => q && allowedTypes.includes(q.type || 'problem'));
    if (!questions.length) {
      console.error('All generated questions were filtered out for grade', grade, '- raw:', text);
      return res.status(502).json({ error: 'Could not generate practice questions. Try again.' });
    }
    // Stamp topic (and difficulty, as a fallback) on every question so grading/mistake-tagging
    // can resolve it the same way generate-exam's questions carry their topic.
    questions.forEach(q => { q.topic = topic; if (!q.difficulty) q.difficulty = diff; });
    res.json({ topic, difficulty: diff, questions });
  } catch (err) {
    if (err.message === 'groq_error') {
      return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    }
    console.error('Question bank generate error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

app.post('/api/question-bank/hint', aiLimiter, async (req, res) => {
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
    if (err.message === 'groq_error') {
      return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    }
    console.error('Question bank hint error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

app.post('/api/question-bank/grade', aiLimiter, async (req, res) => {
  const { grade, topic, questions, answers, lang } = req.body;
  if (!grade || !CURRICULUM[grade]) return res.status(400).json({ error: 'Please provide a valid grade.' });
  if (!topic || !CURRICULUM[grade].includes(topic)) return res.status(400).json({ error: 'Unknown topic for this grade.' });
  if (!Array.isArray(questions) || !Array.isArray(answers) || questions.length !== answers.length || !questions.length) {
    return res.status(400).json({ error: 'Please provide matching questions and answers.' });
  }
  if (!process.env.GROQ_API_KEY) {
    return res.status(500).json({ error: 'Server is missing its API key. Set GROQ_API_KEY in the environment.' });
  }

  const pairs = questions.map((q, i) => {
    const qText = typeof q === 'string' ? q : q.question;
    const qType = typeof q === 'string' ? 'problem' : (q.type || 'problem');
    const choicesLine = (qType === 'mcq' && Array.isArray(q.choices)) ? `\nChoices: ${q.choices.join(', ')}` : '';
    return `Q${i + 1} (${qType}): ${qText}${choicesLine}\nAllowed mistake tags if incorrect: ${tagsForTopic(topic).join(', ')}\nStudent's answer: ${answers[i]}`;
  }).join('\n\n');
  const userMessage = `Grade/branch: ${grade}\nTopic: ${topic}\n\n${pairs}`;

  try {
    const text = await callGroq(withLanguage(EXAM_GRADE_SYSTEM_PROMPT, lang), userMessage, 900);
    let results;
    try {
      results = extractJson(text);
    } catch (e) {
      console.error('Failed to parse question bank grading JSON:', text);
      return res.status(502).json({ error: 'Could not grade this set. Try again.' });
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

    if (pool && req.user) {
      resolveTopicId(grade, topic).then(topicId => {
        questions.forEach((q, i) => {
          const qText = typeof q === 'string' ? q : q.question;
          const r = results[i] || {};
          pool.query(
            `INSERT INTO attempts (user_id, source, topic_id, difficulty, question_text, student_answer, correct, mistake_tag)
             VALUES ($1, 'question_bank', $2, $3, $4, $5, $6, $7)`,
            [req.user.userId, topicId, (q && q.difficulty) || null, qText, answers[i], !!r.correct, r.correct ? null : (r.mistake_tag || 'other')]
          ).catch(err => console.error('Failed to save question bank attempt:', err));
        });
      });
    }

    const scorePct = Math.round((score / results.length) * 1000) / 10;
    const recommendedRevision = scorePct < 60
      ? `Revise ${topic} before moving on — the fundamentals here still need work.`
      : (scorePct < 85
        ? `Solid on ${topic}, but a bit more practice would help before your exam.`
        : `Strong work on ${topic} — you're ready to move on to the next topic.`);

    res.json({ results, score, total: results.length, scorePct, mistakeCounts, recommendedRevision });
  } catch (err) {
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
app.post('/api/diagnostic/start', aiLimiter, async (req, res) => {
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
    const text = await callGroq(withLanguage(DIAGNOSTIC_START_SYSTEM_PROMPT, lang), userMessage, 900);
    let questions;
    try {
      questions = extractJson(text);
    } catch (e) {
      console.error('Failed to parse diagnostic questions JSON:', text);
      return res.status(502).json({ error: 'Could not build the diagnostic quiz. Try again.' });
    }
    res.json({ topic: topicTitle, questions });
  } catch (err) {
    if (err.message === 'groq_error') return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    console.error('Diagnostic start error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

// POST /api/diagnostic/grade — { grade, topic, questions, answers } -> strengths /
// needsReview / possibleMisconceptions, and saves one `attempts` row per question
// (source='diagnostic') so it shows up in the Teacher Dashboard and future study plans
// exactly like exam/lab attempts do.
app.post('/api/diagnostic/grade', requireAuth, aiLimiter, async (req, res) => {
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

    const text = await callGroq(withLanguage(DIAGNOSTIC_GRADE_SYSTEM_PROMPT, lang), userMessage, 700);
    let results;
    try {
      results = extractJson(text);
    } catch (e) {
      console.error('Failed to parse diagnostic grading JSON:', text);
      return res.status(502).json({ error: 'Could not grade the diagnostic quiz. Try again.' });
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
    });

    res.json({
      topic: topicTitle,
      strengths: strengths.map(shortTagLabel),
      needsReview: needsReview.map(shortTagLabel),
      possibleMisconceptions: needsReview,
      results: questions.map((q, i) => ({ question: q.question, targetTag: q.targetTag, correct: !!(results[i] && results[i].correct), feedback: results[i] && results[i].feedback })),
    });
  } catch (err) {
    if (err.message === 'groq_error') return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    console.error('Diagnostic grade error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

// Strips the ": longer description" suffix some taxonomy tags carry, for short display labels.
function shortTagLabel(tag){ return (tag || '').split(':')[0].trim(); }

// --- Formula Library ---
// The formulas themselves (plain strings, e.g. "F = ma") live in the frontend's curriculum.js
// per lesson — this endpoint doesn't re-store them, it explains ONE formula the frontend
// already knows about: symbol meanings, units, when to reach for it, a worked example, and a
// practice question. Generated live via Groq (like the Solver/Study Plan), not pre-baked,
// since doing this for every formula across all 91 topics up front would be a separate,
// much larger content project — this keeps it grounded in the real formula the student is
// looking at instead of guessing/inventing new ones.
const FORMULA_EXPLAIN_SYSTEM_PROMPT = `You are a physics teacher explaining ONE specific formula/law to a Lebanese high school student — the goal is for them to learn not just the formula, but when and why to reach for it.
You will be given: grade/branch, the topic/chapter it belongs to, and the exact formula as written in the curriculum. Do not change or "correct" the formula — explain it exactly as given.
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

app.post('/api/formula/explain', aiLimiter, async (req, res) => {
  const { grade, topic, formula, lang } = req.body;
  if (!grade || !CURRICULUM[grade]) return res.status(400).json({ error: 'Please provide a valid grade.' });
  if (!topic || !CURRICULUM[grade].includes(topic)) return res.status(400).json({ error: 'Unknown topic for this grade.' });
  if (!formula || typeof formula !== 'string' || !formula.trim()) return res.status(400).json({ error: 'Please provide a formula.' });
  if (!process.env.GROQ_API_KEY) return res.status(500).json({ error: 'Server is missing its API key. Set GROQ_API_KEY in the environment.' });

  try {
    const userMessage = `Grade/branch: ${grade}\nTopic: ${topic}\nFormula: ${formula}`;
    const text = await callGroq(withLanguage(FORMULA_EXPLAIN_SYSTEM_PROMPT, lang), userMessage, 700);
    const match = text.match(/\{[\s\S]*\}/);
    let explanation;
    try {
      explanation = JSON.parse(match ? match[0] : text);
    } catch (e) {
      console.error('Failed to parse formula explanation JSON:', text);
      return res.status(502).json({ error: 'Could not explain this formula. Try again.' });
    }
    res.json({ explanation });
  } catch (err) {
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

app.post('/api/lab-attempt', requireAuth, aiLimiter, async (req, res) => {
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
    const text = await callGroq(withLanguage(LAB_GRADE_SYSTEM_PROMPT, lang), userMessage, 300);
    const match = text.match(/\{[\s\S]*\}/);
    let result;
    try {
      result = JSON.parse(match ? match[0] : text);
    } catch (e) {
      console.error('Failed to parse lab grading JSON:', text);
      return res.status(502).json({ error: 'Could not grade this answer. Try again.' });
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
if (pool) {
  pool.query(`CREATE INDEX IF NOT EXISTS idx_attempts_created_at ON attempts (created_at);`).catch(() => {});
}

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
const TEACH_NEXT_SYSTEM_PROMPT = `You are an experienced physics teacher's assistant. You will be given aggregated class performance stats: for each topic, mastery percentage, number of students struggling, and the most common mistake types.
Give ONE short, specific, actionable recommendation (2-4 sentences) about what to teach or review next, in the style of: "Before moving to friction, review net force and free-body diagrams. 38% of students are still showing the same misconception."
Be concrete — name the actual topic and the actual mistake pattern from the data, don't give generic teaching advice. If mastery is broadly high everywhere, say it's fine to move on and suggest the next logical topic.`;

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

    const recommendation = await callGroq(TEACH_NEXT_SYSTEM_PROMPT, `Grade: ${grade}\n\n${summaryLines}`, 300);
    res.json({ recommendation: recommendation || 'No recommendation returned.' });
  } catch (err) {
    if (err.message === 'groq_error') {
      return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    }
    console.error('Teacher recommend error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Physics tutor backend running on port ${PORT}`));
