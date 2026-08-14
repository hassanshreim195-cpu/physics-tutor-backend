const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const { CURRICULUM, tagsForTopic } = require('./topics');

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
    // Allow requests with no Origin header at all (server-to-server calls,
    // curl, mobile webviews) — only browser-sent cross-origin requests carry
    // an Origin header we need to check.
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
}));
app.use(express.json({ limit: '10mb' }));

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
        u.id, u.name, u.email, u.grade, u.created_at,
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

// --- AI (Groq / Llama 3.1 for text; Gemini for the solver, since it can read photos) ---
// Set GROQ_API_KEY and GEMINI_API_KEY in the environment. Both have generous free tiers.
const GROQ_MODEL = 'llama-3.1-8b-instant';
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

const SYSTEM_PROMPT = `You are a physics tutor for Lebanese high school students (Lebanese national curriculum, grades 9-12 / Brevet-Bac).
When given a physics problem (as text, or shown in a photo):
1. Identify the relevant law/formula.
2. Solve step by step, showing each calculation.
3. If the student's own attempt is included and contains a mistake, point out exactly where the mistake is and correct it.
Keep it clear, concise, and appropriate for a high school student. Use simple language.`;

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
    const solution = await callGemini(withLanguage(SYSTEM_PROMPT, lang), problem, image);

    if (pool && req.user) {
      pool.query(
        'INSERT INTO solver_history (user_id, problem, solution) VALUES ($1, $2, $3)',
        [req.user.userId, problem || '(photo)', solution]
      ).catch(err => console.error('Failed to save solver history:', err));

      // Unified data model: log this as an ungraded attempt (source='solver'). `correct` is
      // left null — the solver isn't testing the student, it's solving for them, so
      // correctness doesn't apply unless/until the UI asks for the student's own attempt too.
      classifySolverTopic(problem, solution, grade).then(match => {
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

    res.json({ solution: solution || 'No solution returned.' });
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

  const userMessage = `Grade/branch: ${grade}
Exam date: ${examDate}
Days left until the exam: ${daysLeft}
Physics lessons/topics still to cover:
${lessons}

Other exams around the same time: ${otherExams && otherExams.trim() ? otherExams : 'None mentioned'}

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

const EXAM_GEN_SYSTEM_PROMPT = `You are a physics exam writer for a Lebanese high school student.
Given a grade/branch and a specific list of lesson/chapter names the student chose to be tested on, write exactly 5 exam questions covering those lessons, ordered from easiest to hardest (progressive difficulty).
Use a mix of question types across the 5 questions: at least one True/False, at least one multiple-choice, and at least one problem/calculation question (short-answer, not essay).
Respond with ONLY a JSON array of 5 objects, nothing else — no markdown, no preamble. Each object must have:
- "type": one of "tf", "mcq", "problem"
- "question": the question text
- "choices": an array of 3-4 answer options (ONLY include this field for "mcq" type; omit it for "tf" and "problem")
- "topic": the EXACT lesson name (copied verbatim, character-for-character) from the given lesson list that this question belongs to — never invent or paraphrase a topic name
- "difficulty": one of "easy", "medium", "hard"
Example:
[{"type":"tf","question":"...","topic":"Newton's 2nd Law and its Applications","difficulty":"easy"},{"type":"mcq","question":"...","choices":["A","B","C","D"],"topic":"...","difficulty":"medium"},{"type":"problem","question":"...","topic":"...","difficulty":"hard"}]`;

const EXAM_GRADE_SYSTEM_PROMPT = `You are a physics teacher grading a Lebanese high school student's exam.
You will be given a list of questions (each with a type: "tf", "mcq", or "problem"; mcq ones include their choices; each question also lists its topic and, if the topic is a known one, the exact set of allowed mistake tags for that topic) and the student's answers, in the same order.
For each question, decide if the student's answer is correct — for "tf" and "mcq" compare against the correct option; for "problem" allow reasonable equivalent phrasing/units, don't require exact wording. Write short (1-2 sentence) feedback explaining why, and the correct answer if they got it wrong.
If the answer is INCORRECT, also pick exactly one "mistake_tag" from that question's allowed list that best describes the kind of error — use "other" only if none of the specific tags fit. If the answer is correct, omit "mistake_tag" (or set it to null).
Respond with ONLY a JSON array of objects, nothing else — no markdown, no preamble. Format:
[{"correct": true, "feedback": "short explanation"}, {"correct": false, "feedback": "short explanation with the correct answer", "mistake_tag": "one-of-the-allowed-tags"}]
The array must have exactly as many objects as there are questions, in the same order.`;

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
  const userMessage = `Grade/branch: ${grade}\nLessons to draw questions from (use these EXACT names for "topic"): ${lessonList}`;

  try {
    const text = await callGroq(withLanguage(EXAM_GEN_SYSTEM_PROMPT, lang), userMessage, 800);
    let questions;
    try {
      questions = extractJson(text);
    } catch (e) {
      console.error('Failed to parse exam questions JSON:', text);
      return res.status(502).json({ error: 'Could not generate a valid exam. Try again.' });
    }
    res.json({ questions });
  } catch (err) {
    if (err.message === 'groq_error') {
      return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    }
    console.error('Server error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

app.post('/api/grade-exam', aiLimiter, async (req, res) => {
  // timeSpent is optional for now — an array of seconds per question, same order as
  // questions/answers. The frontend doesn't send this yet (instrumentation is a separate
  // step); when absent every attempt is saved with time_spent_seconds = null.
  const { grade, questions, answers, lang, timeSpent } = req.body;

  if (!grade || !Array.isArray(questions) || !Array.isArray(answers) || questions.length !== answers.length) {
    return res.status(400).json({ error: 'Please provide matching questions and answers.' });
  }
  if (!process.env.GROQ_API_KEY) {
    return res.status(500).json({ error: 'Server is missing its API key. Set GROQ_API_KEY in the environment.' });
  }

  const pairs = questions.map((q, i) => {
    const qText = typeof q === 'string' ? q : q.question;
    const qType = typeof q === 'string' ? 'problem' : (q.type || 'problem');
    const qTopic = typeof q === 'string' ? null : q.topic;
    const choicesLine = (qType === 'mcq' && Array.isArray(q.choices)) ? `\nChoices: ${q.choices.join(', ')}` : '';
    const topicLine = qTopic ? `\nTopic: ${qTopic}` : '';
    const tagsLine = qTopic ? `\nAllowed mistake tags if incorrect: ${tagsForTopic(qTopic).join(', ')}` : '';
    return `Q${i + 1} (${qType}): ${qText}${topicLine}${choicesLine}${tagsLine}\nStudent's answer: ${answers[i]}`;
  }).join('\n\n');
  const userMessage = `Grade/branch: ${grade}\n\n${pairs}`;

  try {
    const text = await callGroq(withLanguage(EXAM_GRADE_SYSTEM_PROMPT, lang), userMessage, 900);
    let results;
    try {
      results = extractJson(text);
    } catch (e) {
      console.error('Failed to parse grading JSON:', text);
      return res.status(502).json({ error: 'Could not grade the exam. Try again.' });
    }

    if (pool && req.user) {
      const score = results.filter(r => r.correct).length;
      pool.query(
        'INSERT INTO exam_results (user_id, grade, score, total, questions) VALUES ($1, $2, $3, $4, $5)',
        [req.user.userId, grade, score, results.length, JSON.stringify(questions)]
      ).catch(err => console.error('Failed to save exam result:', err));

      // Unified data model: one `attempts` row per question, not per exam session.
      // Fire-and-forget per row so a slow/failed insert never blocks the response the
      // student is waiting on for their results.
      questions.forEach((q, i) => {
        const qText = typeof q === 'string' ? q : q.question;
        const qTopic = typeof q === 'string' ? null : q.topic;
        const qDifficulty = typeof q === 'string' ? null : (q.difficulty || null);
        const r = results[i] || {};
        const spent = Array.isArray(timeSpent) ? (Number(timeSpent[i]) || null) : null;

        resolveTopicId(grade, qTopic).then(topicId => {
          pool.query(
            `INSERT INTO attempts
              (user_id, source, topic_id, difficulty, question_text, student_answer, correct, mistake_tag, time_spent_seconds)
             VALUES ($1, 'exam', $2, $3, $4, $5, $6, $7, $8)`,
            [req.user.userId, topicId, qDifficulty, qText, answers[i], !!r.correct, r.correct ? null : (r.mistake_tag || 'other'), spent]
          ).catch(err => console.error('Failed to save exam attempt:', err));
        });
      });
    }

    res.json({ results });
  } catch (err) {
    if (err.message === 'groq_error') {
      return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    }
    console.error('Server error:', err);
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
       FROM attempts a JOIN topics t ON t.id = a.topic_id WHERE t.grade = $1`,
      [grade]
    );
    const totalAttempts = Number(overall.rows[0].total_attempts) || 0;
    const totalCorrect = Number(overall.rows[0].total_correct) || 0;
    const overallMastery = totalAttempts > 0 ? Math.round((totalCorrect / totalAttempts) * 1000) / 10 : null;

    // Start from ALL topics defined for this grade (not just ones with attempts) so
    // topics nobody has practiced yet still show up in the dashboard — a teacher
    // needs to see "0 attempts, nothing here yet" just as much as low-mastery topics.
    const topics = await pool.query(
      `WITH grade_topics AS (
         SELECT id AS topic_id, title AS topic_title FROM topics WHERE grade = $1
       ),
       topic_attempts AS (
         SELECT a.user_id, a.correct, a.mistake_tag, a.question_text, gt.topic_id
         FROM attempts a JOIN grade_topics gt ON gt.topic_id = a.topic_id
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
         SELECT topic_id, mistake_tag, COUNT(*) AS cnt,
                ROW_NUMBER() OVER (PARTITION BY topic_id ORDER BY COUNT(*) DESC, mistake_tag) AS rn
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

    const students = await pool.query(
      `SELECT u.id, u.name, u.email,
              COUNT(*) AS attempts,
              SUM(CASE WHEN a.correct THEN 1 ELSE 0 END) AS correct_count,
              CASE WHEN COUNT(*) >= 3 THEN ROUND(100.0 * SUM(CASE WHEN a.correct THEN 1 ELSE 0 END) / COUNT(*), 1) ELSE NULL END AS mastery_pct
       FROM attempts a JOIN users u ON u.id = a.user_id
       WHERE a.topic_id = $1
       GROUP BY u.id, u.name, u.email
       ORDER BY mastery_pct ASC NULLS LAST, u.name`,
      [topicId]
    );

    const mistakes = await pool.query(
      `SELECT mistake_tag, COUNT(*) AS cnt FROM attempts
       WHERE topic_id = $1 AND correct = false AND mistake_tag IS NOT NULL
       GROUP BY mistake_tag ORDER BY cnt DESC, mistake_tag`,
      [topicId]
    );

    const missedQuestions = await pool.query(
      `SELECT question_text, COUNT(*) AS cnt FROM attempts
       WHERE topic_id = $1 AND correct = false
       GROUP BY question_text ORDER BY cnt DESC, question_text LIMIT 3`,
      [topicId]
    );

    res.json({
      topic: topic.rows[0],
      students: students.rows.map(r => ({
        id: r.id, name: r.name, email: r.email,
        attempts: Number(r.attempts),
        masteryPct: r.mastery_pct === null ? null : Number(r.mastery_pct),
      })),
      mistakeDistribution: mistakes.rows.map(r => ({ tag: r.mistake_tag, count: Number(r.cnt) })),
      mostMissedQuestions: missedQuestions.rows.map(r => ({ question: r.question_text, count: Number(r.cnt) })),
    });
  } catch (err) {
    console.error('Teacher topic-view error:', err);
    res.status(500).json({ error: 'Could not load topic data.' });
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
    const topics = await pool.query(
      `WITH topic_attempts AS (
         SELECT a.*, t.title AS topic_title, t.order_index
         FROM attempts a JOIN topics t ON t.id = a.topic_id WHERE t.grade = $1
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
