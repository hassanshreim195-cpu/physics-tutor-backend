const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

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
  console.log('Database tables ready.');
}
setupDatabase().catch(err => console.error('Database setup failed:', err));

// --- Auth helpers ---
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

function signToken(user){
  return jwt.sign({ userId: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
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

app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, and password are all required.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length) return res.status(409).json({ error: 'An account with this email already exists.' });

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email',
      [name, email.toLowerCase(), hash]
    );
    const user = result.rows[0];
    res.json({ token: signToken(user), name: user.name, email: user.email });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Something went wrong creating the account.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!pool) return res.status(500).json({ error: 'No database connected on the server yet.' });
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Incorrect email or password.' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Incorrect email or password.' });

    res.json({ token: signToken(user), name: user.name, email: user.email });
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
        u.id, u.name, u.email, u.created_at,
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

const SYSTEM_PROMPT = `You are a physics tutor for Lebanese high school students (Lebanese national curriculum, grades 9-12 / Brevet-Bac).
When given a physics problem (as text, or shown in a photo):
1. Identify the relevant law/formula.
2. Solve step by step, showing each calculation.
3. If the student's own attempt is included and contains a mistake, point out exactly where the mistake is and correct it.
Keep it clear, concise, and appropriate for a high school student. Use simple language.`;

app.get('/', (req, res) => {
  res.send('Physics tutor backend is running.');
});

app.post('/api/solve', async (req, res) => {
  const { problem, image } = req.body;

  if ((!problem || typeof problem !== 'string' || !problem.trim()) && !image) {
    return res.status(400).json({ error: 'Please send a physics problem in the "problem" field, or attach an image.' });
  }

  if (!process.env.GEMINI_API_KEY) {
    return res.status(500).json({ error: 'Server is missing its API key. Set GEMINI_API_KEY in the environment.' });
  }

  try {
    const solution = await callGemini(SYSTEM_PROMPT, problem, image);

    if (pool && req.user) {
      pool.query(
        'INSERT INTO solver_history (user_id, problem, solution) VALUES ($1, $2, $3)',
        [req.user.userId, problem || '(photo)', solution]
      ).catch(err => console.error('Failed to save solver history:', err));
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

app.post('/api/study-plan', async (req, res) => {
  const { grade, examDate, daysLeft, lessons, otherExams } = req.body;

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
    const plan = await callGroq(STUDY_PLAN_SYSTEM_PROMPT, userMessage, 900);

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
Example:
[{"type":"tf","question":"..."},{"type":"mcq","question":"...","choices":["A","B","C","D"]},{"type":"problem","question":"..."}]`;

const EXAM_GRADE_SYSTEM_PROMPT = `You are a physics teacher grading a Lebanese high school student's exam.
You will be given a list of questions (each with a type: "tf", "mcq", or "problem", and mcq ones include their choices) and the student's answers, in the same order.
For each question, decide if the student's answer is correct — for "tf" and "mcq" compare against the correct option; for "problem" allow reasonable equivalent phrasing/units, don't require exact wording. Write short (1-2 sentence) feedback explaining why, and the correct answer if they got it wrong.
Respond with ONLY a JSON array of objects, nothing else — no markdown, no preamble. Format:
[{"correct": true, "feedback": "short explanation"}, {"correct": false, "feedback": "short explanation with the correct answer"}]
The array must have exactly as many objects as there are questions, in the same order.`;

function extractJson(text){
  const match = text.match(/\[[\s\S]*\]/);
  return match ? JSON.parse(match[0]) : JSON.parse(text);
}

app.post('/api/generate-exam', async (req, res) => {
  const { grade, lessons } = req.body;

  if (!grade) {
    return res.status(400).json({ error: 'Please provide the grade.' });
  }
  if (!process.env.GROQ_API_KEY) {
    return res.status(500).json({ error: 'Server is missing its API key. Set GROQ_API_KEY in the environment.' });
  }

  const lessonList = Array.isArray(lessons) && lessons.length ? lessons.join(', ') : 'general physics topics for this grade';
  const userMessage = `Grade/branch: ${grade}\nLessons to draw questions from: ${lessonList}`;

  try {
    const text = await callGroq(EXAM_GEN_SYSTEM_PROMPT, userMessage, 800);
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

app.post('/api/grade-exam', async (req, res) => {
  const { grade, questions, answers } = req.body;

  if (!grade || !Array.isArray(questions) || !Array.isArray(answers) || questions.length !== answers.length) {
    return res.status(400).json({ error: 'Please provide matching questions and answers.' });
  }
  if (!process.env.GROQ_API_KEY) {
    return res.status(500).json({ error: 'Server is missing its API key. Set GROQ_API_KEY in the environment.' });
  }

  const pairs = questions.map((q, i) => {
    const qText = typeof q === 'string' ? q : q.question;
    const qType = typeof q === 'string' ? 'problem' : (q.type || 'problem');
    const choicesLine = (qType === 'mcq' && Array.isArray(q.choices)) ? `\nChoices: ${q.choices.join(', ')}` : '';
    return `Q${i + 1} (${qType}): ${qText}${choicesLine}\nStudent's answer: ${answers[i]}`;
  }).join('\n\n');
  const userMessage = `Grade/branch: ${grade}\n\n${pairs}`;

  try {
    const text = await callGroq(EXAM_GRADE_SYSTEM_PROMPT, userMessage, 900);
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Physics tutor backend running on port ${PORT}`));
