# Physics tutor backend

This tiny server is what makes the AI features on the website actually work (solver, study plan, practice exam).
It keeps your API keys private on the server — the website never sees them.

Both APIs used here are **free**:
- **Groq** (running Meta's Llama 3.1) — powers the study plan and practice exam (text only).
- **Gemini** (Google) — powers the solver, including reading photos of problems.

## What it does
- Receives a physics problem (text or photo) from the website
- Sends it to the AI with instructions to solve it step by step (Lebanese curriculum style)
- Sends the solution back to the website to display

## 1. Get your two free API keys

**Groq (for study plan & exam):**
1. Go to https://console.groq.com and create a free account (no credit card needed).
2. Go to "API Keys" → "Create API Key".
3. Copy it somewhere safe (starts with `gsk_...`).

**Gemini (for the solver, including photos):**
1. Go to https://aistudio.google.com/apikey and sign in with a Google account.
2. Click "Create API key" (no credit card needed for the free tier).
3. Copy it somewhere safe.

You'll paste both into Render in step 3 below — never into any file you upload to GitHub.

## 2. Put this code on GitHub
1. Create a free account at https://github.com if you don't have one.
2. Create a new repository (e.g. "physics-tutor-backend").
3. Upload the files in this `backend` folder to that repository (drag-and-drop works on github.com — do NOT upload the `.env` file, only `.env.example`).

## 3. Deploy on Render (free tier)
1. Go to https://render.com and sign up (you can sign up with your GitHub account).
2. Click "New +" -> "Web Service".
3. Connect the GitHub repository you just created.
4. Settings:
   - Build command: `npm install`
   - Start command: `npm start`
5. Under "Environment Variables", add:
   - Key: `GROQ_API_KEY`, Value: (the Groq key from step 1)
   - Key: `GEMINI_API_KEY`, Value: (the Gemini key from step 1)
6. Click "Create Web Service". Wait a few minutes for it to deploy.
7. Render will give you a URL like `https://physics-tutor-backend-xxxx.onrender.com` — copy it.

## 4. Connect the website to it
Open `index.html`, find this line near the top of the script:

```js
const BACKEND_URL = "PASTE_YOUR_RENDER_URL_HERE";
```

Replace `PASTE_YOUR_RENDER_URL_HERE` with the URL from step 3.7 (keep the quotes). Save, re-upload the file wherever your website is hosted, and the solver box will call your real backend.

## Notes
- Render's free tier "sleeps" after 15 minutes of no traffic — the first request after that can take ~30 seconds while it wakes up. That's normal for a free tier.
- You can change the model in `server.js` (the `model:` line) if you want a cheaper/faster or more capable option.

## 5. Accounts (Postgres database) — for later, when you're ready
This backend also supports student accounts (register/login) and saving each student's exam scores, study plans, and solved problems so they see them again next time they log in. To turn this on:

1. On Render, click "New +" → "PostgreSQL". Create a free database.
2. Once created, Render shows an "Internal Database URL" — copy it.
3. Go back to your web service (`physics-tutor-backend`) → "Environment" → add:
   - Key: `DATABASE_URL`, Value: (the URL from step 2)
   - Key: `JWT_SECRET`, Value: any long random string you make up (e.g. mash your keyboard)
4. Redeploy the web service (Manual Deploy → Deploy latest commit).
5. The required tables are created automatically the first time the server starts — no manual database setup needed.
