# Physics tutor backend

This tiny server is what makes the "Try the solver" box on the website actually work.
It keeps your Anthropic API key private on the server — the website never sees it.

## What it does
- Receives a physics problem from the website
- Sends it to Claude with instructions to solve it step by step (Lebanese curriculum style)
- Sends the solution back to the website to display

## 1. Get an API key
1. Go to https://console.anthropic.com and create an account (or log in).
2. Go to "API Keys" and create a new key.
3. Copy it somewhere safe — you'll paste it into Render in step 3 below, not into any file you upload.
4. Add a small amount of credit to the account (Billing section) — the API is pay-as-you-go, very cheap per question.

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
   - Key: `ANTHROPIC_API_KEY`
   - Value: (paste the key you copied in step 1)
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
