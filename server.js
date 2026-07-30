const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const SYSTEM_PROMPT = `You are a physics tutor for Lebanese high school students (Lebanese national curriculum, grades 9-12 / Brevet-Bac).
When given a physics problem:
1. Identify the relevant law/formula.
2. Solve step by step, showing each calculation.
3. If the student's own attempt is included and contains a mistake, point out exactly where the mistake is and correct it.
Keep it clear, concise, and appropriate for a high school student. Use simple language.`;

app.get('/', (req, res) => {
  res.send('Physics tutor backend is running.');
});

app.post('/api/solve', async (req, res) => {
  const { problem } = req.body;

  if (!problem || typeof problem !== 'string' || !problem.trim()) {
    return res.status(400).json({ error: 'Please send a physics problem in the "problem" field.' });
  }

  if (!process.env.ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'Server is missing its API key. Set ANTHROPIC_API_KEY in the environment.' });
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-5',
        max_tokens: 700,
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: problem }],
      }),
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error('Anthropic API error:', errText);
      return res.status(502).json({ error: 'The AI service returned an error. Check the server logs.' });
    }

    const data = await response.json();
    const solution = (data.content || [])
      .filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join('\n');

    res.json({ solution: solution || 'No solution returned.' });
  } catch (err) {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Physics tutor backend running on port ${PORT}`));
