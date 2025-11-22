// Grab UI elements
const pwd = document.getElementById('pwd');
const meter = document.getElementById('meter');
const scoreLabel = document.getElementById('score-label');
const feedbackList = document.getElementById('feedback');
const hibpBtn = document.getElementById('hibp-btn');
const hibpResult = document.getElementById('hibp-result');

// Helper: set meter color by score (0–4 from zxcvbn)
function colorForScore(score) {
  return ['#ef4444', '#f97316', '#f59e0b', '#22c55e', '#16a34a'][score];
}
function labelForScore(score) {
  return ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'][score];
}

// Custom hygiene rules
function customChecks(pwd) {
  const issues = [];
  if (pwd.length < 12) issues.push('Use at least 12 characters.');
  if (!/[A-Z]/.test(pwd)) issues.push('Add uppercase letters (A–Z).');
  if (!/[a-z]/.test(pwd)) issues.push('Add lowercase letters (a–z).');
  if (!/[0-9]/.test(pwd)) issues.push('Include numbers (0–9).');
  if (!/[!@#$%^&*()_\-+=

\[\]

{};:,.<>/?\\|`~]/.test(pwd)) issues.push('Use special symbols.');
  if (/password|qwerty|letmein|welcome|admin|12345|iloveyou/i.test(pwd)) issues.push('Avoid common words or sequences.');
  if (/(.)\1{2,}/.test(pwd)) issues.push('Avoid repeated characters.');
  if (/^[A-Za-z]+$/.test(pwd)) issues.push('Avoid only letters; diversify characters.');
  return issues;
}

// Render feedback list
function renderList(list, items) {
  list.innerHTML = '';
  items.forEach(msg => {
    const li = document.createElement('li');
    li.textContent = msg;
    list.appendChild(li);
  });
}

// Live scoring with zxcvbn + custom rules
pwd.addEventListener('input', () => {
  const val = pwd.value;
  if (!val) {
    meter.style.width = '0%';
    meter.style.background = '#ef4444';
    scoreLabel.textContent = '';
    renderList(feedbackList, []);
    hibpResult.textContent = '';
    return;
  }

  const z = zxcvbn(val);
  const score = z.score; // 0..4
  meter.style.width = `${(score + 1) * 20}%`; // 20% increments
  meter.style.background = colorForScore(score);
  scoreLabel.textContent = `Strength: ${labelForScore(score)} (entropy: ${Math.round(z.entropy)} bits)`;

  const messages = [];
  if (z.feedback.warning) messages.push(z.feedback.warning);
  if (z.feedback.suggestions?.length) messages.push(...z.feedback.suggestions);
  messages.push(...customChecks(val));

  renderList(feedbackList, Array.from(new Set(messages)));
});

// Privacy-safe breach check using HIBP k-anonymity
async function checkHIBP(password) {
  const enc = new TextEncoder();
  const data = enc.encode(password);
  const hashBuf = await crypto.subtle.digest('SHA-1', data);
  const hashHex = Array.from(new Uint8Array(hashBuf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();

  const prefix = hashHex.slice(0, 5);
  const suffix = hashHex.slice(5);

  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  const text = await res.text();

  const lines = text.split('\n');
  const match = lines.find(line => line.startsWith(suffix));
  if (match) {
    const count = parseInt(match.split(':')[1], 10);
    return { pwned: true, count };
  }
  return { pwned: false, count: 0 };
}

hibpBtn.addEventListener('click', async () => {
  const val = pwd.value;
  hibpResult.textContent = 'Checking…';
  if (!val) {
    hibpResult.textContent = 'Enter a password to check.';
    return;
  }
  try {
    const result = await checkHIBP(val);
    if (result.pwned) {
      hibpResult.textContent = `⚠️ This password appears in breaches (${result.count} times). Choose a different one.`;
      hibpResult.style.color = '#f97316';
    } else {
      hibpResult.textContent = '✅ No breach match found for this password.';
      hibpResult.style.color = '#22c55e';
    }
  } catch (e) {
    console.error(e);
    hibpResult.textContent = '❌ Breach check failed. Try again later.';
    hibpResult.style.color = '#ef4444';
  }
});
