import express from 'express';
import cors from 'cors';
import { createClient } from '@supabase/supabase-js';
import { Resend } from 'resend';
import axios from 'axios';
import path from 'path';
import { fileURLToPath } from 'url';
import rateLimit from 'express-rate-limit';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

// ── Env ──────────────────────────────────────────────────────────────────────
const {
  SUPABASE_URL,
  SUPABASE_SERVICE_KEY,
  RESEND_API_KEY,
  RECAPTCHA_SECRET,
  FROM_EMAIL = 'noreply@lastdlc.com',
  PORT = 3000,
} = process.env;

// ── Clients ──────────────────────────────────────────────────────────────────
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
const resend   = new Resend(RESEND_API_KEY);

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); // serve frontend

// Rate limiters
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Слишком много запросов, попробуйте позже' } });
const codeLimiter = rateLimit({ windowMs: 60 * 1000,      max: 5,  message: { error: 'Слишком много попыток' } });

// ── Helpers ───────────────────────────────────────────────────────────────────
async function verifyRecaptcha(token) {
  if (!token) return false;
  try {
    const { data } = await axios.post(
      'https://www.google.com/recaptcha/api/siteverify',
      new URLSearchParams({ secret: RECAPTCHA_SECRET, response: token }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    // reCAPTCHA v3: score >= 0.5 считается человеком
    return data.success && data.score >= 0.5;
  } catch { return false; }
}

function generateCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// ── Routes ────────────────────────────────────────────────────────────────────

// POST /api/register  — шаг 1: проверка данных + отправка кода на email
app.post('/api/register', authLimiter, async (req, res) => {
  const { username, email, password, recaptchaToken } = req.body;

  // Валидация
  if (!username || username.length < 3)
    return res.status(400).json({ error: 'Логин слишком короткий (мин. 3 символа)' });
  if (!email || !email.includes('@'))
    return res.status(400).json({ error: 'Введите корректный email' });
  if (!password || password.length < 6)
    return res.status(400).json({ error: 'Пароль слишком короткий (мин. 6 символов)' });

  // reCAPTCHA v3
  const captchaOk = await verifyRecaptcha(recaptchaToken);
  if (!captchaOk)
    return res.status(400).json({ error: 'reCAPTCHA не прошла. Попробуйте ещё раз' });

  // Проверяем, не занят ли логин / email
  const { data: existing } = await supabase
    .from('users')
    .select('id')
    .or(`username.eq.${username},email.eq.${email}`)
    .maybeSingle();

  if (existing)
    return res.status(409).json({ error: 'Логин или email уже занят' });

  // Генерируем код и сохраняем pending-запись
  const code    = generateCode();
  const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 минут

  const { error: upsertErr } = await supabase
    .from('pending_verifications')
    .upsert({ email, username, password_hash: password, code, expires_at: expires },
             { onConflict: 'email' });

  if (upsertErr) {
    console.error(upsertErr);
    return res.status(500).json({ error: 'Ошибка сервера' });
  }

  // Отправляем email
  await resend.emails.send({
    from: FROM_EMAIL,
    to: email,
    subject: 'Код подтверждения — lastDLC',
    html: emailTemplate(code),
  });

  res.json({ ok: true, message: 'Код отправлен на ' + email });
});

// POST /api/verify-email  — шаг 2: проверка кода → создание аккаунта
app.post('/api/verify-email', codeLimiter, async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code)
    return res.status(400).json({ error: 'Не хватает данных' });

  const { data: pending } = await supabase
    .from('pending_verifications')
    .select('*')
    .eq('email', email)
    .eq('code', code)
    .maybeSingle();

  if (!pending)
    return res.status(400).json({ error: 'Неверный код' });

  if (new Date(pending.expires_at) < new Date())
    return res.status(400).json({ error: 'Код истёк. Зарегистрируйтесь снова' });

  // Создаём пользователя (пароль надо хэшировать на продакшне через bcrypt,
  // здесь упрощено для старта)
  const { data: user, error: insertErr } = await supabase
    .from('users')
    .insert({ username: pending.username, email, password_hash: pending.password_hash })
    .select()
    .single();

  if (insertErr) {
    console.error(insertErr);
    return res.status(500).json({ error: 'Ошибка создания аккаунта' });
  }

  // Чистим pending
  await supabase.from('pending_verifications').delete().eq('email', email);

  res.json({ ok: true, user: { id: user.id, username: user.username, email: user.email } });
});

// POST /api/login
app.post('/api/login', authLimiter, async (req, res) => {
  const { login, password, recaptchaToken } = req.body;
  if (!login || !password)
    return res.status(400).json({ error: 'Введите логин и пароль' });

  // reCAPTCHA v3
  const captchaOk = await verifyRecaptcha(recaptchaToken);
  if (!captchaOk)
    return res.status(400).json({ error: 'reCAPTCHA не прошла. Попробуйте ещё раз' });

  // Ищем по логину или email
  const { data: user } = await supabase
    .from('users')
    .select('*')
    .or(`username.eq.${login},email.eq.${login}`)
    .maybeSingle();

  if (!user || user.password_hash !== password)
    return res.status(401).json({ error: 'Неверный логин или пароль' });

  // Отправляем код на email для 2FA
  const code    = generateCode();
  const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  await supabase
    .from('login_codes')
    .upsert({ user_id: user.id, code, expires_at: expires }, { onConflict: 'user_id' });

  await resend.emails.send({
    from: FROM_EMAIL,
    to: user.email,
    subject: 'Вход в аккаунт — lastDLC',
    html: emailTemplate(code, 'login'),
  });

  res.json({ ok: true, message: 'Код отправлен на ' + user.email, userId: user.id });
});

// POST /api/verify-login
app.post('/api/verify-login', codeLimiter, async (req, res) => {
  const { userId, code } = req.body;

  const { data: row } = await supabase
    .from('login_codes')
    .select('*')
    .eq('user_id', userId)
    .eq('code', code)
    .maybeSingle();

  if (!row)
    return res.status(400).json({ error: 'Неверный код' });
  if (new Date(row.expires_at) < new Date())
    return res.status(400).json({ error: 'Код истёк' });

  const { data: user } = await supabase
    .from('users')
    .select('id, username, email, avatar_url')
    .eq('id', userId)
    .single();

  await supabase.from('login_codes').delete().eq('user_id', userId);

  // Простой session-токен (в продакшне — JWT)
  const token = Buffer.from(`${user.id}:${Date.now()}:${Math.random()}`).toString('base64');
  await supabase.from('sessions').insert({ user_id: user.id, token });

  res.json({ ok: true, token, user: { id: user.id, username: user.username, email: user.email, avatar_url: user.avatar_url } });
});

// GET /api/me  — проверка сессии
app.get('/api/me', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Нет токена' });

  const { data: session } = await supabase
    .from('sessions')
    .select('user_id')
    .eq('token', token)
    .maybeSingle();

  if (!session) return res.status(401).json({ error: 'Сессия не найдена' });

  const { data: user } = await supabase
    .from('users')
    .select('id, username, email, avatar_url')
    .eq('id', session.user_id)
    .single();

  res.json({ user });
});

// POST /api/logout
app.post('/api/logout', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token) await supabase.from('sessions').delete().eq('token', token);
  res.json({ ok: true });
});

// ── Email templates ───────────────────────────────────────────────────────────
function emailTemplate(code, type = 'register') {
  const title = type === 'login' ? 'Подтверждение входа' : 'Подтверждение регистрации';
  const text  = type === 'login'
    ? 'Кто-то входит в ваш аккаунт lastDLC. Если это вы — введите код:'
    : 'Для завершения регистрации введите код:';
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0a0a0a;font-family:'Inter',Arial,sans-serif">
  <div style="max-width:480px;margin:40px auto;background:#161616;border:1px solid rgba(255,255,255,0.07);border-radius:20px;padding:40px;text-align:center">
    <div style="font-family:'Unbounded',Arial,sans-serif;font-weight:900;font-size:22px;color:#f0f0f0;margin-bottom:8px">lastDLC</div>
    <div style="color:#888;font-size:13px;margin-bottom:32px">${title}</div>
    <div style="color:#f0f0f0;font-size:14px;line-height:1.6;margin-bottom:28px">${text}</div>
    <div style="background:#0a0a0a;border:1px solid rgba(255,255,255,0.1);border-radius:14px;padding:24px;letter-spacing:0.3em;font-size:32px;font-weight:800;color:#f0f0f0;font-family:'Unbounded',Arial,sans-serif">${code}</div>
    <div style="color:#666;font-size:12px;margin-top:24px">Код действует 15 минут.<br>Если вы не запрашивали его — просто игнорируйте письмо.</div>
  </div>
</body></html>`;
}

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`lastDLC backend running on :${PORT}`));
