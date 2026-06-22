const express      = require('express');
const multer       = require('multer');
const path         = require('path');
const fs           = require('fs');
const crypto       = require('crypto');
const jwt          = require('jsonwebtoken');
const bcrypt       = require('bcryptjs');
const cookieParser = require('cookie-parser');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);          // behind the nginx reverse proxy
app.use(express.json({ limit: '16kb' }));
app.use(cookieParser());

// ---- Config (override via environment / .env) ----
const PORT            = process.env.PORT || 3001;
const UPLOAD_DIR      = process.env.UPLOAD_DIR || '/uploads';
const MAX_BYTES       = Number(process.env.MAX_BYTES || 10 * 1024 * 1024);
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || '';
const RETENTION_DAYS  = Number(process.env.RETENTION_DAYS || 0);

// ---- Auth config ----
const SESSION_SECRET  = process.env.SESSION_SECRET || '';
const ADMIN_USER      = process.env.ADMIN_USER || 'admin';
let   ADMIN_HASH      = process.env.ADMIN_PASSWORD_HASH || '';
const ADMIN_PASSWORD  = process.env.ADMIN_PASSWORD || '';
const COOKIE_SECURE   = process.env.COOKIE_SECURE === 'true';  // set true once on HTTPS
const TOKEN_TTL       = process.env.TOKEN_TTL || '7d';
const COOKIE_NAME     = 'il_session';

// Accept either a precomputed bcrypt hash (preferred) or a plaintext password.
if (!ADMIN_HASH && ADMIN_PASSWORD) ADMIN_HASH = bcrypt.hashSync(ADMIN_PASSWORD, 10);

// Refuse to start open/insecure: auth must be configured.
if (!SESSION_SECRET || !ADMIN_HASH) {
  console.error('FATAL: set SESSION_SECRET and ADMIN_PASSWORD (or ADMIN_PASSWORD_HASH) in your .env');
  process.exit(1);
}

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ---- Auth helpers ----
function setSession(res, user) {
  const token = jwt.sign({ sub: user }, SESSION_SECRET, { expiresIn: TOKEN_TTL });
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: COOKIE_SECURE,
    maxAge: 7 * 24 * 3600 * 1000,
    path: '/',
  });
}
function requireAuth(req, res, next) {
  try {
    const token = req.cookies[COOKIE_NAME];
    if (!token) return res.status(401).json({ error: 'Not authenticated' });
    req.user = jwt.verify(token, SESSION_SECRET).sub;
    next();
  } catch {
    return res.status(401).json({ error: 'Not authenticated' });
  }
}

// ---- Auth routes ----
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Missing credentials' });
  }
  const userOk = username === ADMIN_USER;
  const passOk = await bcrypt.compare(password, ADMIN_HASH); // always run (reduces timing leak)
  if (!userOk || !passOk) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  setSession(res, username);
  return res.json({ ok: true, user: username });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, { path: '/' });
  return res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => res.json({ user: req.user }));

// ---- Upload (now requires a valid session) ----
const EXT = { jpeg: '.jpg', png: '.png', gif: '.gif', webp: '.webp' };

function detectImage(buf) {
  if (!buf || buf.length < 12) return null;
  if (buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) return 'jpeg';
  if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47 &&
      buf[4] === 0x0D && buf[5] === 0x0A && buf[6] === 0x1A && buf[7] === 0x0A) return 'png';
  const head6 = buf.toString('latin1', 0, 6);
  if (head6 === 'GIF87a' || head6 === 'GIF89a') return 'gif';
  if (buf.toString('latin1', 0, 4) === 'RIFF' && buf.toString('latin1', 8, 12) === 'WEBP') return 'webp';
  return null;
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_BYTES, files: 1 },
});

app.post('/api/upload', requireAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const kind = detectImage(req.file.buffer);
    if (!kind) {
      return res.status(400).json({ error: 'File is not a valid image (JPG, PNG, GIF, WEBP only)' });
    }
    const filename = crypto.randomBytes(16).toString('hex') + EXT[kind];
    await fs.promises.writeFile(path.join(UPLOAD_DIR, filename), req.file.buffer);
    const base = PUBLIC_BASE_URL || `${req.protocol}://${req.get('host')}`;
    console.log('Uploaded:', filename, 'by', req.user);
    return res.json({ url: `${base}/uploads/${filename}`, filename });
  } catch (err) {
    console.error('Upload error:', err);
    return res.status(500).json({ error: 'Upload failed' });
  }
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    const msg = err.code === 'LIMIT_FILE_SIZE'
      ? `File too large (max ${Math.round(MAX_BYTES / (1024 * 1024))} MB)`
      : 'Upload rejected';
    return res.status(400).json({ error: msg });
  }
  console.error('Unhandled error:', err);
  return res.status(500).json({ error: 'Server error' });
});

// ---- Optional retention sweep ----
function sweepOldFiles() {
  if (!RETENTION_DAYS) return;
  const cutoff = Date.now() - RETENTION_DAYS * 86400000;
  fs.readdir(UPLOAD_DIR, (e, files) => {
    if (e) return console.error('Sweep readdir failed:', e.message);
    for (const f of files) {
      const p = path.join(UPLOAD_DIR, f);
      fs.stat(p, (se, st) => {
        if (!se && st.isFile() && st.mtimeMs < cutoff) {
          fs.unlink(p, ue => ue && console.error('Sweep unlink failed:', ue.message));
        }
      });
    }
  });
}
if (RETENTION_DAYS) { sweepOldFiles(); setInterval(sweepOldFiles, 86400000); }

app.listen(PORT, () => console.log(`ImageLink backend running on port ${PORT}`));
