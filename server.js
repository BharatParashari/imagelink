const express = require('express');
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs');
const crypto  = require('crypto');

const app = express();
app.disable('x-powered-by');

// Behind the nginx reverse proxy. Lets req.ip / protocol reflect the real client.
app.set('trust proxy', 1);

// ---- Config (override via environment / docker-compose) ----
const PORT            = process.env.PORT || 3001;
const UPLOAD_DIR      = process.env.UPLOAD_DIR || '/uploads';
const MAX_BYTES       = Number(process.env.MAX_BYTES || 10 * 1024 * 1024); // 10 MB
// Hardcode the public origin so the returned link can't be poisoned via the Host header.
// When you move to a subdomain, set PUBLIC_BASE_URL=https://img.yourdomain.com
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || '';
// Optional auto-cleanup. 0 / unset = keep files forever.
const RETENTION_DAYS  = Number(process.env.RETENTION_DAYS || 0);

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// We decide the extension; the client's filename and declared MIME are never trusted.
const EXT = { jpeg: '.jpg', png: '.png', gif: '.gif', webp: '.webp' };

// Dependency-free magic-byte sniff, scoped to exactly the formats we allow.
// Returns one of: 'jpeg' | 'png' | 'gif' | 'webp' | null. Cannot loop or throw.
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

// Hold the upload in memory so we can verify its real bytes before writing anything.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_BYTES, files: 1 },
});

app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    // Validate by content (magic bytes), NOT by the client-supplied MIME/extension.
    const kind = detectImage(req.file.buffer);
    if (!kind) {
      return res.status(400).json({ error: 'File is not a valid image (JPG, PNG, GIF, WEBP only)' });
    }

    // Server-generated name + extension. No part of this comes from user input,
    // so path traversal, double extensions, and ".html"/".svg" tricks are impossible.
    const filename = crypto.randomBytes(16).toString('hex') + EXT[kind];
    await fs.promises.writeFile(path.join(UPLOAD_DIR, filename), req.file.buffer);

    const base = PUBLIC_BASE_URL || `${req.protocol}://${req.get('host')}`;
    console.log('Uploaded:', filename);
    return res.json({ url: `${base}/uploads/${filename}`, filename });
  } catch (err) {
    console.error('Upload error:', err);
    return res.status(500).json({ error: 'Upload failed' });
  }
});

// Lightweight health endpoint for the container healthcheck.
app.get('/api/health', (req, res) => res.json({ ok: true }));

// Centralised error handler. Logs detail server-side, returns a safe message.
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

// ---- Optional retention sweep (disabled unless RETENTION_DAYS > 0) ----
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
if (RETENTION_DAYS) {
  sweepOldFiles();
  setInterval(sweepOldFiles, 86400000); // daily
}

app.listen(PORT, () => {
  console.log(`ImageLink backend running on port ${PORT}`);
});
