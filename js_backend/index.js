// index.js - Express backend replicating key Flask endpoints (simplified)

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '..', '.env') });

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(helmet());
app.use(cors({
  origin: (origin, callback) => {
    const allowed = process.env.CORS_ORIGINS?.split(',')?.map(o => o.trim()) || [];
    if (!origin || allowed.includes(origin)) callback(null, true);
    else callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiter (per IP)
const apiLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_SEC || 3600) * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX || 5),
  message: { ok: false, reason: 'rate_limited', message: 'Too many requests, try again later.' }
});
app.use('/api/', apiLimiter);

// File upload handling
const uploadDir = path.join(__dirname, 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '.jpg';
    cb(null, `upload_${uuidv4()}${ext}`);
  }
});
const upload = multer({ storage });

// Simple in‑memory token store (mirrors Flask token logic)
const tokenStore = new Map(); // token -> expiry epoch
const TOKEN_TTL_SEC = parseInt(process.env.TOKEN_TTL_SEC || 1800);
function issueToken() {
  const token = uuidv4();
  tokenStore.set(token, Date.now() + TOKEN_TTL_SEC * 1000);
  return token;
}
function validToken(tok) {
  const exp = tokenStore.get(tok);
  if (!exp) return false;
  if (Date.now() > exp) { tokenStore.delete(tok); return false; }
  return true;
}

// ----- Endpoints -----

// Health check – mirrors /api/health
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    service: 'SmartSurround backend (JS)',
    status: 'online',
    admin_pin_configured: !!process.env.ADMIN_PIN,
    auth_disabled: process.env.AUTH_DISABLED === '1'
  });
});

// Placeholder camera analyze – returns dummy detection data
app.post('/api/camera/analyze', upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ ok: false, message: 'No image supplied.' });
  // In a real implementation you would run the AI model here.
  res.json({
    ok: true,
    image: `/uploads/${req.file.filename}`,
    road_condition: 'normal',
    damage_type: 'none',
    confidence: 1.0,
    accepted: true,
    severity: 'none',
    queued_for_admin: false
  });
});

// Auth token endpoint – mirrors /auth/token (simplified PIN check)
app.post('/auth/token', (req, res) => {
  const pin = req.body.pin || req.headers['x-admin-pin'];
  const configuredPin = process.env.ADMIN_PIN || '';
  if (process.env.AUTH_DISABLED !== '1' && (!configuredPin || pin !== configuredPin)) {
    return res.status(403).json({ ok: false, reason: 'blocked', message: 'Invalid PIN.' });
  }
  const token = issueToken();
  res.cookie('ss_token', token, { httpOnly: true, sameSite: 'strict' })
    .set('X-Set-Auth-Token', token)
    .json({ ok: true, message: 'Authenticated.' });
});

// Simple middleware to protect routes
function requireAuth(req, res, next) {
  if (process.env.AUTH_DISABLED === '1') return next();
  const token = req.cookies?.ss_token || req.headers['authorization']?.replace(/^Bearer\s+/i, '') || req.headers['x-auth-token'];
  const pin = req.body.pin || req.headers['x-admin-pin'];
  if (!validToken(token) || pin !== process.env.ADMIN_PIN) {
    return res.status(401).json({ ok: false, reason: 'blocked', message: 'Authentication required.' });
  }
  next();
}

// Admin API placeholder – returns empty arrays for pending/approved/rejected
app.get('/admin/api/detections', requireAuth, (req, res) => {
  res.json({ ok: true, pending: [], approved: [], rejected: [] });
});

// Upload endpoint – mirrors /upload (stores file, returns dummy response)
app.post('/upload', upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ ok: false, message: 'No image supplied.' });
  // In a real system you'd run detection and insert into DB.
  res.json({ ok: true, image: `/uploads/${req.file.filename}` });
});

// Serve uploaded files statically
app.use('/uploads', express.static(uploadDir));

// Start server
app.listen(PORT, () => {
  console.log(`SmartSurround JS backend listening on http://localhost:${PORT}`);
});
