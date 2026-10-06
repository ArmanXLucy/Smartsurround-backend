// index.js - Express backend replicating key Flask endpoints (simplified)

const {
  SageMakerRuntimeClient,
  InvokeEndpointCommand,
} = require("@aws-sdk/client-sagemaker-runtime");

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '..', '.env') });

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================================
// AWS SageMaker configuration
// ============================================================

const sagemakerClient = new SageMakerRuntimeClient({
  region:
    process.env.AWS_REGION ||
    process.env.AWS_DEFAULT_REGION ||
    "ap-southeast-2",
});

const SAGEMAKER_ENDPOINT =
  process.env.SAGEMAKER_ENDPOINT ||
  "smartsurround-road-damage";

const firebaseDatabaseUrl = String(
  process.env.FIREBASE_DATABASE_URL ||
    process.env.VITE_FIREBASE_DATABASE_URL ||
    ''
).replace(/\/+$/, '');

const sensorFreshnessMs = 15000;

let lastSensorHeartbeat = null;
let lastSensorChangeAt = 0;

const stateFile = path.join(__dirname, 'smartsurround-js-state.json');

const firebaseTokenUrl = 'https://oauth2.googleapis.com/token';

let firebaseAccessToken = null;
let firebaseAccessTokenExpiresAt = 0;

const defaultThresholds = [
  {
    sensor: 'PM1.0',
    warning: 20,
    critical: 40,
    minimum: null,
    maximum: null,
    unit: 'µg/m³'
  },
  {
    sensor: 'PM2.5',
    warning: 35,
    critical: 55,
    minimum: null,
    maximum: null,
    unit: 'µg/m³'
  },
  {
    sensor: 'PM10',
    warning: 80,
    critical: 150,
    minimum: null,
    maximum: null,
    unit: 'µg/m³'
  },
  {
    sensor: 'CO2',
    warning: 1000,
    critical: 2000,
    minimum: null,
    maximum: null,
    unit: 'ppm'
  },
  {
    sensor: 'VOC',
    warning: 1,
    critical: 2,
    minimum: null,
    maximum: null,
    unit: 'ppm'
  },
  {
    sensor: 'IAQ',
    warning: 100,
    critical: 200,
    minimum: null,
    maximum: null,
    unit: 'index'
  },
  {
    sensor: 'Temperature',
    warning: null,
    critical: null,
    minimum: 18,
    maximum: 32,
    unit: '°C'
  },
  {
    sensor: 'Humidity',
    warning: null,
    critical: null,
    minimum: 30,
    maximum: 70,
    unit: '%'
  }
];

function loadState() {
  try {
    if (fs.existsSync(stateFile)) {
      const parsed = JSON.parse(
        fs.readFileSync(stateFile, 'utf8')
      );

      return {
        thresholds:
          Array.isArray(parsed.thresholds) &&
          parsed.thresholds.length
            ? parsed.thresholds
            : defaultThresholds,

        alerts: Array.isArray(parsed.alerts)
          ? parsed.alerts
          : [],

        activity: Array.isArray(parsed.activity)
          ? parsed.activity
          : [],

        users: Array.isArray(parsed.users)
          ? parsed.users
          : [],

        locations: Array.isArray(parsed.locations)
          ? parsed.locations
          : [],

        complaints: Array.isArray(parsed.complaints)
          ? parsed.complaints
          : []
      };
    }
  } catch (error) {
    console.warn(
      'Unable to load JS backend state:',
      error.message
    );
  }

  return {
    thresholds: defaultThresholds,
    alerts: [],
    activity: [],
    users: [],
    locations: [],
    complaints: []
  };
}

let backendState = loadState();

function saveState() {
  const temporary = `${stateFile}.tmp`;

  fs.writeFileSync(
    temporary,
    JSON.stringify(backendState, null, 2)
  );

  fs.renameSync(
    temporary,
    stateFile
  );
}

// Middleware

app.use(helmet());

app.use(
  cors({
    origin: (origin, callback) => {
      const allowed =
        process.env.CORS_ORIGINS
          ?.split(',')
          ?.map((o) => o.trim()) || [];

      if (!origin || allowed.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },

    credentials: true
  })
);

app.use(express.json());
app.use(
  express.urlencoded({
    extended: true
  })
);

// Rate limiter (per IP)

const apiLimiter = rateLimit({
  windowMs:
    parseInt(
      process.env.RATE_LIMIT_SEC || 3600
    ) * 1000,

  max:
    parseInt(
      process.env.RATE_LIMIT_MAX || 300
    ),

  message: {
    ok: false,
    reason: 'rate_limited',
    message:
      'Too many requests, try again later.'
  }
});

app.use('/api/', apiLimiter);

// File upload handling

const uploadDir = path.join(
  __dirname,
  'uploads'
);

fs.mkdirSync(
  uploadDir,
  { recursive: true }
);

const storage = multer.diskStorage({
  destination: (req, file, cb) =>
    cb(null, uploadDir),

  filename: (req, file, cb) => {
    const ext =
      path.extname(file.originalname) ||
      '.jpg';

    cb(
      null,
      `upload_${uuidv4()}${ext}`
    );
  }
});

const upload = multer({
  storage
});

// Simple in-memory token store
// (mirrors Flask token logic)

const tokenStore = new Map();

const TOKEN_TTL_SEC =
  parseInt(
    process.env.TOKEN_TTL_SEC || 1800
  );

function issueToken() {
  const token = uuidv4();

  tokenStore.set(
    token,
    Date.now() +
      TOKEN_TTL_SEC * 1000
  );

  return token;
}

function validToken(tok) {
  const exp = tokenStore.get(tok);

  if (!exp) return false;

  if (Date.now() > exp) {
    tokenStore.delete(tok);
    return false;
  }

  return true;
}

function serviceAccountInfo() {
  try {
    if (
      process.env.FIREBASE_SERVICE_ACCOUNT_JSON
    ) {
      return JSON.parse(
        process.env.FIREBASE_SERVICE_ACCOUNT_JSON
      );
    }

    const configuredPath =
      process.env.FIREBASE_SERVICE_ACCOUNT_PATH ||
      'serviceAccountKey.json';

    const servicePath = path.resolve(
      __dirname,
      '..',
      configuredPath
    );

    if (fs.existsSync(servicePath)) {
      return JSON.parse(
        fs.readFileSync(
          servicePath,
          'utf8'
        )
      );
    }
  } catch (error) {
    console.warn(
      'Unable to read Firebase service account:',
      error.message
    );
  }

  return null;
}

function base64Url(value) {
  return Buffer.from(value)
    .toString('base64url');
}

async function getFirebaseAccessToken() {
  if (
    firebaseAccessToken &&
    Date.now() <
      firebaseAccessTokenExpiresAt - 60000
  ) {
    return firebaseAccessToken;
  }

  const account =
    serviceAccountInfo();

  if (
    !account?.client_email ||
    !account?.private_key
  ) {
    return null;
  }

  const now =
    Math.floor(Date.now() / 1000);

  const header = base64Url(
    JSON.stringify({
      alg: 'RS256',
      typ: 'JWT'
    })
  );

  const claim = base64Url(
    JSON.stringify({
      iss: account.client_email,

      scope:
        'https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/userinfo.email',

      aud: firebaseTokenUrl,

      iat: now,

      exp: now + 3600
    })
  );

  const unsigned =
    `${header}.${claim}`;

  const signer =
    crypto.createSign('RSA-SHA256');

  signer.update(unsigned);
  signer.end();

  const assertion =
    `${unsigned}.${signer.sign(
      account.private_key,
      'base64url'
    )}`;

  const response = await fetch(
    firebaseTokenUrl,
    {
      method: 'POST',

      headers: {
        'Content-Type':
          'application/x-www-form-urlencoded'
      },

      body: new URLSearchParams({
        grant_type:
          'urn:ietf:params:oauth:grant-type:jwt-bearer',

        assertion
      })
    }
  );

  if (!response.ok) {
    throw new Error(
      `Firebase access token request failed (${response.status}).`
    );
  }

  const result =
    await response.json();

  firebaseAccessToken =
    result.access_token;

  firebaseAccessTokenExpiresAt =
    Date.now() +
    Number(
      result.expires_in || 3600
    ) *
      1000;

  return firebaseAccessToken;
}

async function firebaseRequest(
  endpoint,
  options = {}
) {
  if (
    !firebaseDatabaseUrl ||
    typeof fetch !== 'function'
  ) {
    throw new Error(
      'FIREBASE_DATABASE_URL is not configured.'
    );
  }

  const token =
    await getFirebaseAccessToken();

  const url = new URL(
    `${firebaseDatabaseUrl}/${String(
      endpoint
    ).replace(/^\/+/, '')}`
  );

  if (token) {
    url.searchParams.set(
      'access_token',
      token
    );
  } else if (
    process.env.FIREBASE_DATABASE_SECRET
  ) {
    url.searchParams.set(
      'auth',
      process.env.FIREBASE_DATABASE_SECRET
    );
  }

  return fetch(
    url,
    {
      cache: 'no-store',

      ...options,

      headers: {
        ...(options.body
          ? {
              'Content-Type':
                'application/json'
            }
          : {}),

        ...(options.headers || {})
      }
    }
  );
}

function finiteNumber(value) {
  if (
    value === null ||
    value === undefined ||
    value === ''
  ) {
    return null;
  }

  const number =
    Number(value);

  return Number.isFinite(number)
    ? number
    : null;
}

function firstPresent(
  source,
  keys
) {
  for (const key of keys) {
    if (
      source &&
      source[key] !== null &&
      source[key] !== undefined &&
      source[key] !== ''
    ) {
      return source[key];
    }
  }

  return null;
}

function normalizeSensorReading(
  root,
  fresh
) {
  const source =
    root &&
    typeof root.sensors === 'object'
      ? root.sensors
      : root || {};

  return {
    pm1: fresh
      ? finiteNumber(source.pm1)
      : null,

    pm25: fresh
      ? finiteNumber(source.pm25)
      : null,

    pm10: fresh
      ? finiteNumber(source.pm10)
      : null,

    temperature: fresh
      ? finiteNumber(
          source.temperature
        )
      : null,

    humidity: fresh
      ? finiteNumber(
          source.humidity
        )
      : null,

    co2: fresh
      ? finiteNumber(
          firstPresent(
            source,
            [
              'co2',
              'co2Equivalent'
            ]
          )
        )
      : null,

    voc: fresh
      ? finiteNumber(
          firstPresent(
            source,
            [
              'voc',
              'vocEquivalent'
            ]
          )
        )
      : null,

    // IAQ is passed through from the ESP32.
    // No frontend or backend fallback.

    iaq: fresh
      ? finiteNumber(
          firstPresent(
            source,
            [
              'iaq',
              'iaqScore',
              'airQualityIndex',
              'IAQ'
            ]
          )
        )
      : null,

    calibrating:
      Boolean(source.calibrating),

    iaqAccuracyText:
      source.iaqAccuracyText ??
      source.iaqAccuracy ??
      null,

    ip:
      source.ip ??
      root?.ip ??
      null,

    uptime: fresh
      ? finiteNumber(
          source.uptime
        )
      : null,

    updatedAt:
      source.updatedAt ??
      source.timestamp ??
      root?.updatedAt ??
      null,

    status: fresh
      ? source.status ?? 'Connected'
      : 'Offline',

    is_connected:
      fresh
  };
}

async function readFirebaseSensors() {
  if (
    !firebaseDatabaseUrl ||
    typeof fetch !== 'function'
  ) {
    return {
      ...normalizeSensorReading(
        {},
        false
      ),

      reason:
        'FIREBASE_DATABASE_URL is not configured.'
    };
  }

  const response =
    await firebaseRequest(
      'sensors.json'
    );

  if (!response.ok) {
    throw new Error(
      `Firebase sensors request failed (${response.status}).`
    );
  }

  const root =
    await response.json();

  const source =
    root &&
    typeof root.sensors === 'object'
      ? root.sensors
      : root || {};

  // Accept ESP32 payloads that do not provide an explicit timestamp.
  // The sensor fields themselves become a heartbeat.

  const heartbeat =
    source.updatedAt ??
    source.timestamp ??
    root?.updatedAt ??
    JSON.stringify({
      pm1: source.pm1,

      pm25: source.pm25,

      pm10: source.pm10,

      temperature:
        source.temperature,

      humidity:
        source.humidity,

      co2:
        source.co2 ??
        source.co2Equivalent,

      voc:
        source.voc ??
        source.vocEquivalent,

      iaq:
        source.iaq ??
        source.iaqScore ??
        source.airQualityIndex ??
        source.IAQ
    });

  if (
    heartbeat !== null &&
    heartbeat !==
      lastSensorHeartbeat
  ) {
    lastSensorHeartbeat =
      heartbeat;

    lastSensorChangeAt =
      Date.now();
  }

  const fresh =
    lastSensorChangeAt > 0 &&
    Date.now() -
      lastSensorChangeAt <=
      sensorFreshnessMs;

  return normalizeSensorReading(
    root,
    fresh
  );
}

const thresholdUnits =
  Object.fromEntries(
    defaultThresholds.map(
      (row) => [
        row.sensor,
        row.unit
      ]
    )
  );

function normalizeThresholdPayload(
  items
) {
  if (!Array.isArray(items)) {
    throw new Error(
      'thresholds must be a list.'
    );
  }

  const seen = new Set();

  const normalized = [];

  for (const item of items) {
    const sensor =
      String(
        item?.sensor || ''
      ).trim();

    if (!thresholdUnits[sensor]) {
      throw new Error(
        `Unsupported threshold sensor: ${
          sensor || 'missing'
        }`
      );
    }

    if (seen.has(sensor)) {
      throw new Error(
        `Duplicate threshold sensor: ${sensor}`
      );
    }

    seen.add(sensor);

    const values = {};

    for (
      const field of [
        'warning',
        'critical',
        'minimum',
        'maximum'
      ]
    ) {
      values[field] =
        item[field] === null ||
        item[field] === undefined ||
        item[field] === ''
          ? null
          : finiteNumber(
              item[field]
            );

      if (
        item[field] !== null &&
        item[field] !== undefined &&
        item[field] !== '' &&
        values[field] === null
      ) {
        throw new Error(
          `${sensor} ${field} must be numeric or blank.`
        );
      }
    }

    if (
      values.warning !== null &&
      values.critical !== null &&
      values.warning >
        values.critical
    ) {
      throw new Error(
        `${sensor} warning cannot exceed critical.`
      );
    }

    if (
      values.minimum !== null &&
      values.maximum !== null &&
      values.minimum >
        values.maximum
    ) {
      throw new Error(
        `${sensor} minimum cannot exceed maximum.`
      );
    }

    normalized.push({
      sensor,
      ...values,
      unit: String(
        item.unit ||
          thresholdUnits[sensor]
      )
    });
  }

  return normalized;
}

function addActivity(
  action,
  target = 'System',
  details = ''
) {
  backendState.activity.unshift({
    id: uuidv4(),

    admin:
      'Administrator',

    action,

    target,

    details,

    timestamp:
      new Date().toISOString()
  });

  backendState.activity =
    backendState.activity.slice(
      0,
      500
    );
}

function evaluateThreshold(
  value,
  threshold
) {
  const number =
    finiteNumber(value);

  if (
    number === null ||
    !threshold
  ) {
    return null;
  }

  const critical =
    finiteNumber(
      threshold.critical
    );

  const warning =
    finiteNumber(
      threshold.warning
    );

  const minimum =
    finiteNumber(
      threshold.minimum
    );

  const maximum =
    finiteNumber(
      threshold.maximum
    );

  if (
    critical !== null &&
    number >= critical
  ) {
    return {
      severity: 'CRITICAL',
      limit: critical
    };
  }

  if (
    warning !== null &&
    number >= warning
  ) {
    return {
      severity: 'WARNING',
      limit: warning
    };
  }

  if (
    minimum !== null &&
    number < minimum
  ) {
    return {
      severity: 'WARNING',
      limit: minimum
    };
  }

  if (
    maximum !== null &&
    number > maximum
  ) {
    return {
      severity: 'WARNING',
      limit: maximum
    };
  }

  return null;
}

async function publishEnvironmentNotification(
  alert
) {
  const payload = {
    type: 'alert',

    title: alert.title,

    message: alert.message,

    severity:
      String(
        alert.severity ||
          'WARNING'
      ).toLowerCase(),

    recipientType:
      'all',

    recipientId:
      null,

    recipientIds:
      null,

    alertId:
      alert.id,

    sensor:
      alert.sensor,

    createdAt:
      Date.now(),

    read:
      false,

    readBy: {},

    soundType:
      String(
        alert.severity ||
          'WARNING'
      ).toLowerCase()
  };

  try {
    const response =
      await firebaseRequest(
        'notifications.json',
        {
          method: 'POST',

          body:
            JSON.stringify(payload)
        }
      );

    if (!response.ok) {
      throw new Error(
        `Firebase notification write failed (${response.status}).`
      );
    }
  } catch (error) {
    console.error(
      'Unable to publish environmental notification:',
      error.message
    );
  }
}

async function processEnvironmentAlerts(
  live
) {
  if (!live?.is_connected) {
    return [];
  }

  const values = {
    'PM1.0': live.pm1,

    'PM2.5': live.pm25,

    PM10: live.pm10,

    CO2: live.co2,

    VOC: live.voc,

    IAQ: live.iaq,

    Temperature:
      live.temperature,

    Humidity:
      live.humidity
  };

  const created = [];

  const thresholdMap =
    Object.fromEntries(
      backendState.thresholds.map(
        (row) => [
          row.sensor,
          row
        ]
      )
    );

  for (
    const [sensor, value]
      of Object.entries(values)
  ) {
    const decision =
      evaluateThreshold(
        value,
        thresholdMap[sensor]
      );

    const existing =
      backendState.alerts.find(
        (alert) =>
          alert.sensor ===
            sensor &&
          alert.status ===
            'Open'
      );

    if (!decision) {
      if (existing) {
        existing.status =
          'Resolved';
      }

      continue;
    }

    if (
      existing &&
      existing.severity ===
        decision.severity
    ) {
      continue;
    }

    if (existing) {
      existing.status =
        'Resolved';
    }

    const threshold =
      thresholdMap[sensor];

    const alert = {
      id: uuidv4(),

      alert_type:
        'Environmental',

      severity:
        decision.severity,

      title:
        `${sensor} threshold exceeded`,

      message:
        `${sensor} is ${value} ${threshold.unit} against configured threshold ${decision.limit}.`,

      sensor,

      current_value:
        finiteNumber(value),

      threshold:
        decision.limit,

      status:
        'Open',

      created_at:
        new Date().toISOString()
    };

    backendState.alerts.unshift(
      alert
    );

    created.push(alert);

    await publishEnvironmentNotification(
      alert
    );
  }

  backendState.alerts =
    backendState.alerts.slice(
      0,
      500
    );

  if (
    created.length ||
    backendState.alerts.some(
      (alert) =>
        alert.status ===
        'Resolved'
    )
  ) {
    saveState();
  }

  return created;
}

function publicThresholds() {
  return backendState.thresholds.map(
    ({
      sensor,
      warning,
      critical,
      minimum,
      maximum,
      unit
    }) => ({
      sensor,
      warning,
      critical,
      minimum,
      maximum,
      unit
    })
  );
}

function parseCookie(
  request,
  name
) {
  const cookies =
    String(
      request.headers.cookie ||
        ''
    ).split(';');

  const entry =
    cookies.find(
      (part) =>
        part
          .trim()
          .startsWith(
            `${name}=`
          )
    );

  return entry
    ? decodeURIComponent(
        entry
          .trim()
          .slice(
            name.length + 1
          )
      )
    : null;
}

function requireUserBearer(
  req,
  res
) {
  const token =
    String(
      req.headers.authorization ||
        ''
    )
      .replace(
        /^Bearer\s+/i,
        ''
      )
      .trim();

  if (
    process.env.AUTH_DISABLED ===
      '1' ||
    token
  ) {
    return true;
  }

  res.status(401).json({
    ok: false,
    message:
      'User authentication required.'
  });

  return false;
}

// ----- Endpoints -----

// Keep the admin control center in sync with authenticated Firebase users.
// The client already supplies its Firebase ID token for these existing calls;
// the backend stores only the operational profile and latest activity needed
// by the admin dashboard.

app.post(
  '/api/user/sync',
  (req, res) => {
    if (
      !requireUserBearer(
        req,
        res
      )
    ) {
      return;
    }

    const userId =
      String(
        req.body?.user_id ||
          ''
      ).trim();

    const email =
      String(
        req.body?.email ||
          ''
      )
        .trim()
        .toLowerCase();

    if (!userId || !email) {
      return res.status(400).json({
        ok: false,
        message:
          'User identity is required.'
      });
    }

    const now =
      new Date().toISOString();

    const existing =
      backendState.users.find(
        (user) =>
          user.user_id ===
          userId
      );

    const user = {
      ...(existing || {}),

      user_id:
        userId,

      name:
        String(
          req.body?.name ||
            existing?.name ||
            email.split('@')[0]
        ),

      email,

      status:
        String(
          req.body?.status ||
            existing?.status ||
            'Working'
        ),

      account_status:
        'Enabled',

      last_active:
        now,

      updated_at:
        now
    };

    if (existing) {
      Object.assign(
        existing,
        user
      );
    } else {
      backendState.users.push(
        user
      );
    }

    saveState();

    res.json({
      ok: true,
      user
    });
  }
);

app.post(
  '/api/user/location',
  (req, res) => {
    if (
      !requireUserBearer(
        req,
        res
      )
    ) {
      return;
    }

    const userId =
      String(
        req.body?.user_id ||
          ''
      ).trim();

    const latitude =
      finiteNumber(
        req.body?.latitude
      );

    const longitude =
      finiteNumber(
        req.body?.longitude
      );

    if (
      !userId ||
      latitude === null ||
      longitude === null
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'User and valid GPS coordinates are required.'
      });
    }

    const location = {
      user_id:
        userId,

      latitude,

      longitude,

      accuracy:
        finiteNumber(
          req.body?.accuracy
        ),

      timestamp:
        req.body?.timestamp ||
        new Date().toISOString(),

      status:
        String(
          req.body?.status ||
            'working'
        )
    };

    backendState.locations = [
      location,

      ...backendState.locations.filter(
        (item) =>
          item.user_id !==
          userId
      )
    ].slice(0, 500);

    const user =
      backendState.users.find(
        (item) =>
          item.user_id ===
          userId
      );

    if (user) {
      user.last_active =
        new Date().toISOString();

      user.status =
        'Working';
    }

    saveState();

    res.json({
      ok: true,
      location
    });
  }
);

app.get(
  '/api/complaints',
  (req, res) => {
    const userId =
      String(
        req.query?.user_id ||
          ''
      ).trim();

    if (!userId) {
      return res.status(400).json({
        ok: false,
        message:
          'user_id is required.'
      });
    }

    res.json({
      ok: true,

      complaints:
        backendState.complaints.filter(
          (complaint) =>
            complaint.user_id ===
            userId
        )
    });
  }
);

app.post(
  '/api/complaints',
  upload.single(
    'attachment'
  ),
  (req, res) => {
    const userId =
      String(
        req.body?.user_id ||
          ''
      ).trim();

    const email =
      String(
        req.body?.email ||
          ''
      ).trim();

    const subject =
      String(
        req.body?.subject ||
          ''
      ).trim();

    const description =
      String(
        req.body?.description ||
          ''
      ).trim();

    const priority =
      String(
        req.body?.priority ||
          'Normal'
      ).trim();

    if (
      !userId ||
      !email ||
      !subject ||
      !description
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Name, email, subject and description are required.'
      });
    }

    if (
      ![
        'Normal',
        'Intermediate',
        'Urgent'
      ].includes(priority)
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Invalid priority.'
      });
    }

    if (subject.length > 160) {
      return res.status(400).json({
        ok: false,
        message:
          'Subject must be 160 characters or fewer.'
      });
    }

    if (
      description.length >
      8000
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Description must be 8000 characters or fewer.'
      });
    }

    if (
      req.file &&
      req.file.size >
        5 * 1024 * 1024
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Attachment must be 5 MB or smaller.'
      });
    }

    const now =
      new Date().toISOString();

    const complaint = {
      id: uuidv4(),

      ticket_id:
        `SS-${now
          .slice(0, 10)
          .replaceAll(
            '-',
            ''
          )}-${crypto
          .randomBytes(3)
          .toString('hex')
          .toUpperCase()}`,

      user_id:
        userId,

      user_name:
        String(
          req.body?.user_name ||
            'User'
        ).trim(),

      email,

      subject,

      description,

      priority,

      attachment_path:
        req.file?.filename ||
        null,

      status:
        'Open',

      admin_reply:
        null,

      created_at:
        now,

      updated_at:
        now,

      category:
        String(
          req.body?.category ||
            'Other'
        ),

      incident_latitude:
        finiteNumber(
          req.body?.incident_latitude
        ),

      incident_longitude:
        finiteNumber(
          req.body?.incident_longitude
        ),

      incident_accuracy:
        finiteNumber(
          req.body?.incident_accuracy
        ),

      incident_gps_time:
        req.body?.incident_gps_time ||
        null,

      verified_by:
        null,

      verified_at:
        null,

      verification_notes:
        null,

      environment_snapshot_json:
        null
    };

    backendState.complaints.unshift(
      complaint
    );

    backendState.complaints =
      backendState.complaints.slice(
        0,
        1000
      );

    saveState();

    res.status(201).json({
      ok: true,
      message:
        'Complaint submitted successfully.',
      complaint
    });
  }
);

// Health check – mirrors /api/health

app.get(
  '/api/health',
  (req, res) => {
    res.json({
      ok: true,

      service:
        'SmartSurround backend (JS)',

      status:
        'online',

      admin_pin_configured:
        !!process.env.ADMIN_PIN,

      auth_disabled:
        process.env.AUTH_DISABLED ===
        '1'
    });
  }
);

// Raw ESP32 telemetry proxy.
// The backend never invents IAQ values.

app.get(
  '/api/readings',
  async (req, res) => {
    try {
      res.set(
        'Cache-Control',
        'no-store'
      );

      const readings =
        await readFirebaseSensors();

      await processEnvironmentAlerts(
        readings
      );

      res.json(readings);
    } catch (error) {
      res.status(503).json({
        ok: false,

        is_connected:
          false,

        iaq:
          null,

        message:
          error.message ||
          'Unable to read ESP32 telemetry.'
      });
    }
  }
);

// ============================================================
// Road Damage AI - AWS SageMaker
// ============================================================

function normalizeRoadDamageResult(
  result
) {
  const root =
    result &&
    typeof result === 'object' &&
    !Array.isArray(result)
      ? result
      : {};

  let detections = [];

  if (Array.isArray(result)) {
    detections = result;
  } else if (
    Array.isArray(
      root.detections
    )
  ) {
    detections =
      root.detections;
  } else if (
    Array.isArray(
      root.predictions
    )
  ) {
    detections =
      root.predictions;
  } else if (
    Array.isArray(
      root.results
    )
  ) {
    detections =
      root.results;
  } else if (
    Array.isArray(
      root.outputs
    )
  ) {
    detections =
      root.outputs;
  }

  const bestDetection =
    [...detections].sort(
      (a, b) =>
        Number(
          b?.confidence ??
            b?.score ??
            b?.probability ??
            0
        ) -
        Number(
          a?.confidence ??
            a?.score ??
            a?.probability ??
            0
        )
    )[0] || {};

  const hazardType =
    root.hazard_type ??
    root.hazardType ??
    root.damage_type ??
    root.damageType ??
    root.class_name ??
    root.class ??
    root.label ??
    root.name ??
    bestDetection.hazard_type ??
    bestDetection.hazardType ??
    bestDetection.damage_type ??
    bestDetection.damageType ??
    bestDetection.class_name ??
    bestDetection.class ??
    bestDetection.name ??
    bestDetection.label ??
    null;

  const hazardCategory =
    root.hazard_category ??
    root.hazardCategory ??
    root.category ??
    bestDetection.hazard_category ??
    bestDetection.hazardCategory ??
    bestDetection.category ??
    null;

  const detected =
    root.detected !== undefined
      ? Boolean(root.detected)
      : root.has_detection !==
          undefined
        ? Boolean(
            root.has_detection
          )
        : detections.length > 0
          ? true
          : hazardType !==
              null;

  const confidence =
    finiteNumber(
      root.confidence ??
        root.score ??
        root.probability ??
        bestDetection.confidence ??
        bestDetection.score ??
        bestDetection.probability
    );

  const valid =
    root.valid !== undefined
      ? Boolean(root.valid)
      : root.accepted !== undefined
        ? Boolean(
            root.accepted
          )
        : null;

  const accepted =
    root.accepted !== undefined
      ? Boolean(
          root.accepted
        )
      : root.valid !== undefined
        ? Boolean(
            root.valid
          )
        : null;

  const severity =
    root.severity ??
    bestDetection.severity ??
    null;

  return {
    hazard_category:
      hazardCategory,

    hazard_type:
      hazardType,

    detected,

    confidence,

    valid,

    accepted,

    severity,

    // Backward-compatible fields
    road_condition:
      root.road_condition ??
      root.roadCondition ??
      null,

    damage_type:
      root.damage_type ??
      root.damageType ??
      hazardType ??
      null,

    queued_for_admin:
      root.queued_for_admin !==
        undefined
        ? Boolean(
            root.queued_for_admin
          )
        : false
  };
}

async function handleRoadDamageDetection(
  req,
  res
) {
  try {
    if (!req.file) {
      return res.status(400).json({
        ok: false,
        message:
          'No image supplied.'
      });
    }

    const imageBytes =
      fs.readFileSync(
        req.file.path
      );

    if (
      !imageBytes.length
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Uploaded image is empty.'
      });
    }

    const contentType =
      process.env.SAGEMAKER_CONTENT_TYPE ||
      req.file.mimetype ||
      'application/octet-stream';

    console.log(
      `Invoking SageMaker endpoint: ${SAGEMAKER_ENDPOINT}`
    );

    console.log(
      `SageMaker content type: ${contentType}`
    );

    const command =
      new InvokeEndpointCommand({
        EndpointName:
          SAGEMAKER_ENDPOINT,

        ContentType:
          contentType,

        Body:
          imageBytes
      });

    const response =
      await sagemakerClient.send(
        command
      );

    const responseText =
      response.Body
        ? await response.Body.transformToString()
        : '';

    console.log(
      'SageMaker raw response:',
      responseText
    );

    let modelResult;

    try {
      modelResult =
        JSON.parse(
          responseText
        );
    } catch {
      modelResult =
        responseText;
    }

    const normalized =
      normalizeRoadDamageResult(
        modelResult
      );

    return res.json({
      ok: true,

      image:
        `/uploads/${req.file.filename}`,

      ...normalized
    });
  } catch (error) {
    console.error(
      'Road damage SageMaker error:',
      error
    );

    return res.status(500).json({
      ok: false,

      message:
        'Road damage detection failed.',

      error:
        error.message
    });
  }
}

// New road-damage endpoint
// Frontend sends:
// FormData -> image

app.post(
  '/api/detect',
  upload.single('image'),
  handleRoadDamageDetection
);

// Keep existing camera endpoint working
// Existing frontend can continue using it.

app.post(
  '/api/camera/analyze',
  upload.single('image'),
  handleRoadDamageDetection
);

// Auth token endpoint – mirrors /auth/token
// (simplified PIN check)

app.post(
  '/auth/token',
  (req, res) => {
    const pin =
      req.body.pin ||
      req.headers[
        'x-admin-pin'
      ];

    const configuredPin =
      process.env.ADMIN_PIN ||
      '';

    if (
      process.env.AUTH_DISABLED !==
        '1' &&
      (!configuredPin ||
        pin !==
          configuredPin)
    ) {
      return res.status(403).json({
        ok: false,
        reason:
          'blocked',
        message:
          'Invalid PIN.'
      });
    }

    const token =
      issueToken();

    res
      .cookie(
        'ss_token',
        token,
        {
          httpOnly: true,
          sameSite: 'strict'
        }
      )
      .set(
        'X-Set-Auth-Token',
        token
      )
      .json({
        ok: true,
        message:
          'Authenticated.'
      });
  }
);

// The admin UI uses this Flask-compatible login path.

app.post(
  '/login/creds',
  (req, res) => {
    const pin =
      req.body?.pin ||
      req.headers[
        'x-admin-pin'
      ];

    const configuredPin =
      process.env.ADMIN_PIN ||
      '';

    if (
      process.env.AUTH_DISABLED !==
        '1' &&
      (!configuredPin ||
        pin !==
          configuredPin)
    ) {
      return res.status(403).json({
        ok: false,
        reason:
          'blocked',
        message:
          'Invalid PIN.'
      });
    }

    const token =
      issueToken();

    res.cookie?.(
      'ss_token',
      token,
      {
        httpOnly: true,
        sameSite: 'strict'
      }
    );

    res
      .set(
        'X-Set-Auth-Token',
        token
      )
      .json({
        ok: true,
        message:
          'Authenticated.'
      });
  }
);

// Simple middleware to protect routes

function requireAuth(
  req,
  res,
  next
) {
  if (
    process.env.AUTH_DISABLED ===
    '1'
  ) {
    return next();
  }

  const token =
    parseCookie(
      req,
      'ss_token'
    ) ||
    req.headers[
      'authorization'
    ]?.replace(
      /^Bearer\s+/i,
      ''
    ) ||
    req.headers[
      'x-auth-token'
    ];

  const pin =
    req.body?.pin ||
    req.headers[
      'x-admin-pin'
    ];

  if (
    !validToken(token) ||
    pin !==
      process.env.ADMIN_PIN
  ) {
    return res.status(401).json({
      ok: false,
      reason:
        'blocked',
      message:
        'Authentication required.'
    });
  }

  next();
}

// User dashboards receive the same administrator-configured
// thresholds used by the backend evaluator.

app.get(
  '/api/user/thresholds',
  async (req, res) => {
    let live =
      normalizeSensorReading(
        {},
        false
      );

    try {
      live =
        await readFirebaseSensors();

      await processEnvironmentAlerts(
        live
      );
    } catch (error) {
      live.reason =
        error.message ||
        'Unable to read live telemetry.';
    }

    res
      .set(
        'Cache-Control',
        'no-store'
      )
      .json({
        ok: true,

        thresholds:
          publicThresholds(),

        is_connected:
          live.is_connected,

        telemetry_error:
          live.reason ||
          null
      });
  }
);

app.get(
  '/admin/api/control-center',
  requireAuth,
  async (req, res) => {
    let live =
      normalizeSensorReading(
        {},
        false
      );

    try {
      live =
        await readFirebaseSensors();

      await processEnvironmentAlerts(
        live
      );
    } catch (error) {
      live.reason =
        error.message ||
        'Unable to read live telemetry.';
    }

    const openAlerts =
      backendState.alerts.filter(
        (alert) =>
          alert.status ===
          'Open'
      );

    const devices =
      live.is_connected
        ? [
            {
              device_id:
                live.ip ||
                'firebase-sensors',

              device_type:
                'ESP32',

              connection:
                'Connected',

              last_update:
                live.updatedAt ||
                new Date().toISOString(),

              sensor_availability:
                Object.entries(
                  live
                )
                  .filter(
                    ([key, value]) =>
                      ![
                        'updatedAt',
                        'status',
                        'is_connected'
                      ].includes(
                        key
                      ) &&
                      value !==
                        null
                  )
                  .map(
                    ([key]) =>
                      key
                  )
                  .join(', ')
            }
          ]
        : [];

    const users =
      backendState.users;

    const locations =
      backendState.locations;

    res.json({
      ok: true,

      thresholds:
        publicThresholds(),

      alerts:
        openAlerts,

      activity:
        backendState.activity,

      complaints:
        backendState.complaints,

      communications: [],

      detections: [],

      users,

      locations,

      recipients: [],

      devices,

      live,

      summary: {
        total_users:
          users.length,

        active_users:
          users.filter(
            (user) =>
              String(
                user.account_status
              ).toLowerCase() ===
              'enabled'
          ).length,

        working_users:
          locations.filter(
            (location) =>
              String(
                location.status
              ).toLowerCase() ===
              'working'
          ).length,

        active_incidents:
          backendState.complaints.filter(
            (complaint) =>
              [
                'Open',
                'In Progress'
              ].includes(
                complaint.status
              )
          ).length,

        connected_devices:
          devices.length,

        offline_devices:
          devices.length
            ? 0
            : 1,

        open_alerts:
          openAlerts.length
      },

      system: {
        admin_configured:
          Boolean(
            process.env.ADMIN_PIN
          ),

        auth_disabled:
          process.env.AUTH_DISABLED ===
          '1',

        firebase_admin_ready:
          Boolean(
            firebaseDatabaseUrl
          )
      }
    });
  }
);

app.get(
  '/admin/api/complaints',
  requireAuth,
  (req, res) => {
    res.json({
      ok: true,
      complaints:
        backendState.complaints
    });
  }
);

app.post(
  '/admin/complaints/:complaintId/update',
  requireAuth,
  (req, res) => {
    const complaint =
      backendState.complaints.find(
        (item) =>
          item.id ===
          req.params
            .complaintId
      );

    if (!complaint) {
      return res.status(404).json({
        ok: false,
        message:
          'Complaint not found.'
      });
    }

    const status =
      String(
        req.body?.status ||
          complaint.status
      ).trim();

    const priority =
      String(
        req.body?.priority ||
          complaint.priority
      ).trim();

    if (
      ![
        'Open',
        'In Progress',
        'Resolved',
        'Closed'
      ].includes(status)
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Invalid complaint status.'
      });
    }

    if (
      ![
        'Normal',
        'Intermediate',
        'Urgent',
        'Critical'
      ].includes(priority)
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Invalid complaint priority.'
      });
    }

    complaint.status =
      status;

    complaint.priority =
      priority;

    if (
      req.body?.admin_reply !==
      undefined
    ) {
      complaint.admin_reply =
        String(
          req.body.admin_reply ||
            ''
        ).trim() ||
        null;
    }

    complaint.updated_at =
      new Date().toISOString();

    saveState();

    res.json({
      ok: true,

      message:
        `Ticket ${complaint.ticket_id} updated.`,

      complaint
    });
  }
);

app.post(
  '/admin/complaints/:complaintId/verify',
  requireAuth,
  (req, res) => {
    const complaint =
      backendState.complaints.find(
        (item) =>
          item.id ===
          req.params
            .complaintId
      );

    if (!complaint) {
      return res.status(404).json({
        ok: false,
        message:
          'Complaint not found.'
      });
    }

    const action =
      String(
        req.body?.action ||
          ''
      )
        .trim()
        .toLowerCase();

    const notes =
      String(
        req.body?.notes ||
          ''
      ).trim() ||
      null;

    if (
      ![
        'verify',
        'request_info',
        'reject',
        'escalate',
        'resolve'
      ].includes(action)
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Unsupported incident action.'
      });
    }

    complaint.status =
      action === 'resolve'
        ? 'Resolved'
        : action === 'reject'
          ? 'Closed'
          : action ===
              'request_info'
            ? 'Open'
            : 'In Progress';

    if (
      action ===
      'escalate'
    ) {
      complaint.priority =
        'Urgent';
    }

    if (
      action !==
      'request_info'
    ) {
      complaint.verified_by =
        'Administrator';

      complaint.verified_at =
        new Date().toISOString();
    } else if (notes) {
      complaint.admin_reply =
        notes;
    }

    complaint.verification_notes =
      notes;

    complaint.updated_at =
      new Date().toISOString();

    saveState();

    res.json({
      ok: true,
      complaint
    });
  }
);

app.get(
  '/admin/complaints/:complaintId/attachment',
  requireAuth,
  (req, res) => {
    const complaint =
      backendState.complaints.find(
        (item) =>
          item.id ===
          req.params
            .complaintId
      );

    if (
      !complaint?.attachment_path
    ) {
      return res
        .status(404)
        .send(
          'Attachment not found.'
        );
    }

    const filename =
      path.basename(
        complaint.attachment_path
      );

    const filePath =
      path.join(
        uploadDir,
        filename
      );

    if (
      !fs.existsSync(
        filePath
      )
    ) {
      return res
        .status(404)
        .send(
          'Attachment not found.'
        );
    }

    res.download(
      filePath,
      filename
    );
  }
);

app.get(
  '/admin/api/thresholds',
  requireAuth,
  (req, res) => {
    res.json({
      ok: true,

      thresholds:
        publicThresholds()
    });
  }
);

app.post(
  '/admin/api/thresholds',
  requireAuth,
  (req, res) => {
    try {
      const normalized =
        normalizeThresholdPayload(
          req.body?.thresholds ||
            []
        );

      backendState.thresholds =
        normalized;

      addActivity(
        'Threshold changed',
        'System',
        `Updated ${normalized.length} threshold(s).`
      );

      saveState();

      res.json({
        ok: true,

        thresholds:
          publicThresholds()
      });
    } catch (error) {
      res.status(400).json({
        ok: false,
        message:
          error.message ||
          'Invalid thresholds.'
      });
    }
  }
);

app.get(
  '/admin/api/activity',
  requireAuth,
  (req, res) => {
    res.json({
      ok: true,

      activity:
        backendState.activity
    });
  }
);

app.get(
  '/admin/api/alerts',
  requireAuth,
  (req, res) => {
    res.json({
      ok: true,

      alerts:
        backendState.alerts
    });
  }
);

app.post(
  '/admin/api/alerts/:id/resolve',
  requireAuth,
  (req, res) => {
    const alert =
      backendState.alerts.find(
        (item) =>
          item.id ===
          req.params.id
      );

    if (!alert) {
      return res.status(404).json({
        ok: false,
        message:
          'Alert not found.'
      });
    }

    alert.status =
      'Resolved';

    addActivity(
      'Alert resolved',
      alert.id
    );

    saveState();

    res.json({
      ok: true,
      alert
    });
  }
);

// Admin API placeholder
// – returns empty arrays for pending/approved/rejected

app.get(
  '/admin/api/detections',
  requireAuth,
  (req, res) => {
    res.json({
      ok: true,
      pending: [],
      approved: [],
      rejected: []
    });
  }
);

// Upload endpoint – mirrors /upload
// (stores file, returns dummy response)

app.post(
  '/upload',
  upload.single('image'),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        ok: false,
        message:
          'No image supplied.'
      });
    }

    // Existing upload behavior.
    // Detection is handled by /api/detect.

    res.json({
      ok: true,
      image:
        `/uploads/${req.file.filename}`
    });
  }
);

// Serve uploaded files statically

app.use(
  '/uploads',
  express.static(
    uploadDir
  )
);

// Start server

app.listen(
  PORT,
  () => {
    console.log(
      `SmartSurround JS backend listening on http://localhost:${PORT}`
    );
  }
);