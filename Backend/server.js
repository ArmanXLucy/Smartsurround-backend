
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";

dotenv.config();

const app = express();

const PORT = process.env.PORT || 3000;
const CAMERA_TOKEN = process.env.CAMERA_TOKEN;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN;

if (!CAMERA_TOKEN) {
  throw new Error("CAMERA_TOKEN is missing");
}

const allowedOrigins = [
  "https://armanxlucy.github.io",
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "http://192.168.1.103:5000",
  FRONTEND_ORIGIN
].filter(Boolean);

// CORS middleware must be before API routes.
// This also handles OPTIONS preflight requests in Express 5.
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      console.log("CORS blocked origin:", origin);
      return callback(null, false);
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    optionsSuccessStatus: 204
  })
);

// Health check
app.get("/health", (req, res) => {
  res.json({
    status: "SmartSurround backend running"
  });
});

// Verify camera token
function authorized(req) {
  const auth = req.headers.authorization || "";

  const suppliedToken = auth.startsWith("Bearer ")
    ? auth.slice(7)
    : "";

  const expected = Buffer.from(CAMERA_TOKEN);
  const supplied = Buffer.from(suppliedToken);

  return (
    expected.length === supplied.length &&
    crypto.timingSafeEqual(expected, supplied)
  );
}

// Store latest uploaded frame in memory
let latestFrame = null;
let lastFrameTime = null;

// ESP32-CAM uploads JPEG frames here
app.post(
  "/api/upload",
  express.raw({
    type: "image/jpeg",
    limit: "500kb"
  }),
  (req, res) => {
    if (!authorized(req)) {
      return res.status(401).json({
        error: "Unauthorized"
      });
    }

    if (!req.body || req.body.length === 0) {
      return res.status(400).json({
        error: "Empty image"
      });
    }

    latestFrame = Buffer.from(req.body);
    lastFrameTime = Date.now();

    console.log(`Frame received: ${latestFrame.length} bytes`);

    res.json({
      success: true,
      receivedBytes: latestFrame.length
    });
  }
);

// React fetches the latest JPEG frame here
app.get("/api/frame", (req, res) => {
  if (!authorized(req)) {
    return res.status(401).json({
      error: "Unauthorized"
    });
  }

  if (!latestFrame) {
    return res.status(503).json({
      error: "No camera frame received yet"
    });
  }

  res.setHeader("Content-Type", "image/jpeg");
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate"
  );
  res.setHeader("X-Frame-Time", String(lastFrameTime));

  res.send(latestFrame);
});

// Camera upload status
app.get("/api/status", (req, res) => {
  if (!authorized(req)) {
    return res.status(401).json({
      error: "Unauthorized"
    });
  }

  res.json({
    cameraHasUploaded: Boolean(latestFrame),
    lastFrameTime
  });
});

// Start server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`SmartSurround backend listening on port ${PORT}`);
});