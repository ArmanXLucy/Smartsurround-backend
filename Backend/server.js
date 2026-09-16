
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

if (FRONTEND_ORIGIN) {
  app.use(cors({
    origin: FRONTEND_ORIGIN
  }));
}

app.get("/health", (req, res) => {
  res.json({
    status: "SmartSurround backend running"
  });
});

function authorized(req) {
  const auth = req.headers.authorization || "";
  const suppliedToken = auth.startsWith("Bearer ")
    ? auth.slice(7)
    : "";

  const expected = Buffer.from(CAMERA_TOKEN);
  const supplied = Buffer.from(suppliedToken);

  return expected.length === supplied.length &&
    crypto.timingSafeEqual(expected, supplied);
}

let latestFrame = null;
let lastFrameTime = null;

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

    res.json({
      success: true,
      receivedBytes: latestFrame.length
    });
  }
);

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
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.setHeader("X-Frame-Time", String(lastFrameTime));

  res.send(latestFrame);
});

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

app.listen(PORT, "0.0.0.0", () => {
  console.log(`SmartSurround backend listening on ${PORT}`);
});