"""
app.py
------
SmartSurround backend — detection queue + admin authority notification.

Track A routes (detection → admin verify → letter PDF):
  GET  /                     upload form (citizen / ESP32-CAM stand-in)
  POST /upload               runs detection, queues for admin review
  GET  /admin                verification queue
  POST /admin/approve/<id>   approved → letter generated (token+pin locked)
  POST /admin/reject/<id>    rejected (token+pin locked)
  GET  /admin/api/clusters   JSON: corroboration clusters (polling)
  POST /admin/authorities/add register authority email (token+pin locked)
  POST /admin/test-email     dev-only live test send (token+pin locked)

Auth:
  GET  /login                login page (pin entry)
  POST /login/creds          verify pin → httpOnly token cookie
  GET  /upload/token         ephemeral upload token (redirect-based flow)

Run:
    python3 app.py
    Then open http://localhost:5000
"""

import os
import time
import uuid
import secrets
import logging
from pathlib import Path
from functools import wraps
from datetime import datetime, timezone
from dotenv import load_dotenv

# Resolve configuration from the backend .env first. For this project the
# frontend already carries the admin PIN in its existing .env, so when the
# backend .env is missing (or still contains the placeholder) we reuse that
# same configured PIN instead of creating a second credential.
_BACKEND_DIR = Path(__file__).resolve().parent
_BACKEND_ENV = _BACKEND_DIR / ".env"
_FRONTEND_ENV = _BACKEND_DIR.parent / "Smartsurround" / ".env"
_PROJECT_ENV = _BACKEND_DIR.parent / ".env"
load_dotenv(_BACKEND_ENV)
load_dotenv(_PROJECT_ENV)

from flask import (
    Flask, request, render_template, redirect, url_for,
    send_from_directory, flash, jsonify, make_response
)
from werkzeug.utils import secure_filename

import db
import detector
import letter_generator
import corroboration
import authority_routing
import email_driver

# Optional Firebase Admin integration used by the admin control center to
# authenticate user location/telemetry submissions and read the live RTDB.
try:
    import firebase_admin
    from firebase_admin import credentials as firebase_credentials
    from firebase_admin import auth as firebase_admin_auth
    from firebase_admin import db as firebase_admin_db
except Exception:  # pragma: no cover - optional dependency in minimal local setups
    firebase_admin = None
    firebase_credentials = None
    firebase_admin_auth = None
    firebase_admin_db = None

logger = logging.getLogger("smart_surround.auth")

# ---------------------------------------------------------------------------
# Pin digest helpers (mirror static/utils.js build_verify_pin)
# ---------------------------------------------------------------------------
def _derive_pin_digest(pin, salt_hex):
    import hashlib
    payload = bytes.fromhex(salt_hex) + str(pin).encode("utf-8")
    return salt_hex + ":" + hashlib.sha256(payload).hexdigest()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(__file__)
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Pin policy: the server NEVER stores the bare pin. If ADMIN_PIN is set we
# derive a salted digest on boot (`salt_hex:sha256(salt||pin)`); verification
# re-hashes the presented pin against that digest with a constant-time compare.
# Same scheme as static/utils.js build_verify_pin (client-side pre-hash
# remains available for the login form if needed).
def _configured_admin_pin():
    """Use the backend PIN when configured; otherwise reuse the frontend
    project's existing ADMIN_PIN. This keeps one source of truth during local
    development and fixes the common case where only Smartsurround/.env exists."""
    pin = os.environ.get("ADMIN_PIN", "").strip()
    placeholders = {"", "change-me", "changeme", "replace-me", "your-pin"}
    if pin.lower() not in placeholders:
        return pin

    try:
        from dotenv import dotenv_values
        frontend_values = dotenv_values(_FRONTEND_ENV)
        frontend_pin = str(frontend_values.get("ADMIN_PIN") or "").strip()
        if frontend_pin and frontend_pin.lower() not in placeholders:
            return frontend_pin

        project_values = dotenv_values(_PROJECT_ENV)
        project_pin = str(project_values.get("ADMIN_PIN") or "").strip()
        if project_pin and project_pin.lower() not in placeholders:
            return project_pin
    except Exception:
        logger.exception("Unable to read the existing frontend .env for ADMIN_PIN fallback.")

    return pin

ADMIN_PIN       = _configured_admin_pin()
_ADMIN_SALT     = secrets.token_hex(16)
_ADMIN_DIGEST   = None
if ADMIN_PIN:
    _ADMIN_DIGEST = _derive_pin_digest(ADMIN_PIN, _ADMIN_SALT)

_DEFAULT_CORS_ORIGINS = [
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://armanxlucy.github.io",
    "https://smartsurround.vercel.app",
]
_CONFIGURED_CORS_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("CORS_ORIGINS", "").split(",")
    if origin.strip()
]
# Keep the known production frontend allowed even when a deployment defines
# CORS_ORIGINS for additional preview or custom domains.
CORS_ORIGINS = list(dict.fromkeys(_DEFAULT_CORS_ORIGINS + _CONFIGURED_CORS_ORIGINS))
TOKEN_TTL_SEC  = 30 * 60          # 30 minutes
RATE_LIMIT_MAX = int(os.environ.get("RATE_LIMIT_MAX", "5"))
RATE_LIMIT_SEC = int(os.environ.get("RATE_LIMIT_SEC", str(60 * 60)))

# AUTH_DISABLED=1 turns the whole pin gate off (dev convenience / trusted LAN).
# When set: @require_auth passes everything through AND /login/creds mints a
# session without a pin, so the admin bootstrap (apiEnsureSession -> /login/creds)
# succeeds trivially and every protected admin action is freely usable.
AUTH_DISABLED = os.environ.get("AUTH_DISABLED", "0") == "1"
CAMERA_API_KEY = os.environ.get("CAMERA_API_KEY", "")

def _migrate_legacy_absolute_paths():
    """One-time at-boot fix for the /uploads/<file> 404 storm.

    New uploads store only the basename (app.py stores os.path.basename(...)),
    but detection rows written before that change carry the FULL absolute path
    (e.g. ``D:\\Program\\New folder\\...\\uploads\\45b4f....png``). The admin
    templates render URLs as ``/uploads/{ d['image_path'].split('/')[-1] }`` —
    and a backslash absolute path is NOT split by '/', so the whole drive path
    leaks into the URL → every image/letter 404s (the flood in the dev log).

    We can't fix it in the template (we must keep both / and \ safe) or at
    write time (rows already exist). So we normalize the stored value to a
    bare basename in-place, once, at boot. idempotent: basename of a basename
    is itself, so re-runs on every start are safe."""
    import itertools
    conn = db.get_conn()
    try:
        for table, col in (("detections", "image_path"),
                           ("detections", "letter_path"),
                           ("corroboration_clusters", "letter_path")):
            try:
                rows = conn.execute(f"SELECT id, {col} FROM {table}").fetchall()
            except Exception:
                continue    # table/column may be absent in older schemas
            for row in rows:
                raw = row[col]
                if raw and (os.sep in raw or "/" in raw):
                    clean = os.path.basename(raw)
                    if clean != raw:
                        conn.execute(f"UPDATE {table} SET {col} = ? WHERE id = ?",
                                     (clean, row["id"]))
        conn.commit()
    finally:
        conn.close()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

db.init_db()
db.seed_default_thresholds()
_migrate_legacy_absolute_paths()

# ---------------------------------------------------------------------------
# Firebase Admin bootstrap (optional but recommended for real user GPS + RTDB)
# ---------------------------------------------------------------------------
FIREBASE_ADMIN_READY = False

def _init_firebase_admin():
    global FIREBASE_ADMIN_READY
    if FIREBASE_ADMIN_READY or firebase_admin is None:
        return FIREBASE_ADMIN_READY
    try:
        if firebase_admin._apps:
            FIREBASE_ADMIN_READY = True
            return True

        service_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON", "").strip()
        service_path = os.environ.get("FIREBASE_SERVICE_ACCOUNT_PATH", "").strip()

        if service_json:
            import json as _json
            info = _json.loads(service_json)
            cred = firebase_credentials.Certificate(info)
        elif service_path and os.path.isfile(service_path):
            cred = firebase_credentials.Certificate(service_path)
        else:
            logger.warning("Firebase Admin credentials are not configured; user GPS sync will remain unavailable.")
            return False

        options = {}
        database_url = os.environ.get("FIREBASE_DATABASE_URL", "").strip()
        if database_url:
            options["databaseURL"] = database_url

        firebase_admin.initialize_app(cred, options)
        FIREBASE_ADMIN_READY = True
        logger.info("Firebase Admin initialized.")
        return True
    except Exception:
        logger.exception("Firebase Admin initialization failed.")
        FIREBASE_ADMIN_READY = False
        return False

_init_firebase_admin()

# ---------------------------------------------------------------------------
# In-memory stores (single-process; adequate for dev)
# ---------------------------------------------------------------------------
_token_store   = {}    # token_str -> expires_at_epoch
_rate_store    = {}    # ip_addr   -> {"failures": int, "cooldown_until": float}
_upload_tokens = {}    # token_str -> expires_at_epoch (for /upload/token flow)

def _pin_ok(pin):
    if not _ADMIN_DIGEST:
        return False
    digest = _derive_pin_digest(pin, _ADMIN_SALT)
    return secrets.compare_digest(digest, _ADMIN_DIGEST)

# ---------------------------------------------------------------------------
# CORS — exact-origin, no wildcard
# ---------------------------------------------------------------------------
@app.after_request
def _apply_cors(resp):
    origin = request.headers.get("Origin", "")
    if origin in CORS_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"]  = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, Authorization, X-Auth-Token, X-Set-Auth-Token, X-Admin-Pin"
        )
        resp.headers["Access-Control-Expose-Headers"] = "X-Set-Auth-Token"
        resp.headers["Access-Control-Allow-Methods"]  = "GET, POST, PUT, DELETE, OPTIONS"
    if request.method == "OPTIONS":
        resp.status_code = 204
    return resp

# ---------------------------------------------------------------------------
# Rate limiter (in-memory, per IP)
# ---------------------------------------------------------------------------
def _rate_limit(ip):
    entry = _rate_store.get(ip)
    if entry and entry.get("cooldown_until", 0) > time.time():
        return True    # still locked
    return False

def _rate_record_fail(ip):
    entry = _rate_store.setdefault(ip, {"failures": 0, "cooldown_until": 0})
    entry["failures"] += 1
    if entry["failures"] >= RATE_LIMIT_MAX:
        entry["cooldown_until"] = time.time() + RATE_LIMIT_SEC
        entry["failures"] = 0

def _rate_reset(ip):
    _rate_store.pop(ip, None)

# ---------------------------------------------------------------------------
# Token helpers (admin token issued on login)
# ---------------------------------------------------------------------------
def _issue_token():
    tok = secrets.token_urlsafe(32)
    _token_store[tok] = time.time() + TOKEN_TTL_SEC
    return tok

def _valid_token(tok):
    if not tok:
        return False
    exp = _token_store.get(tok)
    if exp is None or exp < time.time():
        _token_store.pop(tok, None)
        return False
    return True

# ---------------------------------------------------------------------------
# Upload-token helpers (ephemeral, single-use, per /upload/token)
# ---------------------------------------------------------------------------
def _issue_upload_token():
    tok = secrets.token_urlsafe(24)
    _upload_tokens[tok] = time.time() + 120    # 2-minute window
    return tok

def _valid_upload_token(tok):
    if not tok:
        return False
    exp = _upload_tokens.pop(tok, None)
    return exp is not None and exp >= time.time()

_latest_frame = None
_frame_cond   = threading.Condition()
_last_frame_time = 0          # epoch seconds of last received frame

# ---------------------------------------------------------------------------
# Token-only auth for the MJPEG stream endpoint
# (defined here because @require_stream_token is used below before
#  require_auth is defined further down the file)
# ---------------------------------------------------------------------------
def require_stream_token(f):
    """Token-only gate for the MJPEG stream endpoint.

    An <img> tag GET cannot send custom headers (no PIN possible), so we
    only validate the short-lived session token here.  The token is already
    issued only after full PIN + rate-limit verification, so token possession
    is equivalent proof of an authenticated admin session.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if AUTH_DISABLED:
            return f(*args, **kwargs)
        tok = _token_from_header()
        if not _valid_token(tok):
            return ("Authentication required.", 401)
        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------------------------------
# ESP32-CAM / React live stream endpoints
# ---------------------------------------------------------------------------
@app.route("/api/camera/stream/push", methods=["POST"])
def camera_stream_push():
    global _latest_frame, _last_frame_time
    if CAMERA_API_KEY:
        supplied_key = request.headers.get("X-Camera-Key", "")
        if not secrets.compare_digest(supplied_key, CAMERA_API_KEY):
            return jsonify({"ok": False, "message": "Invalid key."}), 401
    frame = request.data
    if not frame:
        return "No frame", 400
    with _frame_cond:
        _latest_frame      = frame
        _last_frame_time   = time.time()
        _frame_cond.notify_all()
    return "OK", 200

def _generate_mjpeg():
    """Generator that yields MJPEG frames to a streaming HTTP response."""
    while True:
        with _frame_cond:
            # Wait up to 3 s for a new frame before yielding keep-alive data
            _frame_cond.wait(timeout=3.0)
            frame = _latest_frame
        if not frame:
            # No frame yet — yield a keep-alive comment so the connection stays open
            yield b'--frame\r\nContent-Type: text/plain\r\n\r\n\r\n'
            continue
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

@app.route("/api/camera/stream/live")
@require_stream_token
def camera_stream_live():
    return Flask.response_class(
        _generate_mjpeg(),
        mimetype='multipart/x-mixed-replace; boundary=frame'
    )

@app.route("/api/camera/status")
@require_stream_token
def camera_status():
    """Return whether the ESP32-CAM is currently pushing frames.
    A frame is considered fresh if received within the last 5 seconds.
    """
    online = (time.time() - _last_frame_time) < 5.0 if _last_frame_time else False
    return jsonify({
        "online":          online,
        "last_frame_ago":  round(time.time() - _last_frame_time, 1) if _last_frame_time else None,
    })

# ---------------------------------------------------------------------------
# ESP32-CAM / React camera AI endpoint
# ---------------------------------------------------------------------------
@app.route("/api/camera/analyze", methods=["POST", "OPTIONS"])
def camera_analyze():
    """Receive an image from ESP32-CAM/React and run the existing AI model."""
    if request.method == "OPTIONS":
        return ("", 204)

    if CAMERA_API_KEY:
        supplied_key = request.headers.get("X-Camera-Key", "")
        if not secrets.compare_digest(supplied_key, CAMERA_API_KEY):
            return jsonify({"ok": False, "message": "Invalid or missing camera API key."}), 401

    image_file = request.files.get("image")
    if not image_file or not image_file.filename:
        return jsonify({"ok": False, "message": "No image supplied. Use multipart field 'image'."}), 400

    lat = request.form.get("lat") or None
    lon = request.form.get("lon") or None
    description = request.form.get("description") or "ESP32-CAM road image"

    try:
        lat_f = float(lat) if lat else None
        lon_f = float(lon) if lon else None
    except ValueError:
        return jsonify({"ok": False, "message": "lat and lon must be valid numbers."}), 400

    allowed_extensions = {".jpg", ".jpeg", ".png", ".webp"}
    ext = os.path.splitext(image_file.filename)[1].lower()
    if ext not in allowed_extensions:
        ext = ".jpg"

    saved_name = f"camera_{uuid.uuid4().hex}{ext}"
    saved_path = os.path.join(UPLOAD_DIR, saved_name)

    try:
        image_file.save(saved_path)
        result = detector.analyze_road(saved_path)

        damage_class = result.get("damage_type") or "Unclassified damage"
        road_condition = result.get("road_condition", "unknown")
        confidence = float(result.get("confidence", 0) or 0)
        accepted = bool(result.get("accepted", False))
        severity = detector.severity_for(damage_class)

        response = {
            "ok": True,
            "image": f"/uploads/{saved_name}",
            "road_condition": road_condition,
            "damage_type": damage_class,
            "confidence": confidence,
            "accepted": accepted,
            "severity": severity,
            "queued_for_admin": False
        }

        if road_condition != "normal":
            corroboration_area_key = corroboration.fine_area_key(lat_f, lon_f)
            authority_area_key = corroboration.coarse_area_key(lat_f, lon_f)
            new_id = db.insert_detection(
                image_path=os.path.basename(saved_path),
                source="esp32cam",
                damage_class=damage_class,
                confidence=confidence,
                severity=severity,
                lat=lat_f, lon=lon_f,
                description=description,
                ai_accepted=accepted,
                client_ip=_client_ip(),
                hazard_type="road_damage",
                corroboration_area_key=corroboration_area_key,
                authority_area_key=authority_area_key,
            )
            response["detection_id"] = new_id
            response["queued_for_admin"] = True
            try:
                response["emails_sent"] = corroboration.run_lifecycle_sweep()
            except Exception:
                logger.exception("Corroboration sweep failed for camera detection.")
                response["emails_sent"] = 0

        return jsonify(response), 200

    except Exception as exc:
        logger.exception("ESP32-CAM road analysis failed.")
        return jsonify({
            "ok": False,
            "message": "Road image analysis failed.",
            "error": str(exc) if app.debug else "Internal server error."
        }), 500


# ---------------------------------------------------------------------------
# Auth: login flow
# ---------------------------------------------------------------------------
def _set_auth_cookie(resp, tok):
    resp.set_cookie("ss_token", tok, httponly=True, samesite="Strict", max_age=TOKEN_TTL_SEC)
    resp.headers["X-Set-Auth-Token"] = tok
    return resp

@app.route("/auth/token", methods=["POST"])
def auth_token():
    """Token issuance endpoint — the one place a token is minted. Verifies the
    pin (salted digest) then issues a short-lived httpOnly token. Called by
    /login/creds after it confirms the pin; the frontend never touches the token
    except via the browser cookie + X-Set-Auth-Token response header."""
    ip = request.remote_addr or "0.0.0.0"
    if _rate_limit(ip):
        return jsonify({"ok": False, "reason": "rate_limited",
                        "message": "Too many failed attempts. Try again in an hour."}), 429
    pin = _get_pin_from_request()
    if not _pin_ok(pin):
        _rate_record_fail(ip)
        remaining = RATE_LIMIT_MAX - (_rate_store.get(ip, {}).get("failures", 0))
        msg = f"Wrong pin. {max(0, remaining)} attempts remaining."
        if remaining <= 0:
            msg = "Account locked for 1 hour due to too many failed attempts."
        return jsonify({"ok": False, "reason": "blocked", "message": msg}), 403
    _rate_reset(ip)
    tok = _issue_token()
    _admin_activity("Admin login", "Administrator", "PIN authentication succeeded.")
    return _set_auth_cookie(make_response(jsonify({"ok": True, "message": "Authenticated."})), tok)

@app.route("/admin/logout", methods=["POST", "OPTIONS"])
def admin_logout():
    if request.method == "OPTIONS":
        return ("", 204)

    tok = _token_from_header()
    if tok:
        _token_store.pop(tok, None)

    resp = make_response(jsonify({"ok": True, "message": "Admin session closed."}))
    resp.delete_cookie("ss_token", samesite="Strict")
    return resp

@app.route("/login/creds", methods=["POST"])
def login_creds():
    if AUTH_DISABLED:
        # Pin gate is off: mint a session trivially so the admin bootstrap
        # (apiEnsureSession -> POST /login/creds) succeeds with NO pin, and
        # every protected admin action is freely usable end-to-end.
        _rate_reset(request.remote_addr or "0.0.0.0")
        tok = _issue_token()
        _admin_activity("Admin login", "Administrator", "Authentication gate disabled by configuration.")
        return _set_auth_cookie(make_response(jsonify({"ok": True, "message": "Authenticated (auth disabled)."})), tok)
    # delegate to the single token issuance path (same pin policy, same rates)
    pin = _get_pin_from_request()
    ip = request.remote_addr or "0.0.0.0"
    if _rate_limit(ip):
        return jsonify({"ok": False, "reason": "rate_limited",
                        "message": "Too many failed attempts. Try again in an hour."}), 429
    if not _pin_ok(pin):
        _rate_record_fail(ip)
        remaining = RATE_LIMIT_MAX - (_rate_store.get(ip, {}).get("failures", 0))
        msg = f"Wrong pin. {max(0, remaining)} attempts remaining."
        if remaining <= 0:
            msg = "Account locked for 1 hour due to too many failed attempts."
        return jsonify({"ok": False, "reason": "blocked", "message": msg}), 403
    _rate_reset(ip)
    tok = _issue_token()
    return _set_auth_cookie(make_response(jsonify({"ok": True, "message": "Authenticated."})), tok)

def _token_from_header():
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    header = request.headers.get("X-Auth-Token", "")
    if header:
        return header.strip()
    # httpOnly cookie set on login (browser sends it automatically)
    cookie = request.cookies.get("ss_token", "")
    if cookie:
        return cookie.strip()
    query_token = request.args.get("token", "")
    if query_token:
        return query_token.strip()
    return ""

def _get_pin_from_request():
    pin = (
        request.headers.get("X-Admin-Pin")
        or request.form.get("pin")
        or request.form.get("password")
        or request.form.get("admin_password")
        or request.args.get("pin")
        or request.args.get("password")
    )

    if not pin:
        ct = request.content_type or ""

        if "json" in ct:
            data = request.get_json(silent=True) or {}
            pin = data.get("pin") or data.get("password") or data.get("admin_password")

    return pin or ""


def _verify_user_bearer():
    """Verify the existing Firebase user ID token and return decoded claims."""
    if not _init_firebase_admin():
        raise RuntimeError("Firebase Admin is not configured on the backend.")
    auth_header = request.headers.get("Authorization", "")
    token = ""
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
    if not token:
        token = request.headers.get("X-Firebase-Id-Token", "").strip()
    if not token:
        raise ValueError("Firebase authentication token is required.")
    return firebase_admin_auth.verify_id_token(token, check_revoked=False)

def _sensor_source_from_rtdb(root):
    if not isinstance(root, dict):
        return {}
    source = root.get("sensors") if isinstance(root.get("sensors"), dict) else root
    source = dict(source or {})
    gps = source.get("gps") if isinstance(source.get("gps"), dict) else root.get("gps")
    source["_gps"] = gps if isinstance(gps, dict) else {}
    camera = source.get("camera") if isinstance(source.get("camera"), dict) else root.get("camera")
    source["_camera"] = camera if isinstance(camera, dict) else {}
    return source

def _to_float(value):
    try:
        if value in (None, ""):
            return None
        n = float(value)
        return n if n == n and abs(n) != float("inf") else None
    except Exception:
        return None

def _read_live_rtdb():
    if not _init_firebase_admin() or firebase_admin_db is None:
        return None
    database_url = os.environ.get("FIREBASE_DATABASE_URL", "").strip()
    if not database_url:
        return None
    try:
        root = firebase_admin_db.reference("/").get()
        source = _sensor_source_from_rtdb(root)
        now = datetime.now(timezone.utc).isoformat()
        device_id = (
            source.get("deviceId") or source.get("device_id") or
            source.get("ip") or root.get("deviceId") if isinstance(root, dict) else None
        )
        reading = {
            "timestamp": now,
            "device_id": str(device_id) if device_id else "firebase-sensors",
            "temperature": _to_float(source.get("temperature")),
            "humidity": _to_float(source.get("humidity")),
            "pressure": _to_float(source.get("pressure") or source.get("atmosphericPressure")),
            "pm1": _to_float(source.get("pm1")),
            "pm25": _to_float(source.get("pm25")),
            "pm10": _to_float(source.get("pm10")),
            "co2": _to_float(source.get("co2") or source.get("co2Equivalent")),
            "voc": _to_float(source.get("voc") or source.get("vocEquivalent")),
            "iaq": _to_float(source.get("iaq") or source.get("iaqScore")),
            "ip": source.get("ip") or (root.get("ip") if isinstance(root, dict) else None),
            "status": source.get("status") or "Connected",
            "camera_online": bool(
                source.get("cameraOnline")
                if "cameraOnline" in source
                else source.get("_camera", {}).get("online")
            ),
            "camera_ip": source.get("camIp") or source.get("cameraIp") or source.get("_camera", {}).get("ip"),
            "gps": {
                "latitude": _to_float(source.get("_gps", {}).get("latitude") or source.get("_gps", {}).get("lat")
                                     or source.get("latitude")),
                "longitude": _to_float(source.get("_gps", {}).get("longitude") or source.get("_gps", {}).get("lng")
                                       or source.get("_gps", {}).get("lon") or source.get("longitude")),
                "accuracy": _to_float(source.get("_gps", {}).get("accuracy")),
                "timestamp": source.get("_gps", {}).get("time") or source.get("_gps", {}).get("timestamp"),
            },
            "raw": source,
        }
        return reading
    except Exception:
        logger.exception("Unable to read Firebase Realtime Database for admin monitoring.")
        return None

def _admin_activity(action, target=None, details=None):
    try:
        db.add_admin_activity(action, target, details)
    except Exception:
        logger.exception("Unable to record admin activity.")

def require_auth(f):
    """Locked route: must present a valid token + pin (or valid upload-token)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if AUTH_DISABLED:
            # Trusted LAN / dev convenience: the whole pin+token gate is off.
            return f(*args, **kwargs)
        ip = request.remote_addr or "0.0.0.0"
        if _rate_limit(ip):
            return jsonify({"ok": False, "reason": "rate_limited",
                            "message": "Too many failed attempts. Try again later."}), 429

        tok = _token_from_header()
        pin = _get_pin_from_request()

        if not _valid_token(tok):
            # Stale/expired token is a normal login-state condition, NOT a
            # brute-force signal — never count it toward the PIN lockout.
            return jsonify({"ok": False, "reason": "blocked",
                            "message": "Authentication required. Please log in."}), 401

        if not _pin_ok(pin):
            _rate_record_fail(ip)
            remaining = RATE_LIMIT_MAX - (_rate_store.get(ip, {}).get("failures", 0))
            msg = f"Wrong pin. {max(0, remaining)} attempts remaining."
            if remaining <= 0:
                msg = "Account locked for 1 hour due to too many failed attempts."
            return jsonify({"ok": False, "reason": "blocked", "message": msg}), 403

        _rate_reset(ip)
        return f(*args, **kwargs)
    return decorated

# (require_stream_token is defined above, near its first use)

# ---------------------------------------------------------------------------
# Track A — detection → admin queue
# ---------------------------------------------------------------------------
def _client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip() or None
    return request.remote_addr or None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload():
    upload_tok = (request.form.get("_upload_token")
                  or request.args.get("_upload_token")
                  or request.headers.get("X-Upload-Token", ""))
    if not _valid_upload_token(upload_tok):
        return redirect(url_for("login"))

    image_file = request.files.get("image")
    if not image_file or image_file.filename == "":
        flash("Please choose an image to upload.")
        return redirect(url_for("index"))

    source      = request.form.get("source", "citizen")
    lat         = request.form.get("lat") or None
    lon         = request.form.get("lon") or None
    description = request.form.get("description") or None
    client_ip   = _client_ip()
    hazard_type = "road_damage"

    ext       = os.path.splitext(image_file.filename)[1] or ".jpg"
    saved_name = f"{uuid.uuid4().hex}{ext}"
    saved_path = os.path.join(UPLOAD_DIR, saved_name)
    image_file.save(saved_path)

    result = detector.analyze_road(saved_path)
    if result["road_condition"] == "normal":
        flash("No damage detected above the confidence threshold \u2014 nothing queued.")
        return redirect(url_for("index"))

    damage_class = result["damage_type"] or "Unclassified damage"
    severity     = detector.severity_for(damage_class)
    lat_f        = float(lat) if lat else None
    lon_f        = float(lon) if lon else None
    corroboration_area_key = corroboration.fine_area_key(lat_f, lon_f)
    authority_area_key     = corroboration.coarse_area_key(lat_f, lon_f)

    # Store the BASENAME only. The templates build URLs as "/uploads/" +
    # image_path.split("/")[-1]; storing the absolute Windows path leaked the
    # whole drive path into that URL (every image 404'd). os.path.basename
    # strips both / and \ separators, so this is safe regardless of OS.
    new_id = db.insert_detection(
        image_path=os.path.basename(saved_path), source=source, damage_class=damage_class,
        confidence=result["confidence"], severity=severity, lat=lat_f, lon=lon_f,
        description=description, ai_accepted=result["accepted"], client_ip=client_ip,
        hazard_type=hazard_type, corroboration_area_key=corroboration_area_key,
authority_area_key=authority_area_key,
    )

    emailed = corroboration.run_lifecycle_sweep()

    if emailed:
        flash(f"Detection #{new_id} ({damage_class}, {severity}) queued. "
              f"Auto-emailed {emailed} corroborated cluster(s).")
    elif result["road_condition"] == "damaged_unclassified":
        confidence_note = "unclassified \u2014 multiple weak signals, needs a closer look"
        flash(f"Detection #{new_id} ({damage_class}, {severity}, {confidence_note}) "
              f"queued for admin verification.")
    else:
        confidence_note = "high-confidence" if result["accepted"] else "uncertain \u2014 needs a closer look"
        flash(f"Detection #{new_id} ({damage_class}, {severity}, {confidence_note}) "
              f"queued for admin verification.")
    return redirect(url_for("index"))

# ---------------------------------------------------------------------------
# Auth: login flow
# ---------------------------------------------------------------------------
@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/upload/token")
def upload_token_get():
    tok = _issue_upload_token()
    resp = make_response(jsonify({"ok": True, "token": tok}))
    resp.headers["X-Upload-Token"] = tok
    return resp

# ---------------------------------------------------------------------------
# Admin dashboard (clusters + authorities rendered client-side via polling)
# ---------------------------------------------------------------------------
@app.route("/admin")
def admin():
    pending  = db.list_by_status("pending")
    approved = db.list_by_status("approved")
    rejected = db.list_by_status("rejected")
    return render_template("admin.html",
                           pending=pending, approved=approved, rejected=rejected)

@app.route("/admin/api/detections")
@require_auth
def admin_api_detections():
    try:
        pending = db.list_by_status("pending")
        approved = db.list_by_status("approved")
        rejected = db.list_by_status("rejected")

        def serialize(rows):
            return [dict(row) for row in rows]

        return jsonify({
            "ok": True,
            "pending": serialize(pending),
            "approved": serialize(approved),
            "rejected": serialize(rejected)
        })

    except Exception as exc:
        logger.exception("Failed to load admin detections.")
        return jsonify({
            "ok": False,
            "message": "Failed to load detections.",
            "error": str(exc) if app.debug else "Internal server error."
        }), 500

@app.route("/api/health", methods=["GET", "OPTIONS"])
def api_health():
    if request.method == "OPTIONS":
        return ("", 204)
    return jsonify({
        "ok": True,
        "service": "SmartSurround backend",
        "status": "online",
        "admin_pin_configured": bool(_ADMIN_DIGEST),
        "auth_disabled": AUTH_DISABLED,
    })


@app.route("/api/complaints", methods=["GET", "POST", "OPTIONS"])
def complaints_api():
    """User-facing Help Desk API.

    The React client supplies the Firebase UID/email so existing Firebase
    Authentication remains the source of identity. Admin mutation/list routes
    below are separately protected by the existing SmartSurround admin PIN.
    """
    if request.method == "OPTIONS":
        return ("", 204)

    if request.method == "GET":
        user_id = (request.args.get("user_id") or "").strip()
        if not user_id:
            return jsonify({"ok": False, "message": "user_id is required."}), 400
        rows = db.list_complaints_for_user(user_id)
        return jsonify({"ok": True, "complaints": [dict(row) for row in rows]})

    user_id = (request.form.get("user_id") or "").strip()
    user_name = (request.form.get("user_name") or "").strip()
    email = (request.form.get("email") or "").strip()
    subject = (request.form.get("subject") or "").strip()
    description = (request.form.get("description") or "").strip()
    priority = (request.form.get("priority") or "Normal").strip().title()
    category = (request.form.get("category") or "Other").strip()

    if not user_id or not email or not subject or not description:
        return jsonify({"ok": False, "message": "Name, email, subject and description are required."}), 400
    if priority not in {"Normal", "Intermediate", "Urgent"}:
        return jsonify({"ok": False, "message": "Invalid priority."}), 400
    if len(subject) > 160:
        return jsonify({"ok": False, "message": "Subject must be 160 characters or fewer."}), 400
    if len(description) > 8000:
        return jsonify({"ok": False, "message": "Description must be 8000 characters or fewer."}), 400

    attachment_path = None
    attachment = request.files.get("attachment")
    if attachment and attachment.filename:
        if attachment.content_length and attachment.content_length > 5 * 1024 * 1024:
            return jsonify({"ok": False, "message": "Attachment must be 5 MB or smaller."}), 400
        allowed = {".png", ".jpg", ".jpeg", ".webp", ".pdf", ".txt"}
        ext = os.path.splitext(attachment.filename)[1].lower()
        if ext not in allowed:
            return jsonify({"ok": False, "message": "Unsupported attachment type."}), 400
        complaint_dir = os.path.join(UPLOAD_DIR, "complaints")
        os.makedirs(complaint_dir, exist_ok=True)
        filename = f"complaint_{uuid.uuid4().hex}{ext}"
        attachment.save(os.path.join(complaint_dir, filename))
        attachment_path = filename

    try:
        latest_location = db.list_user_location_history(user_id, limit=1)
        loc = latest_location[0] if latest_location else None
        posted_lat = request.form.get("incident_latitude")
        posted_lon = request.form.get("incident_longitude")
        posted_accuracy = request.form.get("incident_accuracy")
        posted_gps_time = request.form.get("incident_gps_time")
        def _float_or_none(value):
            try:
                return float(value) if value not in (None, "") else None
            except (TypeError, ValueError):
                return None
        incident_latitude = _float_or_none(posted_lat)
        incident_longitude = _float_or_none(posted_lon)
        incident_accuracy = _float_or_none(posted_accuracy)
        incident_gps_time = posted_gps_time or (loc["timestamp"] if loc else None)
        if incident_latitude is None or incident_longitude is None:
            incident_latitude = loc["latitude"] if loc else None
            incident_longitude = loc["longitude"] if loc else None
            incident_accuracy = loc["accuracy"] if loc else None

        latest_environment = db.get_latest_environment_for_user(user_id)
        env_snapshot = dict(latest_environment) if latest_environment else None
        row = db.create_complaint(
            user_id, user_name, email, subject, description, priority, attachment_path,
            category=category,
            incident_latitude=incident_latitude,
            incident_longitude=incident_longitude,
            incident_accuracy=incident_accuracy,
            incident_gps_time=incident_gps_time,
            environment_snapshot=env_snapshot,
        )
        return jsonify({"ok": True, "message": "Complaint submitted successfully.", "complaint": dict(row)}), 201
    except Exception as exc:
        logger.exception("Failed to create complaint.")
        return jsonify({"ok": False, "message": "Unable to submit complaint.", "error": str(exc) if app.debug else "Internal server error."}), 500


@app.route("/admin/api/complaints")
@require_auth
def admin_api_complaints():
    rows = db.list_complaints()
    return jsonify({"ok": True, "complaints": [dict(row) for row in rows]})


@app.route("/admin/complaints/<int:complaint_id>/verify", methods=["POST"])
@require_auth
def admin_verify_complaint(complaint_id):
    payload = request.get_json(silent=True) or {}
    action = str(payload.get("action") or "").strip().lower()
    notes = str(payload.get("notes") or "").strip()[:8000]
    if action not in {"verify", "request_info", "reject", "escalate", "resolve"}:
        return jsonify({"ok": False, "message": "Unsupported incident action."}), 400
    mapped_action = "verify" if action in {"verify", "request_info"} else action
    # "request_info" leaves the incident open but records that more details were requested.
    if action == "request_info":
        row = db.update_complaint(
            complaint_id,
            "Open",
            admin_reply=notes or "Additional information requested by administrator.",
        )
        _admin_activity("Incident information requested", str(complaint_id), notes or "")
    else:
        row = db.verify_complaint(complaint_id, mapped_action, notes=notes, admin="Administrator")
        _admin_activity(f"Incident {mapped_action}", str(complaint_id), notes or "")
    if row is None:
        return jsonify({"ok": False, "message": "Incident not found."}), 404
    return jsonify({"ok": True, "complaint": dict(row)})

@app.route("/admin/complaints/<int:complaint_id>/update", methods=["POST"])
@require_auth
def admin_update_complaint(complaint_id):
    payload = request.get_json(silent=True) or request.form
    status = str(payload.get("status") or "Open").strip().title()
    reply = payload.get("admin_reply")
    reply = str(reply).strip() if reply is not None else None
    priority = str(payload.get("priority") or "").strip().title() or None
    allowed_statuses = {"Open", "In Progress", "Resolved", "Closed"}
    allowed_priorities = {"Normal", "Intermediate", "Urgent", "Critical"}
    if status not in allowed_statuses:
        return jsonify({"ok": False, "message": "Invalid complaint status."}), 400
    if priority is not None and priority not in allowed_priorities:
        return jsonify({"ok": False, "message": "Invalid complaint priority."}), 400
    if reply is not None and len(reply) > 8000:
        return jsonify({"ok": False, "message": "Admin reply must be 8000 characters or fewer."}), 400
    row = db.update_complaint(complaint_id, status, reply, priority=priority)
    _admin_activity("Incident status changed", str(complaint_id), f"{status} / {priority or 'unchanged'}")
    if row is None:
        return jsonify({"ok": False, "message": "Complaint not found."}), 404
    return jsonify({"ok": True, "message": f"Ticket {row['ticket_id']} updated.", "complaint": dict(row)})


@app.route("/admin/complaints/<int:complaint_id>/attachment")
@require_auth
def admin_complaint_attachment(complaint_id):
    row = db.get_complaint(complaint_id)
    if row is None or not row["attachment_path"]:
        return "Attachment not found.", 404
    directory = os.path.join(UPLOAD_DIR, "complaints")
    return send_from_directory(directory, row["attachment_path"], as_attachment=True)



# ---------------------------------------------------------------------------
# Admin control-center API
# ---------------------------------------------------------------------------

@app.route("/api/user/sync", methods=["POST", "OPTIONS"])
def api_user_sync():
    if request.method == "OPTIONS":
        return ("", 204)
    try:
        claims = _verify_user_bearer()
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 401

    payload = request.get_json(silent=True) or {}
    user_id = claims.get("uid")
    name = payload.get("name") or claims.get("name") or claims.get("email", "").split("@")[0]
    email = payload.get("email") or claims.get("email") or ""
    phone = payload.get("phone")
    department = payload.get("department")
    device_id = payload.get("device_id")
    row = db.upsert_user(user_id, name, email, phone, department, "user", payload.get("status") or "Idle",
                         "Enabled", device_id)
    db.add_admin_activity("User sync", user_id, f"Synced {email}")
    return jsonify({"ok": True, "user": dict(row)})

@app.route("/api/user/location", methods=["POST", "OPTIONS"])
def api_user_location():
    if request.method == "OPTIONS":
        return ("", 204)
    try:
        claims = _verify_user_bearer()
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 401
    payload = request.get_json(silent=True) or {}
    lat = _to_float(payload.get("latitude"))
    lon = _to_float(payload.get("longitude"))
    accuracy = _to_float(payload.get("accuracy"))
    if lat is None or lon is None or not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
        return jsonify({"ok": False, "message": "Valid GPS latitude and longitude are required."}), 400
    status = str(payload.get("status") or "working").strip().lower()
    if status not in {"working", "idle", "offline"}:
        status = "working"
    user_id = claims.get("uid")
    db.upsert_user(
        user_id,
        name=claims.get("name") or claims.get("email", "").split("@")[0],
        email=claims.get("email") or "",
        role="user",
        status=status.title() if status != "working" else "Working",
        account_status="Enabled",
    )
    row = db.insert_user_location(
        user_id, lat, lon, accuracy,
        timestamp=payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        status=status,
    )
    return jsonify({"ok": True, "location": dict(row)})

@app.route("/api/user/environment", methods=["POST", "OPTIONS"])
def api_user_environment():
    if request.method == "OPTIONS":
        return ("", 204)
    try:
        claims = _verify_user_bearer()
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 401
    payload = request.get_json(silent=True) or {}
    reading = {
        key: payload.get(key) for key in (
            "temperature", "humidity", "pressure", "pm1", "pm25", "pm10", "co2", "voc", "iaq"
        )
    }
    if not any(v not in (None, "") for v in reading.values()):
        return jsonify({"ok": False, "message": "At least one sensor reading is required."}), 400
    device_id = str(payload.get("device_id") or "firebase-sensors")
    reading["timestamp"] = payload.get("timestamp") or datetime.now(timezone.utc).isoformat()
    row = db.record_environment(reading, user_id=claims.get("uid"), device_id=device_id, source="user-dashboard")
    db.upsert_sensor_device(
        device_id,
        "ESP32",
        claims.get("uid"),
        connection="CONNECTED",
        last_update=reading["timestamp"],
        sensor_availability=", ".join(k for k,v in reading.items() if k != "timestamp" and v not in (None, "")),
    )
    return jsonify({"ok": True})

@app.route("/admin/api/control-center")
@require_auth
def admin_api_control_center():
    try:
        live = _read_live_rtdb()
        now = datetime.now(timezone.utc)
        users = [dict(r) for r in db.list_users()]
        locations = [dict(r) for r in db.list_latest_user_locations()]
        devices = [dict(r) for r in db.list_sensor_devices()]
        complaints = [dict(r) for r in db.list_complaints()]
        pending = [dict(r) for r in db.list_by_status("pending")]
        approved = [dict(r) for r in db.list_by_status("approved")]
        rejected = [dict(r) for r in db.list_by_status("rejected")]
        thresholds = [dict(r) for r in db.list_thresholds()]
        alerts = [dict(r) for r in db.list_alerts(limit=100)]
        activity = [dict(r) for r in db.list_admin_activity(250)]
        recipients = [dict(r) for r in db.list_recipients()]
        communications = [dict(r) for r in db.list_communications(150)]
        if live:
            # Record the current Firebase snapshot in history only when values exist.
            db.record_environment(live, device_id=live.get("device_id"), source="firebase-admin")
            db.upsert_sensor_device(
                live.get("device_id") or "firebase-sensors",
                "ESP32",
                None,
                "CONNECTED",
                live.get("timestamp"),
                ", ".join(k for k in ("temperature","humidity","pressure","pm1","pm25","pm10","co2","voc","iaq") if live.get(k) is not None),
                None,
                {"ip": live.get("ip"), "camera_online": live.get("camera_online")},
            )
            devices = [dict(r) for r in db.list_sensor_devices()]
        # Create alert records from real live values + stored thresholds without inventing values.
        if live:
            tmap = {t["sensor"]: t for t in thresholds}
            sensor_values = {
                "PM1.0": live.get("pm1"), "PM2.5": live.get("pm25"), "PM10": live.get("pm10"),
                "CO2": live.get("co2"), "VOC": live.get("voc"), "IAQ": live.get("iaq"),
                "Temperature": live.get("temperature"), "Humidity": live.get("humidity"),
            }
            for sensor, value in sensor_values.items():
                if value is None or sensor not in tmap:
                    continue
                th = tmap[sensor]
                severity = None
                threshold = None
                if th.get("critical") is not None and float(value) >= float(th["critical"]):
                    severity, threshold = "CRITICAL", th["critical"]
                elif th.get("warning") is not None and float(value) >= float(th["warning"]):
                    severity, threshold = "WARNING", th["warning"]
                elif th.get("minimum") is not None and float(value) < float(th["minimum"]):
                    severity, threshold = "WARNING", th["minimum"]
                elif th.get("maximum") is not None and float(value) > float(th["maximum"]):
                    severity, threshold = "WARNING", th["maximum"]
                if severity:
                    recent = [a for a in alerts if a.get("sensor") == sensor and a.get("status") == "Open"]
                    if not recent:
                        created = db.create_alert(
                            "Environmental", severity,
                            f"{sensor} threshold exceeded",
                            f"{sensor} is {value} {th.get('unit','')} against configured threshold {threshold}.",
                            sensor, value, threshold,
                        )
                        alerts.insert(0, dict(created))
        summary = {
            "total_users": len(users),
            "active_users": sum(1 for u in users if str(u.get("account_status","")).lower() == "enabled"),
            "working_users": sum(1 for l in locations if str(l.get("status","")).lower() == "working"),
            "active_incidents": sum(1 for c in complaints if c.get("status") in {"Open", "In Progress"}) + len(pending),
            "critical_incidents": sum(1 for d in pending + approved + rejected if str(d.get("severity","")).lower() == "critical")
                                    + sum(1 for c in complaints if str(c.get("priority","")).lower() == "urgent" and c.get("status") in {"Open","In Progress"}),
            "connected_devices": sum(1 for d in devices if str(d.get("connection","")).upper() == "CONNECTED"),
            "offline_devices": sum(1 for d in devices if str(d.get("connection","")).upper() != "CONNECTED"),
            "environmental_alerts": sum(1 for a in alerts if a.get("status") == "Open"),
        }
        return jsonify({
            "ok": True,
            "summary": summary,
            "users": users,
            "locations": locations,
            "devices": devices,
            "complaints": complaints,
            "detections": {"pending": pending, "approved": approved, "rejected": rejected},
            "thresholds": thresholds,
            "alerts": alerts,
            "activity": activity,
            "recipients": recipients,
            "communications": communications,
            "environment_history": [dict(r) for r in db.list_environment_history(limit=1000)],
            "live": live,
            "system": {
                "admin_configured": bool(_ADMIN_DIGEST),
                "auth_disabled": AUTH_DISABLED,
                "firebase_admin_ready": FIREBASE_ADMIN_READY,
            },
        })
    except Exception as exc:
        logger.exception("Control-center API failed.")
        return jsonify({"ok": False, "message": "Unable to load the admin control center.", "error": str(exc) if app.debug else "Internal server error."}), 500

@app.route("/admin/api/users/<user_id>")
@require_auth
def admin_api_user_detail(user_id):
    row = db.get_user(user_id)
    if row is None:
        return jsonify({"ok": False, "message": "User not found."}), 404
    history = [dict(r) for r in db.list_user_location_history(user_id, limit=500)]
    env = [dict(r) for r in db.list_environment_history(limit=250) if r.get("user_id") == user_id]
    incidents = [dict(r) for r in db.list_complaints() if r.get("user_id") == user_id]
    _admin_activity("User viewed", user_id)
    return jsonify({"ok": True, "user": dict(row), "locations": history, "environment": env, "incidents": incidents})

@app.route("/admin/api/users/<user_id>/account", methods=["POST"])
@require_auth
def admin_api_user_account(user_id):
    payload = request.get_json(silent=True) or {}
    row = db.update_user_account(
        user_id,
        status=payload.get("status"),
        account_status=payload.get("account_status"),
        role=payload.get("role"),
        phone=payload.get("phone"),
        department=payload.get("department"),
    )
    if row is None:
        return jsonify({"ok": False, "message": "User not found."}), 404
    _admin_activity("User edited", user_id, str(payload))
    return jsonify({"ok": True, "user": dict(row)})

@app.route("/admin/api/locations/history")
@require_auth
def admin_api_location_history():
    user_id = (request.args.get("user_id") or "").strip()
    rows = db.list_user_location_history(user_id, request.args.get("start"), request.args.get("end"), limit=1000) if user_id else []
    return jsonify({"ok": True, "locations": [dict(r) for r in rows]})

@app.route("/admin/api/environment/history")
@require_auth
def admin_api_environment_history():
    rows = db.list_environment_history(request.args.get("start"), request.args.get("end"), limit=1000)
    return jsonify({"ok": True, "readings": [dict(r) for r in rows]})

@app.route("/admin/api/alerts/<int:alert_id>/resolve", methods=["POST"])
@require_auth
def admin_api_resolve_alert(alert_id):
    row = db.resolve_alert(alert_id)
    if row is None:
        return jsonify({"ok": False, "message": "Alert not found."}), 404
    _admin_activity("Alert resolved", str(alert_id))
    return jsonify({"ok": True, "alert": dict(row)})

@app.route("/admin/api/thresholds", methods=["GET", "POST"])
@require_auth
def admin_api_thresholds():
    if request.method == "GET":
        return jsonify({"ok": True, "thresholds": [dict(r) for r in db.list_thresholds()]})
    payload = request.get_json(silent=True) or {}
    items = payload.get("thresholds") or []
    if not isinstance(items, list):
        return jsonify({"ok": False, "message": "thresholds must be a list."}), 400
    rows = db.update_thresholds(items, modified_by="Administrator")
    _admin_activity("Threshold changed", "System", f"Updated {len(items)} threshold(s).")
    return jsonify({"ok": True, "thresholds": [dict(r) for r in rows]})

@app.route("/admin/api/activity")
@require_auth
def admin_api_activity():
    return jsonify({"ok": True, "activity": [dict(r) for r in db.list_admin_activity(int(request.args.get("limit", 500)))]})

@app.route("/admin/api/recipients", methods=["GET", "POST"])
@require_auth
def admin_api_recipients():
    if request.method == "GET":
        return jsonify({"ok": True, "recipients": [dict(r) for r in db.list_recipients()]})
    payload = request.get_json(silent=True) or {}
    required = ["name", "email"]
    if any(not str(payload.get(k) or "").strip() for k in required):
        return jsonify({"ok": False, "message": "Name and email are required."}), 400
    row = db.add_recipient(
        str(payload["name"]).strip(), str(payload.get("department") or "").strip(),
        str(payload.get("role") or "").strip(), str(payload["email"]).strip(),
        str(payload.get("notification_type") or "Incident"),
    )
    _admin_activity("Recipient added", str(row["id"]))
    return jsonify({"ok": True, "recipient": dict(row)}), 201

@app.route("/admin/api/recipients/<int:recipient_id>", methods=["DELETE"])
@require_auth
def admin_api_recipient_delete(recipient_id):
    db.delete_recipient(recipient_id)
    _admin_activity("Recipient deleted", str(recipient_id))
    return jsonify({"ok": True, "message": "Recipient removed."})

def _verified_incident_payload(incident_id, kind=None):
    if not incident_id:
        return None
    try:
        if str(kind or "").lower() in {"problem", "complaint"}:
            row = db.get_complaint(int(incident_id))
            return dict(row) if row else None
        if str(kind or "").lower() in {"ai detection", "detection"}:
            row = db.get_detection(int(incident_id))
            return dict(row) if row else None
        # Backward-compatible fallback only when kind is omitted.
        row = db.get_complaint(int(incident_id))
        if row:
            return dict(row)
        row = db.get_detection(int(incident_id))
        return dict(row) if row else None
    except Exception:
        return None

def _draft_incident_email(incident):
    """Create a factual official draft using only recorded incident fields."""
    title = incident.get("subject") or incident.get("damage_class") or "SmartSurround incident"
    incident_id = incident.get("ticket_id") or f"INC-{incident.get('id')}"
    user = incident.get("user_name") or "Recorded user"
    urgency = incident.get("priority") or incident.get("severity") or "Not specified"
    description = incident.get("description") or incident.get("hazard_type") or "[Information required]"
    created = incident.get("created_at") or "[Information required]"
    reply = incident.get("admin_reply") or ""
    gps_lat = incident.get("lat")
    gps_lon = incident.get("lon")
    if gps_lat is None:
        gps_lat = incident.get("incident_latitude")
    if gps_lon is None:
        gps_lon = incident.get("incident_longitude")
    gps_line = f"GPS: {gps_lat}, {gps_lon}" if gps_lat is not None and gps_lon is not None else "GPS: [Information required]"
    body = (
        "SmartSurround Incident Notification\n\n"
        f"Incident ID: {incident_id}\n"
        f"Reported by: {user}\n"
        f"Urgency: {urgency}\n"
        f"Submitted: {created}\n"
        f"{gps_line}\n\n"
        "Verified description:\n"
        f"{description}\n\n"
    )
    if reply:
        body += f"Actions / administrative response:\n{reply}\n\n"
    body += "This draft contains only information recorded in SmartSurround. Review all fields before sending."
    return {
        "subject": f"SmartSurround Incident {incident_id} — {title}",
        "body": body,
        "incident_id": incident.get("id"),
        "ai_generated": True,
        "edited": False,
    }

@app.route("/admin/api/communications/draft", methods=["POST"])
@require_auth
def admin_api_communication_draft():
    payload = request.get_json(silent=True) or {}
    incident = _verified_incident_payload(payload.get("incident_id"), payload.get("kind"))
    if not incident:
        return jsonify({"ok": False, "message": "Incident not found."}), 404
    # Do not let unverified incidents be turned into official communications.
    status = str(incident.get("status") or "").lower()
    if status not in {"approved", "resolved", "closed"} and not incident.get("verified_at"):
        return jsonify({"ok": False, "message": "Verify the incident before generating an official communication."}), 409
    draft = _draft_incident_email(incident)
    row = db.add_communication(
        incident.get("id"), payload.get("recipient") or "",
        draft["subject"], draft["body"], [], True, False, "Draft", None, None,
        incident_kind=("Problem" if str(payload.get("kind") or "").lower() in {"problem","complaint"} else "AI Detection")
    )
    _admin_activity("Email generated", str(row["id"]), f"Incident {incident.get('id')}")
    return jsonify({"ok": True, "draft": {**draft, "id": row["id"]}})

@app.route("/admin/api/communications/<int:communication_id>", methods=["PUT", "POST"])
@require_auth
def admin_api_communication_update(communication_id):
    payload = request.get_json(silent=True) or {}
    row = next((r for r in db.list_communications(500) if int(r["id"]) == int(communication_id)), None)
    if not row:
        return jsonify({"ok": False, "message": "Communication not found."}), 404
    # We update through raw SQL only for this narrow admin editor surface.
    conn = db.get_conn()
    try:
        subject = str(payload.get("subject") or row["subject"]).strip()
        body = str(payload.get("body") or row["body"])
        recipient = str(payload.get("recipient") or row["recipient"] or "")
        conn.execute(
            "UPDATE communications SET subject=?, body=?, recipient=?, edited=?, status=? WHERE id=?",
            (subject, body, recipient, 1, "Draft", communication_id),
        )
        conn.commit()
    finally:
        conn.close()
    _admin_activity("Email edited", str(communication_id))
    return jsonify({"ok": True, "communication": dict(next((r for r in db.list_communications(500) if int(r["id"]) == int(communication_id)), row))})

@app.route("/admin/api/communications/<int:communication_id>/send", methods=["POST"])
@require_auth
def admin_api_communication_send(communication_id):
    rows = db.list_communications(500)
    row = next((r for r in rows if int(r["id"]) == int(communication_id)), None)
    if not row:
        return jsonify({"ok": False, "message": "Communication not found."}), 404
    recipient = str(row["recipient"] or "").strip()
    if not recipient:
        return jsonify({"ok": False, "message": "Choose a recipient email before sending."}), 400
    incident = _verified_incident_payload(row["incident_id"], row["incident_kind"])
    if not incident:
        return jsonify({"ok": False, "message": "Incident not found."}), 404
    result = email_driver.send_authority_email(
        recipient, row["subject"], row["body"], None
    )
    if not result.get("ok"):
        return jsonify({"ok": False, "message": result.get("reason") or "Email provider rejected the message.", "result": result}), 502
    conn = db.get_conn()
    try:
        conn.execute(
            "UPDATE communications SET sent_at=?, sent_by=?, status='Sent' WHERE id=?",
            (datetime.now(timezone.utc).isoformat(), "Administrator", communication_id),
        )
        conn.commit()
    finally:
        conn.close()
    _admin_activity("Email sent", str(communication_id), recipient)
    return jsonify({"ok": True, "communication": dict(next((r for r in db.list_communications(500) if int(r["id"]) == int(communication_id)), row))})

@app.route("/admin/api/report/export")
@require_auth
def admin_api_export_report():
    """Export a real .xlsx workbook for the selected workspace."""
    import io
    from flask import send_file
    data_type = (request.args.get("data") or "incidents").strip().lower()
    start = request.args.get("start")
    end = request.args.get("end")
    def _in_range(row, field):
        value = row.get(field)
        if not value:
            return True
        if start and str(value) < str(start):
            return False
        if end and str(value) > str(end):
            return False
        return True

    if data_type == "users":
        rows = [dict(r) for r in db.list_users() if _in_range(dict(r), "created_at") or _in_range(dict(r), "last_active")]
    elif data_type == "gps":
        if request.args.get("user_id"):
            rows = [dict(r) for r in db.list_user_location_history(request.args.get("user_id"), start, end, limit=10000)]
        else:
            rows = [dict(r) for r in db.list_user_location_history(None, start, end, limit=10000)]
    elif data_type == "environment":
        rows = [dict(r) for r in db.list_environment_history(start, end, 10000)]
    elif data_type == "alerts":
        rows = [dict(r) for r in db.list_alerts(limit=10000) if _in_range(dict(r), "created_at")]
    elif data_type == "devices":
        rows = [dict(r) for r in db.list_sensor_devices() if _in_range(dict(r), "last_update")]
    elif data_type == "admin_activity":
        rows = [dict(r) for r in db.list_admin_activity(10000) if _in_range(dict(r), "timestamp")]
    elif data_type == "communications":
        rows = [dict(r) for r in db.list_communications(10000) if _in_range(dict(r), "created_at") or _in_range(dict(r), "sent_at")]
    else:
        rows = [dict(r) for r in db.list_complaints() if _in_range(dict(r), "created_at")]

    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment
        wb = Workbook()
        ws = wb.active
        ws.title = data_type[:31].replace("_", " ").title()
        keys = list(rows[0].keys()) if rows else ["message"]
        ws.append(keys)
        for cell in ws[1]:
            cell.font = Font(bold=True)
            cell.fill = PatternFill("solid", fgColor="F3E9E1")
            cell.alignment = Alignment(vertical="top")
        for row in rows:
            ws.append([row.get(k, "") for k in keys])
        ws.freeze_panes = "A2"
        for col in ws.columns:
            max_len = min(max(len(str(c.value or "")) for c in col) + 2, 42)
            ws.column_dimensions[col[0].column_letter].width = max_len
        buffer = io.BytesIO()
        wb.save(buffer)
        buffer.seek(0)
        _admin_activity("Data exported", data_type, f"{len(rows)} rows")
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"smartsurround_{data_type}_report.xlsx",
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    except Exception:
        logger.exception("Excel export failed.")
        return jsonify({"ok": False, "message": "Excel export failed. Ensure openpyxl is installed."}), 500

@app.route("/admin/api/clusters")
def admin_api_clusters():
    clusters    = corroboration.list_clusters()
    authorities = authority_routing.list_authorities_for_admin()
    cluster_list = []
    for c in clusters:
        cluster_list.append({
            "id":                    c["id"],
            "corroboration_area_key": c["corroboration_area_key"],
            "hazard_type":           c["hazard_type"],
            "window_start":          c["window_start"],
            "lifecycle":             c["lifecycle"],
            "letter_path":           c["letter_path"],
            "emailed_at":            c["emailed_at"],
            "created_at":            c["created_at"],
        })
    auth_list = []
    for a in authorities:
        auth_list.append({
            "id":                a["id"],
            "authority_area_key": a["authority_area_key"],
            "hazard_type":       a["hazard_type"],
            "email":             a["email"],
            "lifecycle":         a["lifecycle"],
            "created_at":        a["created_at"],
            "verified_at":       a["verified_at"],
            "bounced_at":        a["bounced_at"],
        })
    return jsonify({"ok": True, "clusters": cluster_list, "authorities": auth_list})

@app.route("/admin/authorities/add", methods=["POST"])
@require_auth
def admin_authorities_add():
    area_key  = (request.form.get("authority_area_key") or "").strip()
    hazard    = (request.form.get("hazard_type") or "road_damage").strip()
    email     = (request.form.get("email") or "").strip()
    if not area_key or not email:
        return jsonify({"ok": False, "message": "Area key and email are required."}), 400
    row = db.get_or_create_authority(area_key, hazard, email)
    return jsonify({"ok": True, "authority_id": row["id"],
                    "lifecycle": row["lifecycle"]}), 201

@app.route("/admin/approve/<int:detection_id>", methods=["POST"])
@require_auth
def approve(detection_id):
    detection = db.get_detection(detection_id)
    if detection is None:
        return jsonify({"ok": False, "message": "Detection not found."}), 404

    letter_path = letter_generator.generate_letter(detection)
    db.update_status(detection_id, "approved", letter_path=letter_path)
    _admin_activity("Incident approved", f"INC-{detection_id}", "AI detection approved and letter generated.")

    emailed = corroboration.run_lifecycle_sweep()

    msg = f"Detection #{detection_id} approved \u2014 letter generated."
    if emailed:
        msg += f" Auto-emailed {emailed} corroborated cluster(s)."
    return jsonify({"ok": True, "message": msg})

@app.route("/admin/reject/<int:detection_id>", methods=["POST"])
@require_auth
def reject(detection_id):
    detection = db.get_detection(detection_id)
    if detection is None:
        return jsonify({"ok": False, "message": "Detection not found."}), 404
    db.update_status(detection_id, "rejected")
    _admin_activity("Incident rejected", f"INC-{detection_id}", "AI detection rejected by administrator.")
    return jsonify({"ok": True, "message": f"Detection #{detection_id} rejected."})

@app.route("/admin/authority/<int:authority_id>/verify", methods=["POST"])
@require_auth
def verify_authority(authority_id):
    authority = db.get_authority(authority_id)
    if authority is None:
        return jsonify({"ok": False, "message": f"Authority #{authority_id} not found."}), 404
    authority_routing.verify_authority(authority_id)
    return jsonify({"ok": True, "message": f"Authority #{authority_id} verified."})

@app.route("/admin/authority/<int:authority_id>/bounce", methods=["POST"])
@require_auth
def bounce_authority(authority_id):
    authority = db.get_authority(authority_id)
    if authority is None:
        return jsonify({"ok": False, "message": f"Authority #{authority_id} not found."}), 404
    authority_routing.bounce_authority(authority_id)
    return jsonify({"ok": True,
                    "message": f"Authority #{authority_id} bounced \u2014 flipped back to pending."})

@app.route("/admin/test-email", methods=["POST"])
@require_auth
def test_email():
    approved = db.list_by_status("approved")
    if not approved:
        return jsonify({"ok": False, "message": "No approved detections to use for test."}), 400
    latest = approved[0]
    letter_path = latest["letter_path"]
    if not letter_path or not os.path.isfile(letter_path):
        letter_path = letter_generator.generate_letter(latest)
    result = email_driver.send_authority_email(
        os.environ.get("EMAIL_TEST_RECIPIENT", "codexzero98@gmail.com"),
        f"SmartSurround Test Email \u2014 Detection #{latest['id']}",
        f"Test email sent from SmartSurround.\n\n"
        f"Detection #{latest['id']}: {latest['damage_class'] or 'N/A'}\n"
        f"Severity: {latest['severity'] or 'N/A'}\n"
        f"Mode: {'test (dry run)' if email_driver.TEST_MODE else 'live (real send)'}\n\n"
        f"Config: EMAIL_DRIVER={email_driver.DRIVER}, "
        f"TEST_MODE={email_driver.TEST_MODE}",
        letter_path,
    )
    return jsonify({"ok": result.get("ok"), "reason": result.get("reason"),
                    "mode": result.get("mode"), "to": result.get("effective_recipient")})

# ---------------------------------------------------------------------------
# Static: letters, uploads
# ---------------------------------------------------------------------------
@app.route("/letters/<int:detection_id>")
def download_letter(detection_id):
    detection = db.get_detection(detection_id)
    if detection is None or not detection["letter_path"]:
        return "No letter generated for this detection yet.", 404
    directory, filename = os.path.split(detection["letter_path"])
    return send_from_directory(directory, filename, as_attachment=True)

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
