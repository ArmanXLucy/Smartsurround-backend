# SmartSurround — Road Damage Detection Backend (Part 1)

This is the **no-hardware-required** half of the road-damage detection
feature: detection model → conservative decision layer → verification
queue → auto-generated letter. It's built to be tested right now with
any road photo, before the ESP32-CAM is ever wired up.

Once this works the way you want, the ESP32-CAM (Part 2) will simply
POST to the same `/upload` endpoint this test form already uses — no
backend changes needed.

## What's included

| File | Purpose |
|---|---|
| `detector.py` | Loads the trained YOLOv8 road-damage model and runs detection + acceptance decision |
| `models/road_damage_yolov8s.pt` | The trained weights (see "About the model" below) |
| `db.py` | SQLite storage for the verification queue |
| `letter_generator.py` | Builds the PDF letter to the authority (reportlab) |
| `app.py` | Flask app tying it all together |
| `templates/index.html` | Test upload form (stand-in for ESP32-CAM / citizen portal) |
| `templates/admin.html` | Admin verification queue (Approve / Reject) |

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python3 app.py
```

Then open **http://localhost:5000**.

## Camera & location in the test form

The upload form's camera capture and GPS auto-fill use browser APIs that
only work in a **secure context** (HTTPS, or `localhost`). Served over a
plain `http://<lan-ip>:5000`, both will appear broken even though the
code is correct — the page shows a notice explaining this. For phone
testing from a LAN or production, serve over TLS (Caddy/nginx + Let's
Encrypt) or a tunnel (ngrok / Cloudflare Tunnel). Nothing here changes
the `/upload` endpoint or the admin flow.

The model weights are already included in `models/` — nothing to
download, no API keys, works fully offline after `pip install`.

## About the model

`detector.py` now runs a **real trained road-damage model**, not a
placeholder. It's a YOLOv8-small checkpoint from the open-source
project [oracl4/RoadDamageDetection](https://github.com/oracl4/RoadDamageDetection),
trained on the Japan + India subsets of the CRDDC2022 / RDD2022 dataset.

It detects four classes:

| Class | Mapped severity |
|---|---|
| Potholes | Critical |
| Alligator Crack | Critical |
| Longitudinal Crack | Warning |
| Transverse Crack | Warning |

Reported accuracy (from the source project, on its own validation set):
mAP@0.5 = 0.55 overall (Alligator Crack 0.71, Potholes 0.52). This is a
real, working model — verified by us against its own validation images
before being wired in — but it's a research-grade model, not a
commercial-grade one. Test it against your own Indian road photos before
trusting it in production, and expect to eventually fine-tune it on more
local data (Phase 8 in the project roadmap).

**License note:** the underlying Ultralytics YOLOv8 library is AGPL-3.0
licensed (unless you hold an Ultralytics Enterprise license). AGPL has
network-use copyleft implications for a publicly-run web service — worth
a look before shipping this to production as-is.

### The decision layer (three tiers)

Per the project's design for the citizen-reporting track (Track B —
no admin verification in the long run), the model's raw confidence
alone isn't allowed to trigger a complaint. Three thresholds control
this in `detector.py`:

```bash
export ROAD_DAMAGE_CONF_THRESHOLD=0.35       # minimum confidence to name a specific damage type
export ROAD_DAMAGE_ACCEPT_THRESHOLD=0.60     # minimum confidence to mark a named type "reliable"
export ROAD_DAMAGE_FALLBACK_THRESHOLD=0.45   # combined-evidence bar for the "unclassified damage" fallback
```

- **Below `CONF_THRESHOLD` on every class, and below `FALLBACK_THRESHOLD`
  combined:** not surfaced at all — treated as a normal road.
- **A class between `CONF_THRESHOLD` and `ACCEPT_THRESHOLD`:** surfaced
  and queued, flagged **"AI: uncertain"** — a named type, shaky confidence.
- **A class at/above `ACCEPT_THRESHOLD`:** flagged **"AI: confident"**.
  This is the field (`ai_accepted` in the DB, `accepted` in
  `detector.py`'s output) you'd eventually use to let Track B skip admin
  review entirely for high-confidence detections.
- **No single class reaches `CONF_THRESHOLD`, but several different
  classes each fire weakly on the same photo:** the **"unclassified
  damage" fallback**. Shows up as `damage_class = "Unclassified damage"`,
  "AI: uncertain", severity defaulting to Warning (never auto-Critical,
  since the type is unknown).

**Why the fallback exists:** a photo of severe earthquake-caused
pavement rupture was reported as "no damage detected" — the model's raw
output had actually picked up on the crack (Alligator Crack 0.26,
Longitudinal Crack 0.16, Transverse Crack 0.11, several overlapping
boxes), just not confidently enough on any *one* class to clear 0.35.
Rather than sourcing a second model from another repo, the fallback
combines this model's own sub-threshold signals with a noisy-OR:
`1 - product(1 - confidence_i)` across every raw box. Multiple classes
weakly agreeing that "something's off" in the same photo is itself a
useful signal, even without a clean class win.

*A second model was considered and rejected for now:* almost every
open-source road-damage repo (this one included) trains on the same
handful of public datasets, none of which contain earthquake-style
rupture examples — so a second closed-set classifier from that same
ecosystem would likely share this exact blind spot, adding a second
framework/dependency and a result-merging problem without reliably
fixing the case that prompted this. If you outgrow this in-model
fallback, the more promising direction is a model trained on a
genuinely different task — subjective road *quality* rating, or
one-class anomaly detection trained only on normal roads — not another
closed-set damage-type classifier.

This was tested against the earthquake photo (combined evidence 0.67)
and ~30 sampled frames of ordinary dashcam driving footage (0.00–0.29,
mostly 0.00) — 0.45 cleanly separated the two in that small sample, but
that's a starting point, not a validated production threshold. Test it
against a real batch of your own road photos before trusting it.

### Swapping in a better model later

```bash
export ROAD_DAMAGE_MODEL_PATH=/path/to/new_model.pt
```

Then update `DAMAGE_SEVERITY` in `detector.py` if the new model's class
names differ from the four above.

## Testing the pipeline right now

1. Go to `http://localhost:5000`
2. Upload a road photo, pick a source (citizen/ESP32), optionally add
   GPS coordinates + a description
3. If a detection clears `CONF_THRESHOLD`, it's queued — check `/admin`
   for the "AI: confident" / "AI: uncertain" badge
4. Click **Approve & generate letter**
5. Download the generated PDF from the "Approved" section

## Wiring up the letter's "To" address

Set these environment variables (or edit the defaults directly in
`letter_generator.py`) before running:

```bash
export AUTHORITY_NAME="Kolkata Municipal Corporation — Roads Dept"
export AUTHORITY_ADDRESS="5, S.N. Banerjee Road, Kolkata 700013"
export SENDER_NAME="SmartSurround Monitoring System"
export SENDER_CONTACT="your-email@example.com"
```

Currently the letter is generated as a downloadable PDF on Approve.
To actually *send* it automatically, add an `smtplib` (or SendGrid/etc.)
call right after `letter_generator.generate_letter(...)` in
`app.py`'s `approve()` route.

## Next steps (per the project roadmap)

1. **Evaluate the model properly** — run it against a real batch of
   Indian road photos (not just this repo's Japan-heavy validation set)
   and measure false positives/negatives before trusting the accept
   threshold.
2. **Citizen complaint portal** — point a citizen-facing web form at
   this same `/upload` endpoint with `source=citizen`.
3. **GPS → authority mapping** — add reverse-geocoding + an
   administrative-area → authority-email lookup, kept separate from
   the ML model (as the project context doc specifies).
4. **Fine-tune on Indian data** — once you've collected enough local
   photos, fine-tune `road_damage_yolov8s.pt` rather than training from
   scratch.

## Part 2 (later): ESP32-CAM + NEO-8M

The firmware will:
1. Capture a frame periodically
2. Read GPS from the NEO-8M via `TinyGPSPlus`
3. `POST` the image + `lat`/`lon`/`source=esp32` to `http://<your-server>/upload`

No backend changes required — it's the same endpoint this test form uses.

## Track B — corroboration + authority-email (additive, 2026-09-16)
Track A (detect -> admin verify -> letter PDF) is UNTOUCHED. Track B layers on:

- **Corroboration**: citizen reports with lat/lon are bucketed into a fine
  ~111 m area cell (CORROBORATION_FINE_DECIMALS=3) + hazard_type + a rolling
  window (CORROBORATION_WINDOW_SECONDS, default 7200). The corroboration
  count is **always derived**: COUNT(DISTINCT client_ip) run on demand — no
  stored counter, no stored count column. A cluster flips to "corroborated"
  once its matured window clears CORROBORATION_THRESHOLD (default 3).
- **Authority routing**: reports also carry a coarse ~1.1 km area key
  (CORROBORATION_COARSE_DECIMALS=2). An uthorities row owns
  (area_key, hazard_type) and lifecycle **pending -> verified**, or
  **verified -> bounced -> pending** (a flip, never a new tier). Verified
  owners auto-receive the authority-email; otherwise the cluster routes to
  the admin authority-email queue.
- **Email driver**: EMAIL_DRIVER switch, `resend` by default (Resend REST/SDK,
  `onramp@resend.dev` shared sender — delivers to your own account email; a
  verified custom domain is required to email third parties). `smtplib`
  (stdlib) remains a supported driver. EMAIL_TEST_MODE defaults true -> NO
  mail is ever sent; the driver logs to the screen and returns ok:true,
  recipient overridden to EMAIL_TEST_RECIPIENT (default
  codexzero98@gmail.com — the seed verified authority). With EMAIL_TEST_MODE
  off + valid RESEND_API_KEY (live `.env`), it sends for real. Missing
  creds/bogus domains never crash: they route to the admin queue instead.
- **Admin protection**: every admin mutation route is gated by `@require_auth`
  — a 30-min httpOnly `ss_token` cookie issued at `POST /login/creds` (PIN
  verified against a salted SHA-256 digest, never stored in plaintext) plus
  the PIN in the request body. 5 failed PINs per IP -> 1-hour lockout (429);
  CORS is exact-origin only; `/upload` requires a token from `GET /upload/token`.
  Mirrored zero-dep client crypto lives in `static/utils.js`.
- **Admin UI**: `/admin` polls `GET /admin/api/clusters` (JSON) every 10 s and
  shows lifecycle/email badges (SENT + emailed_at, corroborated, emailed),
  authority registration + verify/bounce buttons, and a dev "send test
  notification email" button (`POST /admin/test-email`, auth-gated).
- New modules: corroboration.py, authority_routing.py, email_driver.py.
  db.py adds detections.client_ip / hazard_type / corroboration_area_key /
  authority_area_key + authorities + corroboration_clusters (additive).
- Env: see .env.example. python-dotenv is loaded in app.py when present, so a
  local .env just works; all vars optional with the safe defaults above.
- Docs: `docs/LOGIN_PROTECTION.md` (auth/rate-limit/upload-token compliance)
  and `docs/TRACKB_WORKLOG.md` (worklog + test plan).

## Help Desk API

The existing SQLite backend now stores SmartSurround user Help Desk tickets in a `complaints` table. The React dashboard can submit and read a user's tickets through `/api/complaints`. The existing admin PIN protection is reused for `/admin/api/complaints` and `/admin/complaints/<id>/update`, so administrators can review urgent tickets, change status (Open / In Progress / Resolved / Closed), and send a reply that the user sees in the dashboard.

For a separately hosted frontend, include its exact origin in `CORS_ORIGINS`.


## SmartSurround Admin Control Center

The React Admin Control Center is authenticated with the existing `ADMIN_PIN` + short-lived backend token. For real user GPS synchronization and server-side Firebase Realtime Database reads, configure:

- `FIREBASE_SERVICE_ACCOUNT_JSON` (preferred on Render)
- `FIREBASE_DATABASE_URL`

The normal Firebase user dashboard sends the browser's granted device GPS to `/api/user/location` using the user's Firebase ID token. The backend verifies that token with Firebase Admin before storing it. Admin-only location data is exposed through protected `/admin/api/*` endpoints.

Do not commit service-account JSON, `ADMIN_PIN`, or database files.


## Admin Control Center — completed workspace map

The current React admin side is organized as one protected control center instead of many unrelated admin pages:

- Dashboard
- Live Operations → Live Map / Live Users / Location History
- Users → Database / User Details / Activity
- Monitoring → Environment / Air Quality / Cameras / Sensors / Alerts
- Problem Desk → Inbox / Verification / Active / History
- Reports → Environment / Users / Incidents / GPS / Devices / Excel Export
- Communications → AI Drafts / Recipients / Sent History
- System → Thresholds / Admin Activity / Settings

The administrator signs in through the existing SmartSurround **Admin Login** flow using `ADMIN_PIN`. Normal user profiles do not expose an Admin Review navigation item.

For production hosting with a separately deployed React frontend, set `VITE_BACKEND_URL` in the frontend environment and set `CORS_ORIGINS` on the Flask service to the exact frontend origin.

For precise user GPS and Firebase sensor reads in the admin center, configure the Firebase Admin service-account variables on the backend:
`FIREBASE_SERVICE_ACCOUNT_JSON` (preferred) or `FIREBASE_SERVICE_ACCOUNT_PATH`, plus `FIREBASE_DATABASE_URL`.

Do not commit credentials, service-account JSON, Wi-Fi passwords, or local database files.
