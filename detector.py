"""
detector.py
------------
Thin wrapper around an Ultralytics YOLO model for road-damage detection.

MODEL
-----
Ships with models/road_damage_yolov8s.pt — a YOLOv8-small checkpoint from
the open-source project https://github.com/oracl4/RoadDamageDetection,
trained on the Japan + India subsets of the CRDDC2022 / RDD2022 dataset.
It detects four classes: Longitudinal Crack, Transverse Crack,
Alligator Crack, Potholes.

DECISION LAYER (three tiers, not two)
--------------------------------------
Per the project's Track B design, the ML model detects and a separate
layer decides how much to trust it. There are three outcomes now:

  1. "damaged"              - a specific class cleared ACCEPT_THRESHOLD.
                              Reliable enough to name a damage type.
  2. "uncertain"             - a specific class cleared CONFIDENCE_THRESHOLD
                              but not ACCEPT_THRESHOLD. Named, but shaky.
  3. "damaged_unclassified"  - NEW. No single class cleared even
                              CONFIDENCE_THRESHOLD, but several different
                              classes each fired weakly in the same image
                              (see FALLBACK below). The model can tell
                              something is off, just not what.
  4. "normal"                - none of the above.

FALLBACK FOR UNCLASSIFIABLE DAMAGE
------------------------------------
This exists because of a real failure case: a photo of severe
earthquake-caused pavement rupture was reported as "no damage detected."
Investigating showed the model's own raw output (before thresholding) had
picked up on the crack — Alligator Crack 0.26, Longitudinal Crack 0.16,
Transverse Crack 0.11, several overlapping boxes — but no single class
alone reached the 0.35 confidence floor, because the damage didn't
cleanly match any one of the four trained categories.

Rather than bolt on a second model from another repo, this combines the
SAME model's own sub-threshold signals: if multiple different damage
classes are each weakly firing in the same photo, that pattern itself is
evidence something abnormal is on the road, even without a clean
class win. We combine all raw per-box confidences with a noisy-OR:

    P(something is wrong) = 1 - product(1 - confidence_i)

Tested against the earthquake photo (0.67) vs. ~30 sampled frames of
ordinary dashcam driving footage (0.00-0.29, mostly 0.00) — a threshold
around 0.45 cleanly separates the two in this small sample. This is a
starting point, not a final answer: validate it against a real batch of
your own road photos before trusting it, the same as the other threshold.

WHY NOT JUST ADD A SECOND MODEL FROM ANOTHER REPO?
-----------------------------------------------------
It was considered and is still an option later, but it has a real
limitation worth knowing before reaching for it: almost every
open-source road-damage repo (including this one) is trained on the same
handful of public datasets (RDD2022/CRDDC2022 and close relatives). A
second closed-set damage classifier sourced from that same ecosystem
would very likely share this exact blind spot, since none of those
datasets contain earthquake-style rupture examples either — so it might
add maintenance cost (a second framework/dependency, another model to
version and re-verify, real thought needed on how to merge two models'
verdicts) without reliably catching the case that prompted this. A model
trained on a genuinely different task framing (e.g. subjective road
*quality* rating, or one-class anomaly detection trained only on normal
roads) would be more likely to add real independent signal — that's the
option worth pursuing if this in-model fallback proves insufficient.
"""

import os
try:
    from ultralytics import YOLO
except ImportError:  # Keep auth and Help Desk available in lightweight installs.
    YOLO = None

BASE_DIR = os.path.dirname(__file__)
DEFAULT_MODEL_PATH = os.path.join(BASE_DIR, "models", "road_damage_yolov8s.pt")

MODEL_PATH = os.environ.get("ROAD_DAMAGE_MODEL_PATH", DEFAULT_MODEL_PATH)
CONFIDENCE_THRESHOLD = float(os.environ.get("ROAD_DAMAGE_CONF_THRESHOLD", 0.35))
ACCEPT_THRESHOLD = float(os.environ.get("ROAD_DAMAGE_ACCEPT_THRESHOLD", 0.60))
FALLBACK_EVIDENCE_THRESHOLD = float(os.environ.get("ROAD_DAMAGE_FALLBACK_THRESHOLD", 0.45))

# The floor used when we pull raw model output — well below
# CONFIDENCE_THRESHOLD, purely so the fallback layer has weak signals to
# combine. Boxes below CONFIDENCE_THRESHOLD are never shown individually,
# only ever folded into the combined evidence score.
RAW_CONF_FLOOR = 0.05

# Map each real model class -> severity tier, matching the
# Normal / Warning / Critical alert system already used in SmartSurround.
# Potholes and alligator cracking are structural/safety-critical; the two
# linear crack types are early-stage damage worth flagging but less urgent.
# "Unclassified damage" (the fallback tier) defaults to Warning, never
# Critical — we don't know what it actually is yet, so it shouldn't
# auto-imply the most urgent tier. A human sets the real severity on review.
DAMAGE_SEVERITY = {
    "Potholes": "Critical",
    "Alligator Crack": "Critical",
    "Longitudinal Crack": "Warning",
    "Transverse Crack": "Warning",
    "Unclassified damage": "Warning",
}

DEFAULT_SEVERITY = "Warning"

_model = None


def get_model():
    global _model
    if _model is None:
        if YOLO is None:
            raise RuntimeError(
                "Road-damage detection requires the optional 'ultralytics' package. "
                "Install the full requirements.txt to enable image analysis."
            )
        _model = YOLO(MODEL_PATH)
    return _model


def severity_for(class_name: str) -> str:
    return DAMAGE_SEVERITY.get(class_name, DEFAULT_SEVERITY)


def _raw_predict(image_path: str):
    """
    Single inference pass at RAW_CONF_FLOOR. Returns every box the model
    produced, however weak, as {"class_name", "confidence", "box"}.
    Both run_detection() and analyze_road() build on this so we only ever
    run the model once per image.
    """
    model = get_model()
    results = model.predict(source=image_path, conf=RAW_CONF_FLOOR, verbose=False)
    raw = []
    for r in results:
        names = r.names
        for box in r.boxes:
            conf = float(box.conf[0])
            cls_id = int(box.cls[0])
            class_name = names.get(cls_id, str(cls_id))
            xyxy = [round(float(v), 1) for v in box.xyxy[0].tolist()]
            raw.append({"class_name": class_name, "confidence": conf, "box": xyxy})
    return raw


def _combined_evidence(raw_boxes) -> float:
    """Noisy-OR: combines every raw sub-threshold box into a single
    'something is abnormal here' score. See module docstring."""
    prob_normal = 1.0
    for d in raw_boxes:
        prob_normal *= (1 - d["confidence"])
    return 1 - prob_normal


def run_detection(image_path: str):
    """
    Returns the list of individually-named detections at/above
    CONFIDENCE_THRESHOLD:
    [{"class_name", "confidence", "severity", "box", "accepted"}, ...]
    Unchanged from before — this does NOT include the unclassified
    fallback tier, which only exists in analyze_road().
    """
    raw = _raw_predict(image_path)
    detections = []
    for d in raw:
        if d["confidence"] < CONFIDENCE_THRESHOLD:
            continue
        detections.append(
            {
                "class_name": d["class_name"],
                "confidence": round(d["confidence"], 3),
                "severity": severity_for(d["class_name"]),
                "box": d["box"],
                "accepted": d["confidence"] >= ACCEPT_THRESHOLD,
            }
        )
    return detections


def analyze_road(image_path: str):
    """
    Primary entry point, matching the project's proposed AI API contract
    (POST /analyze-road). Single top-level verdict per image, now with
    the three-tier decision layer described in the module docstring.
    """
    raw = _raw_predict(image_path)
    named = [d for d in raw if d["confidence"] >= CONFIDENCE_THRESHOLD]

    if named:
        top = max(named, key=lambda d: d["confidence"])
        accepted = top["confidence"] >= ACCEPT_THRESHOLD
        return {
            "road_condition": "damaged" if accepted else "uncertain",
            "damage_type": top["class_name"],
            "confidence": round(top["confidence"], 3),
            "accepted": accepted,
            "bbox": top["box"],
        }

    # No single class was confident enough on its own — check the
    # combined evidence across every weak raw box before giving up.
    evidence = _combined_evidence(raw)
    if evidence >= FALLBACK_EVIDENCE_THRESHOLD:
        best_guess = max(raw, key=lambda d: d["confidence"]) if raw else None
        return {
            "road_condition": "damaged_unclassified",
            "damage_type": None,
            "confidence": round(evidence, 3),
            "accepted": False,  # never auto-accept an unclassified case
            "bbox": best_guess["box"] if best_guess else None,
        }

    return {
        "road_condition": "normal",
        "damage_type": None,
        "confidence": None,
        "accepted": False,
        "bbox": None,
    }
