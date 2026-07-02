# ============================================================
#  Ghost-Writer Pro v3.0 — PII Masking & Secure AI Communication
#  + SQLite persistence (users, history, keywords)
#  + Image redaction (OCR → detect PII → pixelate bounding boxes)
#  mapping_storage stays IN-MEMORY intentionally — it contains
#  original PII and must never be persisted.
# ============================================================

import os
import re
import io
import base64
import bcrypt
import time
import random
import string
from datetime import datetime
from collections import defaultdict
from functools import wraps

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from faker import Faker

# ── SQLAlchemy ─────────────────────────────────────────────
from flask_sqlalchemy import SQLAlchemy

# ── Presidio ──────────────────────────────────────────────
from presidio_analyzer import (
    AnalyzerEngine,
    PatternRecognizer,
    RecognizerResult,
    Pattern,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine

# ── Groq ──────────────────────────────────────────────────
from groq import Groq

# ── Image redaction ───────────────────────────────────────
try:
    from PIL import Image, ImageDraw, ImageFilter
    import pytesseract
    IMAGE_SUPPORT = True
except ImportError:
    IMAGE_SUPPORT = False
    print("⚠️  Pillow/pytesseract not installed — image redaction disabled")

# ===========================================================
#  Flask + DB Setup
# ===========================================================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "ghost-writer-secret-change-me")

# SQLite stored in instance/ folder (same location as existing pii_shield.db)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///" + os.path.join(basedir, "instance", "pii_shield.db")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

os.makedirs(os.path.join(basedir, "instance"), exist_ok=True)

db = SQLAlchemy(app)
CORS(app, supports_credentials=True)

api_key = os.environ.get("GROQ_API_KEY")
if not api_key:
    raise ValueError("GROQ_API_KEY environment variable not set")
groq_client = Groq(api_key=api_key)

fake = Faker("en_IN")

# ===========================================================
#  SQLAlchemy Models
# ===========================================================

class User(db.Model):
    __tablename__ = "users"
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary, nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    histories = db.relationship("OperationHistory", backref="user", lazy=True, cascade="all, delete-orphan")
    keywords  = db.relationship("CustomKeyword",    backref="user", lazy=True, cascade="all, delete-orphan")


class OperationHistory(db.Model):
    __tablename__ = "operation_history"
    id               = db.Column(db.Integer, primary_key=True)
    user_id          = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    time             = db.Column(db.String(20))
    date             = db.Column(db.String(20))
    mode             = db.Column(db.String(60))
    entities         = db.Column(db.Integer, default=0)
    entity_breakdown = db.Column(db.Text, default="{}")   # JSON string
    preview          = db.Column(db.String(120))
    latency          = db.Column(db.Float, default=0)
    session_id       = db.Column(db.String(40))
    risk             = db.Column(db.Integer, default=0)
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)


class CustomKeyword(db.Model):
    __tablename__ = "custom_keywords"
    id      = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    keyword = db.Column(db.String(120), nullable=False)


# ===========================================================
#  Intentionally in-memory: mappings contain original PII
#  and must never be written to disk.
# ===========================================================
mapping_storage: dict = {}   # session_id → {placeholder: original}


# ===========================================================
#  Presidio Setup
# ===========================================================

pan_recognizer = PatternRecognizer(
    supported_entity="IN_PAN",
    patterns=[Pattern("IN_PAN_pattern", r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", 0.9)],
    context=["pan", "permanent account", "income tax"],
)
aadhaar_recognizer = PatternRecognizer(
    supported_entity="IN_AADHAAR",
    patterns=[Pattern("IN_AADHAAR_pattern", r"\b[2-9]{1}\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b", 0.85)],
    context=["aadhaar", "aadhar", "uid", "unique identification"],
)
mobile_recognizer = PatternRecognizer(
    supported_entity="IN_PHONE",
    patterns=[Pattern("IN_MOBILE_pattern", r"\b[6-9]\d{9}\b", 0.75)],
    context=["phone", "mobile", "call", "contact", "whatsapp"],
)
passport_recognizer = PatternRecognizer(
    supported_entity="IN_PASSPORT",
    patterns=[Pattern("IN_PASSPORT_pattern", r"\b[A-Z]{1}[0-9]{7}\b", 0.7)],
    context=["passport", "travel document"],
)
vehicle_recognizer = PatternRecognizer(
    supported_entity="IN_VEHICLE",
    patterns=[Pattern("IN_VEHICLE_pattern", r"\b[A-Z]{2}[0-9]{2}[A-Z]{2}[0-9]{4}\b", 0.7)],
)

try:
    nlp_config = {"nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}]}
    provider   = NlpEngineProvider(nlp_configuration=nlp_config)
    nlp_engine = provider.create_engine()
    analyzer   = AnalyzerEngine(nlp_engine=nlp_engine)
    SPACY_AVAILABLE = True
    print("✅ spaCy en_core_web_lg loaded")
except Exception as e:
    analyzer = AnalyzerEngine()
    SPACY_AVAILABLE = False
    print(f"⚠️  spaCy large model not found, using default. ({e})")

for rec in [pan_recognizer, aadhaar_recognizer, mobile_recognizer, passport_recognizer, vehicle_recognizer]:
    analyzer.registry.add_recognizer(rec)

anonymizer_engine = AnonymizerEngine()

# ===========================================================
#  Regex + Sensitivity
# ===========================================================

REGEX_PATTERNS = {
    "EMAIL":              r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "CREDIT_CARD":        r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
    "SSN":                r"\b\d{3}[-]?\d{2}[-]?\d{4}\b",
    "IP_ADDRESS":         r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "DATE_OF_BIRTH":      r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
    "PINCODE":            r"\b[1-9]\d{5}\b",
    "URL":                r"https?://[^\s]+",
    "BANK_ACCOUNT":       r"\b\d{9,18}\b",
    "IFSC":               r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
    "GSTIN":              r"\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[0-9]{1}[A-Z]{1}[0-9]{1}\b",
    "DL_NUMBER":          r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11}\b",
    "UPI_ID":             r"\b[\w\.\-]+@[\w\-]+\b",
    "BANK_ACCOUNT_INDIA": r"\b[0-9]{9,18}\b",
}

SENSITIVITY = {
    "CREDIT_CARD": 30, "SSN": 30, "IN_AADHAAR": 28, "IN_PAN": 22,
    "IN_PASSPORT": 20, "PASSPORT": 20, "EMAIL": 12, "IN_PHONE": 15,
    "PHONE": 15, "PERSON": 14, "NAME": 14, "BANK_ACCOUNT": 18,
    "IP_ADDRESS": 5, "DATE_OF_BIRTH": 10, "PINCODE": 5, "IN_VEHICLE": 5,
    "URL": 4, "LOCATION": 8, "PROTECTED": 10,
}

# ===========================================================
#  Helpers
# ===========================================================

def compute_risk(stats: dict) -> int:
    total = 0
    for entity, count in stats.items():
        total += SENSITIVITY.get(entity, 5) * min(count, 3)
    return min(100, total)


def detect_names_regex(text: str) -> list:
    name_patterns = [
        r"\b(?:Mr|Mrs|Ms|Dr|Prof|Er|Shri|Smt)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b",
        r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b",
        r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b",
    ]
    names, seen = [], set()
    for pat in name_patterns:
        for m in re.finditer(pat, text):
            orig = m.group()
            if orig not in seen:
                seen.add(orig)
                names.append({"original": orig, "start": m.start(), "end": m.end()})
    return names


def _apply_substitutions(text: str, substitutions: list) -> tuple:
    mapping = {}
    subs = sorted(substitutions, key=lambda x: x[0], reverse=True)
    for start, end, placeholder, original in subs:
        mapping[placeholder] = original
        text = text[:start] + placeholder + text[end:]
    return text, mapping


def _get_user_keywords(username: str) -> list:
    user = User.query.filter_by(username=username).first()
    if not user:
        return []
    return [kw.keyword for kw in user.keywords]


def _save_history(username, mode, stats, latency, preview, session_id, risk=0):
    import json
    user = User.query.filter_by(username=username).first()
    if not user:
        return
    record = OperationHistory(
        user_id          = user.id,
        time             = datetime.now().strftime("%H:%M:%S"),
        date             = datetime.now().strftime("%d %b %Y"),
        mode             = mode,
        entities         = sum(stats.values()),
        entity_breakdown = json.dumps(stats),
        preview          = preview[:60],
        latency          = latency,
        session_id       = session_id,
        risk             = risk,
    )
    db.session.add(record)
    # Keep last 20 per user
    all_records = (OperationHistory.query
                   .filter_by(user_id=user.id)
                   .order_by(OperationHistory.created_at.asc())
                   .all())
    if len(all_records) > 20:
        for old in all_records[:-20]:
            db.session.delete(old)
    db.session.commit()


# ===========================================================
#  Core Masking Engine 1 — Basic
# ===========================================================

def mask_text_basic(text: str, username: str) -> tuple:
    start_time = time.time()
    stats: dict = defaultdict(int)
    substitutions = []
    used_spans: list = []

    def overlaps(s, e):
        return any(s < ue and e > us for us, ue in used_spans)

    def register(start, end, entity_type, original):
        if overlaps(start, end):
            return
        used_spans.append((start, end))
        counter = stats[entity_type]
        placeholder = f"<{entity_type}_{counter}>"
        stats[entity_type] += 1
        substitutions.append((start, end, placeholder, original))

    try:
        presidio_results = analyzer.analyze(
            text=text, language="en",
            entities=[
                "PERSON", "LOCATION", "ORGANIZATION",
                "EMAIL_ADDRESS", "PHONE_NUMBER",
                "CREDIT_CARD", "US_SSN", "IP_ADDRESS", "DATE_TIME",
                "URL", "IBAN_CODE", "MEDICAL_LICENSE",
                "IN_PAN", "IN_AADHAAR", "IN_PHONE", "IN_PASSPORT", "IN_VEHICLE",
            ],
        )
        for result in presidio_results:
            register(result.start, result.end, result.entity_type, text[result.start:result.end])
    except Exception as e:
        print(f"Presidio error: {e}")

    for entity, pattern in REGEX_PATTERNS.items():
        for m in re.finditer(pattern, text):
            register(m.start(), m.end(), entity, m.group())

    for name_info in detect_names_regex(text):
        register(name_info["start"], name_info["end"], "NAME", name_info["original"])

    for keyword in _get_user_keywords(username):
        for m in re.finditer(r"\b" + re.escape(keyword) + r"\b", text, re.IGNORECASE):
            register(m.start(), m.end(), "PROTECTED", m.group())

    masked_text, mapping = _apply_substitutions(text, substitutions)
    latency = round((time.time() - start_time) * 1000, 2)
    risk_score = compute_risk(dict(stats))
    return masked_text, mapping, dict(stats), latency, risk_score


# ===========================================================
#  Core Masking Engine 2 — Differential Privacy
# ===========================================================

def add_epsilon_noise(text: str, epsilon: float) -> str:
    if epsilon <= 0:
        return text
    words = text.split()
    noise_prob = max(0.05, min(0.6, 1.0 / (epsilon + 0.5)))
    noisy = []
    for word in words:
        if random.random() < noise_prob and len(word) > 2:
            choice = random.choice(["swap", "insert", "delete"])
            chars = list(word)
            if choice == "swap" and len(chars) >= 2:
                i = random.randint(0, len(chars) - 2)
                chars[i], chars[i + 1] = chars[i + 1], chars[i]
                word = "".join(chars)
            elif choice == "insert":
                pos = random.randint(0, len(word))
                word = word[:pos] + random.choice(string.ascii_lowercase) + word[pos:]
            elif choice == "delete" and len(word) > 3:
                pos = random.randint(0, len(word) - 1)
                word = word[:pos] + word[pos + 1:]
        noisy.append(word)
    return " ".join(noisy)


def _fake_for(entity: str) -> str:
    entity = entity.upper()
    if entity in ("PERSON", "NAME"):           return fake.name()
    if entity in ("EMAIL_ADDRESS", "EMAIL"):   return fake.email()
    if entity in ("IN_PHONE", "PHONE_NUMBER", "PHONE"):
        digits = re.sub(r"\D", "", fake.phone_number())[:10].ljust(10, "0")
        return digits
    if entity == "IN_AADHAAR":
        return f"{random.randint(2000,9999)} {random.randint(1000,9999)} {random.randint(1000,9999)}"
    if entity == "IN_PAN":
        return "".join(random.choices(string.ascii_uppercase, k=5)) + \
               "".join(random.choices(string.digits, k=4)) + \
               random.choice(string.ascii_uppercase)
    if entity in ("IN_PASSPORT", "PASSPORT"):
        return random.choice(string.ascii_uppercase) + "".join(random.choices(string.digits, k=7))
    if entity == "IN_VEHICLE":
        return ("".join(random.choices(string.ascii_uppercase, k=2)) +
                str(random.randint(10, 99)) +
                "".join(random.choices(string.ascii_uppercase, k=2)) +
                str(random.randint(1000, 9999)))
    if entity == "CREDIT_CARD":   return fake.credit_card_number()
    if entity in ("US_SSN","SSN"):return fake.ssn()
    if entity == "IP_ADDRESS":    return fake.ipv4()
    if entity in ("DATE_TIME","DATE_OF_BIRTH"): return fake.date_of_birth().strftime("%d/%m/%Y")
    if entity == "PINCODE":       return str(random.randint(100000, 999999))
    if entity == "BANK_ACCOUNT":  return "".join(random.choices(string.digits, k=12))
    if entity == "LOCATION":      return fake.city()
    if entity == "ORGANIZATION":  return fake.company()
    if entity == "URL":           return fake.url()
    if entity == "PROTECTED":     return fake.word()
    return f"[REDACTED_{entity}]"


def mask_text_differential(text: str, username: str, epsilon: float = 1.0) -> tuple:
    start_time = time.time()
    stats: dict = defaultdict(int)
    substitutions = []
    used_spans: list = []

    def overlaps(s, e):
        return any(s < ue and e > us for us, ue in used_spans)

    def register(start, end, entity_type, original):
        if overlaps(start, end):
            return
        used_spans.append((start, end))
        fake_val = _fake_for(entity_type)
        stats[entity_type] += 1
        substitutions.append((start, end, fake_val, original))

    try:
        presidio_results = analyzer.analyze(
            text=text, language="en",
            entities=[
                "PERSON", "LOCATION", "ORGANIZATION",
                "EMAIL_ADDRESS", "PHONE_NUMBER",
                "CREDIT_CARD", "US_SSN", "IP_ADDRESS", "DATE_TIME",
                "URL", "IN_PAN", "IN_AADHAAR", "IN_PHONE", "IN_PASSPORT", "IN_VEHICLE",
            ],
        )
        for result in presidio_results:
            register(result.start, result.end, result.entity_type, text[result.start:result.end])
    except Exception as e:
        print(f"Presidio diff error: {e}")

    for entity, pattern in REGEX_PATTERNS.items():
        for m in re.finditer(pattern, text):
            register(m.start(), m.end(), entity, m.group())

    for name_info in detect_names_regex(text):
        register(name_info["start"], name_info["end"], "PERSON", name_info["original"])

    for keyword in _get_user_keywords(username):
        for m in re.finditer(r"\b" + re.escape(keyword) + r"\b", text, re.IGNORECASE):
            register(m.start(), m.end(), "PROTECTED", m.group())

    faked_text, mapping = _apply_substitutions(text, substitutions)
    noisy_text = add_epsilon_noise(faked_text, epsilon)
    latency = round((time.time() - start_time) * 1000, 2)
    risk_score = compute_risk(dict(stats))
    return faked_text, noisy_text, mapping, dict(stats), latency, risk_score


# ===========================================================
#  Re-hydration
# ===========================================================

def decrypt_text(masked_text: str, mapping: dict) -> str:
    result = masked_text
    for placeholder, original in sorted(mapping.items(), key=lambda x: len(x[0]), reverse=True):
        result = result.replace(placeholder, original)
    return result


# ===========================================================
#  Image Redaction Engine
#  Pipeline: decode → OCR with bounding boxes → run PII
#  detection on each word/line → draw black rectangles over
#  PII regions → return redacted image as base64 PNG
# ===========================================================

def redact_image(image_bytes: bytes, username: str) -> dict:
    """
    Redact PII from an image.
    Returns dict with: redacted_image (base64 PNG), entities_found (list),
    stats (dict), total_entities (int), latency_ms (float)
    """
    if not IMAGE_SUPPORT:
        raise RuntimeError("Image redaction requires Pillow and pytesseract. "
                           "Install with: pip install Pillow pytesseract")

    start_time = time.time()

    # Open image
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    draw = ImageDraw.Draw(img)

    # OCR with bounding box data
    # pytesseract.image_to_data returns TSV with columns:
    # level, page_num, block_num, par_num, line_num, word_num,
    # left, top, width, height, conf, text
    ocr_data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)

    words        = ocr_data["text"]
    lefts        = ocr_data["left"]
    tops         = ocr_data["top"]
    widths       = ocr_data["width"]
    heights      = ocr_data["height"]
    confidences  = ocr_data["conf"]

    # Build full text for Presidio analysis (with word positions tracked)
    word_positions = []  # (char_start, char_end, left, top, width, height)
    full_text = ""
    for i, (word, conf) in enumerate(zip(words, confidences)):
        if not word.strip() or int(conf) < 30:   # skip low-confidence / empty
            continue
        char_start = len(full_text)
        full_text += word + " "
        char_end = len(full_text) - 1
        word_positions.append((char_start, char_end, lefts[i], tops[i], widths[i], heights[i]))

    if not full_text.strip():
        # No text found — return original image unchanged
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return {
            "redacted_image": base64.b64encode(buf.getvalue()).decode(),
            "entities_found": [],
            "stats": {},
            "total_entities": 0,
            "latency_ms": round((time.time() - start_time) * 1000, 2),
            "message": "No readable text found in image",
        }

    # Run the same masking logic to find which spans are PII
    _, _, stats, _, _ = mask_text_basic(full_text, username)

    # Re-run Presidio to get actual spans (mask_text_basic doesn't return spans)
    pii_spans = []   # list of (char_start, char_end, entity_type)

    try:
        presidio_results = analyzer.analyze(
            text=full_text, language="en",
            entities=[
                "PERSON", "LOCATION", "ORGANIZATION",
                "EMAIL_ADDRESS", "PHONE_NUMBER",
                "CREDIT_CARD", "US_SSN", "IP_ADDRESS", "DATE_TIME",
                "URL", "IN_PAN", "IN_AADHAAR", "IN_PHONE", "IN_PASSPORT", "IN_VEHICLE",
            ],
        )
        for r in presidio_results:
            pii_spans.append((r.start, r.end, r.entity_type, r.score))
    except Exception as e:
        print(f"Presidio image error: {e}")

    # Regex patterns
    for entity, pattern in REGEX_PATTERNS.items():
        for m in re.finditer(pattern, full_text):
            pii_spans.append((m.start(), m.end(), entity, 0.8))

    # Name regex
    for name_info in detect_names_regex(full_text):
        pii_spans.append((name_info["start"], name_info["end"], "NAME", 0.7))

    # Custom keywords
    for keyword in _get_user_keywords(username):
        for m in re.finditer(r"\b" + re.escape(keyword) + r"\b", full_text, re.IGNORECASE):
            pii_spans.append((m.start(), m.end(), "PROTECTED", 0.9))

    # For each PII span, find which word bounding boxes it overlaps
    # and draw a solid black rectangle over them on the image
    entities_found = []
    redacted_count = defaultdict(int)
    img_width, img_height = img.size

    for span_start, span_end, entity_type, score in pii_spans:
        boxes_to_redact = []
        for (ws, we, left, top, width, height) in word_positions:
            # Word overlaps with span?
            if ws < span_end and we > span_start:
                boxes_to_redact.append((left, top, width, height))

        if not boxes_to_redact:
            continue

        # Merge boxes into one bounding box with small padding
        pad = 3
        x0 = max(0, min(b[0] for b in boxes_to_redact) - pad)
        y0 = max(0, min(b[1] for b in boxes_to_redact) - pad)
        x1 = min(img_width,  max(b[0] + b[2] for b in boxes_to_redact) + pad)
        y1 = min(img_height, max(b[1] + b[3] for b in boxes_to_redact) + pad)

        # Draw filled black rectangle (redaction bar)
        draw.rectangle([x0, y0, x1, y1], fill=(0, 0, 0))

        redacted_count[entity_type] += 1
        entities_found.append({
            "entity":  entity_type,
            "text":    full_text[span_start:span_end].strip(),
            "score":   round(score, 3),
            "bbox":    [x0, y0, x1, y1],
        })

    # Encode redacted image as base64 PNG
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    redacted_b64 = base64.b64encode(buf.getvalue()).decode()

    latency = round((time.time() - start_time) * 1000, 2)
    return {
        "redacted_image":  redacted_b64,
        "entities_found":  entities_found,
        "stats":           dict(redacted_count),
        "total_entities":  sum(redacted_count.values()),
        "latency_ms":      latency,
        "risk_score":      compute_risk(dict(redacted_count)),
    }


# ===========================================================
#  Auth Decorator
# ===========================================================

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated


# ===========================================================
#  Page Routes
# ===========================================================

@app.route("/")
def index_page():
    if "user_id" in session:
        return render_template("index.html")
    return redirect(url_for("login_page"))

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/register")
def register_page():
    return render_template("register.html")


# ===========================================================
#  Auth API
# ===========================================================

@app.route("/api/register", methods=["POST"])
def api_register():
    try:
        data     = request.get_json()
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()
        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400
        if len(username) < 3:
            return jsonify({"error": "Username must be at least 3 characters"}), 400
        if len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters"}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({"error": "Username already exists"}), 400
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        user = User(username=username, password_hash=hashed)
        db.session.add(user)
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@app.route("/api/login", methods=["POST"])
def api_login():
    try:
        data     = request.get_json()
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401
        if bcrypt.checkpw(password.encode(), user.password_hash):
            session["user_id"] = username
            return jsonify({"success": True, "username": username})
        return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"success": True})


@app.route("/api/check", methods=["GET"])
def api_check():
    if "user_id" in session:
        return jsonify({"authenticated": True, "username": session["user_id"]})
    return jsonify({"authenticated": False})


# ===========================================================
#  PII Masking APIs
# ===========================================================

@app.route("/api/mask", methods=["POST"])
@login_required
def api_mask():
    try:
        data = request.get_json()
        text = data.get("text", "").strip()
        if not text:
            return jsonify({"error": "No text provided"}), 400
        username = session["user_id"]
        masked, mapping, stats, latency, risk_score = mask_text_basic(text, username)
        session_id = datetime.now().strftime("%Y%m%d%H%M%S%f")
        mapping_storage[session_id] = mapping
        _save_history(username, "Basic Mask", stats, latency, masked, session_id, risk_score)
        return jsonify({
            "masked": masked, "stats": stats,
            "total_entities": sum(stats.values()),
            "latency": latency, "session_id": session_id, "risk_score": risk_score,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/differential", methods=["POST"])
@login_required
def api_differential():
    try:
        data    = request.get_json()
        text    = data.get("text", "").strip()
        epsilon = float(data.get("epsilon", 1.0))
        if not text:
            return jsonify({"error": "No text provided"}), 400
        if epsilon <= 0:
            return jsonify({"error": "Epsilon must be greater than 0"}), 400
        username = session["user_id"]
        faked, noisy, mapping, stats, latency, risk_score = mask_text_differential(text, username, epsilon)
        session_id = datetime.now().strftime("%Y%m%d%H%M%S%f")
        mapping_storage[session_id] = mapping
        _save_history(username, f"Differential (ε={epsilon})", stats, latency, noisy, session_id, risk_score)
        return jsonify({
            "faked": faked, "noisy": noisy, "stats": stats,
            "total_entities": sum(stats.values()),
            "latency": latency, "epsilon": epsilon,
            "session_id": session_id, "risk_score": risk_score,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/decrypt", methods=["POST"])
@login_required
def api_decrypt():
    try:
        data        = request.get_json()
        masked_text = data.get("masked_text", "")
        session_id  = data.get("session_id", "")
        if not session_id or session_id not in mapping_storage:
            return jsonify({"error": "Session ID not found or expired"}), 404
        decrypted = decrypt_text(masked_text, mapping_storage[session_id])
        return jsonify({"decrypted": decrypted, "success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ===========================================================
#  Image Redaction API
# ===========================================================

@app.route("/api/redact-image", methods=["POST"])
@login_required
def api_redact_image():
    """
    Accept an uploaded image (PNG/JPG/JPEG), run OCR-based PII detection,
    draw black redaction bars over detected entities, return redacted PNG
    as base64 along with entity stats.
    """
    try:
        if not IMAGE_SUPPORT:
            return jsonify({
                "error": "Image redaction not available. Install: pip install Pillow pytesseract"
            }), 503

        if "image" not in request.files:
            return jsonify({"error": "No image file provided"}), 400

        file = request.files["image"]
        filename = file.filename.lower()
        if not any(filename.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".webp"]):
            return jsonify({"error": "Unsupported format. Use PNG, JPG, JPEG, BMP, TIFF, or WEBP"}), 400

        image_bytes = file.read()
        if len(image_bytes) > 10 * 1024 * 1024:   # 10 MB limit
            return jsonify({"error": "Image too large. Maximum size is 10MB"}), 400

        username = session["user_id"]
        result   = redact_image(image_bytes, username)

        # Log to history (no PII — only metadata)
        session_id = datetime.now().strftime("%Y%m%d%H%M%S%f")
        _save_history(
            username, "Image Redaction",
            result["stats"], result["latency_ms"],
            f"Image: {filename} ({result['total_entities']} entities)",
            session_id, result.get("risk_score", 0)
        )

        return jsonify({
            "redacted_image": result["redacted_image"],
            "entities_found": result["entities_found"],
            "stats":          result["stats"],
            "total_entities": result["total_entities"],
            "latency_ms":     result["latency_ms"],
            "risk_score":     result.get("risk_score", 0),
            "session_id":     session_id,
            "message":        result.get("message", ""),
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ===========================================================
#  Secure AI Chat
# ===========================================================

@app.route("/api/secure-chat", methods=["POST"])
@login_required
def api_secure_chat():
    try:
        data      = request.get_json()
        user_text = data.get("text", "").strip()
        username  = session["user_id"]
        if not user_text:
            return jsonify({"error": "No message provided"}), 400

        groq_api_key = os.environ.get("GROQ_API_KEY")
        if not groq_api_key:
            return jsonify({"error": "GROQ_API_KEY not set"}), 500

        masked_prompt, mapping, stats, latency, risk_score = mask_text_basic(user_text, username)

        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": masked_prompt}],
            max_tokens=1000,
        )
        ai_raw      = response.choices[0].message.content
        final_output = decrypt_text(ai_raw, mapping)

        session_id = datetime.now().strftime("%Y%m%d%H%M%S%f")
        mapping_storage[session_id] = mapping
        _save_history(username, "Secure AI Chat", stats, latency, final_output, session_id, risk_score)

        return jsonify({
            "original_masked": masked_prompt,
            "response":        final_output,
            "stats":           stats,
            "total_entities":  sum(stats.values()),
            "latency":         latency,
            "session_id":      session_id,
            "risk_score":      risk_score,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ===========================================================
#  Analyze API
# ===========================================================

@app.route("/api/analyze", methods=["POST"])
@login_required
def api_analyze():
    try:
        data = request.get_json()
        text = data.get("text", "").strip()
        if not text:
            return jsonify({"error": "No text provided"}), 400
        results  = analyzer.analyze(text=text, language="en")
        entities = [{"entity": r.entity_type, "start": r.start, "end": r.end,
                     "score": round(r.score, 3), "original": text[r.start:r.end]}
                    for r in results]
        entities.sort(key=lambda x: x["score"], reverse=True)
        return jsonify({"entities": entities, "count": len(entities)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ===========================================================
#  Custom Keyword APIs
# ===========================================================

@app.route("/api/add_keyword", methods=["POST"])
@login_required
def api_add_keyword():
    try:
        data     = request.get_json()
        keyword  = data.get("keyword", "").strip().lower()
        username = session["user_id"]
        if not keyword or len(keyword) < 2:
            return jsonify({"error": "Keyword must be at least 2 characters"}), 400
        user = User.query.filter_by(username=username).first()
        existing = [kw.keyword for kw in user.keywords]
        if keyword in existing:
            return jsonify({"error": "Keyword already exists"}), 400
        kw = CustomKeyword(user_id=user.id, keyword=keyword)
        db.session.add(kw)
        db.session.commit()
        return jsonify({"success": True, "keywords": [kw.keyword for kw in user.keywords]})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@app.route("/api/remove_keyword", methods=["POST"])
@login_required
def api_remove_keyword():
    try:
        data     = request.get_json()
        keyword  = data.get("keyword", "").strip().lower()
        username = session["user_id"]
        user = User.query.filter_by(username=username).first()
        kw   = CustomKeyword.query.filter_by(user_id=user.id, keyword=keyword).first()
        if not kw:
            return jsonify({"error": "Keyword not found"}), 400
        db.session.delete(kw)
        db.session.commit()
        return jsonify({"success": True, "keywords": [k.keyword for k in user.keywords]})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@app.route("/api/get_keywords", methods=["GET"])
@login_required
def api_get_keywords():
    username = session["user_id"]
    user = User.query.filter_by(username=username).first()
    return jsonify({"keywords": [kw.keyword for kw in user.keywords] if user else []})


# ===========================================================
#  History & Analytics APIs
# ===========================================================

@app.route("/api/history", methods=["GET"])
@login_required
def api_history():
    import json
    username = session["user_id"]
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"history": []})
    records = (OperationHistory.query
               .filter_by(user_id=user.id)
               .order_by(OperationHistory.created_at.asc())
               .all())
    history = [{
        "time":             r.time,
        "date":             r.date,
        "mode":             r.mode,
        "entities":         r.entities,
        "entity_breakdown": json.loads(r.entity_breakdown or "{}"),
        "preview":          r.preview,
        "latency":          r.latency,
        "session_id":       r.session_id,
        "risk":             r.risk,
    } for r in records]
    return jsonify({"history": history})


@app.route("/api/history/clear", methods=["POST"])
@login_required
def api_history_clear():
    username = session["user_id"]
    user = User.query.filter_by(username=username).first()
    if user:
        OperationHistory.query.filter_by(user_id=user.id).delete()
        db.session.commit()
    return jsonify({"success": True})


@app.route("/api/analytics", methods=["GET"])
@login_required
def api_analytics():
    import json
    username = session["user_id"]
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"total_operations": 0, "average_latency_ms": 0,
                        "total_entities_masked": 0, "average_risk_score": 0,
                        "mode_breakdown": {}, "entity_type_totals": {}})

    records   = OperationHistory.query.filter_by(user_id=user.id).all()
    total_ops = len(records)
    if total_ops == 0:
        return jsonify({"total_operations": 0, "average_latency_ms": 0,
                        "total_entities_masked": 0, "average_risk_score": 0,
                        "mode_breakdown": {}, "entity_type_totals": {}})

    avg_latency    = round(sum(r.latency or 0 for r in records) / total_ops, 2)
    total_entities = sum(r.entities or 0 for r in records)
    avg_risk       = round(sum(r.risk or 0 for r in records) / total_ops, 1)

    mode_breakdown: dict = defaultdict(int)
    entity_totals: dict  = defaultdict(int)
    for r in records:
        mode_key = (r.mode or "Unknown").split("(")[0].strip()
        mode_breakdown[mode_key] += 1
        for etype, count in json.loads(r.entity_breakdown or "{}").items():
            entity_totals[etype] += count

    return jsonify({
        "total_operations":      total_ops,
        "average_latency_ms":    avg_latency,
        "total_entities_masked": total_entities,
        "average_risk_score":    avg_risk,
        "mode_breakdown":        dict(mode_breakdown),
        "entity_type_totals":    dict(entity_totals),
    })


# ===========================================================
#  File Upload API (txt only — document redaction future work)
# ===========================================================

@app.route("/api/upload", methods=["POST"])
@login_required
def api_upload():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400
        file     = request.files["file"]
        filename = file.filename.lower()
        if filename.endswith(".txt"):
            text = file.read().decode("utf-8")
        else:
            return jsonify({"error": "Only .txt files are supported currently"}), 400
        return jsonify({"text": text, "filename": filename, "length": len(text)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ===========================================================
#  Health Check
# ===========================================================

@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({
        "status":          "ok",
        "spacy_lg_loaded": SPACY_AVAILABLE,
        "image_support":   IMAGE_SUPPORT,
        "version":         "3.0.0",
        "storage":         "SQLite (persistent)",
        "mapping_storage": "In-memory (privacy by design)",
    })


# ===========================================================
#  Entry Point
# ===========================================================

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        print("✅ SQLite tables created/verified")

    print("=" * 62)
    print("  👻  GHOST-WRITER PRO  v3.0 — Secure AI Communication")
    print("=" * 62)
    print(f"  spaCy en_core_web_lg : {'✅ Loaded' if SPACY_AVAILABLE else '⚠️  Fallback'}")
    print(f"  Image Redaction      : {'✅ Active (Pillow + pytesseract)' if IMAGE_SUPPORT else '⚠️  Disabled (install Pillow + pytesseract)'}")
    print("  Presidio             : ✅ Active (PAN, Aadhaar, Passport, Vehicle)")
    print("  Differential Privacy : ✅ Faker + ε-noise")
    print("  Secure AI Chat       : ✅ Groq Llama 3.3 70B via masked proxy")
    print("  Custom Keywords      : ✅ Per-user protected word vault")
    print("  Storage              : ✅ SQLite — users, history, keywords persisted")
    print("  PII Mappings         : 🔒 In-memory only (privacy by design)")
    print("=" * 62)
    print("  🌐  Open → http://127.0.0.1:5000")
    print("=" * 62)
    app.run(debug=True, port=5000)
