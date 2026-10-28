# ============================================================
#  Ghost-Writer Pro — Batch redaction
#  ZIP in  ->  redacted ZIP + audit-ready PDF out
#
#  Pipeline per file:
#    1. Safe-read the ZIP member (no extraction to disk)
#    2. Redact (text -> mask_fn, image -> image_fn)
#    3. Optional Groq review of the *already redacted* text
#       (flags residual PII; original text never leaves the box)
#    4. Record SHA-256 of input/output + entity stats for the audit
#
#  The audit PDF intentionally contains NO original PII —
#  only entity types, counts, hashes, scores and reviewer notes.
# ============================================================

import io
import json
import re
import time
import uuid
import base64
import hashlib
import posixpath
import zipfile
from datetime import datetime, timezone
from collections import defaultdict

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)

# ── Limits (zip-bomb / abuse protection) ────────────────────
MAX_ZIP_BYTES        = 25 * 1024 * 1024
MAX_FILES            = 50
MAX_MEMBER_BYTES     = 10 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED = 100 * 1024 * 1024
MAX_REVIEW_CHARS     = 6000

TEXT_EXT  = {".txt", ".md", ".csv", ".log", ".json"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".webp"}


class BatchError(ValueError):
    """Raised for invalid / unsafe uploads."""


# ===========================================================
#  Helpers
# ===========================================================

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_name(raw: str) -> str | None:
    """Normalise a ZIP member name; reject traversal / absolute paths."""
    name = raw.replace("\\", "/")
    norm = posixpath.normpath(name)
    if norm.startswith("/") or norm.startswith("..") or "/../" in f"/{norm}/":
        return None
    if norm in (".", ""):
        return None
    # macOS resource-fork junk
    parts = norm.split("/")
    if parts[0] == "__MACOSX" or parts[-1].startswith("._") or parts[-1] == ".DS_Store":
        return None
    return norm


def _ext(name: str) -> str:
    return posixpath.splitext(name.lower())[1]


def _scrub_for_report(text: str) -> str:
    """Last-line defence: never let obvious PII reach the PDF."""
    text = re.sub(r"[\w.+-]+@[\w-]+\.[\w.]+", "[email]", text)
    text = re.sub(r"\b\d{6,}\b", "[number]", text)
    return text[:200]


# ===========================================================
#  Groq-assisted review
# ===========================================================

REVIEW_SYSTEM_PROMPT = (
    "You are a data-privacy compliance reviewer. You are given text that has "
    "ALREADY been redacted (placeholders look like <PERSON_0>, <IN_PAN_1>). "
    "Identify any personal data that still appears in clear text: names, "
    "emails, phone numbers, government IDs (Aadhaar, PAN, passport), bank or "
    "card numbers, addresses. Respond with ONLY a JSON object: "
    '{"verdict": "PASS" | "REVIEW", "leaks": [{"type": "...", "hint": "..."}]}. '
    "In 'hint' describe WHERE it is (e.g. 'line 3') — never repeat the "
    "sensitive value itself."
)


def groq_review(client, redacted_text: str, model: str = "llama-3.3-70b-versatile") -> dict:
    """
    Ask Groq to double-check a redacted document.
    Fails soft: any error -> verdict 'UNREVIEWED' so the batch still completes.
    """
    if client is None:
        return {"verdict": "UNREVIEWED", "leaks": [], "note": "Groq review disabled"}
    snippet = redacted_text[:MAX_REVIEW_CHARS]
    if not snippet.strip():
        return {"verdict": "PASS", "leaks": [], "note": "Empty document"}
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": REVIEW_SYSTEM_PROMPT},
                {"role": "user", "content": snippet},
            ],
            max_tokens=400,
            temperature=0,
        )
        raw = resp.choices[0].message.content.strip()
        raw = re.sub(r"^```(?:json)?|```$", "", raw, flags=re.MULTILINE).strip()
        data = json.loads(raw)
        verdict = "REVIEW" if data.get("leaks") else str(data.get("verdict", "PASS")).upper()
        leaks = [
            {"type": _scrub_for_report(str(l.get("type", "unknown"))),
             "hint": _scrub_for_report(str(l.get("hint", "")))}
            for l in data.get("leaks", [])[:10] if isinstance(l, dict)
        ]
        return {"verdict": "REVIEW" if leaks else ("PASS" if verdict == "PASS" else "REVIEW"),
                "leaks": leaks, "note": ""}
    except Exception as e:  # network, quota, bad JSON ...
        return {"verdict": "UNREVIEWED", "leaks": [],
                "note": _scrub_for_report(f"Review failed: {type(e).__name__}")}


# ===========================================================
#  Core batch runner
# ===========================================================

def run_batch(zip_bytes: bytes, username: str, mask_fn, image_fn, groq_client=None,
              image_support: bool = True) -> dict:
    """
    mask_fn(text, username)  -> (masked, mapping, stats, latency_ms, risk)
    image_fn(bytes, username)-> dict from redact_image()
    Returns a dict holding the redacted ZIP bytes, audit PDF bytes and a
    JSON-safe summary.
    """
    if len(zip_bytes) > MAX_ZIP_BYTES:
        raise BatchError(f"ZIP too large (max {MAX_ZIP_BYTES // (1024 * 1024)} MB)")
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        raise BatchError("Not a valid ZIP file")

    members = [i for i in zf.infolist() if not i.is_dir()]
    if not members:
        raise BatchError("ZIP is empty")
    if len(members) > MAX_FILES:
        raise BatchError(f"Too many files (max {MAX_FILES})")
    if sum(i.file_size for i in members) > MAX_TOTAL_UNCOMPRESSED:
        raise BatchError("Uncompressed size exceeds limit")

    batch_id   = uuid.uuid4().hex[:12]
    started    = time.time()
    out_buf    = io.BytesIO()
    files_out  = []                      # per-file audit rows
    entity_totals: dict = defaultdict(int)
    used_names: set = set()

    with zipfile.ZipFile(out_buf, "w", zipfile.ZIP_DEFLATED) as out_zip:
        for info in members:
            name = _safe_name(info.filename)
            row = {"file": name or "(rejected path)", "kind": "-", "status": "skipped",
                   "entities": 0, "stats": {}, "risk": 0, "latency_ms": 0.0,
                   "review": {"verdict": "-", "leaks": [], "note": ""},
                   "sha256_in": "", "sha256_out": "", "reason": ""}
            files_out.append(row)

            if name is None:
                row["reason"] = "Unsafe path rejected"
                continue
            ext = _ext(name)
            if info.file_size > MAX_MEMBER_BYTES:
                row["reason"] = "File exceeds 10 MB"
                continue
            if ext not in TEXT_EXT and ext not in IMAGE_EXT:
                row["reason"] = f"Unsupported type '{ext or 'none'}'"
                continue

            try:
                data = zf.read(info)
            except Exception as e:
                row["reason"] = f"Unreadable: {type(e).__name__}"
                continue
            row["sha256_in"] = _sha256(data)

            out_name = f"redacted/{name}"
            if out_name in used_names:
                out_name = f"redacted/{row['sha256_in'][:8]}_{posixpath.basename(name)}"
            try:
                if ext in TEXT_EXT:
                    row["kind"] = "text"
                    text = data.decode("utf-8", errors="replace")
                    masked, _mapping, stats, latency, risk = mask_fn(text, username)
                    # NOTE: mapping is dropped on purpose — batch output is
                    # irreversible, nothing containing PII is retained.
                    out_bytes = masked.encode("utf-8")
                    row["review"] = groq_review(groq_client, masked)
                else:
                    row["kind"] = "image"
                    if not image_support:
                        row["reason"] = "Image redaction unavailable (Pillow/pytesseract)"
                        continue
                    res = image_fn(data, username)
                    out_bytes = base64.b64decode(res["redacted_image"])
                    stats, latency, risk = res["stats"], res["latency_ms"], res.get("risk_score", 0)
                    out_name = posixpath.splitext(out_name)[0] + ".png"
                    row["review"] = {"verdict": "-", "leaks": [],
                                     "note": "Images are not LLM-reviewed"}
            except Exception as e:
                row["reason"] = _scrub_for_report(f"Processing error: {type(e).__name__}")
                continue

            used_names.add(out_name)
            out_zip.writestr(out_name, out_bytes)
            row.update(status="redacted", stats=dict(stats), entities=sum(stats.values()),
                       risk=int(risk), latency_ms=round(float(latency), 2),
                       sha256_out=_sha256(out_bytes), out_name=out_name)
            for k, v in stats.items():
                entity_totals[k] += v

    redacted_rows = [r for r in files_out if r["status"] == "redacted"]
    summary = {
        "batch_id": batch_id,
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "operator": username,
        "files_total": len(files_out),
        "files_redacted": len(redacted_rows),
        "files_skipped": len(files_out) - len(redacted_rows),
        "total_entities": sum(r["entities"] for r in redacted_rows),
        "avg_risk": round(sum(r["risk"] for r in redacted_rows) / len(redacted_rows), 1)
                    if redacted_rows else 0,
        "max_risk": max((r["risk"] for r in redacted_rows), default=0),
        "flagged_for_review": sum(1 for r in redacted_rows if r["review"]["verdict"] == "REVIEW"),
        "entity_totals": dict(entity_totals),
        "elapsed_ms": round((time.time() - started) * 1000, 1),
        "input_sha256": _sha256(zip_bytes),
        "groq_review": groq_client is not None,
    }
    pdf_bytes = build_audit_pdf(summary, files_out)
    return {"summary": summary, "files": files_out,
            "zip_bytes": out_buf.getvalue(), "pdf_bytes": pdf_bytes}


# ===========================================================
#  Audit PDF
# ===========================================================

def _verdict_colour(v: str):
    return {"PASS": colors.HexColor("#2E7D6B"), "REVIEW": colors.HexColor("#C0392B"),
            "UNREVIEWED": colors.HexColor("#B7791F")}.get(v, colors.HexColor("#555555"))


def build_audit_pdf(summary: dict, files: list) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"Ghost-Writer Pro Audit {summary['batch_id']}",
        author="Ghost-Writer Pro",
    )
    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Title"], fontSize=20, spaceAfter=4, alignment=0)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=12, spaceBefore=12, spaceAfter=6)
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("s", parent=body, fontSize=7.5, leading=9.5, textColor=colors.HexColor("#555555"))
    cell = ParagraphStyle("c", parent=body, fontSize=8, leading=10)
    hashst = ParagraphStyle("h", parent=body, fontName="Courier", fontSize=6, leading=8)

    grid = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#C9CED6")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F7FA")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ])

    s = []
    s.append(Paragraph("Redaction Audit Report", h1))
    s.append(Paragraph("Ghost-Writer Pro — Privacy-First AI Middleware", small))
    s.append(Spacer(1, 8))

    meta = [
        ["Batch ID", summary["batch_id"], "Generated", summary["created_utc"]],
        ["Operator", summary["operator"], "Processing time", f"{summary['elapsed_ms']} ms"],
        ["Input SHA-256", Paragraph(summary["input_sha256"], cell), "LLM review",
         "Groq llama-3.3-70b" if summary["groq_review"] else "Disabled"],
    ]
    t = Table(meta, colWidths=[28 * mm, 66 * mm, 30 * mm, 50 * mm])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8), ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#C9CED6")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    s.append(t)

    s.append(Paragraph("Summary", h2))
    kp = [["Files in archive", "Redacted", "Skipped", "Entities removed", "Avg / max risk", "Flagged"],
          [summary["files_total"], summary["files_redacted"], summary["files_skipped"],
           summary["total_entities"], f"{summary['avg_risk']} / {summary['max_risk']}",
           summary["flagged_for_review"]]]
    t = Table(kp, colWidths=[30 * mm] * 6)
    t.setStyle(grid)
    s.append(t)

    if summary["entity_totals"]:
        s.append(Paragraph("Entities removed by type", h2))
        rows = [["Entity type", "Count"]] + sorted(
            [[k, v] for k, v in summary["entity_totals"].items()], key=lambda r: -r[1])
        t = Table(rows, colWidths=[70 * mm, 30 * mm], repeatRows=1)
        t.setStyle(grid)
        s.append(t)

    s.append(Paragraph("Per-file results", h2))
    rows = [["File", "Type", "Entities", "Risk", "Latency", "Review", "Status"]]
    for f in files:
        status = "Redacted" if f["status"] == "redacted" else f"Skipped: {f['reason']}"
        rows.append([
            Paragraph(_scrub_for_report(f["file"]), cell), f["kind"], f["entities"], f["risk"],
            f"{f['latency_ms']} ms", f["review"]["verdict"], Paragraph(status, cell),
        ])
    t = Table(rows, colWidths=[52 * mm, 14 * mm, 16 * mm, 12 * mm, 20 * mm, 22 * mm, 44 * mm],
              repeatRows=1)
    st = TableStyle(grid.getCommands())
    for i, f in enumerate(files, start=1):
        st.add("TEXTCOLOR", (5, i), (5, i), _verdict_colour(f["review"]["verdict"]))
    t.setStyle(st)
    s.append(t)

    flagged = [f for f in files if f["review"]["leaks"]]
    notes = [f for f in files if f["review"]["note"] and f["review"]["verdict"] in ("UNREVIEWED",)]
    if flagged or notes:
        s.append(Paragraph("Reviewer findings", h2))
        for f in flagged:
            s.append(Paragraph(f"<b>{_scrub_for_report(f['file'])}</b> — possible residual PII:", body))
            for l in f["review"]["leaks"]:
                s.append(Paragraph(f"&bull; {l['type']} ({l['hint']})", body))
        for f in notes:
            s.append(Paragraph(f"<b>{_scrub_for_report(f['file'])}</b>: {f['review']['note']}", body))

    s.append(PageBreak())
    s.append(Paragraph("Integrity record (SHA-256)", h2))
    s.append(Paragraph("Hashes allow a reviewer to confirm the redacted files in the delivered "
                       "bundle are the ones this report describes.", small))
    s.append(Spacer(1, 4))
    rows = [["File", "Input hash", "Output hash"]]
    for f in files:
        if f["status"] == "redacted":
            rows.append([Paragraph(_scrub_for_report(f["file"]), cell),
                         Paragraph(f["sha256_in"], hashst),
                         Paragraph(f["sha256_out"], hashst)])
    t = Table(rows, colWidths=[34 * mm, 71 * mm, 71 * mm], repeatRows=1)
    t.setStyle(grid)
    s.append(t)

    s.append(Paragraph("Compliance sign-off", h2))
    s.append(Paragraph("This report contains no original personal data. Redaction is irreversible "
                       "for batch output: no re-identification mapping is stored.", body))
    s.append(Spacer(1, 14))
    sig = Table([["Reviewer name:", "", "Signature:", ""],
                 ["Date:", "", "Decision:", "[   ] Approved     [   ] Rejected"]],
                colWidths=[28 * mm, 55 * mm, 24 * mm, 70 * mm], rowHeights=[14 * mm, 14 * mm])
    sig.setStyle(TableStyle([
        ("LINEBELOW", (1, 0), (1, 0), 0.5, colors.black), ("LINEBELOW", (3, 0), (3, 0), 0.5, colors.black),
        ("LINEBELOW", (1, 1), (1, 1), 0.5, colors.black),
        ("FONTSIZE", (0, 0), (-1, -1), 9), ("VALIGN", (0, 0), (-1, -1), "BOTTOM"),
    ]))
    s.append(sig)

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#777777"))
        canvas.drawString(16 * mm, 10 * mm, f"Ghost-Writer Pro audit · batch {summary['batch_id']}")
        canvas.drawRightString(A4[0] - 16 * mm, 10 * mm, f"Page {d.page}")
        canvas.restoreState()

    doc.build(s, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
