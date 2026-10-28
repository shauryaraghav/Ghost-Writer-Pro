# 👻 Ghost-Writer Pro — Privacy-First AI Middleware

A PII-redaction proxy that scrubs sensitive data from **text and images** before anything reaches an LLM,
then (optionally) re-hydrates the model's answer for the user.

**Stack:** Python · Flask · React · SQLite (SQLAlchemy) · spaCy · Presidio · Tesseract OCR · Groq · ReportLab

## Features
- **20-endpoint REST API** (auth, masking, differential privacy, image redaction, secure chat, keywords,
  history, analytics, batch, health) backed by SQLite.
- **React dashboard** (`/react-dashboard`) — risk scores, entity breakdown and redaction history, auto-refreshing every 5 s.
- **Hybrid detection pipeline** — spaCy `en_core_web_lg` NER + Presidio recognizers + regex, covering ~25 entity types,
  including custom India-specific recognizers: PAN, Aadhaar, mobile, passport, vehicle, IFSC, GSTIN, driving licence, UPI, PIN code.
- **OCR image redaction** — Tesseract word boxes → PII spans → solid redaction bars.
- **Batch ZIP redaction** — upload a `.zip` of text files/images, get back a redacted ZIP plus an
  **audit-ready PDF** (summary, per-file risk, entity totals, SHA-256 integrity record, sign-off block).
  Optional **Groq-assisted review** double-checks *already-redacted* text for residual PII and flags files for human review.
- **Privacy by design** — re-identification mappings are in-memory only; batch output is irreversible and the audit PDF contains no original PII.

## Setup
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_lg
sudo apt install tesseract-ocr          # macOS: brew install tesseract
cp .env.example .env                    # add GROQ_API_KEY
python app.py                           # http://127.0.0.1:5000
```

## API (20 endpoints)
| Area | Endpoints |
|---|---|
| Auth | `POST /api/register` · `POST /api/login` · `POST /api/logout` · `GET /api/check` |
| Masking | `POST /api/mask` · `POST /api/differential` · `POST /api/decrypt` · `POST /api/analyze` |
| Images | `POST /api/redact-image` |
| LLM proxy | `POST /api/secure-chat` |
| Keywords | `POST /api/add_keyword` · `POST /api/remove_keyword` · `GET /api/get_keywords` |
| History | `GET /api/history` · `POST /api/history/clear` · `GET /api/analytics` |
| Files | `POST /api/upload` |
| **Batch** | `POST /api/batch/redact` · `GET /api/batch/<id>/download?format=pdf\|zip` |
| Ops | `GET /api/health` |

## Batch limits
25 MB per ZIP · 50 files · 10 MB per file · 100 MB uncompressed. Path-traversal entries and unsupported types are skipped and recorded in the audit PDF.

## Verify the numbers
```bash
python benchmarks/latency.py   # p50 / p95 masking latency on your machine
python -m pytest tests -q      # batch engine tests (no models required)
```
