"""
Measure PII-masking latency so the README / resume numbers are reproducible.

    python benchmarks/latency.py            # 200 runs per sample
    python benchmarks/latency.py 500

Reports p50 / p95 / max (ms) for the hybrid spaCy + Presidio + regex pipeline.
The first call is a warm-up and is excluded (model load / lazy init).
"""
import os, sys, statistics, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("GROQ_API_KEY", "benchmark-not-used")   # app import requires it; never called here

import app as gw   # noqa: E402

SAMPLES = {
    "short (~15 words)": "Contact Rahul Sharma at rahul.sharma@gmail.com or 9876543210 regarding the invoice.",
    "medium (~60 words)": (
        "Priya Nair, PAN ABCDE1234F, Aadhaar 2345 6789 0123, lives in Kochi, Kerala 682001. "
        "Her HDFC account 50100234567890 (IFSC HDFC0001234) was credited on 12/03/2024. "
        "Reach her on +91 98765 43210 or priya.nair@example.in; vehicle KL07AB1234."
    ),
}

def pct(xs, p):
    xs = sorted(xs); return xs[min(len(xs) - 1, int(len(xs) * p / 100))]

def main():
    runs = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    with gw.app.app_context():
        print(f"spaCy lg loaded: {gw.SPACY_AVAILABLE} | runs/sample: {runs}\n")
        for label, text in SAMPLES.items():
            gw.mask_text_basic(text, "bench")                      # warm-up
            lat = []
            for _ in range(runs):
                t = time.perf_counter()
                gw.mask_text_basic(text, "bench")
                lat.append((time.perf_counter() - t) * 1000)
            print(f"{label:22s} p50={statistics.median(lat):6.1f}  "
                  f"p95={pct(lat,95):6.1f}  max={max(lat):6.1f} ms")

if __name__ == "__main__":
    main()
