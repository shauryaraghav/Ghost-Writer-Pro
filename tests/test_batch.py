"""Run: python -m pytest tests -q   (no Presidio/spaCy needed — redactors are stubbed)"""
import io, json, re, zipfile, base64, os, sys
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import batch


def mask(text, user):
    stats = {}
    def sub(pat, name, t):
        n = len(re.findall(pat, t))
        if n: stats[name] = n
        return re.sub(pat, f"<{name}>", t)
    t = sub(r"[\w.]+@[\w.]+\.\w+", "EMAIL", text)
    t = sub(r"\b[A-Z]{5}\d{4}[A-Z]\b", "IN_PAN", t)
    return t, {}, stats, 1.0, min(100, sum(stats.values()) * 20)

def image(b, u):
    return {"redacted_image": base64.b64encode(b).decode(), "stats": {"PERSON": 1}, "latency_ms": 5.0, "risk_score": 14}

class FakeGroq:
    class chat:
        class completions:
            @staticmethod
            def create(**kw):
                leak = "9876543210" in kw["messages"][1]["content"]
                out = {"verdict": "REVIEW", "leaks": [{"type": "phone", "hint": "line 2"}]} if leak else {"verdict": "PASS", "leaks": []}
                msg = type("M", (), {"content": json.dumps(out)})()
                return type("R", (), {"choices": [type("C", (), {"message": msg})()]})()

def make_zip(files):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for n, d in files.items(): z.writestr(n, d)
    return b.getvalue()

def test_redacts_and_reports():
    r = batch.run_batch(make_zip({"a.txt": "ravi@x.com ABCDE1234F"}), "u", mask, image, FakeGroq())
    out = zipfile.ZipFile(io.BytesIO(r["zip_bytes"])).read("redacted/a.txt").decode()
    assert "ravi@x.com" not in out and "ABCDE1234F" not in out
    assert r["pdf_bytes"].startswith(b"%PDF")
    assert r["summary"]["files_redacted"] == 1

def test_zip_slip_and_junk_rejected():
    r = batch.run_batch(make_zip({"../evil.txt": "x", "/abs.txt": "x", "ok.txt": "hi", "__MACOSX/._ok.txt": "j"}), "u", mask, image)
    assert [f["status"] for f in r["files"]].count("redacted") == 1

def test_unsupported_type_skipped():
    r = batch.run_batch(make_zip({"a.exe": "MZ", "b.txt": "x"}), "u", mask, image)
    assert r["summary"]["files_skipped"] == 1

def test_groq_flags_residual_pii():
    r = batch.run_batch(make_zip({"a.txt": "call 9876543210"}), "u", mask, image, FakeGroq())
    assert r["summary"]["flagged_for_review"] == 1

def test_groq_failure_is_soft():
    class Boom:
        class chat:
            class completions:
                @staticmethod
                def create(**kw): raise RuntimeError("down")
    r = batch.run_batch(make_zip({"a.txt": "hi"}), "u", mask, image, Boom())
    assert r["files"][0]["review"]["verdict"] == "UNREVIEWED"

def test_bad_inputs():
    with pytest.raises(batch.BatchError):
        batch.run_batch(b"nope", "u", mask, image)
    with pytest.raises(batch.BatchError):
        batch.run_batch(make_zip({}), "u", mask, image)
