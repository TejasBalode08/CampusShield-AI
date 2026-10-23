import ast
import re
from pathlib import Path
from urllib.parse import urlparse

APP = Path(__file__).resolve().parents[1] / "app.py"
SOURCE = APP.read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)
FUNCTIONS = {n.name: n for n in TREE.body if isinstance(n, ast.FunctionDef)}
NAMESPACE = {"re": re, "urlparse": urlparse}
for name in ("find_urls", "mask_sensitive_data", "inspect_url", "basic_analysis"):
    exec(compile(ast.Module(body=[FUNCTIONS[name]], type_ignores=[]), str(APP), "exec"), NAMESPACE)

find_urls = NAMESPACE["find_urls"]
mask_sensitive_data = NAMESPACE["mask_sensitive_data"]
inspect_url = NAMESPACE["inspect_url"]
basic_analysis = NAMESPACE["basic_analysis"]


def test_high_risk_message_gets_flagged():
    result = basic_analysis(
        "URGENT! Your bank account will be blocked today. Update your KYC immediately. "
        "Share your OTP and pay a fee at http://192.168.1.2/login"
    )
    assert result["risk_level"] == "High"
    assert result["risk_score"] >= 60
    assert result["reasons"]


def test_normal_message_not_automatically_high_risk():
    result = basic_analysis("Hi, your appointment is confirmed for tomorrow at 10 AM.")
    assert result["risk_level"] == "Low"
    assert result["risk_score"] < 30


def test_shortened_link_is_flagged():
    _, score, flags = inspect_url("https://bit.ly/abc123")
    assert score >= 12
    assert any("shortening" in reason.lower() for reason in flags)


def test_url_detection_trims_punctuation():
    assert find_urls("Visit https://example.com/test.") == ["https://example.com/test"]


def test_personal_data_redaction():
    redacted = mask_sensitive_data("Email me at student@example.com or call 9876543210. OTP: 123456")
    assert "student@example.com" not in redacted
    assert "9876543210" not in redacted
    assert "123456" not in redacted
    assert "REDACTED" in redacted


def test_empty_message_is_handled():
    result = basic_analysis("   ")
    assert result["risk_level"] == "Unknown"
    assert result["risk_score"] == 0


def test_privacy_and_consent_controls_exist():
    assert "gemini_consent" in SOURCE
    assert "mask_sensitive_data(message)" in SOURCE
    assert "No scan history is saved to a database" in SOURCE
    assert "GEMINI_API_KEY" in SOURCE
    assert "AIza" not in SOURCE
