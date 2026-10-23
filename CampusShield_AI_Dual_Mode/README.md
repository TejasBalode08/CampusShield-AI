# CampusShield AI — Privacy-Aware Scam Message Screening

A Streamlit prototype that screens user-pasted SMS, emails, and URLs for common scam/phishing indicators. It has two engines: **Basic Mode** (local rules; no API key needed) and optional **Gemini Mode** (cloud AI with explicit consent and best-effort redaction).

> **Important:** This is a decision-support demo, not a trained/benchmark-validated fraud detector. A score is a heuristic risk indicator, not the probability a message is fraudulent. It can miss scams and flag legitimate messages. Verify claims through official channels.

## Features

- Premium Streamlit dashboard with sample messages and risk assessment.
- Basic Mode works without a Gemini key or network access once Python dependencies are installed.
- Gemini Mode is optional and asks for consent before sending the message to Google Gemini.
- Best-effort redaction of common email addresses, Indian mobile numbers, long numeric identifiers, and OTP-like strings before cloud analysis.
- Local rules for credential requests, payment pressure, account/KYC threats, fake prizes, job-fee scams, authority threats, remote-access tools, suspicious URL patterns, URL shorteners, punycode, IP-address links, and more.
- Gemini failures or missing consent/key safely fall back to Basic Mode with a notice.
- API key read from Streamlit secrets or the `GEMINI_API_KEY` environment variable; no key is hardcoded.
- No database, persistent scan history, or automatic SMS-inbox access.
- Tests for key rule cases, URL inspection, redaction, empty input, and privacy controls.

## Run on Windows (PowerShell)

Open the folder that contains `app.py` in VS Code Terminal, then run:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

If you already created `.venv`, skip the first command. If your project is in a nested folder, `cd` into the folder containing `app.py` before running the commands.

## Optional Gemini setup

1. Create a Gemini API key in your own Google AI Studio account.
2. Create `.streamlit/secrets.toml` inside the project folder (do not upload or commit it).
3. Add:

```toml
GEMINI_API_KEY = "paste-your-own-key-here"
```

4. Restart Streamlit and select **Gemini Mode (Online AI)**. The app asks for consent before calling Gemini.

You can also set `GEMINI_API_KEY` as an environment variable. Never share your key in screenshots, source code, or a public repository.

## Privacy notes

- The app only analyzes text a user pastes; it does not read the phone's SMS inbox.
- Basic Mode runs local rules and does not send message text to an AI service.
- Gemini Mode sends a best-effort-redacted copy to Google after the user checks the consent box. Redaction is not guaranteed to catch every sensitive detail. Do not use confidential real messages in demos.
- The input remains in the active Streamlit session until cleared or the session ends; it is not written to a database by this app.
- The interface loads Google Fonts when internet is available; if offline, a system-font fallback is used. Message text is not sent to Google Fonts.

## Tests

Install pytest if needed, then run:

```powershell
python -m pip install pytest
python -m pytest -q
```

The test suite checks deterministic rule cases and privacy-related safeguards. It does **not** establish real-world detection accuracy. For a credible hackathon evaluation, test against a labelled dataset that you are allowed to use, report precision/recall/F1 and false-positive rates, and describe the dataset and limitations honestly.

## Project structure

```text
CampusShield_AI_Dual_Mode/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── .streamlit/
│   └── secrets.toml.example
└── tests/
    └── test_basic_analysis.py
```
