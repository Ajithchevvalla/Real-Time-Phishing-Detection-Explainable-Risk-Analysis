# PhishGuard AI — Real-Time Phishing Detection

A defensive phishing-analysis prototype that combines ML classification with explainable security rules and domain-registration intelligence.

## Features

- Real-time analysis while typing/pasting an email
- Sender, subject, body and URL analysis
- Word + character TF-IDF ML model
- Phishing / suspicious / legitimate classification
- URL analysis without opening or clicking links
- **Domain age check using RDAP registration metadata**
- Simple AI-style explanation of what could happen if a user follows the request
- Clear recommendation to avoid email links and verify through official channels
- WebSocket live scan history
- Built-in realistic test cases
- No Gmail OAuth or inbox access

## Domain age safety behavior

PhishGuard queries registration metadata only. It never fetches the suspicious URL itself. Domain age is a supporting signal, not a verdict.

RDAP is the standardized registration-data protocol documented by ICANN.

## Run

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

Open `http://127.0.0.1:8000`.

## Test cases

Use the built-in test lab or paste real email text. Test messages can contain URLs; PhishGuard extracts those URLs as text and analyzes them without navigating to them.
