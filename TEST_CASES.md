# PhishGuard AI — Test Cases

Use these cases in the dashboard.

## TC-01 — Obvious phishing
Subject: URGENT: Account suspended
Message:
Your account will be suspended immediately. Click here to verify your password and OTP:
http://192.168.1.50/login/verify-password
Expected: PHISHING, high risk. Indicators should include urgency, credential/OTP request, IP URL, HTTP and credential-related URL.

## TC-02 — Fake payment verification
Subject: Payment failed — verify now
Message:
Your payment failed. Confirm your card and login details immediately at http://secure-payment-login.example/verify.
Expected: PHISHING or SUSPICIOUS, elevated risk.

## TC-03 — Suspicious message
Subject: Security alert
Message:
We detected unusual activity. Please verify your account using this link: http://example.com/login
Expected: SUSPICIOUS or PHISHING depending on model/rules.

## TC-04 — Legitimate meeting
Subject: Team meeting tomorrow
Message:
Hi team, our project meeting is scheduled for tomorrow at 10 AM. Please review the agenda.
Expected: LEGITIMATE, low risk.

## TC-05 — Legitimate newsletter
Subject: Monthly newsletter
Message:
Here is the monthly newsletter with product updates and community news. You can unsubscribe at any time.
Expected: LEGITIMATE, low risk.

## TC-06 — Real-time WebSocket test
1. Open the dashboard in two browser tabs.
2. Scan any message in tab A.
3. Tab B should receive the new scan in Live Scan History automatically.
4. No manual refresh should be required.

## TC-07 — API test
POST `/api/scan` with:
{
  "subject": "Urgent verification",
  "message": "Verify your password immediately at http://192.168.1.50/login"
}
Expected: JSON result containing classification, risk_score, confidence, reasons and recommendation.

## TC-08 — Empty message
Leave Message empty and click Scan.
Expected: Browser-side validation message; no server crash.

## TC-09 — Long message
Paste a long normal message.
Expected: Application remains responsive and returns a result.

## TC-10 — Multiple URLs
Include several URLs in one message.
Expected: URLs are extracted and analyzed; result contains the URL list.
