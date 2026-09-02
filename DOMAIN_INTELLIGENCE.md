# Domain Intelligence & Simple AI Explanation

PhishGuard now performs a **registration-age check** for domains extracted from an email.

- It extracts URLs as text only.
- It does **not** open, crawl, redirect to, or click the email URL.
- It queries public RDAP registration metadata for the domain.
- RDAP is the modern standardized replacement for WHOIS and can provide a domain creation/registration date. ICANN documents RDAP as the current registration-data protocol for gTLDs.
- Domain age is treated as **one signal**, not proof of phishing. A new domain can be legitimate, and an old domain can still be compromised or malicious.

## User-facing explanation

For suspicious messages PhishGuard explains in simple language what could happen if the user follows the email request, for example:

1. The link may lead to a fake login or payment page.
2. Passwords, OTPs, card details, or other information entered there could be stolen.
3. A malicious site could attempt to deliver harmful content.
4. A newly registered domain can be used as a short-lived phishing site.

The recommendation remains: **do not click the email link; verify through the official app or manually typed official website.**

## Network behavior

The application sends the **domain name** to RDAP only for registration metadata. It does not request the suspicious website itself. If RDAP is unavailable, the application reports the age as unknown and does not add domain-age risk.
