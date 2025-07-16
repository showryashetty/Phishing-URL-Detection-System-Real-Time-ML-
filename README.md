# Phishing-URL-Detection-System-Real-Time-ML-
A complete Flask-based web backend that detects phishing URLs using a trained machine learning model (Random Forest) combined with real-time evidence-based checks like DNS resolution, HTTP status, SSL certificate, WHOIS lookup, and form scanning.  🚀 Features:

🔐 Phishing URL Detection System (Real-Time + ML)
A complete Flask-based web backend that detects phishing URLs using a trained machine learning model (Random Forest) combined with real-time evidence-based checks like DNS resolution, HTTP status, SSL certificate, WHOIS lookup, and form scanning.

🚀 Features:
🧠 ML-Based Detection: Trained on 100,000+ URLs with 95%+ accuracy

🌐 Real-Time URL Analysis:

DNS resolution check

HTTP response & content size

SSL certificate issuer

WHOIS domain creation/expiry

Login form scanning using BeautifulSoup

🛡️ Overrides ML if real-world evidence is strong

📩 Email Alerts: Sends full analysis report to your email for every URL

📝 All results logged to visited_urls.log

🔁 Trained on a synthetic + real dataset with both phishing and legitimate URLs

🔗 API Endpoint:
bash
Copy code
POST /check
{ "url": "https://example.com" }
📬 Sample Email Report:
yaml
Copy code
🔍 ANALYSIS REPORT
🔗 URL: http://malicious-site.ru/
🧠 ML Prediction: Phishing 🚨
✔️ DNS Resolved: 203.0.113.5
✔️ HTTP 200, 34500 bytes
⚠️ Login form detected
✔️ SSL issued by US
✔️ Created: 2019-02-01, Expires: 2025-02-01
Let me know if you want badges, deployment instructions, or frontend integration steps!







You said:
tell clearly understandable way how its working


ChatGPT said:
Absolutely! Here's a clear, beginner-friendly explanation of how your phishing detection project works, which you can add to your GitHub README:

🧠 How It Works (Step-by-Step)
This project combines Machine Learning and Real-Time Security Checks to detect phishing websites.

✅ Step 1: Machine Learning Training
The system trains a Random Forest Classifier on a dataset of over 100,000 URLs labeled as:

phishing (malicious)

legitimate (safe)

It extracts URL-based features like:

Length of URL

Number of dots (.)

If it has login, verify, @, -, or IP address

Whether it starts with http:// instead of https://

Example: http://login-paypal-alert.com is suspicious because it’s long, uses “login” and “http”, and has a dash.

🕵️ Step 2: Real-Time Evidence Collection
When you submit a URL via API, the system performs:

Check	Purpose
DNS Lookup	Can the domain resolve to a valid IP?
HTTP Response	Does the site return a valid page (e.g., 200 OK)?
SSL Certificate	Is there a valid HTTPS certificate? Who issued it?
WHOIS Info	When was the domain created? Is it expired?
Form Detection	Does the site have a password input form?

🧮 Step 3: Intelligent Decision Logic
First, the ML model predicts phishing or legitimate.

Then, real-time checks confirm or override the prediction.

Example:
If the ML model says Phishing but all real-time checks are valid → It's likely safe (ML overruled).

If the ML says Legitimate but WHOIS/DNS/SSL/HTTP all fail → It's marked as Suspicious.

📧 Step 4: Email Alert (Automatic)
Every time a URL is scanned, the system sends an email with full analysis to your inbox.

txt
Copy code
🔍 ANALYSIS REPORT
🔗 URL: http://fake-bank-login.com
🧠 ML Prediction: Phishing 🚨
❌ DNS resolution failed
⚠️ No HTTP response
❌ SSL check failed
⚠️ WHOIS lookup failed
📂 Logs
All URLs and their detection result are saved in visited_urls.log.
