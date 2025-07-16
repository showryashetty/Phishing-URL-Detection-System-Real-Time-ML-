from flask import Flask, request
from flask_cors import CORS
import pandas as pd
import re, socket, ssl, whois, requests, smtplib
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from email.mime.text import MIMEText
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

app = Flask(__name__)
CORS(app)

# --------- Load and Train ML Model with Accuracy ---------
df = pd.read_csv('dataset.csv')

features = df['url'].apply(lambda url: {
    'url_length': len(url),
    'dot_count': url.count('.'),
    'has_https': int('https' in url),
    'has_login': int('login' in url or 'signin' in url),
    'has_verify': int('verify' in url),
    'has_at': int('@' in url),
    'has_dash': int('-' in url),
    'starts_with_http': int(url.startswith('http://')),
    'has_ip': int(bool(re.match(r"http[s]?://\d{1,3}(\.\d{1,3}){3}", url)))
})
X = pd.DataFrame(features.tolist())
y = df['label'].map({'legitimate': 0, 'phishing': 1})

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier().fit(X_train, y_train)
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"🎯 ML Model Accuracy: {accuracy * 100:.2f}%")

# --------- Email Alert ---------
def send_email(url, ml_result, dns, http, form, ssl_info, whois_info):
    sender = "showryashetty20112004@gmail.com"
    password = "umlyhniffcvkthbl"  # Gmail App Password
    to = sender

    body = f"""🔍 ANALYSIS REPORT
🔗 URL: {url}
🧠 ML Prediction: {ml_result}
{dns}
{http}
{form}
{ssl_info}
{whois_info}
--------------------------------------------------"""

    msg = MIMEText(body)
    msg['Subject'] = f"Phishing Alert: {ml_result}"
    msg['From'] = sender
    msg['To'] = to

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, password)
            server.send_message(msg)
        print(f"📧 Email sent for: {url}")
    except Exception as e:
        print("❌ Email sending failed:", e)

# --------- Logging ---------
def log_url(url, risk):
    try:
        with open("visited_urls.log", "a", encoding="utf-8") as log:
            log.write(f"{url} - {risk}\n")
    except Exception as e:
        print("❌ Logging failed:", e)

# --------- Real-time Analyzer ---------
def analyze_url(url):
    safe_domains = [
        "mail.google.com", "google.com", "youtube.com",
        "nseindia.com", "chatgpt.com", "chrome://newtab"
    ]
    parsed = urlparse(url).netloc.lower()
    if any(safe in parsed for safe in safe_domains):
        print(f"🟢 Skipped safe domain: {url}")
        log_url(url, "✅ Safe (whitelisted)")
        return "✅ Safe (whitelisted)"

    feat = pd.DataFrame([{
        'url_length': len(url),
        'dot_count': url.count('.'),
        'has_https': int('https' in url),
        'has_login': int('login' in url or 'signin' in url),
        'has_verify': int('verify' in url),
        'has_at': int('@' in url),
        'has_dash': int('-' in url),
        'starts_with_http': int(url.startswith('http://')),
        'has_ip': int(bool(re.match(r"http[s]?://\d{1,3}(\.\d{1,3}){3}", url)))
    }])
    ml_prediction = model.predict(feat)[0]
    ml_result = "Phishing 🚨" if ml_prediction else "Legitimate ✅"

    domain = re.sub(r"https?://", "", url).split('/')[0]

    # --- Real-time Checks ---
    try:
        ip = socket.gethostbyname(domain)
        dns_check = f"✔️ DNS Resolved: {ip}"
        dns_ok = True
    except:
        dns_check = "❌ DNS resolution failed"
        dns_ok = False

    try:
        response = requests.get(url, timeout=5)
        http_check = f"✔️ HTTP {response.status_code}, {len(response.text)} bytes"
        http_ok = response.status_code == 200
    except:
        http_check = "⚠️ No HTTP content or unreachable"
        http_ok = False

    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        form_check = "⚠️ Login form detected" if soup.find('input', {'type': 'password'}) else "✔️ No login form"
    except:
        form_check = "⚠️ Cannot scan for form"

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = cert['issuer'][0][0][1]
                ssl_check = f"✔️ SSL issued by {issuer}"
                ssl_ok = True
    except:
        ssl_check = "❌ SSL check failed or not available"
        ssl_ok = False

    try:
        info = whois.whois(domain)
        created = info.creation_date
        expires = info.expiration_date
        whois_check = f"✔️ Created: {created}, Expires: {expires}"
        whois_ok = created is not None
    except:
        whois_check = "⚠️ WHOIS lookup failed"
        whois_ok = False

    # --- Final Risk Logic ---
    if ml_result == "Phishing 🚨" and (dns_ok and http_ok and ssl_ok and whois_ok):
        risk = "✅ Legitimate (Overruled ML)"
    elif ml_result == "Legitimate ✅" and not (dns_ok or http_ok or ssl_ok or whois_ok):
        risk = "⚠️ Suspicious"
    else:
        risk = ml_result

    log_url(url, risk)
    send_email(url, ml_result, dns_check, http_check, form_check, ssl_check, whois_check)

    return risk

# --------- API Route ---------
@app.route('/check', methods=['POST'])
def check_url():
    data = request.json
    url = data.get('url')
    if not url:
        return {"error": "No URL provided"}, 400
    try:
        risk = analyze_url(url)
        return {"result": risk}
    except Exception as e:
        return {"error": str(e)}, 500

# --------- Run Server ---------
if __name__ == '__main__':
    app.run(port=5050)
