from flask import Flask, render_template, request
import tldextract
import requests
from bs4 import BeautifulSoup
import ssl
import whois

app = Flask(__name__)

# Define the suspicious keywords and ISO standards
suspicious_keywords = {'login', 'signin', 'password', 'verify', 'account', 'update', 'secure', 'bank'}
iso_standards = ['com', 'org', 'net', 'edu']  # Add more if needed

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        suspicion_score = calculate_suspicion_score(url)
        return render_template('result.html', url=url, suspicion_score=suspicion_score)
    return render_template('index.html')

def calculate_suspicion_score(url):
    # Extract the domain from the URL
    domain = tldextract.extract(url).domain

    # Calculate the length of the domain
    domain_length = len(domain)

    # Check if the domain contains suspicious keywords
    contains_suspicious_keywords = any(keyword in domain.lower() for keyword in suspicious_keywords)

    # Check if the domain matches ISO standards
    matches_iso_standards = any(iso_standard.lower() in domain.lower() for iso_standard in iso_standards)

    # Initialize suspicion score
    suspicion_score = 0

    # URL structure analysis
    if len(url) > 100 or url.count('/') > 5 or url.count('.') > 3:
        suspicion_score += 20

    # Content analysis
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        if soup.find_all('input', {'type': 'password'}) or soup.find_all('form'):
            suspicion_score += 30
    except:
        # Failed to fetch content or parse HTML
        pass

    # SSL/TLS certificate analysis
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        cert = ssl.get_server_certificate((domain, 443), ssl_context=ssl_context)
        issuer = cert.get_issuer().get_components()
        if b'Let\'s Encrypt' not in issuer:  # Adjust based on trusted certificate issuers
            suspicion_score += 10
    except:
        # Failed to retrieve or analyze SSL certificate
        pass

    # Domain reputation checking (using WHOIS)
    try:
        domain_info = whois.whois(domain)
        if 'creation_date' in domain_info:
            creation_date = domain_info['creation_date']
            if isinstance(creation_date, list):
                creation_date = min(creation_date)
            if (datetime.datetime.now() - creation_date).days < 365:
                suspicion_score += 20
    except:
        # Failed to retrieve WHOIS information
        pass

    # Normalize the suspicion score to the range of 0 to 100%
    suspicion_score = max(0, min(100, suspicion_score))

    return suspicion_score

if __name__ == '__main__':
    app.run(debug=True)
