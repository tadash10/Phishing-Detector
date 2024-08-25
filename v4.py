from flask import Flask, render_template, request
import tldextract
import requests
from bs4 import BeautifulSoup
import ssl
import socket
import whois
import datetime
import logging

# Initialize Flask app
app = Flask(__name__)

# Define the suspicious keywords and ISO standards
suspicious_keywords = {'login', 'signin', 'password', 'verify', 'account', 'update', 'secure', 'bank'}
iso_standards = ['com', 'org', 'net', 'edu']  # Add more if needed

# Set up logging
logging.basicConfig(filename='app.log', level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s')

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
    except requests.RequestException as e:
        logging.error(f"Failed to fetch or parse URL content: {e}")

    # SSL/TLS certificate analysis
    if check_ssl_certificate(domain):
        suspicion_score += 10

    # Domain reputation checking (using WHOIS)
    if get_domain_info(domain):
        suspicion_score += 20

    # Normalize the suspicion score to the range of 0 to 100%
    suspicion_score = max(0, min(100, suspicion_score))

    return suspicion_score

def check_ssl_certificate(domain):
    try:
        ssl_context = ssl.create_default_context()
        with ssl_context.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert()
            issuer = dict(x[0] for x in cert['issuer'])
            issuer_name = issuer.get('organizationName', '')
            return 'Let\'s Encrypt' not in issuer_name
    except ssl.SSLError as e:
        logging.error(f"SSL error: {e}")
        return False
    except socket.error as e:
        logging.error(f"Socket error: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error in SSL certificate check: {e}")
        return False

def get_domain_info(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.get('creation_date')
        if isinstance(creation_date, list):
            if not creation_date:
                return False
            creation_date = min(creation_date)
        elif not isinstance(creation_date, datetime.datetime):
            return False
        return (datetime.datetime.now() - creation_date).days < 365
    except whois.WhoisError as e:
        logging.error(f"WHOIS error: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error in domain info retrieval: {e}")
        return False

if __name__ == '__main__':
    app.run(debug=True)
