from flask import Blueprint, render_template, request
from app.utils import check_ssl_certificate, get_domain_info, is_valid_url
import tldextract
import requests
from bs4 import BeautifulSoup

main = Blueprint('main', __name__)

@main.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('url')
        if not is_valid_url(url):
            return render_template('index.html', error="Invalid URL format.")
        suspicion_score = calculate_suspicion_score(url)
        return render_template('result.html', url=url, suspicion_score=suspicion_score)
    return render_template('index.html')

def calculate_suspicion_score(url):
    domain = tldextract.extract(url).domain
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

    # Normalize the suspicion score
    suspicion_score = max(0, min(100, suspicion_score))

    return suspicion_score
