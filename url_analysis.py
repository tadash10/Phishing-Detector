import re
import requests
from bs4 import BeautifulSoup
import tldextract
import asyncio
import aiohttp
from datetime import datetime
import socket
import ssl
import whois

def extract_domain(url):
    try:
        extracted = tldextract.extract(url)
        return extracted.domain, extracted.suffix
    except Exception as e:
        return None, None

def analyze_url_structure(url):
    if len(url) > 100 or url.count('/') > 5 or url.count('.') > 3:
        return 20
    return 0

async def fetch_content(url):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                return await response.text()
    except Exception as e:
        return None

def analyze_content(content):
    soup = BeautifulSoup(content, 'html.parser')
    if soup.find_all('input', {'type': 'password'}) or soup.find_all('form'):
        return 30
    return 0

def check_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert()
            issuer = dict(x[0] for x in cert['issuer'])
            return 'Let\'s Encrypt' not in issuer.get('organizationName', '')
    except Exception as e:
        return True

def analyze_whois(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info['creation_date']
        if isinstance(creation_date, list):
            creation_date = min(creation_date)
        if (datetime.now() - creation_date).days < 365:
            return 20
    except Exception as e:
        pass
    return 0

def check_suspicious_keywords(domain, keywords):
    return any(keyword in domain.lower() for keyword in keywords)

async def analyze_redirections(url):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.head(url, allow_redirects=True) as response:
                if len(response.history) > 1:
                    return 25
    except Exception as e:
        pass
    return 0

async def calculate_suspicion_score(url, keywords, iso_standards):
    domain, suffix = extract_domain(url)
    if not domain:
        return 0

    suspicion_score = 0
    suspicion_score += analyze_url_structure(url)

    content = await fetch_content(url)
    if content:
        suspicion_score += analyze_content(content)

    if check_ssl_certificate(domain):
        suspicion_score += 10

    suspicion_score += analyze_whois(domain)

    if '.' in domain:
        subdomain = domain.split('.')[0]
        if check_suspicious_keywords(subdomain, keywords):
            suspicion_score += 15

    suspicion_score += await analyze_redirections(url)

    if 'https://' not in url:
        suspicion_score += 15

    return max(0, min(100, suspicion_score))
