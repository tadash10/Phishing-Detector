import ssl
import socket
import whois
import datetime
import logging
from urllib.parse import urlparse

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

def is_valid_url(url):
    parsed_url = urlparse(url)
    return parsed_url.scheme in ['http', 'https'] and parsed_url.netloc
