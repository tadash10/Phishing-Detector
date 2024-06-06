def check_ssl_certificate(domain):
    try:
        ssl_context = ssl.create_default_context()
        with ssl_context.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert()
            issuer = dict(x[0] for x in cert['issuer'])
            return 'Let\'s Encrypt' not in issuer.get('organizationName', '')
    except Exception as e:
        # Log error
        return False

def get_domain_info(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info['creation_date']
        if isinstance(creation_date, list):
            creation_date = min(creation_date)
        return (datetime.datetime.now() - creation_date).days < 365
    except Exception as e:
        # Log error
        return False
