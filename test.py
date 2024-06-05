import tldextract

def is_potential_phishing(url):
    iso_standards = ['ISO/IEC 27001', 'ISO/IEC 27002', 'ISO/IEC 27005', 'ISO/IEC 27701']
    
    domain = tldextract.extract(url).domain
    
    if any(iso_standard.lower() in domain.lower() for iso_standard in iso_standards):
        return True
    else:
        return False

# Test the function
url = input("Enter the URL to check for phishing: ")
if is_potential_phishing(url):
    print(f"The provided URL {url} is potentially a phishing website.")
else:
    print(f"The provided URL {url} is not identified as a phishing website.")
