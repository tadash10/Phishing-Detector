from flask import Flask, render_template, request
import tldextract

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

    # Calculate the suspicion score based on various factors
    suspicion_score = 0

    # Weight the domain length
    if domain_length <= 10:
        suspicion_score += 10
    elif domain_length <= 15:
        suspicion_score += 5

    # Weight the match with suspicious keywords
    if contains_suspicious_keywords:
        suspicion_score += 30

    # Weight the match with ISO standards
    if matches_iso_standards:
        suspicion_score -= 20

    # Normalize the suspicion score to the range of 0 to 100%
    suspicion_score = max(0, min(100, suspicion_score))
    
    return suspicion_score

if __name__ == '__main__':
    app.run(debug=True)
