# Phishing-Detector

This Flask application calculates the suspicion score of a given URL based on various criteria including URL structure analysis, content analysis, SSL/TLS certificate analysis, and domain reputation checking. It helps identify potentially suspicious URLs that may pose security risks such as phishing attacks.
Installation

    Clone the repository:

bash

git clone https://github.com/your_username/url-suspicion-score-calculator.git

    Navigate to the project directory:

bash

cd url-suspicion-score-calculator

    Install dependencies:

bash

pip install -r requirements.txt

Usage
Command Line Interface (CLI)

    Run the Flask application:

bash

python app.py

    Open a web browser and go to http://localhost:5000.

    Enter a URL in the provided form and submit to view the suspicion score.

Windows Command Prompt (CMD)

    Run the Flask application:

cmd

python app.py

    Open a web browser and go to http://localhost:5000.

    Enter a URL in the provided form and submit to view the suspicion score.

Functionality

    URL Structure Analysis: Detects patterns in the URL that might indicate suspicious behavior such as long sequences of random characters, excessive subdomains, or uncommon URL paths.

    Content Analysis: Fetches the content of the webpage corresponding to the URL and analyzes it for signs of phishing, such as requests for sensitive information, suspicious links, or deceptive content.

    SSL/TLS Certificate Analysis: Checks the validity and issuer of the SSL/TLS certificate associated with the URL to assess the trustworthiness of the website.

    Domain Reputation Checking: Queries domain reputation databases or services to assess the reputation of the domain and flag domains with a history of malicious activity.

Contributing

Contributions are welcome! If you have any suggestions, feature requests, or bug reports, please open an issue or submit a pull request.
License

This project is licensed under the MIT License - see the LICENSE file for details.
