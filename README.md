# Phishing-Detector

This Flask application calculates the suspicion score of a given URL based on various criteria including URL structure analysis, content analysis, SSL/TLS certificate analysis, and domain reputation checking. It helps identify potentially suspicious URLs that may pose security risks such as phishing attacks.
Installation


clone this repository: 
git clone (https://github.com/tadash10/Phishing-Detector)
    Navigate to the project directory:

Project Overview

Purpose: The project is a Flask web application that evaluates the suspicion level of a given URL. It provides a suspicion score based on several factors such as URL structure, SSL/TLS certificate information, and domain reputation. This can be useful for identifying potentially fraudulent or insecure websites.

Features:

    URL Structure Analysis: Checks the length and format of the URL.
    Content Analysis: Looks for security-related elements like password fields and forms on the webpage.
    SSL/TLS Certificate Check: Assesses the SSL certificate issuer to detect if it’s from a trusted Certificate Authority (CA).
    Domain Information: Evaluates the domain's age using WHOIS information to assess its legitimacy.

How It Works:

    User Input: A user submits a URL through a web form.
    URL Validation: The URL is validated to ensure it is correctly formatted.
    Suspicion Score Calculation: The application calculates a suspicion score based on the URL structure, content, SSL certificate, and domain age.
    Results Display: The suspicion score is displayed on the results page.

Step-by-Step Installation and Usage on Windows 11
1. Install Python

Ensure Python 3.8 or later is installed on your Windows 11 system. If not, download and install it from the official Python website.

    Download Python Installer: Go to Python Downloads and download the latest version for Windows.
    Run Installer: Run the installer and make sure to check the box for "Add Python to PATH". Then, click "Install Now".

2. Set Up a Virtual Environment

Open Command Prompt or Windows Terminal and follow these steps:

    Create a Project Directory:

    cmd

mkdir url_suspicion_checker
cd url_suspicion_checker

Create a Virtual Environment:

cmd

python -m venv venv

Activate the Virtual Environment:

cmd

    venv\Scripts\activate

    You should see (venv) at the beginning of the command line, indicating that the virtual environment is active.

3. Install Dependencies

With the virtual environment activated, install the required Python packages:

    Create a requirements.txt file with the following content:

    text

Flask
Flask-Caching
Flask-Limiter
tldextract
requests
beautifulsoup4
whois

Install the packages:

cmd

    pip install -r requirements.txt

4. Set Up the Project

    Create the Project Files and Directories:

    You can either create the files manually or copy the code from the previous response into appropriate files within the url_suspicion_checker directory.
        app/__init__.py
        app/routes.py
        app/utils.py
        app/config.py
        app/errors.py
        app/templates/index.html
        app/templates/result.html
        app/templates/404.html
        app/templates/500.html
        Dockerfile (if using Docker)
        requirements.txt
        run.py

    Add Content to Files:

    Copy and paste the provided code snippets into the respective files. Ensure that your directory structure matches the one described.

5. Run the Application

    Start the Flask Application:

    With the virtual environment activated, run the Flask application:

    cmd

    python run.py

    The Flask application will start, and you should see output indicating that the server is running, typically on http://127.0.0.1:5000/.

    Access the Application:

    Open a web browser and go to http://127.0.0.1:5000/ to access the application.
        Homepage: You will see a form where you can enter a URL.
        Results Page: After submitting a URL, the application will display the suspicion score and any relevant information.

6. Troubleshooting

    If the Application Doesn’t Start:
        Ensure all dependencies are installed correctly.
        Check the app.log file for error messages and resolve any issues indicated.

    If You Encounter Errors with SSL or WHOIS:
        Ensure network connectivity and correct configuration.
        Verify that the required ports are open and not blocked by a firewall.

Summary

By following these steps, you will have a functional Flask application running locally on your Windows 11 system. This application helps evaluate the suspicion level of URLs by analyzing various aspects such as URL structure, SSL certificates, and domain information.
