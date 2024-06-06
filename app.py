from flask import Flask, render_template, request
from config import Config
from url_analysis import calculate_suspicion_score
import asyncio

app = Flask(__name__)
app.config.from_object(Config)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        suspicion_score = asyncio.run(calculate_suspicion_score(url, app.config['SUSPICIOUS_KEYWORDS'], app.config['ISO_STANDARDS']))
        return render_template('result.html', url=url, suspicion_score=suspicion_score)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
