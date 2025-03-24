# Cyber Threat Detector
A Flask-based cybersecurity tool to detect network threats using ML, APIs, and blockchain logging.

## Features
- Real-time threat detection (`app.py`)
- ML models: Random Forest, Isolation Forest, Logistic Regression
- APIs: Hybrid Analysis, AbuseIPDB
- Blockchain incident logging
- Cyberpunk UI (`index.html`, `login.html`)

## Setup
1. Clone the repo: `git clone https://github.com/krishna225-393/cyber-threat-detector.git`
2. Install dependencies: `pip install -r requirements.txt`
3. Add your `.env` file with API keys and email creds.
4. Run: `python app.py`

## Files
- `app.py`: Main Flask app
- `detector.py`: Simple threat detector
- `generate_data.py`: Mock log generator
- `detector_ml.py`: ML-based detector
- `*.html`: UI templates