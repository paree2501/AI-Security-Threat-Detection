# AI Security – Threat Detection & Incident Analysis

An AI-powered cybersecurity platform designed to monitor security events, detect suspicious activities, analyze potential threats, and assist with security incident investigation.

The system combines rule-based threat detection, statistical anomaly scoring, risk assessment, and Gemini-powered AI explanations to help security analysts understand and investigate potential security incidents.

## Overview

AI Security is a defensive cybersecurity monitoring and incident analysis platform that processes security event logs and identifies potentially suspicious activities.

It provides a centralized dashboard where users can review security events, investigate detections, manage incidents, analyze anomalies, and generate AI-assisted explanations.

## Key Features

### 1. Rule-Based Threat Detection
Implements configurable detection rules to identify suspicious activities, including:

- Repeated Failed Login Attempts (Potential Brute-Force)
- Suspicious Login Sequences
- Unusual Network Activity
- Suspicious Administrative Activity
- Dangerous File and Process Activity
- Unclassified Security Events

### 2. Machine Learning-Based Anomaly Detection

Uses a multi-feature statistical anomaly detection approach to identify unusual patterns in security events.

Features analyzed include:
- Failed login attempt count
- Network data transfer volume
- Off-hours activity
- Privileged user activity
- Suspicious keywords in event logs
- Anomalous destination ports

The model uses feature standardization, weighted anomaly scoring, and a 70/30 training and evaluation split.

Evaluation metrics include:
- Accuracy
- Precision
- Recall
- F1-Score
- Confusion Matrix

### 3. Risk Scoring and Severity Classification

Each detection receives a risk score between 0 and 100 based on weighted detection factors.

Severity levels:
- LOW: 0–29
- MEDIUM: 30–59
- HIGH: 60–79
- CRITICAL: 80–100

The scoring system helps prioritize alerts based on their potential security impact.

### 4. AI-Powered Incident Analysis

Integrates Google's Gemini API to provide AI-assisted security alert investigation.

The AI assistant provides:
- Alert summaries
- Detailed technical analysis
- Evidence breakdown
- Possible legitimate explanations
- Investigation recommendations
- Defensive remediation steps
- Beginner-friendly explanations

The integration also includes input sanitization, defensive system instructions, and a deterministic heuristic fallback when the Gemini API key is unavailable.

### 5. Security Event Management

- Upload security events through CSV or JSON.
- Load sample security event datasets.
- Search and filter security events.
- View detection results and associated evidence.
- Track and update security incidents.

### 6. Incident Management and Reporting

- Create and manage security incidents.
- Update incident status.
- Review related detections.
- Export security reports and detection data.
- Generate structured audit information.

### 7. Security Configuration and Testing

- Configure detection thresholds.
- Enable or disable individual detection rules.
- Retrain the anomaly detection model.
- Execute the automated test suite.
- Review test execution results.

## Technology Stack

| Category | Technologies |
|---|---|
| Frontend | React 19, TypeScript |
| Styling | Tailwind CSS |
| Backend | Node.js, Express.js |
| Build Tool | Vite |
| Machine Learning | Statistical Anomaly Detection |
| AI Integration | Google Gemini API |
| Python Engine | Python 3, SQLite3 |
| Data Visualization | Recharts |
| Testing | Python unittest |

## Project Architecture

The application follows a modular architecture:

1. **Frontend Layer:** React and TypeScript provide the security monitoring dashboard and user interface.
2. **Backend Layer:** Express.js handles API requests, event ingestion, validation, and communication between application modules.
3. **Detection Engine:** Applies configurable security rules and calculates risk scores.
4. **ML Engine:** Extracts security features, calculates anomaly scores, and evaluates detection performance.
5. **AI Analysis Layer:** Uses Gemini API to generate contextual explanations and investigation recommendations.
6. **Python Reference Engine:** Provides a Python-based security processing implementation with SQLite storage and automated tests.

## Installation and Setup

### Prerequisites

- Node.js
- npm
- Python 3

### Step 1: Clone the Repository

```bash
git clone YOUR_REPOSITORY_URL
cd AI-Security-Threat-Detection
```

### Step 2: Install Dependencies

```bash
npm install
```

### Step 3: Configure Environment Variables

Create a `.env` file in the project root.

```env
GEMINI_API_KEY=your_gemini_api_key
```

You can obtain your API key from Google AI Studio:

https://aistudio.google.com/apikey

Keep your actual API key private. Never commit your `.env` file to GitHub.

The AI analysis module also provides a deterministic fallback when the API key is not configured.

### Step 4: Start the Application

```bash
npm run dev
```

Open your browser and visit:

```text
http://localhost:3000
```

## Running Automated Tests

The project includes a Python unittest suite covering event processing, threat detection, risk scoring, incident management, AI fallback handling, input sanitization, and ML evaluation.

Run the tests using:

```bash
python -m unittest tests/test_detection.py
```

## Important Implementation Notes and Limitations

- The project uses demonstration security event data for testing and evaluation.
- ML evaluation results on synthetic data do not establish real-world enterprise threat detection accuracy.
- Anomaly scoring is based on statistical feature analysis and predefined feature weights, not a production-trained deep learning model.
- AI-generated explanations are intended to support security investigation, not replace human security analysts.
- The platform does not automatically execute remediation commands or block network traffic.
- Detection results indicate potentially suspicious behavior and require further investigation.

## Future Enhancements

- Integration with real-time SIEM log sources.
- Advanced threat intelligence enrichment.
- Improved anomaly detection using real-world security datasets.
- Integration with network monitoring tools.
- Automated incident response workflows.
- Enhanced cloud security monitoring.

## Disclaimer

This project is developed for educational, research, and defensive cybersecurity purposes. It is not a replacement for enterprise-grade SIEM or Security Operations Center (SOC) solutions.

---

**Developed as a Cybersecurity & Digital Forensics project.**
