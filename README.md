# 🛡️ SentinelCode AI — Automated Repository Security Auditor

**SentinelCode AI** is an autonomous DevSecOps agent and static application security testing (SAST) platform built with **Python 3.12**, **Streamlit**, and the **Google Gemini API** (`google-genai` SDK).

It allows developers and security auditors to scan public GitHub repositories or code snippets, detect critical security vulnerabilities (OWASP Top 10, logic flaws, hardcoded credentials, injection threats), generate automated security patches, and export executive PDF security reports.

---

## Key Features

- Automated GitHub Repository Scanning:** Ingests public repositories directly via GitHub ZIP archive endpoints.
- AI-Powered Vulnerability Analysis:** Leverages Gemini to inspect source code for security flaws, memory leaks, and unsafe dependencies.
- Single Snippet Quick Audit:** Fast-track security inspection for individual source code files or blocks.
- Automated Security Patching:** Generates verified fix recommendations and local testing guidelines.
- Executive PDF Security Reports:** Generates structured security audit reports ready for download.
- Streamlit Cloud Deployment:** Optimized for zero-downtime deployment with environment secret handling.

---

## Tech Stack

- **Frontend / UI:** [Streamlit](https://streamlit.io/)
- **AI Engine:** [Google Gemini API](https://ai.google.dev/) (`google-genai` Python SDK)
- **Runtime:** Python 3.12
- **Document Engine:** ReportLab / PyPDF

---

## Repository Structure

```text
├── app.py              # Streamlit dashboard & main application entrypoint
├── core_agent.py       # Gemini API client, repository fetcher, and audit logic
├── pdf_generator.py    # Executive PDF report builder
├── requirements.txt    # Project Python dependencies
└── README.md           # Project documentation

-Getting Started
​Prerequisites
​Ensure you have Python 3.12 installed on your system along with git.
​1. Installation
​-Clone the repository and install the required Python packages:
  +git clone [https://github.com/your-username/sentinelcode-ai.git](https://github.com/your-username/sentinelcode-ai.git)
  +cd sentinelcode-ai
  +pip install -r requirements.txt

2. Environment Configuration
​Create a .env file in the root directory and add your Gemini API Key:
   GEMINI_API_KEY="your_gemini_api_key_here"

Streamlit Cloud Setup:
When deploying to Streamlit Cloud, navigate to App Settings \rightarrow Secrets and add:
   GEMINI_API_KEY = "your_gemini_api_key_here"

3. Run Locally
​Launch the Streamlit web application:

  streamlit run app.py

-**The application will automatically open in your default browser at http://localhost:8501.

4.Usage Guide
​Enter GitHub URL: Paste a public GitHub repository link (e.g., https://github.com/fastapi/fastapi).
​Fetch & Audit: Click Fetch & Audit GitHub Repo to start the security inspection.
​Review Vulnerabilities: Inspect identified vulnerabilities, severity levels, affected files, and recommended patches.
​Export PDF: Click Download PDF Report to generate an executive audit document.
