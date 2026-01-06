# 🛡️ MalGuard - AdvancedWeb Malware Analysis Platform

**MalGuard** is a robust, microservices-based web application designed for real-time malware detection and analysis. It combines local heuristic engines with cloud-based intelligence (VirusTotal) to provide comprehensive protection against file-based threats.

![Dashboard Preview](https://via.placeholder.com/800x400?text=MalGuard+Dashboard+Preview)

## ✨ Key Features

- **🔍 Multi-Engine Scanning**: analysis using VirusTotal API integration.
- **🧠 Local Heuristics**: sophisticated local analysis checking for:
    - High Entropy (Packed/Encrypted/Ransomware detection).
    - Suspicious Double Extensions.
    - PE Header Anomalies.
- **⚡ Real-time Monitoring**: Watchdog-based service that monitors specific directories for new files and scans them instantly.
- **☢️ Auto-Quarantine**: Automatically isolates critical threats to a secure, encrypted quarantine vault.
- **📄 PDF Reports**: Generates professional, downloadable PDF reports for scan results.
- **📜 Audit Logs**: Centralized logging of all manual scans and background monitoring events.

## 🏗️ Architecture

The project is built as a set of **Microservices**:

1.  **Gateway Service (5050)**: API Gateway routing requests to internal services.
2.  **Scan Service (5051)**: Handles file uploads, local analysis, VT integration, and PDF generation.
3.  **Monitor Service (5052)**: Manages file system watching, logging, and quarantine operations.
4.  **History Service (5053)**: Persists scan results in a SQLite database.
5.  **Frontend**: Static HTML/JS application (decoupled from backend).

## 🚀 Quick Start (Local)

### Prerequisites
- Python 3.11+
- `pip`

### Installation

1.  **Clone the repository**
    ```bash
    git clone https://github.com/om-73/masterware.git
    cd masterware
    ```

2.  **Install Backend Dependencies**
    ```bash
    pip install -r backend/requirements.txt
    ```

3.  **Run Services**
    ```bash
    # Starts all microservices
    ./backend/run_services.sh
    ```

4.  **Run Frontend**
    ```bash
    # In a new terminal
    python -m http.server 8000 -d frontend
    ```

5.  **Access App**
    Open [http://localhost:8000](http://localhost:8000)

## ☁️ Deployment

- **Backend**: Ready for Docker deployment (e.g., Render). See [Dockerfile](./Dockerfile).
- **Frontend**: Ready for static hosting (e.g., Vercel, Netlify).

*For detailed deployment instructions, see [deployment.md](./deployment.md) (generated artifact).*

## 🔒 Configuration

Environment variables can be set in a `.env` file or your cloud provider:
- `VIRUSTOTAL_API_KEY`: Your VirusTotal API Key.
- `PORT`: (Optional) Port for the Gateway service.

## 🤝 Contributing

1.  Fork the repo
2.  Create your feature branch (`git checkout -b feature/amazing-feature`)
3.  Commit your changes (`git commit -m 'Add some amazing feature'`)
4.  Push to the branch (`git push origin feature/amazing-feature`)
5.  Open a Pull Request

---

