# Splunk AI Analyzer

A small Python project that monitors recent Windows failed-login events in Splunk, analyzes each event with a Gemini-powered retrieval-augmented generation (RAG) pipeline, and emails an alert when the result is classified as malicious.

> **Status:** Educational prototype. Validate detections and alerting in a test environment before using this with production logs. Model output can be inaccurate, and this project is not a substitute for a SIEM detection rule or incident-response process.

## Features

- Searches a configurable Splunk index for Windows Event ID 4625 events.
- Uses a local FAISS index built from `data/security_knowledge.txt` as retrieval context.
- Requests a structured verdict and reason from Google Gemini.
- Sends email alerts for malicious verdicts through configurable SMTP settings.
- Reads credentials from environment variables; secrets are not committed to the repository.

## Requirements

- Python 3.10 or newer
- A Splunk instance with access to the target index and events
- A Google AI API key
- An SMTP account if email notifications are needed

## Setup

1. Clone this repository and enter its directory.

   ```bash
   git clone https://github.com/<your-username>/splunk-ai-analyzer.git
   cd splunk-ai-analyzer
   ```

2. Create and activate a virtual environment.

   ```bash
   python -m venv .venv
   # Windows PowerShell
   .venv\Scripts\Activate.ps1
   # macOS / Linux
   source .venv/bin/activate
   ```

3. Install dependencies and create your local configuration.

   ```bash
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

   Copy `.env.example` to `.env`, then fill in the values for your environment. Keep `.env` private.

4. Build the local vector index. This calls Google's embedding API and may incur usage charges.

   ```bash
   python create_knowledge_base.py
   ```

5. Start monitoring.

   ```bash
   python main.py
   ```

Press `Ctrl+C` to stop the monitor.

## Configuration

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `GOOGLE_API_KEY` | Yes | — | Google AI API key for embeddings and Gemini |
| `SPLUNK_HOST` | Yes | — | Splunk management host name or IP |
| `SPLUNK_PORT` | No | `8089` | Splunk management port |
| `SPLUNK_SCHEME` | No | `https` | Splunk connection scheme |
| `SPLUNK_USERNAME` | Yes | — | Splunk account name |
| `SPLUNK_PASSWORD` | Yes | — | Splunk account password |
| `SPLUNK_INDEX` | No | `main` | Index to search |
| `SPLUNK_LOOKBACK_SECONDS` | No | `60` | Search window for each polling cycle |
| `SPLUNK_RESULT_LIMIT` | No | `10` | Maximum matching events per search |
| `POLL_INTERVAL_SECONDS` | No | `10` | Delay between searches |
| `GEMINI_MODEL` | No | `gemini-2.0-flash` | Gemini model name |
| `FAISS_INDEX_PATH` | No | `faiss_index` | Local vector index directory |
| `EMAIL_SENDER` | For email alerts | — | SMTP account used to send alerts |
| `EMAIL_PASSWORD` | For email alerts | — | SMTP password or app password |
| `EMAIL_RECEIVER` | For email alerts | — | Alert recipient |
| `SMTP_HOST` | No | `smtp.gmail.com` | SMTP server host |
| `SMTP_PORT` | No | `465` | SSL SMTP server port |
| `LOG_LEVEL` | No | `INFO` | Python logging level |

Email credentials are only needed if alerts are expected. For Gmail, use an app password rather than your normal account password.

## Detection behavior and limitations

The sample Splunk query deliberately searches for `EventCode=4625`, a Windows failed-logon event. The prompt also tells the model to classify that event code as `Malicious`; this is a demonstration rule, not a claim that every failed login is malicious. Tune the search and decision logic to your environment before relying on the results.

The process remembers event fingerprints only in memory. Restarting it clears that set, and overlapping searches can produce duplicate notifications after a restart. The Splunk query currently interpolates the configured index directly, so use a trusted index name in `.env`.

The FAISS index is generated locally and intentionally excluded from Git. It uses Python pickle metadata; only load an index you created yourself or otherwise trust. Rebuild it after changing the knowledge source.

## Project layout

```text
splunk-ai-analyzer/
├── data/
│   └── security_knowledge.txt
├── .env.example
├── .gitignore
├── create_knowledge_base.py
├── main.py
└── requirements.txt
```

## License

No license is included. Add a license file if you want to grant others specific reuse rights.
