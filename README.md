# log-cluster-agent

SOC alert triage tool. Ingests raw security logs, clusters related events using ML + AI, and surfaces the distinct incidents a tier-1 analyst actually needs to review — cutting through alert fatigue.

## Features (planned)
- Ingest logs from files (CSV, JSON, syslog) or stdin
- Cluster related events using TF-IDF + k-means / DBSCAN
- AI-assisted cluster labelling via Gemini ("what kind of attack is this cluster?")
- Output ranked incident summary with severity estimate

## Stack
- Python 3.11+
- pandas (log ingestion + manipulation)
- scikit-learn (clustering)
- Google Gemini API (cluster labelling)
- Typer CLI + Rich

## Setup
```bash
pip install -r requirements.txt
cp .env.example .env  # add your GEMINI_API_KEY
python main.py --help
```
