# SEPSES Cybersecurity Knowledge Graph Chatbot

SEPSES Cybersecurity Knowledge Graph Chatbot is an LLM-based cybersecurity analysis assistant that integrates Large Language Models (LLMs) with the [SEPSES Cybersecurity Knowledge Graph (CSKG)](https://github.com/sepses/cyber-kg-converter) to provide explainable and context-aware cybersecurity analysis.

Unlike general-purpose AI chatbots that rely only on pretrained language knowledge, this system utilizes structured cybersecurity knowledge from SEPSES CSKG combined with Retrieval-Augmented Generation (RAG) / GraphRAG mechanisms to reduce hallucination and improve analytical accuracy.

The chatbot supports cybersecurity question-answering, threat actor analysis, malware investigation, vulnerability relationship analysis, and security log analysis.

---

## Team Members

| Name | Student ID | Role |
|---|---|---|
| Diayu Nur Aini | 24/537751/PA/22792 |Frontend & UI/UX |
| Freta Yordinia Laura | 24/533444/PA/22576 | Backend & KG Integration |
| Herlina Iin Nur Soleha | 24/541333/PA/22962 | NLP & Security Analysis |
| Ananda Auliya Rahma | 24/533691/PA/22608 | Model Evaluation & Technical Documentation |

---

## Project Objectives

- Integrate SEPSES CSKG with LLMs for cybersecurity analysis
- Implement GraphRAG / RAG architecture
- Support explainable cybersecurity question-answering
- Analyze relationships between vulnerabilities, malware, threat actors, and attacks
- Evaluate multiple LLMs for cybersecurity tasks
- Provide an interactive chatbot interface for analysts and researchers

---

## Features

### Cybersecurity Question Answering
- Ask cybersecurity-related questions using natural language
- Retrieve structured information from SEPSES CSKG
- Generate explainable responses with graph context

### Threat Actor Analysis
- Analyze threat actors and associated attack patterns
- Discover related malware, vulnerabilities, and campaigns

### Malware Investigation
- Investigate malware families and their behaviors
- Explore malware relationships within the knowledge graph

###  Vulnerability Relationship Analysis
- Analyze CVE relationships
- Discover affected systems, attack vectors, and linked malware

###  Security Log Analysis
- Upload and analyze local security logs
- Combine vector database retrieval with LLM reasoning

###  RAG / GraphRAG Integration
- Knowledge retrieval from RDF/SPARQL resources
- Context-aware answer generation using LLMs

---

## System Overview

The system consists of the following components:

- **Frontend Interface** — User chatbot interface (Next.js 15)
- **Backend Service** — Handles query processing and LLM orchestration (FastAPI + LangChain)
- **Knowledge Retrieval Layer**
  - SPARQL queries to SEPSES CSKG (public endpoint + Virtuoso fallback)
  - RDF/Turtle graph traversal
  - Vector database retrieval (ChromaDB)
- **LLM Layer**
  - Gemini-2.5-Flash (cloud) via Google AI API
  - Llama3.2:3b (local) via Ollama
- **RAG / GraphRAG Pipeline**
  - Combines retrieved graph data + semantic search results
  - Feeds structured context into LLM for final response
### Analysis Modes

| Mode | Sources Activated |
|---|---|
| `threat_intelligence` | SPARQL → SEPSES CSKG + MITRE ATT&CK |
| `log_analysis` | ChromaDB (local logs) |
| `combined` | SPARQL + MITRE ATT&CK + ChromaDB |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 15 (TypeScript, React) |
| Backend | FastAPI + LangChain (Python) |
| LLM Cloud | Gemini-2.5-Flash via Google AI API |
| LLM Local | Llama3.2:3b via Ollama |
| Knowledge Graph | SEPSES CSKG (public SPARQL endpoint) |
| KG Fallback | Virtuoso 7 (Docker, local RDF store) |
| Threat Intel | MITRE ATT&CK Enterprise (STIX 2.0 JSON) |
| Vector DB | ChromaDB (semantic log search) |
| Infra | Docker Compose |

---

## Getting Started

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) & Docker Compose
- A **Gemini API key** from [Google AI Studio](https://aistudio.google.com/)
- *(Optional)* [Ollama](https://ollama.com/) installed locally for `llama3.2:3b`

### 1. Clone the Repository

```bash
git clone https://github.com/Software-Engineering-2026-Class/Kel9-LLM-Chatbot-SEPSESCSKG.git
cd Kel9-LLM-Chatbot-SEPSESCSKG
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` and fill in your credentials:

```env
GEMINI_API_KEY=your_gemini_api_key_here
DEFAULT_MODEL=gemini:gemini-2.5-flash

# Optional: Ollama (if running locally)
OLLAMA_BASE_URL=http://host.docker.internal:11434
```

### 3. Download MITRE ATT&CK Dataset

```bash
python scripts/download_mitre.py
```

Downloads `enterprise-attack.json` (~60 MB STIX bundle) into `data/`.

### 4. Start All Services

```bash
docker compose up --build
```

Starts four services: `virtuoso`, `virtuoso-loader`, `backend` (port 8000), and `frontend` (port 3000). First startup may take 2–5 minutes as ChromaDB embeds `sample_logs.txt` automatically.

### 5. Open the App

-
---
## Running Locally (Development)

> You will need **5 terminals** running simultaneously. Do not close terminals 2, 3, and 4.

### Terminal 1 — Setup & Frontend Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
python scripts/download_mitre.py
cd frontend
npm install
```

### Terminal 2 — Docker (keep open)

```bash
docker compose up --build
```

### Terminal 3 — Ollama Server (keep open)

```bash
ollama serve
```

### Terminal 4 — Ollama Model (keep open)

```bash
ollama run llama3.2:3b
```

> Terminals 3 & 4 can be separate tabs in the same terminal app.

### Terminal 5 — Frontend Dev Server (keep open)

```bash
npm run dev
```

> Alternatively, run `npm run dev` as a tab in Terminal 1 after `npm install` finishes.

---
## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/chat` | Chat with one LLM |
| `POST` | `/api/compare` | Compare two LLMs side-by-side |
| `POST` | `/api/logs` | Upload new log file to ChromaDB |
| `GET` | `/api/logs/stats` | Log statistics per type |
| `DELETE` | `/api/logs` | Reset ChromaDB |
| `POST` | `/api/kg` | Test NL2SPARQL query generation |

---

## Evaluation

Benchmarks both LLMs on 10 cybersecurity questions across 3 categories. Run with:

```bash
python -m evaluation.run_eval
```

**Composite score** = Accuracy×30% + Hallucination×30% + Relevance×20% + Completeness×20%

| Metric | Gemini-2.5-Flash | Llama3.2:3b |
|---|---|---|
| Accuracy (avg/2) | **1.90** | 1.80 |
| Hallucination ↑ (avg/2) | **1.80** | 1.40 |
| Relevance (avg/2) | 1.60 | **1.70** |
| Completeness (avg/2) | **1.90** | 1.70 |
| Avg latency | **12.81s** | 47.42s |
| Fabricated CVEs | **1** | 4 |

> ↑ Higher hallucination score = less hallucination (better). Gemini wins on accuracy, completeness, and speed. Llama is better for air-gapped/offline deployments at zero API cost.

---
## Project Structure

```text
Kel9-LLM-Chatbot-SEPSESCSKG/

├── frontend/                  # Next.js 15 app
│   └── src/app/
│       ├── chat/              # Main chat interface
│       ├── analysis/          # Evaluation dashboard & charts
│       ├── graph/             # KG triple visualization
│       └── sidebar/           # Session nav & model picker
│
├── backend/                   # FastAPI application
│   ├── main.py                # Entry point, REST endpoints
│   ├── config.py              # Env vars & model config
│   ├── patterns.py            # Regex: CVE/CWE/entity detection
│   ├── pipeline/
│   │   ├── orchestrator.py    # Query router + RAG orchestration
│   │   └── prompts.py         # System prompts per mode
│   ├── sources/
│   │   ├── sparql.py          # SPARQL client
│   │   ├── mitre.py           # MITRE ATT&CK integration
│   │   └── logs.py            # Log ingestion & search
│   └── llm/
│       └── llm_models.py      # Gemini + Ollama via LangChain
│
├── evaluation/                # LLM benchmarking scripts
│   ├── questions.py
│   ├── scoring.py
│   ├── llm_eval.py
│   ├── run_eval.py
│   └── report_generator.py
│
├── data/
│   ├── cskg_dumps/            # Virtuoso TTL dumps
│   ├── enterprise-attack.json # MITRE ATT&CK data
│   └── sample_logs.txt
│
├── scripts/
│   ├── download_mitre.py
│   ├── virtuoso_init.sh
│   └── generate_schema_report.py
│
├── docker-compose.yml
└── .env.example
```

## Dataset & Knowledge Sources

Primary dataset: **SEPSES Cybersecurity Knowledge Graph (CSKG)**
- GitHub: https://github.com/sepses/cyber-kg-converter

### Vocabularies

| Prefix | Description | Link |
|---|---|---|
| `capec` | Common Attack Pattern Enumeration and Classification | http://w3id.org/sepses/vocab/ref/capec |
| `cwe` | Common Weakness Enumeration | http://w3id.org/sepses/vocab/ref/cwe |
| `cve` | Common Vulnerabilities and Exposures | http://w3id.org/sepses/vocab/ref/cve |
| `cvss` | Common Vulnerability Scoring System | http://w3id.org/sepses/vocab/ref/cvss |
| `cpe` | Common Platform Enumeration | http://w3id.org/sepses/vocab/ref/cpe |

---

## Access Services

Example queries are available in `example-queries.txt`, testable on the [SPARQL endpoint](https://w3id.org/sepses/sparql).

Other interfaces:
- [Linked Data Interface](https://sepses.ifs.tuwien.ac.at/resource/cve/CVE-2018-4449) (example)
- [Triple Pattern Fragments](http://ldf-server.sepses.ifs.tuwien.ac.at/)
- [Dump files](https://sepses.ifs.tuwien.ac.at/index.php/datasets/) (`.turtle` and `.HDT`)

---

## References

- Kiesling et al., *The SEPSES Knowledge Graph: An Integrated Resource for Cybersecurity*, ISWC 2019 — [link](https://link.springer.com/chapter/10.1007/978-3-030-30796-7_13)
- Kurniawan et al., *The ICS-SEC KG*, ISWC 2024 — [link](https://eprints.cs.univie.ac.at/8177/1/ISWC24_ICS-SEC__Andreas%20Ekelhart.pdf)
- Kurniawan et al., *AgCyRAG: An Agentic KG-based RAG Framework*, RAGE-KG 2025 — [link](https://ceur-ws.org/Vol-4079/paper11.pdf)
- Lewis et al., *Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks*, NeurIPS 2020

---

## License

Released under the [MIT License](http://opensource.org/licenses/MIT).

