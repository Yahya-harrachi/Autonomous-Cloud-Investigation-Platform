# 🔍 ACIP - Autonomous Cloud Investigation Platform

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-green.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.0%2B-61DAFB.svg)](https://reactjs.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15.0-336791.svg)](https://www.postgresql.org/)
[![AWS](https://img.shields.io/badge/AWS-CloudTrail%2C%20SQS%2C%20EventBridge-FF9900.svg)](https://aws.amazon.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **ACIP** is a production-ready security incident detection and investigation platform that automatically ingests AWS CloudTrail events, calculates severity scores using a configurable rule engine, creates incidents for high-risk events, collects comprehensive evidence from multiple AWS services, and provides a modern React dashboard with real-time updates and AI-powered investigation capabilities.

---

## 🎯 Key Features

### 🔄 Real-time Event Processing
- **AWS CloudTrail Integration**: Automatic ingestion of AWS API activity
- **EventBridge + SQS**: Scalable event buffering and routing
- **WebSocket Updates**: Live incident notifications without page refresh

### 🧠 Intelligent Severity Scoring
- **Configurable Rule Engine**: Event type, identity, context, and threat intelligence rules
- **Modifier System**: Identity (Root: 2.0x, Service Account: 0.8x) and Context (Off-hours: 2.0x, Public IP: 1.3x)
- **Threat Intelligence**: AbuseIPDB integration (Malicious: 2.5x, Suspicious: 1.8x)
- **Explainable AI**: Full reasoning in `severity_reason` field

### 📊 Comprehensive Evidence Collection

| Collector | Evidence Collected |
|-----------|---------------------|
| **CloudTrailCollector** | Events, timelines, attack patterns |
| **IAMCollector** | User details, MFA, access keys, policies |
| **IAMPolicyCollector** | Policy documents, permissions, risk analysis |
| **IAMRoleCollector** | Role details, trust policies |
| **S3Collector** | Bucket details, policy, encryption, public access |
| **EC2Collector** | Security groups, inbound/outbound rules, instances |

### 🔐 Integrity Verification
- **SHA-256 Hashing**: Every evidence artifact is cryptographically hashed
- **Auto-Verify**: Evidence is automatically verified on load
- **Tamper Detection**: Any modification to evidence is immediately detected

### 🤖 AI-Powered Investigation Assistant
- **Local LLM**: Runs Llama 3.2 3B locally via Ollama (no external API costs)
- **Natural Language Queries**: "Show me all critical incidents from today"
- **Tool-Based Architecture**: Controlled access to ACIP capabilities
- **No Hallucinations**: Strict enforcement of tool-only responses
- **Conversation Context**: Multi-turn investigations with context awareness

### 📱 Notifications & Alerts
- **Telegram Integration**: Real-time incident notifications
- **Incident Assignment**: Assign incidents to SOC analysts
- **Status Tracking**: Pending → Investigating → Completed → Resolved

### 📤 Export & Reporting
- **JSON Export**: Export incidents with all evidence
- **PDF Reports**: Professional incident investigation reports
- **Evidence Export**: Download evidence artifacts

### 🎨 Modern React Dashboard
- **Real-time Events**: Live event stream with LIVE badge
- **Incident Management**: Full CRUD with status filtering
- **Evidence Display**: All 6 evidence types with security findings
- **Timeline View**: Visual event timelines with 15+ events
- **Rule Management**: Create, edit, enable/disable risk rules
- **AI Chat Interface**: Natural language investigation assistant

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              ACIP ARCHITECTURE                                   │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                    │
│  AWS CloudTrail ──▶ EventBridge ──▶ SQS ──▶ ACIP Backend                          │
│                                                                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐        │
│  │                        Backend (FastAPI)                             │        │
│  │                                                                        │        │
│  │  SQS Consumer ──▶ Normalizer ──▶ Severity Engine ──▶ Incident        │        │
│  │                                                                        │        │
│  │  Incident ──▶ Evidence Orchestrator ──▶ Evidence Collectors          │        │
│  │                    │                                                   │        │
│  │                    ├── CloudTrailCollector                            │        │
│  │                    ├── IAMCollector                                   │        │
│  │                    ├── IAMPolicyCollector                             │        │
│  │                    ├── IAMRoleCollector                               │        │
│  │                    ├── S3Collector                                    │        │
│  │                    └── EC2Collector                                   │        │
│  │                                                                        │        │
│  │  PostgreSQL (Incidents, Evidence, Rules, Playbooks)                   │        │
│  │  WebSocket Server (Real-time updates)                                 │        │
│  │  AI Orchestrator (Llama 3.2 3B via Ollama)                            │        │
│  └─────────────────────────────────────────────────────────────────────┘        │
│                                     │                                             │
│                                     ▼                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐        │
│  │                        Frontend (React)                              │        │
│  │                                                                        │        │
│  │  Dashboard │ Incidents │ Live Events │ Rules │ AI Assistant           │        │
│  │                                                                        │        │
│  │  Evidence Display │ Timeline │ Integrity Verification                 │        │
│  │  Real-time WebSocket │ Export (JSON/PDF)                              │        │
│  └─────────────────────────────────────────────────────────────────────┘        │
│                                                                                    │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

```bash
# Required:
- Docker & Docker Compose
- Python 3.9+
- Node.js 18+
- AWS CLI (configured with credentials)
- PostgreSQL 15 (or use Docker)

# For AI Assistant:
- Ollama (local LLM)
- Llama 3.2 3B model
```

### 1. Clone the Repository

```bash
git clone https://github.com/Yahya-harrachi/Autonomous-Cloud-Investigation-Platform.git
cd Autonomous-Cloud-Investigation-Platform
```

### 2. Environment Configuration

```bash
cp backend/.env.example backend/.env
```

Edit `backend/.env`:

```env
# AWS Configuration
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_DEFAULT_REGION=us-east-1
AWS_ACCOUNT_ID=your_account_id

# Database
DATABASE_URL=postgresql://acip:acip@localhost:5432/acip

# AbuseIPDB (Threat Intelligence)
ABUSEIPDB_API_KEY=your_api_key

# Telegram Notifications
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Application
DEBUG=True
SECRET_KEY=your_secret_key
```

### 3. Start Services

```bash
# Start PostgreSQL and LocalStack
docker-compose up -d

# Install backend dependencies
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run database migrations
alembic upgrade head

# Start backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 4. Start Frontend

```bash
# In a new terminal
cd frontend
npm install
npm start
```

### 5. Start AI Assistant (Optional)

```bash
# Install Ollama (macOS)
brew install ollama

# Start Ollama service
ollama serve

# Pull Llama 3.2 3B model
ollama pull llama3.2:3b

# Verify model is available
ollama list
```

### 6. Access the Platform

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000/api
- **API Docs**: http://localhost:8000/docs

---

## 📊 Data Flow

### Incident Creation Flow

```
AWS Event → CloudTrail → EventBridge → SQS → ACIP Backend
    ↓
Normalize Event → Severity Engine → Decision Engine → Incident Created
    ↓
Evidence Orchestrator → Collectors → Evidence Artifacts → PostgreSQL
    ↓
WebSocket Broadcast → Frontend Display → Telegram Notification → SOC Analyst
```

### Evidence Collection Flow

```
Incident Created → Evidence Orchestrator → Playbook Selection
    ↓
Parallel Collection:
    ├── CloudTrailCollector (Events, Timeline, Patterns)
    ├── IAMCollector (User, MFA, Policies, Keys)
    ├── IAMPolicyCollector (Policy Documents, Permissions)
    ├── IAMRoleCollector (Role Details, Trust Policies)
    ├── S3Collector (Bucket, Policy, Encryption)
    └── EC2Collector (Security Groups, Rules, Instances)
    ↓
SHA-256 Hashing → Evidence Storage → Integrity Verification
    ↓
Frontend Display → AI Assistant → SOC Investigation
```

---

## 🛠️ Technology Stack

### Backend

| Technology | Purpose |
|------------|---------|
| FastAPI | REST API & WebSocket server |
| SQLAlchemy | PostgreSQL ORM |
| boto3 | AWS SDK for Python |
| Alembic | Database migrations |
| WebSocket | Real-time communication |
| Ollama | Local LLM for AI Assistant |
| ReportLab | PDF report generation |
| httpx | Async HTTP client for LLM |

### Frontend

| Technology | Purpose |
|------------|---------|
| React | UI framework |
| Tailwind CSS | Styling |
| Axios | HTTP client |
| WebSocket | Real-time updates |
| React Router | Navigation |

### Infrastructure

| Technology | Purpose |
|------------|---------|
| PostgreSQL | Primary database |
| AWS CloudTrail | Event source |
| AWS EventBridge | Event routing |
| AWS SQS | Event buffering |
| Docker | Containerization |

---

## 📁 Project Structure

```
acip/
├── backend/
│   ├── app/
│   │   ├── ai/
│   │   │   ├── orchestrator.py      # LLM orchestration
│   │   │   └── tools.py             # Tool registry
│   │   ├── api/
│   │   │   └── routes/
│   │   │       ├── incidents.py     # Incident endpoints
│   │   │       ├── evidence.py      # Evidence endpoints
│   │   │       ├── rules.py         # Rule management
│   │   │       └── ai.py            # AI chat endpoints
│   │   ├── domain/
│   │   │   └── models/              # Domain models
│   │   ├── evidence/
│   │   │   ├── collectors/          # Evidence collectors
│   │   │   ├── enrichers/           # Threat intelligence
│   │   │   └── orchestrator.py      # Evidence orchestration
│   │   ├── models/                  # SQLAlchemy models
│   │   ├── services/
│   │   │   ├── ollama_service.py    # Ollama communication
│   │   │   ├── pdf_generator.py     # PDF reports
│   │   │   └── telegram_notifier.py # Telegram notifications
│   │   └── main.py                  # FastAPI entry point
│   ├── migrations/                  # Alembic migrations
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── evidence/            # Evidence components
│   │   │   ├── ai/                  # AI chat component
│   │   │   └── layout/              # Layout components
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── IncidentDetail.jsx
│   │   │   ├── IncidentList.jsx
│   │   │   ├── LiveEvents.jsx
│   │   │   ├── RulesManagement.jsx
│   │   │   └── AIAssistant.jsx
│   │   └── services/
│   └── package.json
├── docker-compose.yml
└── README.md
```

---

## 🔐 Severity Scoring System

### Score Calculation

```
Final Score = Base Score × Identity Modifier × Context Modifier × Threat Intel Modifier
```

### Severity Mapping

| Score Range | Severity | Action |
|-------------|----------|--------|
| 70-100 | CRITICAL | Incident Created (Always) |
| 50-69 | HIGH | Incident Created (Always) |
| 30-49 | MEDIUM | Incident Created (if score ≥ 40) |
| 10-29 | LOW | No Incident |
| 0-9 | INFO | No Incident |

### Rule Types

| Rule Type | Description | Example |
|-----------|--------------|---------|
| Event Type | Base score per event | DeleteTrail: 40 |
| Identity | Modifier per identity | Root: 2.0x |
| Context | Modifier per context | Off-hours: 2.0x |
| Threat Intel | Modifier from AbuseIPDB | Malicious: 2.5x |

---

## 🤖 AI Assistant Features

### Available Tools

| Tool | Description |
|------|--------------|
| `search_incidents` | Search incidents by severity, status, or keyword |
| `get_incident` | Get detailed incident information |
| `get_incident_stats` | Get incident statistics |
| `get_incident_evidence` | Get all evidence for an incident |

### Example Queries

```
"Show me all critical incidents from today"
"How many incidents are pending?"
"Tell me about incident inc-72ccbbef-3c6"
"Give me the evidence for incident inc-72ccbbef-3c6"
"What's the latest incident?"
"Is there any incident today?"
```

---

## 📋 API Endpoints

### Incidents

| Method | Endpoint | Description |
|--------|----------|--------------|
| GET | `/api/incidents` | List incidents |
| GET | `/api/incidents/stats` | Get incident statistics |
| GET | `/api/incidents/{id}` | Get incident details |
| PATCH | `/api/incidents/{id}` | Update incident |
| GET | `/api/incidents/{id}/evidence` | Get incident evidence |
| GET | `/api/incidents/{id}/export` | Export incident with evidence |
| GET | `/api/incidents/{id}/export/pdf` | Export as PDF |

### Evidence

| Method | Endpoint | Description |
|--------|----------|--------------|
| POST | `/api/evidence/{id}/verify` | Verify evidence integrity |
| GET | `/api/evidence/{id}` | Get evidence artifact |
| GET | `/api/evidence/{id}/download` | Download evidence |

### AI Assistant

| Method | Endpoint | Description |
|--------|----------|--------------|
| POST | `/api/ai/chat` | Send message to AI |
| GET | `/api/ai/health` | Check AI service health |
| GET | `/api/ai/info` | Get AI system info |

---

## 🔧 Development

### Adding a New Evidence Collector

1. Create collector in `app/evidence/collectors/`
2. Register in `app/evidence/collectors/__init__.py`
3. Add to `EvidenceOrchestrator` in `app/evidence/orchestrator.py`
4. Update playbook in `app/evidence/playbooks/initial_data.py`
5. Add frontend summary component in `EvidenceCard.jsx`

### Adding a New Rule Type

1. Create rule handler in severity engine
2. Add rule type to `app/domain/models/rule.py`
3. Update rule management UI
4. Add rule evaluation in severity engine

### Running Tests

```bash
# Backend tests
cd backend
pytest tests/

# Frontend tests
cd frontend
npm test
```

---



## 🤝 Contributing

Contributions are welcome! Please read our Contributing Guide for details.

## 📞 Support

- **Documentation**: docs.acip.io
- **Issues**: GitHub Issues


## ⚠️ Disclaimer

This tool is designed for security investigation purposes. Users are responsible for ensuring they have appropriate authorization to monitor their AWS environments.

---

Built with ❤️ by the ACIP Team  - Harrachi Yahya & Msillane Yahya