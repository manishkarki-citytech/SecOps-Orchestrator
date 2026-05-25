# SecOps Orchestrator MVP

A lightweight, centralized platform that integrates with existing CI/CD tools and security scanners to automate security checks, aggregate findings, enforce policies, and provide a clear, actionable dashboard.

## Features

- **Pipeline Integration & Orchestration Engine**: Connects to CI/CD platforms via webhooks/APIs
- **Centralized Vulnerability Dashboard**: Single-pane-of-glass view for all security findings
- **Policy Definition & Enforcement**: Define and enforce security policies automatically
- **Developer Feedback Loop**: Integration with issue trackers and remediation advice

## Technical Stack

- **Backend**: FastAPI (Python), PostgreSQL, RabbitMQ
- **Frontend**: React (Vite)
- **Infrastructure**: Docker Compose

## Setup

1. Start services (use `docker compose` without hyphen):
   ```bash
   cd /home/citytech/Projects/SecOps-Orchestrator
   docker compose up -d
   ```

2. Run backend:
   ```bash
   cd backend && uvicorn main:app --reload
   ```

3. Run frontend:
   ```bash
   cd frontend && npm run dev
   ```

## API Endpoints

- `POST /scan-results/` - Ingest scan results
- `GET /dashboard/vulnerabilities/` - Get all vulnerabilities
- `GET /dashboard/stats/` - Get vulnerability statistics
- `POST /policies/check/` - Check policy compliance
- `POST /feedback/` - Create feedback ticket
- `GET /remediation/?severity=&vuln_type=` - Get remediation advice

## Dashboard

Access the dashboard at `http://localhost:5173`

## Policy Configuration

Policies are defined in `policies/security_policies.yaml`

## Test Data

Send a test scan result:
```bash
curl -X POST http://localhost:8000/scan-results/ \
  -H "Content-Type: application/json" \
  -d '{
    "scanner": "semgrep",
    "timestamp": "2026-05-25T12:00:00Z",
    "findings": [
      {
        "severity": "CRITICAL",
        "type": "SQL Injection",
        "description": "Unparameterized query in login endpoint",
        "project": "webapp",
        "repository": "myorg/webapp",
        "branch": "main"
      }
    ]
  }'
```
