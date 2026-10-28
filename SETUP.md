# Glasshouse Setup and Usage Guide

## Overview

This guide will help you set up and run your Person 2 component of the Glasshouse project: the Policy Broker, audit logging, and dashboard.

## Prerequisites

Make sure you have installed:
- **Python 3.11+** (for backend development)
- **Node.js 18+** (for frontend development)
- **Docker and Docker Compose** (for deployment)
- **Git** (for version control)

## Quick Start (5 Minutes)

### 1. Generate Cryptographic Keys

```bash
cd backend
python scripts/generate_keys.py
```

Copy the output keys and add them to your `.env` file.

### 2. Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env and paste the keys you just generated
nano .env  # or use your preferred editor
```

Make sure these variables are set:
```bash
TOKEN_SIGNING_KEY=<your_generated_key>
AUDIT_SIGNING_KEY=<your_generated_key>
```

### 3. Start with Docker

```bash
# Build and start all services
docker-compose up -d

# Pull and run the Ollama model (first time only)
docker exec -it glasshouse-ollama ollama pull llama3.2:3b
```

### 4. Verify Everything Works

Open your browser:
- **Dashboard**: http://localhost:3000
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

### 5. Run the Demo

```bash
# Wait a minute for services to be fully ready
sleep 60

# Run the security demo
cd scripts
python demo_runner.py
```

You should see test results showing authorized and unauthorized requests!

---

## Development Setup (Without Docker)

If you want to develop without Docker:

### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Generate keys
python scripts/generate_keys.py

# Configure .env (as above)
cp ../.env.example ../.env
# Edit .env with your keys

# Run the broker
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm start
```

The dashboard will open at http://localhost:3000

### Ollama Setup (Local)

```bash
# Install Ollama from https://ollama.ai
# Or use Docker:
docker run -d -p 11434:11434 --name ollama ollama/ollama

# Pull the model
ollama pull llama3.2:3b
```

---

## Running Tests

### Backend Tests

```bash
cd backend
pytest tests/ -v

# With coverage
pytest tests/ --cov=app --cov-report=html
```

### Test Audit Log Verification

```bash
cd scripts
python verify_audit.py
```

### Timing Normalization Benchmark

```bash
cd scripts
python timing_benchmark.py
```

---

## Using the System

### 1. Access the Dashboard

Open http://localhost:3000 to see:
- Zone status (Red, Blue, Model, Broker)
- Real-time event feed
- Request statistics
- Audit log verification
- Attack test results

### 2. Make API Requests

#### Health Check
```bash
curl http://localhost:8000/health
```

#### Inference Request (Requires Token)
```python
import requests

# You'll need to generate a token (see Token Management below)
response = requests.post("http://localhost:8000/infer", json={
    "prompt": "Hello, how are you?",
    "tenant_id": "demo-tenant",
    "zone": "blue",
    "token": "<your_token_here>"
})

print(response.json())
```

### 3. Token Management

Tokens are issued programmatically. For development:

```python
from app.auth.tokens import create_dev_token
from app.models import Zone

# Create a development token
signing_key, token = create_dev_token(tenant_id="test-tenant", zone=Zone.BLUE)

print(f"Token: {token}")
```

### 4. Check Audit Log

```bash
# Via API
curl http://localhost:8000/events?limit=50

# Via script
cd scripts
python verify_audit.py
```

### 5. Run the Demo Suite

```bash
cd scripts
python demo_runner.py --output results.json
```

This runs all 5 demonstration steps and produces a JSON report.

---

## API Endpoints

### Core Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/` | API information | No |
| `GET` | `/health` | Health check | No |
| `POST` | `/infer` | AI inference | Yes |
| `POST` | `/payload` | Access protected payloads | Yes |
| `POST` | `/defense` | Defense operations | Yes |
| `GET` | `/events` | Retrieve audit events | No |
| `GET` | `/verify-log` | Verify audit integrity | No |
| `GET` | `/docs` | OpenAPI documentation | No |

### Request Format Example

```json
{
  "prompt": "What is AI security?",
  "tenant_id": "demo-tenant",
  "zone": "blue",
  "token": "eyJhbGc..."
}
```

### Response Format Example

```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "response": "AI security involves...",
  "tenant_id": "demo-tenant",
  "processing_time_ms": 2000.5
}
```

---

## Policy Configuration

The policy file is located at `config/policy.json`. It controls what each zone can do.

### Policy Structure

```json
{
  "version": "1.0.0",
  "default_decision": "deny",
  "rules": [
    {
      "name": "blue-can-infer",
      "source_zone": "blue",
      "action": "infer",
      "allowed": true,
      "conditions": {}
    }
  ]
}
```

### Modifying Policy

1. Edit `config/policy.json`
2. Restart the broker (or it will auto-reload on next request)
3. Test with the demo runner

**Security Note**: The default policy follows "default-deny" - anything not explicitly allowed is blocked.

---

## Troubleshooting

### Problem: "TOKEN_SIGNING_KEY is not configured"

**Solution**: Run `python scripts/generate_keys.py` and add the keys to `.env`

### Problem: "Ollama not responding"

**Solutions**:
1. Check Ollama is running: `docker ps | grep ollama`
2. Check the model is downloaded: `docker exec glasshouse-ollama ollama list`
3. Pull the model: `docker exec glasshouse-ollama ollama pull llama3.2:3b`

### Problem: "Policy file not found"

**Solution**: Make sure `config/policy.json` exists. The example is included in the repository.

### Problem: Dashboard shows "Cannot connect to broker"

**Solutions**:
1. Check broker is running: `curl http://localhost:8000/health`
2. Check nginx proxy configuration in frontend
3. Check CORS settings in the broker

### Problem: Tests failing

**Solutions**:
1. Make sure you're in a virtual environment
2. Install test dependencies: `pip install pytest pytest-asyncio`
3. Check that temporary files can be created

### Problem: Audit log verification fails

This could be intentional! The verification is designed to detect tampering. Check:
1. Has the database been modified manually?
2. Have the signing keys changed?
3. Is this a test of the tamper detection? (If so, it's working!)

---

## Integration with Team

### For Person 1 (Docker/Infrastructure)

I've provided:
- `docker-compose.yml` with the broker service
- Service name: `broker` on `glasshouse-network`
- Exposed ports: 8000 (API)
- Environment variables required (in `.env`)

You'll need to:
- Integrate the red and blue zone containers
- Set up network isolation between zones
- Ensure only the broker can communicate with Ollama

### For Person 3 (Policy/Testing)

I've provided:
- Policy file format (`config/policy.json`)
- Attack test JSON format (see `demo_runner.py` output)
- API endpoints for testing (`/infer`, `/payload`, `/defense`)
- Audit log format for verification

You'll need to:
- Create comprehensive policy rules
- Build your attack test suite
- Generate test results JSON for the dashboard

---

## Security Notes

### What This Provides

✓ **Default-deny authorization** - Only explicitly allowed actions succeed
✓ **Cryptographic tokens** - Signed with NaCl, short-lived
✓ **Tenant isolation** - Separate AI sessions per tenant
✓ **Tamper-evident logging** - Hash chain + signatures
✓ **Timing normalization** - Configurable response padding

### Limitations (Be Honest)

⚠ **Token system**: Tokens are signed but not encrypted; don't put secrets in them
⚠ **Audit log**: Tamper-evident but not tamper-proof; attacker with DB + key access can rewrite
⚠ **Timing normalization**: Reduces variance but doesn't eliminate all timing channels
⚠ **Ollama isolation**: We control conversation history; internal Ollama caching is implementation-dependent
⚠ **Container isolation**: API-level enforcement; true isolation requires Docker networking (Person 1)

### Production Considerations

For a real deployment:
1. Use a proper secret management system (not .env files)
2. Enable HTTPS/TLS
3. Implement rate limiting
4. Add authentication/session management
4. Export audit logs to external storage
6. Use production-grade database (PostgreSQL instead of SQLite)
7. Implement log rotation and backup
8. Add monitoring and alerting

---

## Next Steps

1. **Run the tests**: `pytest backend/tests/ -v`
2. **Start the system**: `docker-compose up -d`
3. **Run the demo**: `python scripts/demo_runner.py`
4. **Check the dashboard**: http://localhost:3000
5. **Read API docs**: http://localhost:8000/docs
6. **Integrate with Person 1 and Person 3**

---

## Questions?

Key files to understand:
- `backend/app/main.py` - FastAPI application and endpoints
- `backend/app/auth/policy.py` - Authorization engine
- `backend/app/auth/tokens.py` - Capability tokens
- `backend/app/audit/logger.py` - Audit logging
- `backend/app/ollama_client.py` - AI integration
- `frontend/src/App.jsx` - Dashboard UI

Good luck with your Glasshouse project! 🏛️
