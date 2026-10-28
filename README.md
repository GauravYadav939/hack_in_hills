<<<<<<< HEAD
# Glasshouse - AI Security Testing Environment

## Project Overview

Glasshouse is a security testing environment for AI models that demonstrates isolation, authorization, and audit logging in AI systems.

### Architecture

The system consists of four main components:

1. **Red Zone (Attacker)**: Sends potentially malicious prompts and attempts unauthorized access
2. **Blue Zone (Defender)**: Contains defensive resources and security tools
3. **Model Zone**: Runs the AI model (Ollama)
4. **Policy Broker**: Your component - the central security gateway

### Person 2 Responsibilities (This Component)

You are building the **Policy Broker** - the security heart of Glasshouse:

- FastAPI backend with authorization
- Capability token system
- Policy enforcement engine
- Ollama integration with tenant isolation
- Tamper-evident audit logging
- Timing normalization
- React dashboard
- Demo runner

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Docker and Docker Compose
- Ollama (for local AI)

### Installation

```bash
# 1. Install backend dependencies
cd backend
pip install -r requirements.txt

# 2. Generate cryptographic keys
python scripts/generate_keys.py

# 3. Configure environment
cp .env.example .env
# Edit .env with your settings

# 4. Install frontend dependencies
cd ../frontend
npm install

# 5. Start with Docker
cd ..
docker-compose up
```

### Running Tests

```bash
# Backend tests
cd backend
pytest tests/ -v

# Run demo
python scripts/demo_runner.py
```

## Project Structure

```
glasshouse/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI application
│   │   ├── models.py            # Pydantic models
│   │   ├── auth/
│   │   │   ├── tokens.py        # Capability tokens
│   │   │   └── policy.py        # Policy engine
│   │   ├── audit/
│   │   │   ├── logger.py        # Audit logging
│   │   │   └── verifier.py      # Chain verification
│   │   ├── ollama_client.py     # AI integration
│   │   └── config.py            # Configuration
│   ├── tests/
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   └── components/
│   └── package.json
├── config/
│   └── policy.json              # Authorization rules
├── scripts/
│   ├── generate_keys.py
│   ├── demo_runner.py
│   └── verify_audit.py
├── docker-compose.yml
└── .env.example
```

## API Endpoints

- `POST /infer` - Send prompts to AI with authorization
- `POST /payload` - Access protected test payloads
- `POST /defense` - Defense operations
- `GET /health` - Service health check
- `GET /events` - Retrieve audit events
- `GET /verify-log` - Verify audit log integrity

## Security Features

1. **Default-Deny Authorization**: Only explicitly allowed actions are permitted
2. **Cryptographic Tokens**: Signed, time-limited capability tokens
3. **Tenant Isolation**: Separate AI sessions per tenant
4. **Tamper-Evident Logging**: Hash-chained audit log with signatures
5. **Timing Normalization**: Response time padding to reduce side channels

## Integration with Team

- **Person 1 (Docker/Infrastructure)**: Provides container isolation and networking
- **Person 3 (Policy/Testing)**: Provides policy files and attack test suite

## Documentation

See `/docs` for detailed documentation:
- API specification
- Token format
- Policy file format
- Audit log schema
- Setup and troubleshooting

## Development Status

Building Phase C: Core backend implementation

## License

Educational project for security testing demonstration
=======
# hack_in_hills
>>>>>>> 8b3668b43dde7b330f8d3950eeb5f19b39cc7208
