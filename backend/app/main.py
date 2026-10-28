"""
Glasshouse Policy Broker - Main FastAPI Application

This is the central security gateway for the Glasshouse AI testing environment.
It enforces authorization, logs all requests, and provides controlled access
to the Ollama AI model.

Architecture:
- Policy-based authorization (default deny)
- Cryptographic capability tokens
- Tamper-evident audit logging
- Tenant isolation
- Timing normalization

Person 2 Component - Integrates with:
- Person 1: Docker networking and container isolation
- Person 3: Policy files and attack test suite
"""

import uuid
import asyncio
from datetime import datetime
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.models import (
    InferRequest, InferResponse,
    PayloadRequest, PayloadResponse,
    DefenseRequest, DefenseResponse,
    HealthResponse, ErrorResponse,
    EventsResponse, AuditEvent,
    VerificationResult,
    AuthorizationDecision, Zone, Action
)
from app.auth import CapabilityTokenManager, PolicyEngine, TokenError
from app.audit import AuditLogger
from app.ollama_client import get_ollama_client


# ============================================================================
# Global State
# ============================================================================

# Initialize core components
token_manager: Optional[CapabilityTokenManager] = None
policy_engine: Optional[PolicyEngine] = None
audit_logger: Optional[AuditLogger] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.

    Initializes security components on startup and cleans up on shutdown.
    """
    global token_manager, policy_engine, audit_logger

    print("\n" + "=" * 70)
    print("Starting Glasshouse Policy Broker")
    print("=" * 70)

    # Initialize token manager
    try:
        token_manager = CapabilityTokenManager(
            signing_key_b64=settings.token_signing_key,
            expiration_seconds=settings.token_expiration_seconds
        )
        print("✓ Token manager initialized")
    except Exception as e:
        print(f"✗ Failed to initialize token manager: {e}")
        raise

    # Initialize policy engine
    try:
        policy_engine = PolicyEngine(settings.policy_file_path)
        print("✓ Policy engine initialized")
    except Exception as e:
        print(f"✗ Failed to initialize policy engine: {e}")
        raise

    # Initialize audit logger
    try:
        audit_logger = AuditLogger(
            db_path=settings.audit_db_path,
            signing_key_b64=settings.audit_signing_key
        )
        print("✓ Audit logger initialized")
    except Exception as e:
        print(f"✗ Failed to initialize audit logger: {e}")
        raise

    # Initialize Ollama client
    try:
        ollama = get_ollama_client(
            base_url=settings.ollama_base_url,
            model=settings.ollama_model,
            timeout=settings.ollama_timeout
        )
        health = await ollama.check_health()
        if health:
            print(f"✓ Ollama connected: {settings.ollama_base_url}")
            print(f"  Model: {settings.ollama_model}")
        else:
            print(f"⚠ Ollama not responding: {settings.ollama_base_url}")
            print("  (Broker will start but /infer will fail)")
    except Exception as e:
        print(f"⚠ Ollama check failed: {e}")

    print(f"\n✓ Broker ready on {settings.broker_host}:{settings.broker_port}")
    print("=" * 70 + "\n")

    yield

    # Cleanup
    print("\nShutting down Glasshouse Broker...")
    ollama = get_ollama_client(settings.ollama_base_url, settings.ollama_model)
    await ollama.close()


# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(
    title="Glasshouse Policy Broker",
    description="Security gateway for AI testing environment",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Helper Functions
# ============================================================================

def generate_request_id() -> str:
    """Generate unique request ID."""
    return str(uuid.uuid4())


async def apply_timing_normalization(actual_time_seconds: float) -> float:
    """
    Apply timing normalization if enabled.

    Pads the response time to a fixed target to reduce timing side channels.

    Returns:
        Total time including padding
    """
    if not settings.timing_normalization_enabled:
        return actual_time_seconds

    target = settings.timing_normalization_target

    if actual_time_seconds < target:
        padding = target - actual_time_seconds
        await asyncio.sleep(padding)
        return target

    return actual_time_seconds


async def authorize_request(
    token: str,
    tenant_id: str,
    zone: Zone,
    action: Action,
    request_id: str
) -> tuple[bool, str]:
    """
    Authorize a request using token verification and policy evaluation.

    Returns:
        Tuple of (authorized, reason)
    """
    # Step 1: Verify and check token
    authorized, reason, claims = token_manager.check_authorization(
        token=token,
        required_tenant=tenant_id,
        required_zone=zone,
        required_action=action
    )

    if not authorized:
        await audit_logger.log_event(
            request_id=request_id,
            tenant_id=tenant_id,
            zone=zone,
            action=action,
            decision=AuthorizationDecision.DENY,
            reason=f"Token check failed: {reason}",
            outcome="blocked"
        )
        return False, reason

    # Step 2: Check policy
    policy_decision = policy_engine.evaluate(
        tenant_id=tenant_id,
        zone=zone,
        action=action
    )

    if not policy_decision.is_allowed():
        await audit_logger.log_event(
            request_id=request_id,
            tenant_id=tenant_id,
            zone=zone,
            action=action,
            decision=AuthorizationDecision.DENY,
            reason=f"Policy denied: {policy_decision.reason}",
            outcome="blocked"
        )
        return False, policy_decision.reason

    # Authorized - log it
    await audit_logger.log_event(
        request_id=request_id,
        tenant_id=tenant_id,
        zone=zone,
        action=action,
        decision=AuthorizationDecision.ALLOW,
        reason=policy_decision.reason,
        outcome="authorized"
    )

    return True, policy_decision.reason


# ============================================================================
# API Endpoints
# ============================================================================

@app.post("/infer", response_model=InferResponse)
async def infer(request: InferRequest):
    """
    Perform AI inference with authorization and audit logging.

    This endpoint:
    1. Verifies the capability token
    2. Checks policy authorization
    3. Forwards the prompt to Ollama (if authorized)
    4. Logs everything to the audit log
    5. Applies timing normalization
    """
    request_id = generate_request_id()
    start_time = datetime.utcnow()

    try:
        # Authorize the request
        authorized, reason = await authorize_request(
            token=request.token,
            tenant_id=request.tenant_id,
            zone=request.zone,
            action=Action.INFER,
            request_id=request_id
        )

        if not authorized:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Unauthorized: {reason}"
            )

        # Get Ollama client
        ollama = get_ollama_client(
            settings.ollama_base_url,
            settings.ollama_model,
            settings.ollama_timeout
        )

        # Generate response
        try:
            result = await ollama.generate(
                tenant_id=request.tenant_id,
                prompt=request.prompt,
                use_history=True
            )

            response_text = result["response"]
            actual_processing_time = result["processing_time_seconds"]

            # Log successful inference
            await audit_logger.log_event(
                request_id=request_id,
                tenant_id=request.tenant_id,
                zone=request.zone,
                action=Action.INFER,
                decision=AuthorizationDecision.ALLOW,
                reason="Inference completed",
                outcome="success"
            )

        except Exception as e:
            # Log failure
            await audit_logger.log_event(
                request_id=request_id,
                tenant_id=request.tenant_id,
                zone=request.zone,
                action=Action.INFER,
                decision=AuthorizationDecision.ALLOW,
                reason="Inference attempted",
                outcome=f"error: {str(e)}"
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"AI model unavailable: {str(e)}"
            )

        # Apply timing normalization
        total_time = (datetime.utcnow() - start_time).total_seconds()
        normalized_time = await apply_timing_normalization(total_time)

        return InferResponse(
            request_id=request_id,
            response=response_text,
            tenant_id=request.tenant_id,
            processing_time_ms=normalized_time * 1000
        )

    except HTTPException:
        raise
    except Exception as e:
        await audit_logger.log_event(
            request_id=request_id,
            tenant_id=request.tenant_id,
            zone=request.zone,
            action=Action.INFER,
            decision=AuthorizationDecision.DENY,
            reason="Internal error",
            outcome=f"error: {str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@app.post("/payload", response_model=PayloadResponse)
async def payload(request: PayloadRequest):
    """
    Access protected test payloads.

    This endpoint provides access to sensitive test data that only
    authorized zones (typically Blue zone) should be able to access.
    """
    request_id = generate_request_id()

    try:
        # Authorize the request
        authorized, reason = await authorize_request(
            token=request.token,
            tenant_id=request.tenant_id,
            zone=request.zone,
            action=Action.PAYLOAD,
            request_id=request_id
        )

        if not authorized:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Unauthorized: {reason}"
            )

        # Simulate payload retrieval
        # In a real system, this would fetch actual test data
        payload_data = {
            "payload_id": request.payload_id,
            "description": "Protected test payload",
            "data": f"Sensitive data for {request.payload_id}",
            "accessed_by": request.tenant_id,
            "zone": request.zone.value
        }

        # Log successful access
        await audit_logger.log_event(
            request_id=request_id,
            tenant_id=request.tenant_id,
            zone=request.zone,
            action=Action.PAYLOAD,
            decision=AuthorizationDecision.ALLOW,
            reason="Payload accessed",
            outcome="success"
        )

        return PayloadResponse(
            request_id=request_id,
            payload_id=request.payload_id,
            data=payload_data
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@app.post("/defense", response_model=DefenseResponse)
async def defense(request: DefenseRequest):
    """
    Perform defense operations.

    This endpoint provides access to defensive capabilities that only
    authorized zones (typically Blue zone) should be able to use.
    """
    request_id = generate_request_id()

    try:
        # Authorize the request
        authorized, reason = await authorize_request(
            token=request.token,
            tenant_id=request.tenant_id,
            zone=request.zone,
            action=Action.DEFENSE,
            request_id=request_id
        )

        if not authorized:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Unauthorized: {reason}"
            )

        # Simulate defense operation
        # In a real system, this would perform actual defensive actions
        result_data = {
            "operation": request.operation,
            "status": "completed",
            "performed_by": request.tenant_id,
            "parameters": request.parameters,
            "timestamp": datetime.utcnow().isoformat()
        }

        # Log successful operation
        await audit_logger.log_event(
            request_id=request_id,
            tenant_id=request.tenant_id,
            zone=request.zone,
            action=Action.DEFENSE,
            decision=AuthorizationDecision.ALLOW,
            reason=f"Defense operation: {request.operation}",
            outcome="success"
        )

        return DefenseResponse(
            request_id=request_id,
            operation=request.operation,
            result=result_data
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@app.get("/health", response_model=HealthResponse)
async def health():
    """
    Health check endpoint.

    Returns the status of the broker and its dependencies.
    No authorization required - anyone can check health.
    """
    # Check Ollama availability
    ollama = get_ollama_client(
        settings.ollama_base_url,
        settings.ollama_model
    )
    ollama_available = await ollama.check_health()

    # Check if audit log is writable
    audit_writable = True
    try:
        test_id = generate_request_id()
        await audit_logger.log_event(
            request_id=test_id,
            tenant_id="health-check",
            zone=Zone.BROKER,
            action=Action.HEALTH,
            decision=AuthorizationDecision.ALLOW,
            reason="Health check",
            outcome="success"
        )
    except:
        audit_writable = False

    return HealthResponse(
        status="healthy" if (ollama_available and audit_writable) else "degraded",
        timestamp=datetime.utcnow(),
        ollama_available=ollama_available,
        audit_log_writable=audit_writable
    )


@app.get("/events", response_model=EventsResponse)
async def events(limit: int = 100):
    """
    Retrieve recent audit events.

    Used by the dashboard to display recent activity.
    """
    try:
        events_data = await audit_logger.get_recent_events(limit=limit)
        total_count = await audit_logger.get_event_count()

        # Convert to Pydantic models
        audit_events = [
            AuditEvent(
                id=e["id"],
                request_id=e["request_id"],
                timestamp=datetime.fromisoformat(e["timestamp"]),
                tenant_id=e["tenant_id"],
                zone=Zone(e["zone"]),
                action=Action(e["action"]),
                decision=AuthorizationDecision(e["decision"]),
                reason=e["reason"],
                outcome=e["outcome"],
                previous_hash=e["previous_hash"],
                current_hash=e["current_hash"],
                signature=e["signature"]
            )
            for e in events_data
        ]

        return EventsResponse(
            events=audit_events,
            total_count=total_count
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve events: {str(e)}"
        )


@app.get("/verify-log", response_model=VerificationResult)
async def verify_log():
    """
    Verify audit log integrity.

    Checks the hash chain and signatures of all audit entries.
    """
    try:
        result = audit_logger.verify_integrity()

        return VerificationResult(
            valid=result["valid"],
            total_entries=result["total_entries"],
            first_invalid_entry=result.get("first_invalid_entry"),
            error_message=result.get("error_message"),
            verified_at=datetime.utcnow()
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Verification failed: {str(e)}"
        )


# ============================================================================
# Error Handlers
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom handler for HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.status_code,
            "message": exc.detail
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Custom handler for unexpected exceptions."""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "internal_server_error",
            "message": "An unexpected error occurred"
        }
    )


# ============================================================================
# Root Endpoint
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "service": "Glasshouse Policy Broker",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "infer": "POST /infer - AI inference with authorization",
            "payload": "POST /payload - Access protected payloads",
            "defense": "POST /defense - Defense operations",
            "health": "GET /health - Health check",
            "events": "GET /events - Audit log events",
            "verify": "GET /verify-log - Verify audit integrity",
            "docs": "GET /docs - OpenAPI documentation"
        }
    }
