"""
Pydantic models for request and response validation.

These models define the structure of data flowing through the API,
ensuring type safety and automatic validation.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum


class Zone(str, Enum):
    """Valid zones in the Glasshouse system."""
    RED = "red"
    BLUE = "blue"
    MODEL = "model"
    BROKER = "broker"


class Action(str, Enum):
    """Valid actions that can be requested."""
    INFER = "infer"
    PAYLOAD = "payload"
    DEFENSE = "defense"
    HEALTH = "health"


class AuthorizationDecision(str, Enum):
    """Result of an authorization check."""
    ALLOW = "allow"
    DENY = "deny"


# ============================================================================
# Token Models
# ============================================================================

class TokenClaims(BaseModel):
    """Claims contained in a capability token."""
    tenant_id: str = Field(..., description="Unique identifier for the tenant")
    zone: Zone = Field(..., description="Zone this token grants access from")
    actions: List[Action] = Field(..., description="Allowed actions")
    scopes: List[str] = Field(default_factory=list, description="Additional scopes")
    issued_at: datetime = Field(..., description="Token issuance time")
    expires_at: datetime = Field(..., description="Token expiration time")
    jti: str = Field(..., description="Unique token identifier (JWT ID)")


# ============================================================================
# Request Models
# ============================================================================

class InferRequest(BaseModel):
    """Request to perform AI inference."""
    prompt: str = Field(..., min_length=1, max_length=10000, description="The prompt to send to the AI")
    tenant_id: str = Field(..., description="Tenant making the request")
    zone: Zone = Field(..., description="Zone the request originates from")
    token: str = Field(..., description="Capability token")

    @field_validator('prompt')
    @classmethod
    def prompt_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Prompt cannot be empty or only whitespace")
        return v


class PayloadRequest(BaseModel):
    """Request to access protected test payloads."""
    payload_id: str = Field(..., description="Identifier of the payload to access")
    tenant_id: str = Field(..., description="Tenant making the request")
    zone: Zone = Field(..., description="Zone the request originates from")
    token: str = Field(..., description="Capability token")


class DefenseRequest(BaseModel):
    """Request to perform defense operations."""
    operation: str = Field(..., description="Defense operation to perform")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Operation parameters")
    tenant_id: str = Field(..., description="Tenant making the request")
    zone: Zone = Field(..., description="Zone the request originates from")
    token: str = Field(..., description="Capability token")


# ============================================================================
# Response Models
# ============================================================================

class InferResponse(BaseModel):
    """Response from AI inference."""
    request_id: str = Field(..., description="Unique identifier for this request")
    response: str = Field(..., description="AI-generated response")
    tenant_id: str = Field(..., description="Tenant that made the request")
    processing_time_ms: float = Field(..., description="Time taken to process (including padding)")


class PayloadResponse(BaseModel):
    """Response containing requested payload."""
    request_id: str = Field(..., description="Unique identifier for this request")
    payload_id: str = Field(..., description="Identifier of the payload")
    data: Dict[str, Any] = Field(..., description="Payload data")


class DefenseResponse(BaseModel):
    """Response from defense operation."""
    request_id: str = Field(..., description="Unique identifier for this request")
    operation: str = Field(..., description="Defense operation performed")
    result: Dict[str, Any] = Field(..., description="Operation result")


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(..., description="Service status")
    timestamp: datetime = Field(..., description="Current server time")
    ollama_available: bool = Field(..., description="Whether Ollama is reachable")
    audit_log_writable: bool = Field(..., description="Whether audit log is writable")


class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str = Field(..., description="Error category")
    message: str = Field(..., description="Human-readable error message")
    request_id: Optional[str] = Field(None, description="Request ID if available")


# ============================================================================
# Audit Log Models
# ============================================================================

class AuditEvent(BaseModel):
    """A single audit log event."""
    id: int = Field(..., description="Unique event ID (sequence number)")
    request_id: str = Field(..., description="Request identifier")
    timestamp: datetime = Field(..., description="Event timestamp")
    tenant_id: str = Field(..., description="Tenant identifier")
    zone: Zone = Field(..., description="Originating zone")
    action: Action = Field(..., description="Requested action")
    decision: AuthorizationDecision = Field(..., description="Authorization decision")
    reason: str = Field(..., description="Decision reason")
    outcome: str = Field(..., description="Request outcome")
    previous_hash: str = Field(..., description="Hash of previous entry")
    current_hash: str = Field(..., description="Hash of this entry")
    signature: str = Field(..., description="Cryptographic signature of this entry")


class EventsResponse(BaseModel):
    """Response containing audit events."""
    events: List[AuditEvent] = Field(..., description="List of audit events")
    total_count: int = Field(..., description="Total number of events in the log")


class VerificationResult(BaseModel):
    """Result of audit log verification."""
    valid: bool = Field(..., description="Whether the log is valid")
    total_entries: int = Field(..., description="Total entries checked")
    first_invalid_entry: Optional[int] = Field(None, description="ID of first invalid entry")
    error_message: Optional[str] = Field(None, description="Error details if invalid")
    verified_at: datetime = Field(..., description="Verification timestamp")


# ============================================================================
# Policy Models
# ============================================================================

class PolicyRule(BaseModel):
    """A single policy rule."""
    name: str = Field(..., description="Rule name")
    source_zone: Zone = Field(..., description="Zone making the request")
    action: Action = Field(..., description="Action being requested")
    allowed: bool = Field(..., description="Whether this is allowed")
    conditions: Dict[str, Any] = Field(default_factory=dict, description="Additional conditions")


class PolicyDocument(BaseModel):
    """Complete policy document."""
    version: str = Field(..., description="Policy version")
    default_decision: AuthorizationDecision = Field(default=AuthorizationDecision.DENY)
    rules: List[PolicyRule] = Field(..., description="Policy rules")


# ============================================================================
# Demo/Testing Models
# ============================================================================

class AttackTestResult(BaseModel):
    """Result of a single attack test."""
    test_id: str = Field(..., description="Test identifier")
    test_name: str = Field(..., description="Human-readable test name")
    category: str = Field(..., description="Attack category")
    passed: bool = Field(..., description="Whether the test passed (attack was blocked)")
    expected_outcome: str = Field(..., description="What should have happened")
    actual_outcome: str = Field(..., description="What actually happened")
    request_id: Optional[str] = Field(None, description="Request ID if applicable")


class AttackTestSuite(BaseModel):
    """Complete attack test suite results."""
    suite_name: str = Field(..., description="Test suite name")
    run_timestamp: datetime = Field(..., description="When tests were run")
    total_tests: int = Field(..., description="Total number of tests")
    passed_tests: int = Field(..., description="Number of passed tests")
    failed_tests: int = Field(..., description="Number of failed tests")
    results: List[AttackTestResult] = Field(..., description="Individual test results")
