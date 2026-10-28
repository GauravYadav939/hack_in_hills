"""
Unit tests for the Glasshouse Policy Broker.

Run with: pytest tests/ -v
"""

import pytest
import asyncio
from datetime import datetime, timedelta
import tempfile
import os

from app.auth.tokens import CapabilityTokenManager, TokenExpiredError, TokenInvalidError, create_dev_token
from app.auth.policy import PolicyEngine, PolicyDecision
from app.models import Zone, Action, AuthorizationDecision


class TestCapabilityTokens:
    """Test capability token issuance and verification."""

    @pytest.fixture
    def token_manager(self):
        """Create a token manager with a test key."""
        signing_key, _ = create_dev_token()
        return CapabilityTokenManager(signing_key, expiration_seconds=300)

    def test_issue_and_verify_token(self, token_manager):
        """Test basic token issuance and verification."""
        # Issue a token
        token = token_manager.issue_token(
            tenant_id="test-tenant",
            zone=Zone.BLUE,
            actions=[Action.INFER, Action.PAYLOAD]
        )

        # Verify it
        claims = token_manager.verify_token(token)

        assert claims.tenant_id == "test-tenant"
        assert claims.zone == Zone.BLUE
        assert Action.INFER in claims.actions
        assert Action.PAYLOAD in claims.actions

    def test_expired_token(self):
        """Test that expired tokens are rejected."""
        signing_key, _ = create_dev_token()
        # Create manager with 0 second expiration
        manager = CapabilityTokenManager(signing_key, expiration_seconds=0)

        token = manager.issue_token(
            tenant_id="test-tenant",
            zone=Zone.BLUE,
            actions=[Action.INFER]
        )

        # Token should be immediately expired
        with pytest.raises(TokenExpiredError):
            manager.verify_token(token)

    def test_invalid_token_format(self, token_manager):
        """Test that malformed tokens are rejected."""
        with pytest.raises(TokenInvalidError):
            token_manager.verify_token("not.a.valid.token")

    def test_tampered_token(self, token_manager):
        """Test that tampered tokens are rejected."""
        token = token_manager.issue_token(
            tenant_id="test-tenant",
            zone=Zone.BLUE,
            actions=[Action.INFER]
        )

        # Tamper with the token
        tampered = token[:-5] + "XXXXX"

        with pytest.raises(TokenInvalidError):
            token_manager.verify_token(tampered)

    def test_authorization_check(self, token_manager):
        """Test combined verification and authorization check."""
        token = token_manager.issue_token(
            tenant_id="test-tenant",
            zone=Zone.BLUE,
            actions=[Action.INFER]
        )

        # Should authorize correct tenant/zone/action
        authorized, reason, claims = token_manager.check_authorization(
            token=token,
            required_tenant="test-tenant",
            required_zone=Zone.BLUE,
            required_action=Action.INFER
        )
        assert authorized is True

        # Should deny wrong tenant
        authorized, reason, claims = token_manager.check_authorization(
            token=token,
            required_tenant="wrong-tenant",
            required_zone=Zone.BLUE,
            required_action=Action.INFER
        )
        assert authorized is False

        # Should deny wrong zone
        authorized, reason, claims = token_manager.check_authorization(
            token=token,
            required_tenant="test-tenant",
            required_zone=Zone.RED,
            required_action=Action.INFER
        )
        assert authorized is False

        # Should deny action not in capabilities
        authorized, reason, claims = token_manager.check_authorization(
            token=token,
            required_tenant="test-tenant",
            required_zone=Zone.BLUE,
            required_action=Action.DEFENSE
        )
        assert authorized is False


class TestPolicyEngine:
    """Test policy engine and authorization."""

    @pytest.fixture
    def policy_file(self):
        """Create a temporary policy file."""
        policy_content = {
            "version": "1.0.0",
            "default_decision": "deny",
            "rules": [
                {
                    "name": "blue-can-infer",
                    "source_zone": "blue",
                    "action": "infer",
                    "allowed": True,
                    "conditions": {}
                },
                {
                    "name": "red-cannot-defense",
                    "source_zone": "red",
                    "action": "defense",
                    "allowed": False,
                    "conditions": {}
                }
            ]
        }

        import json
        fd, path = tempfile.mkstemp(suffix='.json')
        with os.fdopen(fd, 'w') as f:
            json.dump(policy_content, f)

        yield path
        os.unlink(path)

    def test_policy_loading(self, policy_file):
        """Test that policy files load correctly."""
        engine = PolicyEngine(policy_file)
        assert engine.policy is not None
        assert len(engine.policy.rules) == 2

    def test_allowed_action(self, policy_file):
        """Test that explicitly allowed actions are authorized."""
        engine = PolicyEngine(policy_file)

        decision = engine.evaluate(
            tenant_id="test-tenant",
            zone=Zone.BLUE,
            action=Action.INFER
        )

        assert decision.is_allowed()
        assert "blue-can-infer" in decision.matched_rule

    def test_explicitly_denied_action(self, policy_file):
        """Test that explicitly denied actions are blocked."""
        engine = PolicyEngine(policy_file)

        decision = engine.evaluate(
            tenant_id="test-tenant",
            zone=Zone.RED,
            action=Action.DEFENSE
        )

        assert not decision.is_allowed()
        assert decision.decision == AuthorizationDecision.DENY

    def test_default_deny(self, policy_file):
        """Test that actions without rules are denied by default."""
        engine = PolicyEngine(policy_file)

        # No rule for red->payload, should be denied
        decision = engine.evaluate(
            tenant_id="test-tenant",
            zone=Zone.RED,
            action=Action.PAYLOAD
        )

        assert not decision.is_allowed()
        assert decision.decision == AuthorizationDecision.DENY

    def test_missing_policy_file(self):
        """Test that missing policy file raises an error."""
        with pytest.raises(ValueError):
            PolicyEngine("/nonexistent/policy.json")


@pytest.mark.asyncio
class TestAuditLogger:
    """Test audit logging and verification."""

    @pytest.fixture
    async def audit_logger(self):
        """Create an audit logger with temporary database."""
        from app.audit.logger import AuditLogger

        fd, db_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)

        signing_key, _ = create_dev_token()
        logger = AuditLogger(db_path, signing_key)

        yield logger

        # Cleanup
        os.unlink(db_path)

    async def test_log_event(self, audit_logger):
        """Test logging an event."""
        entry_id = await audit_logger.log_event(
            request_id="test-req-1",
            tenant_id="test-tenant",
            zone=Zone.BLUE,
            action=Action.INFER,
            decision=AuthorizationDecision.ALLOW,
            reason="Test event",
            outcome="success"
        )

        assert entry_id == 1

        # Verify event was logged
        events = await audit_logger.get_recent_events(limit=10)
        assert len(events) == 1
        assert events[0]['request_id'] == "test-req-1"

    async def test_hash_chain(self, audit_logger):
        """Test that hash chain is maintained."""
        # Log multiple events
        for i in range(5):
            await audit_logger.log_event(
                request_id=f"test-req-{i}",
                tenant_id="test-tenant",
                zone=Zone.BLUE,
                action=Action.INFER,
                decision=AuthorizationDecision.ALLOW,
                reason=f"Test event {i}",
                outcome="success"
            )

        # Verify integrity
        result = audit_logger.verify_integrity()
        assert result["valid"] is True
        assert result["total_entries"] == 5

    async def test_tamper_detection(self, audit_logger):
        """Test that tampering is detected."""
        # Log some events
        for i in range(3):
            await audit_logger.log_event(
                request_id=f"test-req-{i}",
                tenant_id="test-tenant",
                zone=Zone.BLUE,
                action=Action.INFER,
                decision=AuthorizationDecision.ALLOW,
                reason=f"Test event {i}",
                outcome="success"
            )

        # Verify it's currently valid
        result = audit_logger.verify_integrity()
        assert result["valid"] is True

        # Tamper with an entry directly in the database
        import sqlite3
        conn = sqlite3.connect(audit_logger.db_path)
        conn.execute("UPDATE audit_log SET reason = 'TAMPERED' WHERE id = 2")
        conn.commit()
        conn.close()

        # Verification should now fail
        result = audit_logger.verify_integrity()
        assert result["valid"] is False
        assert result["first_invalid_entry"] == 2


class TestOllamaClient:
    """Test Ollama client with tenant isolation."""

    def test_salted_cache_isolation(self):
        """Test that cache is tenant-isolated."""
        from app.ollama_client import TenantCache

        cache = TenantCache()

        # Same prompt, different tenants
        cache.set("tenant-A", "Hello", "Response A")
        cache.set("tenant-B", "Hello", "Response B")

        # Each tenant gets their own cached response
        assert cache.get("tenant-A", "Hello") == "Response A"
        assert cache.get("tenant-B", "Hello") == "Response B"

    def test_session_isolation(self):
        """Test that conversation sessions are tenant-isolated."""
        from app.ollama_client import OllamaSession

        session_a = OllamaSession("tenant-A", "llama3.2")
        session_b = OllamaSession("tenant-B", "llama3.2")

        # Add different messages
        session_a.add_message("user", "Hello from A")
        session_b.add_message("user", "Hello from B")

        # Each session has only its own messages
        assert len(session_a.messages) == 1
        assert len(session_b.messages) == 1
        assert session_a.messages[0]["content"] == "Hello from A"
        assert session_b.messages[0]["content"] == "Hello from B"


def test_create_dev_token():
    """Test development token creation helper."""
    signing_key, token = create_dev_token(tenant_id="dev-test", zone=Zone.BLUE)

    # Should be able to verify the token
    manager = CapabilityTokenManager(signing_key)
    claims = manager.verify_token(token)

    assert claims.tenant_id == "dev-test"
    assert claims.zone == Zone.BLUE


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
