"""
Capability token system for Glasshouse Broker.

This module implements cryptographically signed, time-limited tokens that
grant specific capabilities to tenants. Tokens are signed using NaCl
(libsodium) and include:
- Tenant identity
- Source zone
- Allowed actions
- Scopes
- Expiration time

Key Security Properties:
1. Tokens are SIGNED, not just encoded - forgery is cryptographically hard
2. Tokens have short lifetimes (default 5 minutes)
3. Tokens specify exactly what actions are allowed
4. Expired tokens are rejected
5. Tampered tokens are detected via signature verification
"""

import json
import base64
import uuid
from datetime import datetime, timedelta
from typing import List, Optional

import nacl.signing
import nacl.encoding
from nacl.exceptions import BadSignatureError

from app.models import Zone, Action, TokenClaims, AuthorizationDecision


class TokenError(Exception):
    """Base exception for token-related errors."""
    pass


class TokenExpiredError(TokenError):
    """Token has expired."""
    pass


class TokenInvalidError(TokenError):
    """Token signature is invalid or token is malformed."""
    pass


class CapabilityTokenManager:
    """
    Manages issuance and verification of capability tokens.

    Tokens are signed using Ed25519 (via NaCl) and encoded in base64.
    The token format is: base64(signature) + "." + base64(claims_json)
    """

    def __init__(self, signing_key_b64: str, expiration_seconds: int = 300):
        """
        Initialize the token manager.

        Args:
            signing_key_b64: Base64-encoded NaCl signing key
            expiration_seconds: Token lifetime in seconds (default: 5 minutes)

        Raises:
            ValueError: If signing key is invalid
        """
        try:
            # Decode the base64 signing key
            key_bytes = base64.b64decode(signing_key_b64)
            self.signing_key = nacl.signing.SigningKey(key_bytes)
            self.verify_key = self.signing_key.verify_key
            self.expiration_seconds = expiration_seconds
        except Exception as e:
            raise ValueError(f"Invalid signing key: {e}")

    def issue_token(
        self,
        tenant_id: str,
        zone: Zone,
        actions: List[Action],
        scopes: Optional[List[str]] = None
    ) -> str:
        """
        Issue a new capability token.

        Args:
            tenant_id: Unique identifier for the tenant
            zone: Zone this token grants access from
            actions: List of allowed actions
            scopes: Additional scopes (optional)

        Returns:
            Signed token string

        Example:
            >>> manager = CapabilityTokenManager(signing_key)
            >>> token = manager.issue_token("tenant-123", Zone.BLUE, [Action.INFER])
        """
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=self.expiration_seconds)

        # Create claims
        claims = TokenClaims(
            tenant_id=tenant_id,
            zone=zone,
            actions=actions,
            scopes=scopes or [],
            issued_at=now,
            expires_at=expires_at,
            jti=str(uuid.uuid4())  # Unique token ID
        )

        # Serialize claims to JSON
        claims_json = claims.model_dump_json()
        claims_bytes = claims_json.encode('utf-8')

        # Sign the claims
        signed = self.signing_key.sign(claims_bytes)

        # Extract signature (first 64 bytes) and message
        signature = signed.signature

        # Encode as: base64(signature).base64(claims)
        signature_b64 = base64.b64encode(signature).decode('ascii')
        claims_b64 = base64.b64encode(claims_bytes).decode('ascii')

        token = f"{signature_b64}.{claims_b64}"
        return token

    def verify_token(self, token: str) -> TokenClaims:
        """
        Verify and decode a capability token.

        Args:
            token: Token string to verify

        Returns:
            TokenClaims if valid

        Raises:
            TokenInvalidError: If token is malformed or signature is invalid
            TokenExpiredError: If token has expired
        """
        try:
            # Parse token format: signature.claims
            parts = token.split('.')
            if len(parts) != 2:
                raise TokenInvalidError("Token format invalid (expected: signature.claims)")

            signature_b64, claims_b64 = parts

            # Decode from base64
            signature = base64.b64decode(signature_b64)
            claims_bytes = base64.b64decode(claims_b64)

            # Verify signature
            try:
                self.verify_key.verify(claims_bytes, signature)
            except BadSignatureError:
                raise TokenInvalidError("Token signature verification failed")

            # Parse claims
            claims_dict = json.loads(claims_bytes.decode('utf-8'))
            claims = TokenClaims(**claims_dict)

            # Check expiration
            now = datetime.utcnow()
            if now > claims.expires_at:
                raise TokenExpiredError(
                    f"Token expired at {claims.expires_at.isoformat()}"
                )

            return claims

        except TokenError:
            # Re-raise our specific errors
            raise
        except Exception as e:
            raise TokenInvalidError(f"Token verification failed: {e}")

    def check_authorization(
        self,
        token: str,
        required_tenant: str,
        required_zone: Zone,
        required_action: Action
    ) -> tuple[bool, str, Optional[TokenClaims]]:
        """
        Verify token and check if it authorizes a specific action.

        Args:
            token: Token to verify
            required_tenant: Expected tenant ID
            required_zone: Expected zone
            required_action: Action being requested

        Returns:
            Tuple of (authorized, reason, claims)
            - authorized: True if authorized, False otherwise
            - reason: Human-readable reason for the decision
            - claims: TokenClaims if valid, None if invalid

        This is a convenience method that combines verification and authorization.
        """
        try:
            claims = self.verify_token(token)
        except TokenExpiredError as e:
            return False, f"Token expired: {e}", None
        except TokenInvalidError as e:
            return False, f"Invalid token: {e}", None

        # Check tenant matches
        if claims.tenant_id != required_tenant:
            return False, f"Token tenant mismatch: {claims.tenant_id} != {required_tenant}", claims

        # Check zone matches
        if claims.zone != required_zone:
            return False, f"Token zone mismatch: {claims.zone} != {required_zone}", claims

        # Check action is in allowed list
        if required_action not in claims.actions:
            return False, f"Action {required_action} not in token capabilities", claims

        # All checks passed
        return True, "Token valid and authorizes action", claims


def create_dev_token(tenant_id: str = "dev-tenant", zone: Zone = Zone.BLUE) -> tuple[str, str]:
    """
    Helper function to create a development token.

    Returns:
        Tuple of (signing_key, token) for testing purposes

    WARNING: Only use for development/testing!
    """
    # Generate a temporary key
    signing_key = nacl.signing.SigningKey.generate()
    signing_key_b64 = signing_key.encode(encoder=nacl.encoding.Base64Encoder).decode('ascii')

    # Create manager and issue token
    manager = CapabilityTokenManager(signing_key_b64, expiration_seconds=3600)
    token = manager.issue_token(
        tenant_id=tenant_id,
        zone=zone,
        actions=[Action.INFER, Action.PAYLOAD, Action.DEFENSE, Action.HEALTH]
    )

    return signing_key_b64, token
