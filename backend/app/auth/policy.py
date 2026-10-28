"""
Policy engine for Glasshouse Broker.

This module implements default-deny authorization based on a policy file.
Every request must be explicitly allowed by policy; unknown zones, actions,
or missing rules result in denial.

Key Principle: FAIL SECURE
- If policy file is missing/corrupt → DENY ALL
- If rule is ambiguous → DENY
- If zone/action unknown → DENY
- Only explicit "allow" rules grant access
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime

from app.models import (
    Zone, Action, AuthorizationDecision, PolicyDocument, PolicyRule
)


class PolicyDecision:
    """Result of a policy evaluation."""

    def __init__(
        self,
        decision: AuthorizationDecision,
        reason: str,
        matched_rule: Optional[str] = None
    ):
        self.decision = decision
        self.reason = reason
        self.matched_rule = matched_rule
        self.evaluated_at = datetime.utcnow()

    def is_allowed(self) -> bool:
        """Check if the decision allows the action."""
        return self.decision == AuthorizationDecision.ALLOW


class PolicyEngine:
    """
    Enforces authorization policy with default-deny behavior.

    The policy engine:
    1. Loads a policy document from JSON
    2. Evaluates requests against explicit rules
    3. Denies anything not explicitly allowed
    4. Fails securely if policy is invalid/missing
    """

    def __init__(self, policy_path: str):
        """
        Initialize the policy engine.

        Args:
            policy_path: Path to the policy JSON file

        Raises:
            ValueError: If policy file cannot be loaded or is invalid
        """
        self.policy_path = Path(policy_path)
        self.policy: Optional[PolicyDocument] = None
        self._load_policy()

    def _load_policy(self) -> None:
        """
        Load and validate the policy document.

        Raises:
            ValueError: If policy is invalid or missing
        """
        if not self.policy_path.exists():
            raise ValueError(
                f"Policy file not found: {self.policy_path}\n"
                "The broker cannot start without a valid policy file.\n"
                "Create a policy file or use the example: config/policy.json"
            )

        try:
            with open(self.policy_path, 'r') as f:
                policy_data = json.load(f)

            # Validate using Pydantic model
            self.policy = PolicyDocument(**policy_data)

            # Log successful load
            print(f"✓ Policy loaded: {len(self.policy.rules)} rules from {self.policy_path}")
            print(f"  Policy version: {self.policy.version}")
            print(f"  Default decision: {self.policy.default_decision.value}")

        except json.JSONDecodeError as e:
            raise ValueError(f"Policy file is not valid JSON: {e}")
        except Exception as e:
            raise ValueError(f"Policy validation failed: {e}")

    def evaluate(
        self,
        tenant_id: str,
        zone: Zone,
        action: Action,
        context: Optional[Dict[str, Any]] = None
    ) -> PolicyDecision:
        """
        Evaluate whether an action is authorized.

        Args:
            tenant_id: Tenant making the request
            zone: Zone the request originates from
            action: Action being requested
            context: Additional context for evaluation (optional)

        Returns:
            PolicyDecision with allow/deny and reason

        Security: This method ALWAYS returns a decision.
        If anything goes wrong, it returns DENY.
        """
        # Safety check: If policy didn't load, deny everything
        if self.policy is None:
            return PolicyDecision(
                decision=AuthorizationDecision.DENY,
                reason="Policy engine not initialized"
            )

        # Validate that zone and action are recognized
        try:
            zone = Zone(zone) if isinstance(zone, str) else zone
            action = Action(action) if isinstance(action, str) else action
        except ValueError:
            return PolicyDecision(
                decision=AuthorizationDecision.DENY,
                reason=f"Unknown zone or action: {zone}, {action}"
            )

        # Find matching rules
        matching_rules = self._find_matching_rules(zone, action)

        if not matching_rules:
            # No matching rule = default deny
            return PolicyDecision(
                decision=self.policy.default_decision,
                reason=f"No policy rule for {zone.value} → {action.value}"
            )

        # Check each matching rule
        for rule in matching_rules:
            # Check additional conditions if present
            if rule.conditions:
                if not self._check_conditions(rule.conditions, context or {}):
                    continue  # Conditions not met, try next rule

            # Rule matches and conditions pass
            if rule.allowed:
                return PolicyDecision(
                    decision=AuthorizationDecision.ALLOW,
                    reason=f"Allowed by rule: {rule.name}",
                    matched_rule=rule.name
                )
            else:
                return PolicyDecision(
                    decision=AuthorizationDecision.DENY,
                    reason=f"Explicitly denied by rule: {rule.name}",
                    matched_rule=rule.name
                )

        # Rules matched but conditions didn't pass
        return PolicyDecision(
            decision=AuthorizationDecision.DENY,
            reason=f"Rules found but conditions not met for {zone.value} → {action.value}"
        )

    def _find_matching_rules(self, zone: Zone, action: Action) -> List[PolicyRule]:
        """Find all rules matching the zone and action."""
        if not self.policy:
            return []

        return [
            rule for rule in self.policy.rules
            if rule.source_zone == zone and rule.action == action
        ]

    def _check_conditions(
        self,
        conditions: Dict[str, Any],
        context: Dict[str, Any]
    ) -> bool:
        """
        Check if conditions are satisfied by the context.

        Simple implementation: All conditions must match context exactly.
        More sophisticated implementations could support operators, wildcards, etc.
        """
        for key, expected_value in conditions.items():
            if context.get(key) != expected_value:
                return False
        return True

    def get_policy_summary(self) -> Dict[str, Any]:
        """Get a summary of the current policy."""
        if not self.policy:
            return {"status": "not_loaded"}

        return {
            "status": "loaded",
            "version": self.policy.version,
            "default_decision": self.policy.default_decision.value,
            "total_rules": len(self.policy.rules),
            "rules_by_zone": self._count_rules_by_zone(),
            "rules_by_action": self._count_rules_by_action()
        }

    def _count_rules_by_zone(self) -> Dict[str, int]:
        """Count rules by source zone."""
        if not self.policy:
            return {}

        counts: Dict[str, int] = {}
        for rule in self.policy.rules:
            zone = rule.source_zone.value
            counts[zone] = counts.get(zone, 0) + 1
        return counts

    def _count_rules_by_action(self) -> Dict[str, int]:
        """Count rules by action."""
        if not self.policy:
            return {}

        counts: Dict[str, int] = {}
        for rule in self.policy.rules:
            action = rule.action.value
            counts[action] = counts.get(action, 0) + 1
        return counts

    def reload_policy(self) -> None:
        """
        Reload the policy from disk.

        Useful for updating policy without restarting the broker.

        Raises:
            ValueError: If the new policy is invalid
        """
        self._load_policy()
