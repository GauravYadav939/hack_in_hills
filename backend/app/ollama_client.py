"""
Ollama client with tenant isolation for Glasshouse Broker.

This module:
1. Connects to Ollama's HTTP API
2. Maintains separate conversation sessions per tenant
3. Implements a salted cache to prevent cross-tenant data leakage
4. Provides session cleanup capabilities

Key Security Properties:
- Each tenant gets isolated conversation history
- Cache keys are salted with tenant ID to prevent cache-timing attacks
- Sessions can be explicitly wiped between test runs
- Timeout prevents indefinite hangs on model unavailability

Important Limitations:
- We control the conversation history we pass to Ollama
- Ollama's internal caching/state is implementation-dependent
- This provides logical isolation; container isolation comes from Docker (Person 1)
- For strongest guarantees, restart Ollama between sensitive tests
"""

import httpx
import hashlib
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
from collections import defaultdict


class OllamaSession:
    """Represents a single tenant's conversation session."""

    def __init__(self, tenant_id: str, model: str):
        self.tenant_id = tenant_id
        self.model = model
        self.messages: List[Dict[str, str]] = []
        self.created_at = datetime.utcnow()
        self.last_accessed = datetime.utcnow()

    def add_message(self, role: str, content: str):
        """Add a message to the conversation history."""
        self.messages.append({"role": role, "content": content})
        self.last_accessed = datetime.utcnow()

    def get_history(self) -> List[Dict[str, str]]:
        """Get the full conversation history."""
        self.last_accessed = datetime.utcnow()
        return self.messages.copy()

    def clear(self):
        """Clear the conversation history."""
        self.messages.clear()
        self.last_accessed = datetime.utcnow()


class TenantCache:
    """
    Salted cache to prevent cross-tenant cache timing attacks.

    Each cache key is hashed with the tenant ID, so:
    - Tenant A asking "What is X?" gets cache entry: hash(tenantA + "What is X?")
    - Tenant B asking "What is X?" gets cache entry: hash(tenantB + "What is X?")

    This prevents timing-based inference about what other tenants asked.
    """

    def __init__(self):
        self._cache: Dict[str, str] = {}

    def _make_key(self, tenant_id: str, prompt: str) -> str:
        """Create a salted cache key."""
        combined = f"{tenant_id}::{prompt}"
        return hashlib.sha256(combined.encode('utf-8')).hexdigest()

    def get(self, tenant_id: str, prompt: str) -> Optional[str]:
        """Retrieve cached response if available."""
        key = self._make_key(tenant_id, prompt)
        return self._cache.get(key)

    def set(self, tenant_id: str, prompt: str, response: str):
        """Cache a response."""
        key = self._make_key(tenant_id, prompt)
        self._cache[key] = response

    def clear(self, tenant_id: Optional[str] = None):
        """Clear cache for a specific tenant or entire cache."""
        if tenant_id:
            # Clear only this tenant's entries
            # Note: Since keys are hashed, we can't directly identify tenant keys
            # In production, you'd maintain a tenant->keys mapping
            # For now, this is a placeholder that clears everything
            self._cache.clear()
        else:
            # Clear entire cache
            self._cache.clear()


class OllamaClient:
    """
    Client for Ollama API with tenant isolation.

    Each tenant gets:
    - Separate conversation session
    - Isolated cache entries
    - Independent context
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        timeout: int = 30,
        enable_cache: bool = True
    ):
        """
        Initialize Ollama client.

        Args:
            base_url: Ollama API base URL (e.g., http://ollama:11434)
            model: Model name (e.g., llama3.2:3b)
            timeout: Request timeout in seconds
            enable_cache: Whether to enable response caching
        """
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.timeout = timeout
        self.enable_cache = enable_cache

        # Tenant sessions
        self._sessions: Dict[str, OllamaSession] = {}

        # Salted cache
        self._cache = TenantCache()

        # HTTP client
        self._client = httpx.AsyncClient(timeout=timeout)

    async def generate(
        self,
        tenant_id: str,
        prompt: str,
        use_history: bool = True
    ) -> Dict[str, Any]:
        """
        Generate a response from Ollama.

        Args:
            tenant_id: Tenant making the request
            prompt: User prompt
            use_history: Whether to include conversation history

        Returns:
            Dictionary with response, processing time, and metadata

        Raises:
            httpx.TimeoutException: If Ollama doesn't respond in time
            httpx.HTTPError: If Ollama returns an error
        """
        start_time = datetime.utcnow()

        # Check cache first
        if self.enable_cache:
            cached_response = self._cache.get(tenant_id, prompt)
            if cached_response:
                processing_time = (datetime.utcnow() - start_time).total_seconds()
                return {
                    "response": cached_response,
                    "processing_time_seconds": processing_time,
                    "cached": True,
                    "model": self.model
                }

        # Get or create session
        session = self._get_or_create_session(tenant_id)

        # Add user message to history
        session.add_message("user", prompt)

        # Prepare messages for Ollama
        messages = session.get_history() if use_history else [{"role": "user", "content": prompt}]

        # Call Ollama API
        try:
            response = await self._client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": messages,
                    "stream": False
                }
            )
            response.raise_for_status()

            data = response.json()
            assistant_message = data.get("message", {}).get("content", "")

            # Add assistant response to history
            session.add_message("assistant", assistant_message)

            # Cache the response
            if self.enable_cache:
                self._cache.set(tenant_id, prompt, assistant_message)

            processing_time = (datetime.utcnow() - start_time).total_seconds()

            return {
                "response": assistant_message,
                "processing_time_seconds": processing_time,
                "cached": False,
                "model": self.model,
                "done": data.get("done", True)
            }

        except httpx.TimeoutException:
            raise Exception(f"Ollama request timed out after {self.timeout}s")
        except httpx.HTTPError as e:
            raise Exception(f"Ollama API error: {e}")

    async def check_health(self) -> bool:
        """
        Check if Ollama is available.

        Returns:
            True if Ollama responds, False otherwise
        """
        try:
            response = await self._client.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False

    def _get_or_create_session(self, tenant_id: str) -> OllamaSession:
        """Get existing session or create new one for tenant."""
        if tenant_id not in self._sessions:
            self._sessions[tenant_id] = OllamaSession(tenant_id, self.model)
        return self._sessions[tenant_id]

    def get_session_info(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a tenant's session."""
        session = self._sessions.get(tenant_id)
        if not session:
            return None

        return {
            "tenant_id": session.tenant_id,
            "model": session.model,
            "message_count": len(session.messages),
            "created_at": session.created_at.isoformat(),
            "last_accessed": session.last_accessed.isoformat()
        }

    def clear_tenant_session(self, tenant_id: str):
        """
        Clear a specific tenant's session and cache.

        Use this between test runs to ensure isolation.
        """
        if tenant_id in self._sessions:
            self._sessions[tenant_id].clear()

        # Clear cache (note: current implementation clears all)
        self._cache.clear(tenant_id)

    def clear_all_sessions(self):
        """
        Clear all tenant sessions and cache.

        Use this for complete context reset between experiments.
        """
        self._sessions.clear()
        self._cache.clear()

    def get_active_sessions(self) -> List[str]:
        """Get list of tenant IDs with active sessions."""
        return list(self._sessions.keys())

    async def close(self):
        """Close the HTTP client."""
        await self._client.aclose()


# Singleton instance management
_ollama_client: Optional[OllamaClient] = None


def get_ollama_client(
    base_url: str,
    model: str,
    timeout: int = 30
) -> OllamaClient:
    """
    Get or create the global Ollama client instance.

    This ensures we maintain a single client with consistent tenant sessions
    throughout the broker's lifetime.
    """
    global _ollama_client

    if _ollama_client is None:
        _ollama_client = OllamaClient(
            base_url=base_url,
            model=model,
            timeout=timeout
        )

    return _ollama_client
