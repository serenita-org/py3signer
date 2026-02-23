"""Health check endpoints."""

from __future__ import annotations

from litestar import Controller, get

from py3signer.storage import KeyStorage  # noqa: TC001

from .base import HealthResponse, Web3SignerHealthResponse


class HealthController(Controller):  # type: ignore[misc]
    """Health check endpoints."""

    path = "/"

    @get("/health")  # type: ignore[untyped-decorator]
    async def health(self, storage: KeyStorage) -> HealthResponse:
        """Health check endpoint."""
        return HealthResponse(status="healthy", keys_loaded=len(storage))

    @get("/healthcheck")  # type: ignore[untyped-decorator]
    async def healthcheck(self) -> Web3SignerHealthResponse:
        """Health check endpoint for compatibility with Vero validator client.

        Returns Web3Signer-compatible healthcheck response.
        """
        return Web3SignerHealthResponse(status="UP", outcome="UP")
