"""Collection package — public API re-exports."""

from __future__ import annotations

from fleet_audit.collection._orchestrator import CollectionError, collect_snapshot

__all__ = ["CollectionError", "collect_snapshot"]
