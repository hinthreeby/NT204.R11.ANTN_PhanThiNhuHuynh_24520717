"""Optional persistence around the unchanged AlertManager public interface."""

from copy import deepcopy
from dataclasses import dataclass

from .manager import AlertManager
from .models import Alert, AlertGroup, AlertResult
from .repository import AlertRepository


class PersistenceWriteError(RuntimeError):
    """Storage failed; the adapter retains the result for retry_pending().

    The original error is available through __cause__. Aggregation has already
    advanced, so retry the pending write rather than reprocessing the event.
    """


class PendingPersistenceError(RuntimeError):
    """A pending write must succeed before another process()/flush() call."""


@dataclass(frozen=True, slots=True)
class _PendingWrite:
    outcome: AlertResult | tuple[AlertGroup, ...]
    inserts: tuple[Alert, ...]
    updates: tuple[Alert, ...]


class AlertPersistenceAdapter:
    """Use process()/flush() exclusively through this adapter for one manager.

    repository=None disables storage and preserves the manager's behavior.
    Otherwise, new alerts are inserted, aggregated snapshots are updated, and
    expired/flush summaries are retained by updating their existing rows.
    A late singleton is inserted once even though it also appears in finalized.

    Each output batch is persisted atomically. A failed batch is retained in
    memory and blocks new work until retry_pending() succeeds; never replay the
    detection after a storage error. No unbounded pending queue is maintained.
    No durable retry log, aggregator restoration or member-history table exists.
    This adapter is single-threaded and does not own/close the repository.
    Attach it before processing, or seed existing open groups in storage first.
    """

    def __init__(self, manager: AlertManager, repository: AlertRepository | None = None) -> None:
        if not isinstance(manager, AlertManager):
            raise TypeError("Expected AlertManager")
        if repository is not None and not isinstance(repository, AlertRepository):
            raise TypeError("Expected AlertRepository or None")
        self._manager = manager
        self._repository = repository
        self._pending: _PendingWrite | None = None

    @property
    def has_pending(self) -> bool:
        return self._pending is not None

    def _ready(self) -> None:
        if self.has_pending:
            raise PendingPersistenceError("Call retry_pending() before processing or flushing more input")

    def _commit(self, pending: _PendingWrite) -> None:
        self._pending = pending
        try:
            repository = self._repository
            if repository is None:
                raise RuntimeError("No repository configured for pending output")
            repository.apply_changes(inserts=pending.inserts, updates=pending.updates)
        except Exception as exc:
            raise PersistenceWriteError(
                "Persistence failed; output retained in adapter. Call retry_pending(), do not replay the event"
            ) from exc
        self._pending = None

    def process(self, detection_event: object) -> AlertResult:
        """Return a result only after its storage batch succeeds (when enabled)."""
        self._ready()
        result = self._manager.process(detection_event)
        if self._repository is None or result.status in {"rejected", "filtered", "suppressed"}:
            return result
        if result.alert is None:
            raise ValueError("A successful manager result must include an Alert")
        if result.status not in {"created", "aggregated", "finalized"}:
            raise ValueError("Unsupported manager result status")
        inserts = (result.alert,) if result.status in {"created", "finalized"} else ()
        updates = tuple(group.summary for group in result.finalized
                        if group.summary.alert_id != result.alert.alert_id)
        if result.status == "aggregated":
            updates += (result.alert,)
        pending = deepcopy(_PendingWrite(result, inserts, updates))
        self._commit(pending)
        return result

    def flush(self) -> tuple[AlertGroup, ...]:
        """Persist all flushed summaries once; failed output stays available for retry."""
        self._ready()
        groups = self._manager.flush()
        if self._repository is None or not groups:
            return groups
        pending = deepcopy(_PendingWrite(groups, (), tuple(group.summary for group in groups)))
        self._commit(pending)
        return groups

    def retry_pending(
        self, repository: AlertRepository | None = None,
    ) -> AlertResult | tuple[AlertGroup, ...] | None:
        """Retry SQL only, returning the original outcome; None if nothing is pending.

        Optionally supply a reopened repository for the same database after a
        closed-connection failure. The caller is responsible for that identity.
        Successful repeated calls are no-ops, never duplicate inserts/counts.
        """
        if repository is not None and not isinstance(repository, AlertRepository):
            raise TypeError("Expected AlertRepository or None")
        if self._pending is None:
            return None
        if repository is not None:
            self._repository = repository
        pending = self._pending
        self._commit(pending)
        return deepcopy(pending.outcome)
