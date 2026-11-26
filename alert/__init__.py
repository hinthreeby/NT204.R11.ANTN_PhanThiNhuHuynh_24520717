"""Manage alerts produced from Detection Events."""

from .aggregation_config import AggregationConfig
from .filtering import AlertFilterConfig
from .manager import AlertManager
from .models import Alert, AlertResult
from .repository import AlertRepository, RepositoryDataError, RepositorySchemaError
from .repository_config import RepositoryConfig
from .repository_integration import AlertPersistenceAdapter, PendingPersistenceError, PersistenceWriteError
from .severity import SeverityConfig


__all__ = [
    "AggregationConfig", "Alert", "AlertFilterConfig", "AlertManager", "AlertResult",
    "AlertRepository", "RepositoryConfig", "RepositoryDataError", "RepositorySchemaError",
    "AlertPersistenceAdapter", "PendingPersistenceError", "PersistenceWriteError",
    "SeverityConfig",
]
