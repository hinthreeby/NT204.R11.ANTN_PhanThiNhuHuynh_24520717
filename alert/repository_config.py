from dataclasses import dataclass
from pathlib import PureWindowsPath
import re


@dataclass(frozen=True, slots=True)
class RepositoryConfig:
    """Configure persistent SQLite storage without performing filesystem I/O.

    Paths are strings, preserved verbatim (including Windows separators/spaces).
    Relative paths resolve against cwd when the repository is opened.
    The repository, not this config, creates parents and validates access.
    In-memory databases and SQLite URI paths are intentionally unsupported.
    """

    storage_type: str = "sqlite"
    storage_path: str = "output/alerts.db"

    def __post_init__(self) -> None:
        if not isinstance(self.storage_type, str) or self.storage_type != "sqlite":
            raise ValueError("storage_type must be 'sqlite'")
        path = self.storage_path
        if not isinstance(path, str) or not path.strip():
            raise ValueError("storage_path must be a non-empty string")
        if any(ord(char) < 32 for char in path):
            raise ValueError("storage_path must not contain control characters")
        if path.lower() == ":memory:" or path.lower().startswith("file:") or re.match(
            r"^[A-Za-z][A-Za-z0-9+.-]*://", path
        ):
            raise ValueError("storage_path must be a persistent file path, not a URI or :memory:")
        if (path.endswith(("/", "\\"))
                or re.split(r"[/\\]", path)[-1] in {".", ".."}
                or not PureWindowsPath(path).name):
            raise ValueError("storage_path must name a database file")
