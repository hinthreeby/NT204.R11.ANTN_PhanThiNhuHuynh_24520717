import json
from pathlib import Path


class JSONLWriter:
    """
    Write normalized IDS events to a JSON Lines file.
    """

    def __init__(
        self,
        file_path: str,
    ) -> None:
        self.file_path = Path(file_path)
        self.file = None

    def __enter__(self):
        """
        Open the JSONL output file.
        """

        parent_directory = self.file_path.parent

        if str(parent_directory) != ".":
            parent_directory.mkdir(
                parents=True,
                exist_ok=True,
            )

        self.file = self.file_path.open(
            mode="w",
            encoding="utf-8",
        )

        return self

    def write_event(
        self,
        event: dict,
    ) -> None:
        """
        Write one normalized IDS event as one JSON line.
        """

        if self.file is None:
            raise RuntimeError(
                "JSONL writer is not open"
            )

        json_line = json.dumps(
            event,
            ensure_ascii=False,
            separators=(",", ":"),
        )

        self.file.write(
            json_line + "\n"
        )

        self.file.flush()

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ) -> None:
        """
        Close the JSONL output file.
        """

        if self.file is not None:
            self.file.close()