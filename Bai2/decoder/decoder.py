from copy import deepcopy

from config import Bai2Config
from decoder.http_decoder import (
    decode_http_application,
)


class Decoder:
    """
    Decode encoded or represented application data.
    """

    def __init__(
        self,
        config: Bai2Config,
    ) -> None:
        self.config = config

    def process(
        self,
        event: dict,
    ) -> dict:
        """
        Decode one normalized IDS event.
        """

        decoded_event = deepcopy(
            event
        )

        decoded_event["decoder"] = {
            "status": "unchanged",
            "reason": None,
        }

        application = decoded_event.get(
            "application"
        )

        if not isinstance(
            application,
            dict,
        ):
            decoded_event["decoder"] = {
                "status": "partial",
                "reason": (
                    "Missing or invalid "
                    "application data"
                ),
            }

            return decoded_event

        protocol = str(
            application.get(
                "protocol",
                "UNKNOWN",
            )
        ).upper()


        # HTTP
        if protocol == "HTTP":
            try:
                decoded_application = (
                    decode_http_application(
                        application
                    )
                )

                decoded_event[
                    "application"
                ] = decoded_application

                decoded_event["decoder"] = {
                    "status": (
                        decoded_application.get(
                            "decode_status",
                            "success",
                        )
                    ),
                    "reason": (
                        decoded_application.get(
                            "decode_reason"
                        )
                    ),
                }

            except Exception as exc:
                decoded_event["decoder"] = {
                    "status": "partial",
                    "reason": (
                        f"{type(exc).__name__}: "
                        f"{exc}"
                    ),
                }

        return decoded_event