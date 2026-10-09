from copy import deepcopy

from config import IDSConfig
from flow.flow import (
    Flow,
    build_flow_key,
    create_flow_id,
)


TRACKED_PROTOCOLS = {
    "TCP",
    "UDP",
}


class FlowTracker:
    """
    Track bidirectional TCP and UDP flows.
    """

    def __init__(
        self,
        config: IDSConfig,
    ) -> None:
        self.config = config

        self.active_flows = {}

    def _untracked_metadata(
        self,
        reason: str,
    ) -> dict:
        """
        Return metadata for an event that cannot be tracked.
        """

        return {
            "tracked": False,
            "flow_id": None,
            "direction": None,
            "reason": reason,
        }

    def process(
        self,
        event: dict,
    ) -> dict:
        """
        Attach bidirectional flow metadata to one event.
        """

        result = deepcopy(
            event
        )

        # Do not create a flow from an invalid event.
        if (
            result.get(
                "preprocess_status"
            )
            == "invalid"
        ):
            result["flow"] = (
                self._untracked_metadata(
                    "Invalid preprocessed event"
                )
            )

            return result

        network = result.get(
            "network"
        )

        transport = result.get(
            "transport"
        )

        application = result.get(
            "application"
        )

        if not isinstance(
            network,
            dict,
        ):
            result["flow"] = (
                self._untracked_metadata(
                    "Missing network data"
                )
            )

            return result

        if not isinstance(
            transport,
            dict,
        ):
            result["flow"] = (
                self._untracked_metadata(
                    "Missing transport data"
                )
            )

            return result

        protocol = str(
            transport.get(
                "protocol",
                "UNKNOWN",
            )
        ).upper()

        if (
            protocol
            not in TRACKED_PROTOCOLS
        ):
            result["flow"] = (
                self._untracked_metadata(
                    "Unsupported transport protocol"
                )
            )

            return result

        src_ip = network.get(
            "src_ip"
        )

        dst_ip = network.get(
            "dst_ip"
        )

        src_port = transport.get(
            "src_port"
        )

        dst_port = transport.get(
            "dst_port"
        )

        timestamp = result.get(
            "timestamp"
        )

        if (
            src_ip is None
            or dst_ip is None
            or src_port is None
            or dst_port is None
            or timestamp is None
        ):
            result["flow"] = (
                self._untracked_metadata(
                    "Incomplete flow key data"
                )
            )

            return result

        # Bidirectional flow key

        flow_key = build_flow_key(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
        )

        flow = self.active_flows.get(
            flow_key
        )

        # Application protocol
        application_protocol = (
            "UNKNOWN"
        )

        if isinstance(
            application,
            dict,
        ):
            application_protocol = str(
                application.get(
                    "protocol",
                    "UNKNOWN",
                )
            ).upper()

        # Create new flow
        if flow is None:
            flow = Flow(
                flow_id=create_flow_id(
                    flow_key,
                    timestamp,
                ),

                key=flow_key,

                protocol=protocol,

                endpoint_a_ip=src_ip,
                endpoint_a_port=src_port,

                endpoint_b_ip=dst_ip,
                endpoint_b_port=dst_port,

                application_protocol=(
                    application_protocol
                ),

                start_time=timestamp,
                last_seen=timestamp,
            )

            self.active_flows[
                flow_key
            ] = flow

        # Existing flow
        else:
            flow.last_seen = max(
                flow.last_seen,
                timestamp,
            )

            flow.update_application_protocol(
                application_protocol
            )

        # Direction
        direction = flow.get_direction(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
        )

        # TCP connection state
        if protocol == "TCP":
            flags = transport.get(
                "flags",
                [],
            )

            flow.update_tcp_state(
                flags=flags,
                direction=direction,
            )

        result["flow"] = (
            flow.to_event_metadata(
                direction
            )
        )

        return result