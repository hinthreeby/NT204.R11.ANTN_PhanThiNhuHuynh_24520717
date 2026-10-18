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

    def _get_packet_size(
        self,
        event: dict,
    ) -> int:
        """
        Get packet size from normalized event data.

        Prefer IPv4 total_length, then legacy network length
        fields, then transport payload length. Use one size only;
        reject negative, fractional, boolean and non-finite values.
        """

        network = event.get(
            "network",
            {},
        )

        if isinstance(
            network,
            dict,
        ):
            for field_name in (
                "total_length",
                "len",
                "length",
                "packet_length",
            ):
                value = network.get(
                    field_name
                )

                if value is None:
                    continue

                if isinstance(value, bool):
                    continue

                try:
                    size = int(
                        value
                    )

                except (
                    TypeError,
                    ValueError,
                    OverflowError,
                ):
                    continue

                if isinstance(value, float) and value != size:
                    continue

                if size >= 0:
                    return size

        transport = event.get(
            "transport",
            {},
        )

        if isinstance(
            transport,
            dict,
        ):
            value = transport.get("payload_length", 0)
            if isinstance(value, bool):
                return 0

            try:
                payload_length = int(
                    value
                )

            except (
                TypeError,
                ValueError,
                OverflowError,
            ):
                payload_length = 0

            if isinstance(value, float) and value != payload_length:
                return 0

            return max(
                payload_length,
                0,
            )

        return 0

    def _get_idle_timeout(
        self,
        flow: Flow,
    ) -> float:
        """
        Return the configured idle timeout for a flow.
        """

        if flow.protocol == "TCP":
            return (
                self.config
                .tcp_idle_timeout
            )

        return (
            self.config
            .udp_idle_timeout
        )

    def expire_idle_flows(
        self,
        current_time: float,
    ) -> list[dict]:
        """
        Expire flows whose idle time exceeds
        the configured timeout.
        """

        expired_flows = []
        expired_keys = []

        for (
            flow_key,
            flow,
        ) in self.active_flows.items():

            timeout = (
                self._get_idle_timeout(
                    flow
                )
            )

            idle_time = (
                current_time
                - flow.last_seen
            )

            if idle_time > timeout:
                close_reason = {
                    "CLOSED": "tcp_closed",
                    "RESET": "tcp_reset",
                }.get(flow.tcp_state, "idle_timeout")
                expired_flows.append(
                    flow.to_expired_summary(
                        close_reason
                    )
                )

                expired_keys.append(
                    flow_key
                )

        for flow_key in expired_keys:
            del self.active_flows[
                flow_key
            ]

        return expired_flows

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

        # Keep output schema consistent.
        result["expired_flows"] = []

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

        # -------------------------
        # Validate network data
        # -------------------------

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

        # -------------------------
        # Validate transport data
        # -------------------------

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

        # -------------------------
        # Extract flow fields
        # -------------------------

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

        # -------------------------
        # Expire old idle flows
        # -------------------------

        result["expired_flows"] = (
            self.expire_idle_flows(
                timestamp
            )
        )

        # -------------------------
        # Bidirectional flow key
        # -------------------------

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

        flags = transport.get("flags", [])
        if isinstance(flags, str):
            flag_set = {flags.upper()}
        elif isinstance(flags, (list, tuple, set)):
            flag_set = {str(flag).upper() for flag in flags}
        else:
            flag_set = set()

        previous_flow_id = None
        if (
            flow is not None
            and protocol == "TCP"
            and flow.tcp_state in {"CLOSED", "RESET"}
            and "SYN" in flag_set
            and not flag_set.intersection({"ACK", "FIN", "RST"})
        ):
            # Retire the complete old instance; never clear its counters.
            close_reason = "tcp_closed" if flow.tcp_state == "CLOSED" else "tcp_reset"
            result["expired_flows"].append(flow.to_expired_summary(close_reason))
            previous_flow_id = flow.flow_id
            flow = None

        # -------------------------
        # Application protocol
        # -------------------------

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

        # -------------------------
        # Create new flow
        # -------------------------

        if flow is None:
            flow = Flow(
                flow_id=create_flow_id(
                    flow_key,
                    timestamp,
                    previous_flow_id=previous_flow_id,
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

        # -------------------------
        # Existing flow
        # -------------------------

        else:
            flow.update_application_protocol(
                application_protocol
            )

        # -------------------------
        # Direction
        # -------------------------

        direction = flow.get_direction(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
        )

        # -------------------------
        # TCP connection state
        # -------------------------

        if protocol == "TCP":
            flow.update_tcp_state(
                flags=flags,
                direction=direction,
            )

        # -------------------------
        # Flow statistics
        # -------------------------

        packet_size = (
            self._get_packet_size(
                result
            )
        )

        flow.update_statistics(
            packet_size=packet_size,
            flags=flags,
            direction=direction,
            timestamp=timestamp,
        )

        # -------------------------
        # Attach flow metadata
        # -------------------------

        result["flow"] = (
            flow.to_event_metadata(
                direction
            )
        )

        return result
