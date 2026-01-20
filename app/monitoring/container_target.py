from typing import TYPE_CHECKING, Optional
import threading

from constants import MonitorType
from monitoring.base import MonitoredTarget, SourceMetadata

if TYPE_CHECKING:
    from docker_monitoring.monitor import MonitoredContainerContext, DockerLogMonitor
    from docker_monitoring.helpers import ContainerActionResult


class MonitoredContainerTarget(MonitoredTarget):
    """
    Adapter that wraps MonitoredContainerContext + DockerLogMonitor
    to implement MonitoredTarget protocol.
    """

    def __init__(
        self,
        context: "MonitoredContainerContext",
        monitor: "DockerLogMonitor"
    ):
        self._context = context
        self._monitor = monitor

    @property
    def target_name(self) -> str:
        return self._context.target_name

    @property
    def target_config(self):
        return self._context.target_config

    @property
    def stop_monitoring_event(self) -> threading.Event:
        return self._context.stop_monitoring_event

    @property
    def hostname(self) -> Optional[str]:
        return self._context.hostname

    @property
    def host_identifier(self) -> Optional[str]:
        return self._context.host_identifier

    @property
    def monitor_type(self) -> MonitorType:
        return self._context.monitor_type

    def get_log_tail(self, lines: int) -> Optional[str]:
        return self._monitor.tail_logs(self._context.container_id, lines)

    def supports_container_actions(self) -> bool:
        return True

    def perform_container_action(self, action: str, cooldown: int) -> "ContainerActionResult":
        return self._monitor.trigger_container_action(
            action_to_perform=action,
            triggered_by_container_name=self._context.container_name,
            action_cooldown=cooldown,
        )

    def get_metadata(self) -> SourceMetadata:
        snap = self._context.snapshot
        return SourceMetadata(
            target_name=self.target_name,
            monitor_type=self._context.monitor_type,
            container_id=snap.id,
            container_name=snap.name,
            image=snap.image,
            service_name=snap.service_name,
            stack_name=snap.stack_name,
            labels=snap.labels,
        )
