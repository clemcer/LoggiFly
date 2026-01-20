from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional
import threading

from constants import MonitorType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from config.config_model import ContainerConfig, SwarmServiceConfig
    from docker_monitoring.helpers import ContainerActionResult

@dataclass
class SourceMetadata:
    """
    Source-agnostic metadata for notifications.
    Used by NotificationContext instead of ContainerSnapshot directly.
    """
    target_name: str
    monitor_type: MonitorType

    # Container-specific fields
    container_id: Optional[str] = None
    container_name: Optional[str] = None
    image: Optional[str] = None
    service_name: Optional[str] = None
    stack_name: Optional[str] = None
    labels: Optional[dict] = None


class MonitoredTarget(ABC):
    """
    Abstract base for any monitored log source.

    Implementations:
    - MonitoredContainerTarget: Docker containers and swarm services
    """

    @property
    @abstractmethod
    def target_name(self) -> str:
        """Unique identifier for this target (container name, service.replica)."""
        ...

    @property
    @abstractmethod
    def target_config(self) -> "ContainerConfig | SwarmServiceConfig":
        """Configuration object (ContainerConfig, SwarmServiceConfig)."""
        ...

    @property
    @abstractmethod
    def stop_monitoring_event(self) -> threading.Event:
        """Event signaling monitoring should stop."""
        ...

    @property
    @abstractmethod
    def hostname(self) -> Optional[str]:
        """Hostname of the monitored source."""
        ...

    @property
    @abstractmethod
    def host_identifier(self) -> Optional[str]:
        """Host identifier for multi-host/swarm setups."""
        ...

    @property
    @abstractmethod
    def monitor_type(self) -> MonitorType:
        """Type of monitor (CONTAINER, SWARM)."""
        ...

    @abstractmethod
    def get_log_tail(self, lines: int) -> Optional[str]:
        """
        Get last N lines of logs.
        """
        ...

    def supports_container_actions(self) -> bool:
        """Whether this source supports container actions (restart/stop/start)."""
        return False

    def perform_container_action(self, action: str, cooldown: int) -> Optional["ContainerActionResult"]:
        """
        Perform a container action.
        Override in subclass if supported. Returns None by default.
        """
        return None


    @abstractmethod
    def get_metadata(self) -> SourceMetadata:
        """Get source metadata for notifications."""
        ...
