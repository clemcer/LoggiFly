from dataclasses import dataclass
import logging
from typing import TYPE_CHECKING
from enum import Enum

from config.config_model import GlobalConfig
from config.config_model import ContainerConfig as ModelContainerConfig, SwarmServiceConfig as ModelSwarmServiceConfig
from config.load_config import validate_unit_config
from constants import MonitorType
from docker_monitoring.docker_helpers import ContainerSnapshot, parse_label_config

if TYPE_CHECKING:
    from docker_monitoring.monitor import MonitoredContainerContext

logger = logging.getLogger(__name__)

@dataclass
class MonitorDecision:
    result: 'MonitorDecision.Result'
    reason: str = ""
    config_key: str | None = None
    unit_config: ModelContainerConfig | ModelSwarmServiceConfig | None = None
    config_via_labels: bool | None = None


    class Result(Enum):
        """Possible monitoring decision outcomes."""
        MONITOR = "monitor"              # Start or continue monitoring
        SKIP = "skip"                    # Explicitly excluded (via label or config)
        NOT_CONFIGURED = "not_configured"  # Not in config, monitor_all disabled
        STOP_MONITORING = "stop"         # Currently monitored but should stop (reload)

    class LabelDecision(Enum):
        """Outcome of checking loggifly.monitor label."""
        MONITOR = "monitor"
        SKIP = "skip"
        UNKNOWN = "unknown"

    @staticmethod
    def _check_label(labels: dict | None) -> 'MonitorDecision.LabelDecision':
        """Extract and check the 'loggifly.monitor' label value."""
        if labels is None:
            return MonitorDecision.LabelDecision.UNKNOWN
        monitor_value = labels.get("loggifly.monitor", "").lower().strip()
        if not monitor_value:
            return MonitorDecision.LabelDecision.UNKNOWN
        if monitor_value == "true":
            return MonitorDecision.LabelDecision.MONITOR
        elif monitor_value == "false":
            return MonitorDecision.LabelDecision.SKIP
        return MonitorDecision.LabelDecision.UNKNOWN

    @property
    def should_monitor(self) -> bool:
        """Whether monitoring should start or continue."""
        return self.result == MonitorDecision.Result.MONITOR

    @property
    def should_stop(self) -> bool:
        """Whether existing monitoring should stop."""
        return self.result == MonitorDecision.Result.STOP_MONITORING

    @classmethod
    def evaluate(
        cls,
        snapshot: ContainerSnapshot,
        global_config: GlobalConfig,
        hostname: str,
        skip_labels: bool = False,
    ) -> 'MonitorDecision':
        """
        Decide if a container should be monitored based on labels, config, and settings.

        Decision precedence:
        1. Labels (if not skip_labels): loggifly.monitor=true/false
        2. Explicit config: containers.{name} or swarm_services.{name}
        3. Global settings: monitor_all_containers/monitor_all_swarm_services
        4. Exclusions: excluded_containers/excluded_swarm_services
        """
        if snapshot.is_swarm_service:
            return cls._evaluate_swarm(
                snapshot=snapshot,
                global_config=global_config,
                skip_labels=skip_labels,
            )
        else:
            return cls._evaluate_container(
                snapshot=snapshot,
                global_config=global_config,
                hostname=hostname,
                skip_labels=skip_labels,
            )

    @classmethod
    def evaluate_for_reload(
        cls,
        ctx: 'MonitoredContainerContext',
        new_config: GlobalConfig,
        hostname: str,
    ) -> 'MonitorDecision':
        """
        Decide if a currently monitored container should continue being monitored.

        Used during config reload to determine if monitoring should stop or continue
        with updated configuration.
        """
        if ctx.monitor_type == MonitorType.CONTAINER:
            return cls._evaluate_container_for_reload(
                ctx=ctx,
                new_config=new_config,
                hostname=hostname,
            )
        elif ctx.monitor_type == MonitorType.SWARM:
            return cls._evaluate_swarm_for_reload(
                ctx=ctx,
                new_config=new_config,
            )
        else:
            raise ValueError(f"Invalid monitor type: {ctx.monitor_type}")
            
    @staticmethod
    def _get_container_settings_for_host(global_config: GlobalConfig, hostname: str):
        """Extract host-specific container settings."""
        host_config = global_config.hosts.get(hostname) if isinstance(global_config.hosts, dict) and hostname else None
        containers = dict(global_config.containers or {})  # Create copy!

        if host_config:
            monitor_all_containers = host_config.monitor_all_containers if host_config.monitor_all_containers is not None else global_config.settings.monitor_all_containers
            excluded_containers = host_config.excluded_containers or global_config.settings.excluded_containers or []
            containers.update(host_config.containers or {})
        else:
            monitor_all_containers = global_config.settings.monitor_all_containers
            excluded_containers = global_config.settings.excluded_containers or []

        return containers, monitor_all_containers, excluded_containers

    @classmethod
    def _evaluate_swarm(
        cls,
        snapshot: ContainerSnapshot,
        global_config: GlobalConfig,
        skip_labels: bool,
    ) -> 'MonitorDecision':
        service_name = snapshot.service_name
        stack_name = snapshot.stack_name
        unit_name = snapshot.unit_name

        assert service_name is not None, "service_name must not be None for swarm service containers"

        # Check labels first (both service labels and container labels as fallback)
        decision = cls.LabelDecision.UNKNOWN
        label_source = None

        if not skip_labels:
            # Try service labels first
            if snapshot.service_labels:
                decision = cls._check_label(snapshot.service_labels)
                label_source = "swarm service labels"

            # Fallback to container labels if unknown
            if decision == cls.LabelDecision.UNKNOWN:
                decision = cls._check_label(snapshot.labels)
                label_source = "container labels"

        # Labels explicitly say monitor
        if decision == cls.LabelDecision.MONITOR:
            unit_config = validate_unit_config(
                MonitorType.SWARM,
                parse_label_config(snapshot.service_labels or snapshot.labels)
            )
            if unit_config is None:
                labels_info = snapshot.service_labels or snapshot.labels
                logger.error(
                    f"Could not validate swarm service config for '{service_name}' from {label_source}.\n"
                    f"Labels: {labels_info}"
                )
            else:
                return cls(
                    result=cls.Result.MONITOR,
                    reason=f"monitored via {label_source}",
                    config_key=service_name,
                    unit_config=unit_config,
                    config_via_labels=True
                )

        # Labels explicitly say skip
        if decision == cls.LabelDecision.SKIP:
            return cls(
                result=cls.Result.SKIP,
                reason=f"label says loggifly.monitor=false ({label_source})"
            )

        monitor_all_swarm_services = global_config.settings.monitor_all_swarm_services
        excluded_swarm_services = global_config.settings.excluded_swarm_services or []
        swarm_services = global_config.swarm_services or {}
        # Check explicit config
        if swarm_services:
            if service_name in swarm_services:
                unit_config = swarm_services[service_name]
                return cls(
                    result=cls.Result.MONITOR,
                    reason=f"monitored via config.yaml",
                    config_key=service_name,
                    unit_config=unit_config,
                    config_via_labels=False
                )
            if stack_name and stack_name in swarm_services:
                unit_config = swarm_services[stack_name]
                return cls(
                    result=cls.Result.MONITOR,
                    reason=f"monitored via config.yaml",
                    config_key=stack_name,
                    unit_config=unit_config,
                    config_via_labels=False
                )

        # Check monitor_all_swarm_services with exclusions
        if monitor_all_swarm_services:
            if any(n in excluded_swarm_services for n in [service_name, stack_name, unit_name]):
                return cls(
                    result=cls.Result.SKIP,
                    reason=f"excluded via excluded_swarm_services setting"
                )
            return cls(
                result=cls.Result.MONITOR,
                reason="monitored via monitor_all_swarm_services setting",
                config_key=service_name,
                unit_config=ModelSwarmServiceConfig(),
                config_via_labels=False
            )

        # Not configured anywhere
        return cls(
            result=cls.Result.NOT_CONFIGURED,
            reason="not in config and monitor_all_swarm_services is disabled"
        )

    @classmethod
    def _evaluate_container(
        cls,
        snapshot: ContainerSnapshot,
        global_config: GlobalConfig,
        hostname: str,
        skip_labels: bool,
    ) -> 'MonitorDecision':
        cname = snapshot.name

        # Check labels
        decision = cls.LabelDecision.UNKNOWN if skip_labels else cls._check_label(snapshot.labels)

        # Labels explicitly say monitor
        if decision == cls.LabelDecision.MONITOR:
            unit_config = validate_unit_config(
                MonitorType.CONTAINER,
                parse_label_config(snapshot.labels)
            )
            if unit_config is None:
                logger.error(
                    f"Could not validate container config for '{cname}' from labels.\n"
                    f"Labels: {snapshot.labels}"
                )
            else:
                return cls(
                    result=cls.Result.MONITOR,
                    reason="monitored via container labels",
                    config_key=cname,
                    unit_config=unit_config,
                    config_via_labels=True
                )

        # Labels explicitly say skip
        if decision == cls.LabelDecision.SKIP:
            return cls(
                result=cls.Result.SKIP,
                reason="label says loggifly.monitor=false"
            )
        containers, monitor_all_containers, excluded_containers = cls._get_container_settings_for_host(global_config, hostname)
        # Check explicit config
        if cname in containers:
            unit_config = containers[cname]
            if hostname and unit_config.hosts and not any(hn.strip() == hostname for hn in unit_config.hosts.split(",")):
                return cls(
                    result=cls.Result.SKIP,
                    reason=f"container {cname} is configured for host(s) '{unit_config.hosts}' but this instance is running on host '{hostname}'. Skipping this container."
                )
            return cls(
                result=cls.Result.MONITOR,
                reason=f"monitored via config.yaml",
                config_key=cname,
                unit_config=unit_config,
                config_via_labels=False
            )

        # Check monitor_all_containers with exclusions
        if monitor_all_containers:
            if cname in excluded_containers:
                return cls(
                    result=cls.Result.SKIP,
                    reason="excluded via excluded_containers setting"
                )
            return cls(
                result=cls.Result.MONITOR,
                reason="monitored via monitor_all_containers setting",
                config_key=cname,
                unit_config=ModelContainerConfig(),
                config_via_labels=False
            )

        # Not configured anywhere
        return cls(
            result=cls.Result.NOT_CONFIGURED,
            reason="not in config and monitor_all_containers is disabled"
        )

    @classmethod
    def _evaluate_container_for_reload(
        cls,
        ctx: 'MonitoredContainerContext',
        new_config: GlobalConfig,
        hostname: str,
    ) -> 'MonitorDecision':
        # Label-based configs are not affected by config reloads
        if ctx.config_via_labels:
            return cls(
                result=cls.Result.MONITOR,
                reason="monitored via labels (unchanged)",
                config_key=ctx.config_key,
                unit_config=ctx.unit_config,
                config_via_labels=ctx.config_via_labels
            )
        containers, monitor_all_containers, excluded_containers = cls._get_container_settings_for_host(new_config, hostname)
        # Check if excluded
        if monitor_all_containers:
            if ctx.config_key in excluded_containers:
                return cls(
                    result=cls.Result.STOP_MONITORING,
                    reason="excluded via excluded_containers"
                )
            return cls(
                result=cls.Result.MONITOR,
                reason="monitored via monitor_all_containers setting",
                config_key=ctx.config_key,
                unit_config=ModelContainerConfig(),
                config_via_labels=False
            )
        else:
            # Not monitor_all - must be explicitly in config
            if ctx.config_key not in containers:
                return cls(
                    result=cls.Result.STOP_MONITORING,
                    reason="not present in current config"
                )
            else:
                unit_config = containers[ctx.config_key]
                if hostname and unit_config.hosts and not any(hn.strip() == hostname for hn in unit_config.hosts.split(",")):
                    return cls(
                        result=cls.Result.STOP_MONITORING,
                        reason=f"container {ctx.config_key} is configured for host(s) '{unit_config.hosts}' but this instance is running on host '{hostname}'. Stopping monitoring for this container."
                    )

        # Still should be monitored - get updated config
        unit_config = containers.get(ctx.config_key)
        if unit_config is None:
            # This shouldn't happen but handle gracefully
            return cls(
                result=cls.Result.STOP_MONITORING,
                reason="config not found in new config"
            )

        return cls(
            result=cls.Result.MONITOR,
            reason="config updated from config.yaml",
            config_key=ctx.config_key,
            unit_config=unit_config,
            config_via_labels=False
        )

    @classmethod
    def _evaluate_swarm_for_reload(
        cls,
        ctx: 'MonitoredContainerContext',
        new_config: GlobalConfig,
    ) -> 'MonitorDecision':
        # Label-based configs are not affected by config reloads
        if ctx.config_via_labels:
            return cls(
                result=cls.Result.MONITOR,
                reason="monitored via labels (unchanged)",
                config_key=ctx.config_key,
                unit_config=ctx.unit_config,
                config_via_labels=ctx.config_via_labels
            )

        monitor_all_swarm_services = new_config.settings.monitor_all_swarm_services
        excluded_swarm_services = new_config.settings.excluded_swarm_services or []
        swarm_services = new_config.swarm_services or {}

        # Check if excluded
        if monitor_all_swarm_services:
            if any(n in excluded_swarm_services for n in [ctx.config_key, ctx.unit_name]):
                return cls(
                    result=cls.Result.STOP_MONITORING,
                    reason="excluded via excluded_swarm_services"
                )
            return cls(
                result=cls.Result.MONITOR,
                reason="monitored via monitor_all_swarm_services setting",
                config_key=ctx.config_key,
                unit_config=ModelSwarmServiceConfig(),
                config_via_labels=False
            )
        else:
            # Not monitor_all - must be explicitly in config
            if ctx.config_key not in swarm_services:
                return cls(
                    result=cls.Result.STOP_MONITORING,
                    reason="not present in current config"
                )

        # Still should be monitored - get updated config
        unit_config = swarm_services.get(ctx.config_key)
        if unit_config is None:
            return cls(
                result=cls.Result.STOP_MONITORING,
                reason="config not found in new config"
            )

        return cls(
            result=cls.Result.MONITOR,
            reason="config updated from config.yaml",
            config_key=ctx.config_key,
            unit_config=unit_config,
            config_via_labels=False
        )
