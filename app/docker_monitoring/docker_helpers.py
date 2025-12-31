from config.config_model import GlobalConfig
from constants import MonitorLabelDecision
from dataclasses import dataclass
import re
import logging
from typing import Any


@dataclass(frozen=True)
class ContainerSnapshot:

    """
    Lightweight, immutable snapshot of container metadata for monitoring decisions.

    Avoids passing heavy Docker container objects around. Created once from a container,
    then can be reused for multiple decision evaluations.
    """
    name: str
    id: str
    labels: dict  # Container labels

    # Swarm-specific fields (None for regular containers)
    service_name: str | None = None
    stack_name: str | None = None
    service_labels: dict | None = None  # Labels from the swarm service (not container)

    @property
    def is_swarm_service(self) -> bool:
        return self.service_name is not None

    @property
    def unit_name(self) -> str:
        """
        Compute the unit name for this container.
        For swarm services, includes replica number (e.g., "service.1").
        For regular containers, returns the container name.
        """
        if self.is_swarm_service:
            return get_service_unit_name(self.labels) or self.name
        return self.name

    @classmethod
    def from_container(cls, container, client) -> 'ContainerSnapshot':
        """
        Extract minimal metadata from a Docker container object.
        """
        service_info = get_service_info(container, client)
        if service_info:
            service_name, stack_name, service_labels = service_info
            return cls(
                name=container.name,
                id=container.id,
                labels=container.labels or {},
                service_name=service_name,
                stack_name=stack_name,
                service_labels=service_labels or {}
            )
        return cls(
            name=container.name,
            id=container.id,
            labels=container.labels or {}
        )

def get_configured(config: GlobalConfig, hostname: str) -> tuple[list[str], list[str]]:
    selected_containers = []
    selected_swarm_services = []
    host_config = config.hosts.get(hostname) if isinstance(config.hosts, dict) and hostname else None
    containers = dict(config.containers or {})
    if host_config:
        containers.update(host_config.containers or {})    
    swarm_services = config.swarm_services or {}
    
    configs_to_check = [
        (containers, selected_containers),
        (swarm_services, selected_swarm_services),
    ]
    for (objects_in_config, selected) in configs_to_check:
        if not objects_in_config:
            continue
        for object_name in objects_in_config:
            config_object = objects_in_config[object_name]
            if hostname and config_object.hosts is not None:
                hostnames = config_object.hosts.split(",")
                if all(hn.strip() != hostname for hn in hostnames):
                    continue
            selected.append(object_name)
    return selected_containers, selected_swarm_services

def check_monitor_label(labels) -> MonitorLabelDecision:
    """Extract and check the 'loggifly.monitor' label value."""
    if labels is None:
        return MonitorLabelDecision.UNKNOWN
    monitor_value = labels.get("loggifly.monitor", "").lower().strip()
    if not monitor_value:
        return MonitorLabelDecision.UNKNOWN
    if monitor_value == "true":
        return MonitorLabelDecision.MONITOR
    elif monitor_value == "false":
        return MonitorLabelDecision.SKIP
    return MonitorLabelDecision.UNKNOWN


def get_service_info(container, client) -> tuple[str, str, dict] | None:
    """Get Docker Swarm service information from a container."""
    container_labels = container.labels
    if not container_labels or not container_labels.get("com.docker.swarm.service.id"):
        return None
    service_name = container_labels.get("com.docker.swarm.service.name", "")
    stack_name = container_labels.get("com.docker.stack.namespace", "")
    try:
        service = client.services.get(container_labels.get("com.docker.swarm.service.id", ""))
        service_labels = service.attrs["Spec"]["Labels"]
        return service_name, stack_name, service_labels
    except Exception as e:
        return service_name, stack_name, {}


def get_service_unit_name(labels) -> str | None:
    """
    Extract the service name with their replica id from container labels so that we have a unique name for each replica.
    Converts service_name.1.1234567890 to service_name.1
    """
    task_id = labels.get("com.docker.swarm.task.id")
    task_name = labels.get("com.docker.swarm.task.name")
    service_name = labels.get("com.docker.swarm.service.name", "")
    stack_name = labels.get("com.docker.stack.namespace", "")
    if not any([service_name, task_id, task_name]):
        return None
    # Regex: service_name.<replica>.<task_id>
    pattern = re.escape(service_name) + r"\.(\d+)\." + re.escape(task_id) + r"$"
    regex = re.compile(pattern)
    match = regex.search(task_name)
    if match:
        return f"{service_name}.{match.group(1)}"
    else:
        return service_name or stack_name


def parse_label_config(labels: dict) -> dict[str, Any]:
    """Parse LoggiFly configuration from Docker labels."""
    keywords_by_index = {}
    config = {}
    if labels.get("loggifly.monitor", "false").lower() != "true":
        return config
    logging.debug("Parsing loggifly monitor labels...")
    keywords_to_append = []
    for key, value in labels.items():
        if not key.startswith("loggifly."):
            continue
        parts = key[9:].split('.') 
        if len(parts) == 1:
            # Simple comma-separated keyword list
            if parts[0] == "keywords" and isinstance(value, str):
                keywords_to_append = [kw.strip() for kw in value.split(",") if kw.strip()]
            # Top Level Fields (e.g. ntfy_topic, attach_logfile, etc.)
            elif parts[0] == "excluded_keywords" and isinstance(value, str):
                config["excluded_keywords"] = [kw.strip() for kw in value.split(",") if kw.strip()]
            else:
                config[parts[0]] = value
        # Keywords
        elif parts[0] == "keywords":
            index = parts[1]
            # Simple keywords (direct value instead of dict)
            if len(parts) == 2:
                keywords_by_index[index] = value
            # Complex Keyword (Dict with fields)
            else:
                field = parts[2]
                if index not in keywords_by_index:
                    keywords_by_index[index] = {}
                if field == "keyword_group":
                    keywords_by_index[index][field] = [kw.strip() for kw in value.split(",") if kw.strip()]
                elif field == "excluded_keywords":
                    keywords_by_index[index][field] = [kw.strip() for kw in value.split(",") if kw.strip()]
                else:
                    keywords_by_index[index][field] = value
    
    config["keywords"] = [keywords_by_index[k] for k in sorted(keywords_by_index)]
    if keywords_to_append:
        config["keywords"].extend(keywords_to_append)
    logging.debug(f"Parsed config: {config}")
    return config

def parse_event_type(event: dict) -> str | None:
    """
    Parse the event type from the event string.
    """
    if not event:
        return None
    action = event.get("Action", "").strip()
    status = event.get("status", "").strip()
    logging.debug(f"Action: {action}, Status: {status}")
    exit_code = event.get("Actor", {}).get("Attributes", {}).get("exitCode")
    logging.debug(f"Exit Code: {exit_code}")
    if status.startswith("health_status"):
        parts = status.split(":", 1)
        if len(parts) == 2:
            return parts[1].strip()  # -> "healthy" / "unhealthy" / "starting"
    if action == "die":
        try:
            exit_code = int(exit_code)
        except ValueError:
            exit_code = None
        if exit_code != 0:
            return "crash"
        return "die"
    return action
