from config.config_model import GlobalConfig
from dataclasses import dataclass
import os
import re
import time
import logging
import traceback
from typing import Any, Optional
from docker.models.containers import Container
from docker.client import DockerClient
import docker.errors
import socket
from constants import Actions

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ContainerSnapshot:

    """
    Lightweight, immutable snapshot of container metadata for monitoring decisions.

    Avoids passing heavy Docker container objects around. Created once from a container,
    then can be reused for multiple decision evaluations.
    """
    name: str
    id: str
    labels: dict # Container labels
    image: str # Image name

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
                image=container.attrs.get("Config", {}).get("Image"),
                labels=container.labels or {},
                service_name=service_name,
                stack_name=stack_name,
                service_labels=service_labels or {}
            )
        return cls(
            name=container.name,
            id=container.id,
            image=container.attrs.get("Config", {}).get("Image"),
            labels=container.labels or {}
        )

@dataclass
class ContainerActionResult:
    """Result of a container action attempt"""
    success: bool
    message: str
    action_type: str # e.g. "start"
    action_target: str # e.g. "container_name"
    is_on_cooldown: bool = False

class ContainerActionError(Exception):
    """Base exception for container action failures"""
    pass

class ContainerValidationError(ContainerActionError):
    """Container state is invalid for the requested action"""
    pass

def format_docker_error(error: Exception) -> str:
    """
    Extract user-friendly message from Docker exception.
            """
    error_str = str(error)
    if "403" in error_str or "Forbidden" in error_str:
        return "Permission denied (403 Forbidden)"
    if "404" in error_str or "Not Found" in error_str:
        return "Container not found (404)"
    if "500" in error_str or "Internal Server Error" in error_str:
        return "Docker daemon error (500)"
    if "permission denied" in error_str.lower():
        return "Permission denied"
    if "timeout" in error_str.lower():
        return "Operation timed out"
    return "See logs for details."

def cleanup_stale_action_cooldowns(
    action_cooldowns: dict,
    max_age_seconds: int = 86400,  # 24 hours default
    size_threshold: int = 1000      # Cleanup when dict has >1000 containers
) -> None:
    """
    Remove action cooldown entries older than max_age_seconds.
    Only runs if dict size exceeds threshold (lazy cleanup).
    
    Args:
        action_cooldowns: The nested dict {container: {action: timestamp}}
        max_age_seconds: Remove entries older than this (default 24h)
        size_threshold: Only cleanup if dict has this many containers
    """
    # Only run cleanup if dict is getting large
    if len(action_cooldowns) < size_threshold:
        return
    now = time.time()
    cutoff_time = now - max_age_seconds
    # Find stale containers (all actions are old)
    stale_containers = []
    for container, actions in action_cooldowns.items():
        # Check if ALL actions for this container are stale
        if all(timestamp < cutoff_time for timestamp in actions.values()):
            stale_containers.append(container)
    # Remove stale containers
    for container in stale_containers:
        del action_cooldowns[container]
    # Also cleanup stale individual actions within containers
    for container, actions in action_cooldowns.items():
        stale_actions = [action for action, timestamp in actions.items() if timestamp < cutoff_time]
        for action in stale_actions:
            del actions[action]


def parse_action_target(action: str, container_name: str) -> tuple:
    action_parts = action.split("@")
    if len(action_parts) == 1:
        action_name = action_parts[0].strip().lower()
        container_name = container_name
    elif len(action_parts) == 2:
        action_name = action_parts[0].strip().lower()
        container_name = action_parts[1].strip()
    else:
        logger.error(f"Invalid action syntax: {action}")
        return None, None
    return action_name, container_name


def validate_container_for_action(
    container: Container,
    client: DockerClient,
) -> None:
    """
    Validate container is suitable for actions.
    
    Raises:
        Exception: If container is swarm service or is LoggiFly itself
    """
    if get_service_info(container, client):
        raise Exception(f"Container '{container.name}' belongs to a swarm service.")

    if container.id and socket.gethostname() == container.id[:12]:
        raise Exception("LoggiFly cannot perform actions on itself.")


def container_action(container: Container, action: str, logger: logging.Logger) -> str:
    """
    Perform an action on a container (start, stop, restart).

    Args:
        container: Container object
        action: action string
    Returns:
        str: Result message describing action outcome to append to a notification title
    Raises:
        ContainerValidationError: Container state is invalid for action
        ContainerActionError: Docker operation failed
    """
    container_name = container.name

    try:
        container.reload()
        logger.debug(f"Performing action '{action}' on container {container_name} with status {container.status}.")

        if action == Actions.STOP.value:
            if container.status != "running":
                raise ContainerValidationError(f"Did not stop {container_name}, container is not running")
            logger.info(f"Stopping Container: {container_name}.")
            container.stop()
            container.wait(timeout=10)
            container.reload()
            logger.info(f"Container {container_name} has been stopped: Status: {container.status}")
            return f"{container_name} has been stopped!"

        elif action == Actions.RESTART.value:
            logger.info(f"Restarting Container: {container_name}.")
            container.restart()
            container.reload()
            logger.info(f"Container {container_name} has been restarted. Status: {container.status}")
            return f"{container_name} has been restarted!"

        elif action == Actions.START.value:
            if container.status == "running":
                raise ContainerValidationError(f"Did not start {container_name}, container is already running")
            logger.info(f"Starting Container: {container_name}.")
            container.start()
            start_time = time.time()
            while True:
                container.reload()
                if container.status == "running":
                    break
                if time.time() - start_time > 10:
                    raise ContainerValidationError(f"Timeout waiting for {container_name} to start")
                time.sleep(1)
            logger.info(f"Container {container_name} has been started. Status: {container.status}")
            return f"{container_name} has been started!"
        else:
            raise AssertionError(f"Unknown action: {action}")
    except ContainerValidationError:
        raise
    except docker.errors.APIError as e:
        logger.error(f"Docker API error while performing {action} on {container_name}: {e}")
        logger.debug(traceback.format_exc())
        error_detail = format_docker_error(e)
        raise ContainerActionError(f"Failed to {action} {container_name}. {error_detail}")
    except Exception as e:
        logger.error(f"Unexpected error while performing {action} on {container_name}: {e}")
        logger.debug(traceback.format_exc())
        error_detail = format_docker_error(e)
        raise ContainerActionError(f"Failed to {action} {container_name}. {error_detail}")


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
    keywords_to_append = []
    container_events_by_index = {}
    container_events_to_append = []
    config = {}
    if labels.get("loggifly.monitor", "false").lower() != "true":
        return config
    logging.debug("Parsing loggifly monitor labels...")
    for key, value in labels.items():
        if not key.startswith("loggifly."):
            continue
        parts = key[9:].split('.') 
        if len(parts) == 1:
            # Simple comma-separated keyword list
            if parts[0] == "keywords" and isinstance(value, str):
                keywords_to_append = [kw.strip() for kw in value.split(",") if kw.strip()]
            elif parts[0] == "excluded_keywords" and isinstance(value, str):
                config["excluded_keywords"] = [kw.strip() for kw in value.split(",") if kw.strip()]
            elif parts[0] == "container_events" and isinstance(value, str):
                container_events_to_append = [event.strip() for event in value.split(",") if event.strip()]
            # Top Level Fields (e.g. ntfy_topic, attach_logfile, etc.)
            else:
                config[parts[0]] = value
        # Keywords
        elif parts[0] == "keywords":
            index = parts[1]
            # Simple keywords (direct value instead of dict) - loggifly.keywords.1 = value
            if len(parts) == 2:
                keywords_by_index.setdefault(index, {})["keyword"] = value 
            # Complex Keyword (Dict with fields) - loggifly.keywords.1.keyword = value or loggifly.keywords.1.regex = value
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
        elif parts[0] == "container_events":
            index = parts[1]
            # simple event, direct value - loggifly.container_events.1 = event
            if len(parts) == 2:
                container_events_by_index.setdefault(index, {})["event"] = value
            # complex event, dict with fields - loggifly.container_events.1.event = event and loggifly.container_events.1.action = action
            else:
                field = parts[2]
                if index not in container_events_by_index:
                    container_events_by_index[index] = {}
                container_events_by_index[index][field] = value
    config["keywords"] = [keywords_by_index[k] for k in sorted(keywords_by_index)]
    if keywords_to_append:
        config["keywords"].extend(keywords_to_append)

    if container_events_by_index or container_events_to_append:
        config["container_events"] = [container_events_by_index[k] for k in sorted(container_events_by_index)]
        if container_events_to_append:
            config["container_events"].extend(container_events_to_append)    
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

def swarm_mode_enabled() -> bool:
    return os.getenv("LOGGIFLY_MODE", "").strip().lower() == "swarm"