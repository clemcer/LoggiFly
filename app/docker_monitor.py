import logging
import threading
import socket
import traceback
import time
import os
import random
import re
import requests
from typing import Optional, Any
import docker
import docker.errors
from datetime import datetime
from notifier import send_notification
from line_processor import LogProcessor
from config.config_model import (
    GlobalConfig, HostConfig, 
    ContainerConfig as ModelContainerConfig, 
    SwarmServiceConfig as ModelSwarmServiceConfig
    )
from config.load_config import validate_unit_config, get_pretty_yaml_config
from constants import (
    Actions,
    MonitorType, 
    MonitorDecision, 
)


class ContainerConfig:

    def __init__(self, monitor_type, config_key, unit_name, unit_config, container_name, container_id, config_via_labels=False):
        self.monitor_type = monitor_type  # MonitorType.CONTAINER or MonitorType.SWARM
        self.config_key = config_key  # The key used in the configuration (for swawrm it can be stack or service name)
        self.unit_name = unit_name  # Unique name for container/service (also if it is a swarm service container replica)
        self.unit_config = unit_config  # The config for the unit in GlobalConfig
        self.config_via_labels = config_via_labels  # True if the context was created from labels, False if it was created from config
        self.container_name = container_name
        self.container_id = container_id


class MonitoredContainerContext(ContainerConfig):

    def __init__(self, monitor_type, config_key, unit_name, container_name, container_id, unit_config, config_via_labels):
        super().__init__(monitor_type, config_key, unit_name, unit_config, container_name, container_id, config_via_labels)
        self.generation = 0  # Used to track container restarts
        self.stop_monitoring_event = threading.Event()  # Signal to stop monitoring
        self.monitoring_stopped_event = threading.Event()  # Signal that the monitoring thread has stopped
        self.log_stream = None  # Will be set when the log stream is opened
        self.processor = None  # Will be set after initialization

    @classmethod
    def from_container_config(cls, container_config):
        return cls(
            monitor_type=container_config.monitor_type,
            config_key=container_config.config_key,
            unit_name=container_config.unit_name,
            container_name=container_config.container_name,
            container_id=container_config.container_id,
            unit_config=container_config.unit_config,
            config_via_labels=container_config.config_via_labels
        )   

    def set_processor(self, processor):
        self.processor = processor


class MonitoredContainerRegistry:
    """
    Registry of monitored containers and formerly monitored containers.
    Provides lookup by container ID and unit name.
    """
    
    def __init__(self):
        """Initialize empty registry with lookup indexes."""
        self._by_id = {}
        self._by_unit_name = {}

    def add(self, container_context: MonitoredContainerContext):
        monitor_type = container_context.monitor_type
        container_id = container_context.container_id
        unit_name = container_context.unit_name
       
        self._by_id[container_id] = container_context
        self._by_unit_name[(monitor_type, unit_name)] = container_context
        
    def get_by_id(self, container_id: str) -> MonitoredContainerContext | None:
        return self._by_id.get(container_id)
    
    def get_by_unit_name(self, monitor_type: MonitorType, unit_name: str) -> MonitoredContainerContext | None:
       
        return self._by_unit_name.get((monitor_type, unit_name))
            
    def get_actively_monitored(self, monitor_type: MonitorType | None = None) -> list[MonitoredContainerContext]:
        """
        Return a list of actively monitored containers.
        
        Args:
            monitor_type: Filter by MonitorType.CONTAINER, MonitorType.SWARM, or None for all
            
        Returns:
            list: List of actively monitored container contexts
        """
        if monitor_type == MonitorType.SWARM:
            return [
                ctx for ctx in self._by_id.values()
                if not ctx.monitoring_stopped_event.is_set() and ctx.monitor_type == MonitorType.SWARM
            ]
        elif monitor_type == MonitorType.CONTAINER:   
            return [
                ctx for ctx in self._by_id.values()
                if not ctx.monitoring_stopped_event.is_set() and ctx.monitor_type == MonitorType.CONTAINER
            ]
        else:
            return [ctx for ctx in self._by_id.values() if not ctx.monitoring_stopped_event.is_set()]

    def update_id(self, old_id, new_id):
        """Update container ID in registry when container is recreated."""
        if (container_context := self._by_id.pop(old_id, None)) is not None:
            container_context.container_id = new_id
            self._by_id[new_id] = container_context

    def values(self) -> list[MonitoredContainerContext]:
        """Get all container contexts in the registry."""
        return list(self._by_id.values())


class DockerLogMonitor:
    """
    Monitors Docker containers and events for a given host.

    Starts a thread for each monitored container and a thread for Docker event monitoring.
    Handles config reloads, container start/stop, and log processing.
    """
    
    def __init__(self, config, hostname, host):
        """Initialize Docker log monitor for a specific host."""
        self.hostname = hostname  # empty string if only one client is being monitored, otherwise the hostname of the client do differentiate between the hosts
        self.host = host
        self.config = config
        self.swarm_mode = os.getenv("LOGGIFLY_MODE", "").strip().lower() == "swarm"
        self._registry = MonitoredContainerRegistry()
        self.registry_lock = threading.Lock()
        self.event_stream = None

        self.shutdown_event = threading.Event()
        self.cleanup_event = threading.Event()
        self.threads = []
        self.threads_lock = threading.Lock()
        self.selected_containers = []
        self.selected_swarm_services = []
        
    def _init_logging(self):
        """Configure logger to include hostname for multi-host or swarm setups."""
        self.logger = logging.getLogger(f"Monitor-{self.hostname}")
        self.logger.handlers.clear()
        handler = logging.StreamHandler()
        formatter = (
            logging.Formatter(f'%(asctime)s - %(levelname)s - [Host: {self.hostname}] - %(message)s')
            if self.hostname else logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.log_level = self.config.settings.log_level.upper()
        self.logger.setLevel(getattr(logging, self.log_level, logging.INFO))
        self.logger.propagate = False

    def _add_thread(self, thread):
        with self.threads_lock:
            self.threads.append(thread)

    def _get_host_config(self):
        # self.swarm_services_config = self.config.swarm_services or {} # TODO
        host_config = self.config.hosts.get(self.hostname) if isinstance(self.config.hosts, dict) and self.hostname else None
        self.monitor_all_swarm_services = self.config.settings.monitor_all_swarm_services
        self.excluded_swarm_services = self.config.settings.excluded_swarm_services or []
        if not host_config:
            containers_config = self.config.containers or {}
            self.monitor_all_containers = self.config.settings.monitor_all_containers
            self.excluded_containers = self.config.settings.excluded_containers or []
        else:
            containers_config = host_config.containers or {}
            self.monitor_all_containers = host_config.monitor_all_containers if host_config.monitor_all_containers is not None else self.config.settings.monitor_all_containers
            self.excluded_containers = host_config.excluded_containers or self.config.settings.excluded_containers or []
            if self.config.containers:
                for container_name, container_config in self.config.containers.items():
                    if container_name not in containers_config:
                        containers_config[container_name] = container_config
        return containers_config

    def _get_selected_containers(self):
        """
        Build lists of containers and swarm services to monitor based on config.
        Respects host filtering when multiple Docker hosts are configured.
        """
        self.selected_containers = []
        self.selected_swarm_services = []
        configs_to_check = [
            (self.containers_config, self.selected_containers, "Container"),
            (self.config.swarm_services, self.selected_swarm_services, "Swarm Service"),
        ]
        for (config, selected, type_placeholder) in configs_to_check:
            if not config:
                continue
            for object_name in config:
                config_object = config[object_name]
                if self.hostname and config_object.hosts is not None:
                    hostnames = config_object.hosts.split(",")
                    if all(hn.strip() != self.hostname for hn in hostnames):
                        self.logger.debug(f"{type_placeholder} {object_name} is configured for host(s) '{', '.join(hostnames)}' but this instance is running on host '{self.hostname}'. Skipping this {type_placeholder}.")
                        continue
                selected.append(object_name)
        self.logger.debug(f"Selected {len(self.selected_containers)} containers and {len(self.selected_swarm_services)} swarm services via yaml config or environment variables.")

    def _should_monitor(self, container, skip_labels=False) -> ContainerConfig | None:
        """Determine if a container should be monitored based on configuration and labels."""
        cname = container.name
        cid = container.id
        container_labels = container.labels or {}

        # Check if the container is a swarm service
        if service_info := get_service_info(container, self.client):
            service_name, stack_name, labels = service_info
            label_source = "swarm service labels"
            unit_name = get_service_unit_name(container_labels) or container.name
            decision = check_monitor_label(labels) if not skip_labels else MonitorDecision.UNKNOWN
            # If the decision is unknown, check the container labels as fallback. Service Labels can only be read on manager nodes.
            if not skip_labels and decision == MonitorDecision.UNKNOWN:
                labels, label_source = container_labels, "container labels"
                decision = check_monitor_label(labels) if not skip_labels else MonitorDecision.UNKNOWN
         
            if decision == MonitorDecision.MONITOR:
                unit_config = validate_unit_config(MonitorType.SWARM, parse_label_config(labels))
                if unit_config is None:
                    self.logger.error(f"Could not validate swarm service config for '{service_name}' from {label_source}.\nLabels: {labels}")
                    return None
                self.logger.info(f"Validated swarm service config for '{unit_name}' from {label_source}:\n{get_pretty_yaml_config(unit_config, top_level_key=service_name)}")
                return ContainerConfig(MonitorType.SWARM, service_name, unit_name, unit_config, cname, cid, config_via_labels=True)
            elif decision == MonitorDecision.SKIP:
                return None
            elif decision == MonitorDecision.UNKNOWN and self.config.swarm_services:
                if service_name in self.selected_swarm_services:
                    return ContainerConfig(MonitorType.SWARM, service_name, unit_name, self.config.swarm_services[service_name], cname, cid)
                elif stack_name in self.selected_swarm_services:
                    return ContainerConfig(MonitorType.SWARM, stack_name, unit_name, self.config.swarm_services[stack_name], cname, cid)
            # Check if it should be monitored because of `monitor_all_swarm_services` setting
            if decision == MonitorDecision.UNKNOWN and self.monitor_all_swarm_services:
                if not any(n in self.excluded_swarm_services for n in [service_name, stack_name, unit_name]):
                    return ContainerConfig(MonitorType.SWARM, service_name, unit_name, ModelSwarmServiceConfig(), cname, cid)
                else:
                    self.logger.debug(f"Swarm Service {service_name} is excluded from monitoring. Skipping.")
        else:
            # Check if the container is configured via labels
            decision = check_monitor_label(container_labels) if not skip_labels else MonitorDecision.UNKNOWN
            if decision == MonitorDecision.MONITOR:
                unit_config = validate_unit_config(MonitorType.CONTAINER, parse_label_config(container_labels))
                if unit_config is None:
                    self.logger.error(f"Could not validate container config for '{container.name}' from labels. Skipping.\nLabels: {container_labels}")
                    return None
                self.logger.info(f"Validated container config for '{container.name}' from labels:\n{get_pretty_yaml_config(unit_config, top_level_key=container.name)}")
                return ContainerConfig(MonitorType.CONTAINER, cname, cname, unit_config, cname, cid, config_via_labels=True)
            elif decision == MonitorDecision.SKIP:
                return None
            # Check if the container is configured via normal configuration
            elif decision == MonitorDecision.UNKNOWN and container.name in self.selected_containers:
                return ContainerConfig(MonitorType.CONTAINER, cname, cname, self.containers_config[cname], cname, cid)
            # Check if it should be monitored because of `monitor_all_containers` setting
            elif decision == MonitorDecision.UNKNOWN and self.monitor_all_containers:
                if not cname in self.excluded_containers:
                    return ContainerConfig(MonitorType.CONTAINER, cname, cname, ModelContainerConfig(), cname, cid)
                else:
                    self.logger.debug(f"Container {cname} is excluded from monitoring. Skipping.")
            return None

    def _maybe_monitor_container(self, container, skip_labels=False) -> bool:
        """ 
        Check if a container should be monitored based on its configuration and labels
        and start the monitoring.
        Returns:
            bool: True if monitoring was started, False otherwise
        """
        container_config = self._should_monitor(container, skip_labels=skip_labels)
        if container_config is None:
            return False
        if socket.gethostname() == container.id[:12]:
            self.logger.warning("LoggiFly can not monitor itself. Skipping.")
            return False

        # Start monitoring the container
        container_context = self._prepare_monitored_container_context(container, container_config)
        self._start_monitoring_thread(container, container_context)
        return True

    def _prepare_monitored_container_context(self, container, container_config: ContainerConfig) -> MonitoredContainerContext:
        """Prepare or reuse monitoring context for a container."""
        # Check if we already have a context for this container and maybe stop the old monitoring thread
        if (ctx := self._registry.get_by_unit_name(container_config.monitor_type, container_config.unit_name)) and ctx.processor:  
            # Close old stream connection to stop old monitoring thread if it exists
            self._close_stream_connection(ctx.container_id)
            if not ctx.monitoring_stopped_event.wait(2):
                self.logger.warning(f"Old monitoring thread for {container_config.unit_name} might not have been closed.")
            self.logger.debug(f"{container_config.unit_name}: Re-Using old context")
            ctx.unit_config = container_config.unit_config
            ctx.processor.load_config_variables(self.config, ctx.unit_config)
            ctx.generation += 1
            ctx.stop_monitoring_event.clear()
            ctx.processor.start_flush_thread_if_needed()
            self._registry.update_id(ctx.container_id, container.id)
        else:
            ctx = MonitoredContainerContext.from_container_config(container_config)
            with self.registry_lock:
                self._registry.add(ctx)
            # Create a log processor for this container
            processor = LogProcessor(
                self.logger, 
                self.config, 
                unit_name=container_config.unit_name,
                monitor_instance=self,
                unit_stop_event=ctx.stop_monitoring_event, 
                hostname=self.hostname, 
                monitor_type=container_config.monitor_type,
                unit_config=container_config.unit_config
            )
            # Add the processor to the container context
            ctx.set_processor(processor)
        return ctx
        
    def _close_stream_connection(self, container_id):
        """Close log stream connection for a specific container."""
        if not container_id:
            self.logger.debug("No container_id provided to close stream connection.")
            return
        if container_context := self._registry.get_by_id(container_id):
            unit_name = container_context.unit_name
            if stream := container_context.log_stream:
                with self.registry_lock:
                    container_context.stop_monitoring_event.set()
                    self.logger.info(f"Closing Log Stream connection for {unit_name}")
                    try:
                        stream.close()
                        container_context.log_stream = None
                    except Exception as e:
                        self.logger.warning(f"Error trying do close log stream for {unit_name}: {e}")
            else:
                self.logger.debug(f"No log stream found for container {unit_name}. Nothing to close.")
        else:
            self.logger.debug(f"Could not find container context for container_id {container_id}. Cannot close stream connection.")
           
    def start(self, client) -> str:
        """
        Start monitoring for all configured containers and Docker events using the provided Docker client.
        Handles swarm mode and hostname assignment.

        Args:
            client: Docker client instance
            
        Returns:
            str: Summary message about started monitoring
        """
        self.client = client

        if self.swarm_mode:
            # Find out if manager or worker and set hostname to differentiate between the instances
            try:
                swarm_info = client.info().get("Swarm")
                node_id = swarm_info.get("NodeID")
            except Exception as e:
                self.logger.error(f"Could not get info via docker client. Needed to get info about swarm role (manager/worker)")
                node_id = None
            if node_id:
                try:
                    node = client.nodes.get(node_id)
                    manager = True if node.attrs["Spec"]["Role"] == "manager" else False
                except Exception as e:
                    manager = False
                try:
                    self.hostname = ("manager" if manager else "worker") + "@" + self.client.info()["Name"]
                except Exception as e:
                    self.hostname = ("manager" if manager else "worker") + "@" + socket.gethostname()
        self._init_logging()
        if self.swarm_mode:
            self.logger.info(f"Running in swarm mode.")
        self.containers_config = self._get_host_config()
        self._get_selected_containers()

        for container in self.client.containers.list():
            self._maybe_monitor_container(container)

        self._watch_events()
        return self._start_message()

    def reload_config(self, config: GlobalConfig) -> str:
        """
        Reload configuration and update monitoring for containers.
        Called by ConfigHandler when config.yaml changes or on reconnection.
        Updates keywords and settings in processor instances, starts/stops monitoring as needed.
        Returns a summary message to app.py.
        """
        self.config = config if config is not None else self.config
        self.containers_config = self._get_host_config()
        self.host_config = self.config.hosts.get(self.hostname) if self.config.hosts and self.hostname else None
        self.log_level = self.config.settings.log_level.upper()
        self.logger.setLevel(getattr(logging, self.log_level, logging.INFO))
        self._get_selected_containers()  
        if self.shutdown_event.is_set():
            self.logger.debug("Shutdown event is set. Not applying config changes.")
            return ""
        try:
            # stop monitoring containers that are no longer in the config and update config in line processor instances
            for ctx in list(self._registry.values()):
                if ctx.config_via_labels or not ctx.processor:
                    continue
                if ctx.monitor_type == MonitorType.CONTAINER:                            
                    ctx.unit_config = self.containers_config.get(ctx.config_key) if self.containers_config else None
                    ctx.processor.load_config_variables(self.config, ctx.unit_config)
                    if self.monitor_all_containers:
                        if ctx.config_key in self.excluded_containers:
                            self.logger.debug(f"Container {ctx.config_key} is excluded from monitoring. Stopping monitoring.")
                            self._close_stream_connection(ctx.container_id)
                    elif ctx.config_key not in self.selected_containers and not ctx.monitoring_stopped_event.is_set():
                        self.logger.debug(f"Container {ctx.config_key} is not in the config. Stopping monitoring.")
                        self._close_stream_connection(ctx.container_id)
                elif ctx.monitor_type == MonitorType.SWARM:
                    ctx.unit_config = self.config.swarm_services.get(ctx.config_key) if self.config.swarm_services else None
                    ctx.processor.load_config_variables(self.config, ctx.unit_config)
                    if self.monitor_all_swarm_services:
                        if any(n in self.excluded_swarm_services for n in [ctx.config_key, ctx.unit_name]):
                            self.logger.debug(f"Swarm Service {ctx.config_key} is excluded from monitoring. Stopping monitoring.")
                            self._close_stream_connection(ctx.container_id)
                    elif ctx.config_key not in self.selected_swarm_services and not ctx.monitoring_stopped_event.is_set():
                        self.logger.debug(f"Swarm Service {ctx.config_key} is not in the config. Stopping monitoring.")
                        self._close_stream_connection(ctx.container_id)
            # start monitoring containers that are in the config but not monitored yet
            for container in self.client.containers.list():
                # Only start monitoring containers that are newly added to the config.yaml, not monitored yet and not configured via labels
                if not (ctx := self._registry.get_by_id(container.id)) or ctx.monitoring_stopped_event.is_set():
                    self._maybe_monitor_container(container, skip_labels=True)

            return self._start_message()
        except Exception as e:
            self.logger.error(f"Error handling config changes: {e}")
        return ""

    def _start_message(self) -> str:
        """Compose a summary message about monitored containers and services."""
        messages = []
        separator = ", " if self.config.settings.compact_summary_message else "\n - "
        prefix = ": " if self.config.settings.compact_summary_message else ":\n - "
        monitored_container_names = [c.unit_name for c in self._registry.get_actively_monitored(monitor_type=MonitorType.CONTAINER)]
        unmonitored_containers = [c for c in self.selected_containers if c not in monitored_container_names]
        if monitored_container_names:
            messages.append("These containers are being monitored" + prefix + separator.join(monitored_container_names))
        if unmonitored_containers:
            messages.append("These selected containers are not running" + prefix + separator.join(unmonitored_containers))
        actively_monitored_swarm = [context for context in self._registry.get_actively_monitored(monitor_type=MonitorType.SWARM)]
        unmonitored_swarm_services = [s for s in self.selected_swarm_services if s not in [s.config_key for s in actively_monitored_swarm]]
        monitored_swarm_service_units = [s.unit_name for s in actively_monitored_swarm]
        if monitored_swarm_service_units:
            messages.append("These Swarm Containers are being monitored" + prefix + separator.join(monitored_swarm_service_units))
        if unmonitored_swarm_services:
            messages.append("These Swarm Services are not running" + prefix + separator.join(unmonitored_swarm_services))
        if not monitored_container_names and not unmonitored_containers and not monitored_swarm_service_units and not unmonitored_swarm_services:
            messages.append("No containers are configured.")
        message = "\n\n".join(messages)
        if self.hostname:
            message = f"[{self.hostname}]\n" + message
        return message

    def _handle_error(self, error_count, last_error_time, container_name=None):
        """
        Handle errors for event and log stream threads.
        Stops threads on repeated errors and triggers cleanup if Docker host is unreachable.
        """
        MAX_ERRORS = 5
        ERROR_WINDOW = 60
        now = time.time()
        error_count = 0 if now - last_error_time > ERROR_WINDOW else error_count + 1
        last_error_time = now

        if error_count > MAX_ERRORS:
            if container_name:
                self.logger.error(f"Too many errors for {container_name}. Count: {error_count}")
            else:
                self.logger.error(f"Too many errors for Docker Event Watcher. Count: {error_count}")
            disconnected = False
            try:
                if not self.client.ping():
                    disconnected = True
            except Exception as e:
                logging.error(f"Error while trying to ping Docker Host {self.host}: {e}")
                disconnected = True
            if disconnected and not self.shutdown_event.is_set():
                self.logger.error(f"Connection lost to Docker Host {self.host} ({self.hostname if self.hostname else ''}).")
                self.cleanup(timeout=30)
            return error_count, last_error_time, True  # True = to_many_errors (break while loop)

        time.sleep(random.uniform(0.9, 1.2) * error_count)  # to prevent all threads from trying to reconnect at the same time
        return error_count, last_error_time, False

    def _start_monitoring_thread(self, container, container_context: MonitoredContainerContext):
        """Start a monitoring thread for a specific container."""
        def check_container(container_start_time, error_count):
            """
            Check if the container is still running and matches the original start time.
            Used to stop monitoring if the container is stopped or replaced.
            """
            try:
                container.reload()
                if container.status != "running":
                    self.logger.debug(f"Container {container.name} is not running. Stopping monitoring.")
                    return False
                if container.attrs['State']['StartedAt'] != container_start_time:
                    self.logger.debug(f"Container {container.name}: Stopping monitoring for old thread.")
                    return False
            except docker.errors.NotFound:
                self.logger.error(f"Container {container.name} not found during container check. Stopping monitoring.")
                return False
            except requests.exceptions.ConnectionError as ce:
                if error_count == 1 or self.log_level == "DEBUG":
                    self.logger.error(f"Can not connect to Container {container.name} {ce}")
            except Exception as e:
                if error_count == 1 or self.log_level == "DEBUG":
                    self.logger.error(f"Error while checking container {container.name}: {e}")
            return True

        def log_monitor():
            """
            Stream logs from a container and process each line with a LogProcessor instance.
            Handles buffering, decoding, and error recovery.
            """
            driver = container.attrs['HostConfig']['LogConfig'].get('Type', '')
            if driver in ('none', ''):
                self.logger.warning(f"Container {container.name} has LoggingDriver 'none' – no logs available.")
                return
            container_start_time = container.attrs['State']['StartedAt']
            error_count, last_error_time = 0, time.time()
            too_many_errors = False

            nonlocal container_context
            stop_monitoring_event = container_context.stop_monitoring_event
            monitoring_stopped_event = container_context.monitoring_stopped_event
            gen = container_context.generation  # get the generation of the current thread to check if a new thread is started for this container
            unit_name = container_context.unit_name
            processor = container_context.processor
            if not processor:
                self.logger.error(f"Processor not found for container {unit_name}. Stopping monitoring.")
                return

            while not self.shutdown_event.is_set() and not stop_monitoring_event.is_set():
                buffer = b""
                not_found_error = False
                try:
                    now = datetime.now()
                    log_stream = container.logs(stream=True, follow=True, since=now)
                    container_context.log_stream = log_stream
                    monitoring_stopped_event.clear()
                    self.logger.info(f"Monitoring for Container started: {unit_name}")
                    for chunk in log_stream:
                        MAX_BUFFER_SIZE = 10 * 1024 * 1024  # 10MB
                        buffer += chunk
                        if len(buffer) > MAX_BUFFER_SIZE:
                            self.logger.error(f"{unit_name}: Buffer overflow detected for container, resetting")
                            buffer = b""
                        while b'\n' in buffer:
                            line, buffer = buffer.split(b'\n', 1)
                            try:
                                log_line_decoded = str(line.decode("utf-8")).strip()
                            except UnicodeDecodeError:
                                log_line_decoded = line.decode("utf-8", errors="replace").strip()
                                self.logger.warning(f"{unit_name}: Error while trying to decode a log line. Used errors='replace' for line: {log_line_decoded}")
                            if log_line_decoded:
                                processor.process_line(log_line_decoded)
                except docker.errors.NotFound as e:
                    self.logger.error(f"Container {unit_name} not found during Log Stream: {e}")
                    not_found_error = True
                except Exception as e:
                    error_count, last_error_time, too_many_errors = self._handle_error(error_count, last_error_time, unit_name)
                    if error_count == 1 or self.log_level == "DEBUG":  # log error only once
                        self.logger.error("Error trying to monitor %s: %s", unit_name, e)
                        self.logger.debug(traceback.format_exc())
                finally:
                    if self.shutdown_event.is_set():
                        break
                    if gen != container_context.generation:  # if there is a new thread running for this container this thread stops
                        self.logger.debug(f"{unit_name}: Stopping monitoring thread because a new thread was started for this container.")
                        break
                    elif (stop_monitoring_event.is_set() or too_many_errors or not_found_error 
                    or check_container(container_start_time, error_count) is False):
                        self._close_stream_connection(container.id)
                        break
                    else:
                        self.logger.info(f"{unit_name}: Log Stream stopped. Reconnecting... {'error count: ' + str(error_count) if error_count > 0 else ''}")
            self.logger.info(f"Monitoring stopped for container {unit_name}.")
            stop_monitoring_event.set() 
            monitoring_stopped_event.set()  

        thread = threading.Thread(target=log_monitor, daemon=True)
        self._add_thread(thread)
        thread.start()
        
    def _watch_events(self):
        """
        Monitor Docker events to start/stop monitoring containers based on the config as they are started or stopped.
        """
        def event_handler():
            error_count = 0
            last_error_time = time.time()
            while not self.shutdown_event.is_set():
                now = time.time()
                too_many_errors = False
                container = None
                try:
                    self.event_stream = self.client.events(decode=True, filters={"event": ["start", "stop"]}, since=now)
                    self.logger.info("Docker Event Watcher started. Watching for new containers...")
                    for event in self.event_stream:
                        if self.shutdown_event.is_set():
                            self.logger.debug("Shutdown event is set. Stopping event handler.")
                            break
                        container_id = event["Actor"]["ID"]
                        container_name = event["Actor"].get("Attributes", {}).get("name", "")
                        if event.get("Action") == "start":
                            container = self.client.containers.get(container_id)
                            if self._maybe_monitor_container(container):
                                if self.config.settings.disable_container_event_message is False:
                                    if ctx := self._registry.get_by_id(container.id):
                                        unit_name = ctx.unit_name
                                    else:
                                        unit_name = container_name
                                    send_notification(self.config, "Loggifly", "LoggiFly", f"Monitoring new container: {unit_name}", hostname=self.hostname)
                        elif event.get("Action") == "stop":
                            if self._registry.get_by_id(container_id):
                                self.logger.debug(f"The Container {container_name or container_id} was stopped. Stopping Monitoring now.")
                                self._close_stream_connection(container_id)

                except docker.errors.NotFound as e:
                    self.logger.error(f"Docker Event Handler: Container {container} not found: {e}")
                except Exception as e:
                    error_count, last_error_time, too_many_errors = self._handle_error(error_count, last_error_time)
                    if error_count == 1 or self.log_level == "DEBUG":
                        self.logger.error(f"Docker Event-Handler was stopped {e}. Trying to restart it.")
                finally:
                    if self.shutdown_event.is_set() or too_many_errors:
                        self.logger.debug("Docker Event Watcher is shutting down.")
                        break
                    else:
                        self.logger.info(f"Docker Event Watcher stopped. Reconnecting... {'error count: ' + str(error_count) if error_count > 0 else ''}")
            self.logger.info("Docker Event Watcher stopped.")
            self.event_stream = None
            
        thread = threading.Thread(target=event_handler, daemon=True)
        self._add_thread(thread)
        thread.start()

    def cleanup(self, timeout=1.5):
        """
        Clean up all monitoring threads and connections on shutdown or error when client is unreachable.
        Closes log streams, joins threads, and closes the Docker client.
        """
        self.logger.info(f"Starting cleanup for host {self.hostname}..." if self.hostname else "...")
        self.cleanup_event.set()
        self.shutdown_event.set()
        for context in self._registry.get_actively_monitored():
            if context.log_stream is not None:
                self._close_stream_connection(context.container_id)
        if self.event_stream:
            try:
                self.event_stream.close()
                self.logger.info("Docker Event Stream closed.")
            except Exception as e:
                self.logger.warning(f"Error while trying to close Docker Event Stream: {e}")

        with self.threads_lock:
            alive_threads = []
            for thread in self.threads:
                if thread is not threading.current_thread() and thread.is_alive():
                    thread.join(timeout=timeout)
                    if thread.is_alive():
                        self.logger.debug(f"Thread {thread.name} was not stopped")
                        alive_threads.append(thread)
            self.threads = alive_threads
        try:
            self.client.close()
            self.logger.info("Shutdown completed")
        except Exception as e:
            self.logger.warning(f"Error while trying do close docker client connection during cleanup: {e}")

        self.cleanup_event.clear()

    def tail_logs(self, unit_name, monitor_type, lines=10) -> Optional[str]:
        """
        Tail the last n lines of logs for a specific container.
        unit_name and monitor_type are used to get the container_id from the registry.
        """
        if container_context := self._registry.get_by_unit_name(monitor_type, unit_name):
            if container := self.client.containers.get(container_context.container_id):
                try:
                    logs = container.logs(tail=lines).decode('utf-8')
                    return logs
                except docker.errors.NotFound:
                    logging.error(f"Failed to read last {lines} lines of container logs. Container not found.")
                    return None
                except Exception as e:
                    logging.error(f"Error while trying to tail logs for: {e}")
                    return None
            else:
                self.logger.error(f"Container {unit_name} not found. Cannot tail logs.")
                return None
        else:
            self.logger.error(f"Unit {unit_name} not found in registry. Cannot tail logs.\nMonitor Type: {monitor_type}")
            return None
        
    def container_action(self, monitor_type, unit_name, action):
        """
        Perform an action on a container (start, stop, restart).
        
        Args:
            monitor_type: MonitorType.CONTAINER or MonitorType.SWARM
            unit_name: Unique unit name
            action: Action string (e.g., "restart", "stop@container_name")
            
        Returns:
            str or None: Result message describing action outcome to append to a notification title
        """        
        action_parts = action.split("@")
        if len(action_parts) == 1:
            action_name = action_parts[0].strip().lower()
            if not (container_context := self._registry.get_by_unit_name(monitor_type, unit_name)):
                self.logger.error(f"Container {unit_name} not found in registry. Cannot perform action: {action}")
                return None
            container_name = container_context.container_name
        elif len(action_parts) == 2:
            action_name = action_parts[0].strip().lower()
            container_name = action_parts[1].strip()
        else:
            self.logger.error(f"Invalid action syntax: {action}")
            return None

        try:
            container = self.client.containers.get(container_name)
            if get_service_info(container, self.client):
                self.logger.error(f"Container {container_name} belongs to a swarm service. Cannot perform action: {action}")
                return f"did not perform action. Container '{container_name}' belongs to a swarm service."
            if socket.gethostname() == container.id[:12]:
                self.logger.warning("LoggiFly can not perform actions on itself. Skipping.")
                return "did not perform action. LoggiFly can not perform actions on itself."
        except docker.errors.NotFound:
            self.logger.error(f"Container {container_name} not found. Could not perform action: {action}")
            return f"did not perform action. Container '{container_name}' not found."
        except Exception as e:
            self.logger.error(f"Unexpected error while trying to perform action on container {container_name}: {e}")
            return f"did not perform action. Unexpected error: {e}"

        try:
            container_name = container.name
            container.reload()  
            self.logger.debug(f"Performing action '{action_name}' on container {container_name} with status {container.status}.")
            if action_name == Actions.STOP.value:
                if container.status != "running":
                    self.logger.info(f"not starting container {container_name}. Container {container_name} is not running.")
                    return f"did not stop {container_name}, container is not running"
                self.logger.info(f"Stopping Container: {container_name}.")
                container = container
                container.stop()
                if container.wait(timeout=10):
                    container.reload()
                    self.logger.info(f"Container {container_name} has been stopped: Status: {container.status}")
                return f"{container_name} has been stopped!"
            elif action_name == Actions.RESTART.value:
                self.logger.info(f"Restarting Container: {container_name}.")
                container = container
                container.restart()
                container.reload()
                self.logger.info(f"Container {container_name} has been restarted. Status: {container.status}")
                return f"{container_name} has been restarted!"
            elif action_name == Actions.START.value:
                if container.status == "running":
                    self.logger.info(f"Not performing action 'start' on container {container_name}. Container {container_name} is already running.")
                    return f"did not start {container_name}, container is already running"
                self.logger.info(f"Starting Container: {container_name}.")
                container = container
                container.start()
                start_time = time.time()
                while True:
                    container.reload()
                    if container.status == "running":
                        break
                    if time.time() - start_time > 10:
                        self.logger.warning(f"Timeout while waiting for container {container_name} to start.")
                        return f"Timeout while waiting for container {container_name} to start."
                    time.sleep(1)
                self.logger.info(f"Container {container_name} has been started. Status: {container.status}")
                return f"{container_name} has been started!"
        except Exception as e:
            self.logger.error(f"Failed to {action_name} {container_name}: {e}")
        return f"failed to {action_name} {container_name}"    


def check_monitor_label(labels) -> MonitorDecision:
    """Extract and check the 'loggifly.monitor' label value."""
    if labels is None:
        return MonitorDecision.UNKNOWN
    monitor_value = labels.get("loggifly.monitor", "").lower().strip()
    if not monitor_value:
        return MonitorDecision.UNKNOWN            
    if monitor_value == "true":
        return MonitorDecision.MONITOR
    elif monitor_value == "false":
        return MonitorDecision.SKIP
    return MonitorDecision.UNKNOWN


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
    service_name = labels.get("com.docker.swarm.service.name", "")#
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

