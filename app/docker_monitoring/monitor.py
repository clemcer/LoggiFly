import logging
import threading
import socket
import traceback
import time
import os
import random
import requests
from typing import Optional
import docker
from docker.models.containers import Container
import docker.errors
from datetime import datetime, timedelta
from notifier import send_notification
from line_processor import LogProcessor
from config.config_model import GlobalConfig
from config.config_model import ContainerConfig, SwarmServiceConfig
from config.load_config import get_pretty_yaml_config
from constants import (
    Actions,
    MonitorType,
    MAP_CONFIG_EVENTS_TO_DOCKER_EVENTS,
)
from utils import convert_to_int
from notification_formatter import NotificationContext
from trigger import process_trigger
from docker_monitoring.decision import MonitorDecision
from docker_monitoring.docker_helpers import ContainerSnapshot, get_service_info, get_configured, parse_action_target

class MonitoredContainerContext:
    """
    Runtime monitoring state for a container.

    Holds the container snapshot, monitoring configuration, and runtime state
    (threads, events, processor, etc.).
    """

    def __init__(self, snapshot: ContainerSnapshot, config_key: str,
                 unit_config, config_via_labels: bool):
        """
        Initialize monitoring context for a container.

        Args:
            snapshot: Container metadata snapshot
            config_key: Configuration key (container/service name)
            unit_config: Unit configuration object
            config_via_labels: Whether config came from Docker labels
        """
        self.snapshot = snapshot
        self.config_key = config_key
        self.unit_config = unit_config
        self.config_via_labels = config_via_labels

        # Derived from snapshot
        self.monitor_type = MonitorType.SWARM if snapshot.is_swarm_service else MonitorType.CONTAINER
        self.unit_name = snapshot.unit_name
        self.container_name = snapshot.name
        self.container_id = snapshot.id

        # Runtime state
        self.generation = 0  # Used to track container restarts
        self.stop_monitoring_event = threading.Event()  # Signal to stop monitoring
        self.monitoring_stopped_event = threading.Event()  # Signal that the monitoring thread has stopped
        self.log_stream = None  # Will be set when the log stream is opened
        self.processor = None  # Will be set after initialization
        self.currently_configured = True
        self.not_monitored_since: datetime | None = None

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
        self._lock = threading.Lock()
        self.logger = logging.getLogger(__name__)

    def add(self, container_context: MonitoredContainerContext):
        monitor_type = container_context.monitor_type
        container_id = container_context.container_id
        unit_name = container_context.unit_name
        with self._lock:
            self._by_id[container_id] = container_context
            self._by_unit_name[(monitor_type, unit_name)] = container_context

    def get_by_id(self, container_id: str) -> MonitoredContainerContext | None:
        with self._lock:
            return self._by_id.get(container_id)
    
    def get_by_unit_name(self, monitor_type: MonitorType, unit_name: str) -> MonitoredContainerContext | None:
        with self._lock:
            return self._by_unit_name.get((monitor_type, unit_name))
            
    def is_monitored(self, container_id: str) -> bool:
        with self._lock:
            ctx = self._by_id.get(container_id)
            return ctx is not None and not ctx.monitoring_stopped_event.is_set()

    def get_actively_monitored(self, monitor_type: MonitorType | None = None) -> list[MonitoredContainerContext]:
        """
        Return a list of actively monitored containers.
        
        Args:
            monitor_type: Filter by MonitorType.CONTAINER, MonitorType.SWARM, or None for all
            
        Returns:
            list: List of actively monitored container contexts
        """
        with self._lock:
            values = list(self._by_id.values())
        if monitor_type == MonitorType.SWARM:
            return [ctx for ctx in values if not ctx.monitoring_stopped_event.is_set() and ctx.monitor_type == MonitorType.SWARM]
        elif monitor_type == MonitorType.CONTAINER:
            return [ctx for ctx in values if not ctx.monitoring_stopped_event.is_set() and ctx.monitor_type == MonitorType.CONTAINER]
        return [ctx for ctx in values if not ctx.monitoring_stopped_event.is_set()]

    def update_id(self, old_id, new_id):
        """Update container ID in registry when container is recreated."""
        with self._lock:
            if (container_context := self._by_id.pop(old_id, None)) is not None:
                container_context.container_id = new_id
                self._by_id[new_id] = container_context

    def remove(self, container_id: str):
        """Remove a container context from the registry."""
        with self._lock:
            ctx = self._by_id.pop(container_id, None)
            if ctx:
                self._by_unit_name.pop((ctx.monitor_type, ctx.unit_name), None)

    def values(self) -> list[MonitoredContainerContext]:
        """Get all container contexts in the registry."""
        with self._lock:
            return list(self._by_id.values())

    def cleanup_stale_contexts(self, stale_threshold_hours: int, threshold_hours_configured: int = 24*7):
        """
        Remove contexts that haven't been active for stale_threshold_hours.
        """
        now = datetime.now()
        stale_threshold = timedelta(hours=stale_threshold_hours)
        configured_threshold = timedelta(hours=threshold_hours_configured)

        to_remove = []
        with self._lock:
            for container_id, ctx in self._by_id.items():
                if not ctx.monitoring_stopped_event.is_set():
                    continue
                if ctx.not_monitored_since is None:
                    continue
                time_since_stopped = now - ctx.not_monitored_since
                if ctx.currently_configured:
                    if time_since_stopped <= configured_threshold:
                        continue
                else:
                    if time_since_stopped <= stale_threshold:
                        continue
                to_remove.append(container_id)

        for container_id in to_remove: 
            self.logger.debug(f"Removing stale context for container {container_id}")
            self.remove(container_id)
        return len(to_remove)

class DockerLogMonitor:
    """
    Monitors Docker containers and events for a given host.

    Starts a thread for each monitored container and a thread for Docker event monitoring.
    Handles config reloads, container start/stop, and log processing.
    """
    
    def __init__(self, config, client, hostname, host):
        """Initialize Docker log monitor for a specific host."""
        self.hostname = hostname  # empty string if only one client is being monitored, otherwise the hostname of the client do differentiate between the hosts
        self.host = host
        self.config = config
        self.client = client
        self.swarm_mode = os.getenv("LOGGIFLY_MODE", "").strip().lower() == "swarm"
        self._init_swarm_mode()
        self._init_logging()
        if self.swarm_mode:
            self.logger.info(f"Running in swarm mode.")

        self.event_stream = None
        self.shutdown_event = threading.Event()
        self.cleanup_event = threading.Event()
        self.threads = []
        self.threads_lock = threading.Lock()
        self.last_action_time_per_container = {}
        self.last_action_lock = threading.Lock()
        self._registry = MonitoredContainerRegistry()

        self.stale_threshold_hours = convert_to_int(os.getenv("CLEANUP_THRESHOLD_HOURS", "24"), fallback_value=24)
        self.cleanup_interval_minutes = convert_to_int(os.getenv("CLEANUP_INTERVAL_MINUTES", "60"), fallback_value=60)
        self._start_cleanup_thread()


    def _init_swarm_mode(self):
        if self.swarm_mode:
            # Find out if manager or worker and set hostname to differentiate between the instances
            try:
                swarm_info = self.client.info().get("Swarm")
                node_id = swarm_info.get("NodeID")
            except Exception as e:
                logging.error(f"Could not get info via docker client. Needed to get info about swarm role (manager/worker)")
                node_id = None
            if node_id:
                try:
                    node = self.client.nodes.get(node_id)
                    manager = True if node.attrs["Spec"]["Role"] == "manager" else False
                except Exception as e:
                    manager = False
                try:
                    self.hostname = ("manager" if manager else "worker") + "@" + self.client.info()["Name"]
                except Exception as e:
                    self.hostname = ("manager" if manager else "worker") + "@" + socket.gethostname()
    
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

    def _start_cleanup_thread(self):
        def cleanup_stale_contexts():
            while not self.shutdown_event.is_set():
                removed = self._registry.cleanup_stale_contexts(self.stale_threshold_hours)
                if removed > 0:
                    self.logger.info(f"Removed {removed} stale contexts.")
                self.shutdown_event.wait(self.cleanup_interval_minutes * 60)

        thread = threading.Thread(target=cleanup_stale_contexts, daemon=True)
        thread.start()
        self._add_thread(thread)

    def _add_thread(self, thread):
        with self.threads_lock:
            self.threads.append(thread)

    def _build_decision(self, snapshot: ContainerSnapshot, skip_labels: bool = False) -> MonitorDecision:
        return MonitorDecision.evaluate(
            snapshot=snapshot,
            global_config=self.config,
            hostname=self.hostname,
            skip_labels=skip_labels,
        )

    def _maybe_monitor_container(self, container, skip_labels=False) -> bool:
        """
        Check if a container should be monitored and start monitoring if so.

        Args:
            container: Docker container object
            skip_labels: If True, ignore container labels (used during config reload)

        Returns:
            bool: True if monitoring was started, False otherwise
        """
        # Create snapshot and evaluate decision
        try:
            snapshot = ContainerSnapshot.from_container(container, self.client)
            decision = self._build_decision(snapshot, skip_labels)
        except ValueError as e:
            self.logger.error(f"Configuration validation error for container {container.name}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error evaluating container {container.name}: {e}")
            self.logger.debug(traceback.format_exc())
            return False

        # Log decision
        if not decision.should_monitor:
            if decision.result == MonitorDecision.Result.SKIP:
                self.logger.debug(f"Skipping {snapshot.name}: {decision.reason}")
            elif decision.result == MonitorDecision.Result.NOT_CONFIGURED:
                self.logger.debug(f"Not monitoring {snapshot.name}: {decision.reason}")
            return False
            
        # Self-monitoring check
        if socket.gethostname() == container.id[:12]:
            self.logger.warning("LoggiFly cannot monitor itself. Skipping.")
            return False

        # Start monitoring
        if decision.config_via_labels:
            self.logger.info(
                f"Monitoring for {snapshot.name} via docker labels.\
                    \nConfig:\n{get_pretty_yaml_config(decision.unit_config, top_level_key=snapshot.name)}"
                    )
        else:
            self.logger.info(f"Starting monitoring for {snapshot.name}: {decision.reason}")

        container_context = self._prepare_monitored_container_context(container, snapshot, decision)
        container_context.currently_configured = True
        self._start_monitoring_thread(container, container_context)
        return True

    def _prepare_monitored_container_context(self, container, snapshot: ContainerSnapshot,
                                             decision: MonitorDecision) -> MonitoredContainerContext:
        """Prepare or reuse monitoring context for a container."""
        # Type narrowing: these fields must be set when should_monitor is True
        assert decision.config_key is not None, "config_key must be set when monitoring"
        assert decision.unit_config is not None, "unit_config must be set when monitoring"
        assert decision.config_via_labels is not None, "config_via_labels must be set when monitoring"

        monitor_type = MonitorType.SWARM if snapshot.is_swarm_service else MonitorType.CONTAINER

        if (ctx := self._registry.get_by_unit_name(monitor_type, snapshot.unit_name)):
            if not ctx.processor:  
                self.logger.error(f"Processor not found for container {snapshot.unit_name}. Stopping monitoring.")
                self._stop_and_remove_context(ctx)
            else:
                self._stop_and_close_stream(ctx.container_id)
                if not ctx.monitoring_stopped_event.wait(2):
                    self.logger.warning(f"Old monitoring thread for {snapshot.unit_name} might not have been closed.")
                self.logger.debug(f"{snapshot.unit_name}: Re-Using old context")
                self._registry.update_id(ctx.container_id, container.id)
                ctx.snapshot = snapshot
                ctx.unit_config = decision.unit_config
                ctx.config_via_labels = decision.config_via_labels
                ctx.unit_name = snapshot.unit_name
                ctx.container_name = snapshot.name
                # ctx.container_id = snapshot.id # handled in _registry.update_id()
                ctx.generation += 1
                ctx.stop_monitoring_event.clear()
                ctx.currently_configured = True
                ctx.not_monitored_since = None
                ctx.processor.load_config_variables(self.config, decision.unit_config)
                ctx.processor.start_flush_thread_if_needed()
                return ctx

        ctx = MonitoredContainerContext(
            snapshot=snapshot,
            config_key=decision.config_key,
            unit_config=decision.unit_config,
            config_via_labels=decision.config_via_labels
        )
        self._registry.add(ctx)
        # Create a log processor for this container
        processor = LogProcessor(
            self.logger,
            self.config,
            unit_context=ctx,
            monitor_instance=self,
            hostname=self.hostname,
            unit_config=ctx.unit_config
        )
        # Add the processor to the container context
        ctx.set_processor(processor)
        return ctx

    def _stop_and_close_stream(self, container_id):
        """Close log stream connection for a specific container."""
        if not container_id:
            self.logger.debug("No container_id provided to close stream connection.")
            return
        if container_context := self._registry.get_by_id(container_id):
            unit_name = container_context.unit_name
            if stream := container_context.log_stream:
                # with self._registry._lock:
                container_context.stop_monitoring_event.set()
                self.logger.info(f"Closing Log Stream connection for {unit_name}")
                try:
                    stream.close()
                    container_context.log_stream = None
                    container_context.not_monitored_since = datetime.now()
                except Exception as e:
                    self.logger.warning(f"Error trying do close log stream for {unit_name}: {e}")
            else:
                self.logger.debug(f"No log stream found for container {unit_name}. Nothing to close.")
        else:
            self.logger.debug(f"Could not find container context for container_id {container_id}. Cannot close stream connection.")

    def _stop_and_remove_context(self, container_context: MonitoredContainerContext, wait_timeout: float = 2.0, wait_for_thread: bool = True):
        """Signal a monitoring thread to stop, close its stream, and remove the context from the registry."""
        unit_name = container_context.unit_name
        container_context.stop_monitoring_event.set()
        if stream := container_context.log_stream:
            self.logger.info(f"Closing Log Stream connection for {unit_name}")
            try:
                stream.close()
            except Exception as e:
                self.logger.warning(f"Error trying to close log stream for {unit_name}: {e}")
            finally:
                container_context.log_stream = None
        if wait_for_thread:
            if not container_context.monitoring_stopped_event.wait(wait_timeout):
                self.logger.debug(f"Monitoring thread for {unit_name} did not stop within {wait_timeout} seconds.")
        self._registry.remove(container_context.container_id)

           
    def start(self) -> str:
        for container in self.client.containers.list():
            self._maybe_monitor_container(container)

        self._watch_events()
        return self._start_message()

    def reload_config(self, config: GlobalConfig | None) -> str:
        """
        Reload configuration and update monitoring for containers.
        Called by ConfigHandler when config.yaml changes or on reconnection.
        Updates keywords and settings in processor instances, starts/stops monitoring as needed.
        Returns a summary message to app.py.
        """
        self.config = config if config is not None else self.config
        self.log_level = self.config.settings.log_level.upper()
        self.logger.setLevel(getattr(logging, self.log_level, logging.INFO))
        if self.shutdown_event.is_set():
            self.logger.debug("Shutdown event is set. Not applying config changes.")
            return ""
        try:
            # stop monitoring containers that are no longer in the config and update config in line processor instances
            for ctx in list(self._registry.values()):
                if not ctx.processor:
                    continue

                # Evaluate whether to continue monitoring with new config
                decision = MonitorDecision.evaluate_for_reload(
                    ctx=ctx,
                    new_config=self.config,
                    hostname=self.hostname,
                )

                if decision.should_stop:
                    if not ctx.monitoring_stopped_event.is_set():
                        self.logger.info(f"Stopping monitoring for {ctx.unit_name}: {decision.reason}")
                        self._stop_and_close_stream(ctx.container_id)
                    ctx.currently_configured = False
                elif decision.should_monitor:
                    # Type narrowing: unit_config must be set when should_monitor is True
                    assert decision.unit_config is not None, "unit_config must be set when should_monitor is True"
                    # Update context with new config
                    ctx.unit_config = decision.unit_config
                    ctx.processor.load_config_variables(self.config, ctx.unit_config)
                    ctx.currently_configured = True
                    self.logger.debug(f"Updated config for {ctx.unit_name}: {decision.reason}")
            # start monitoring containers that are in the config but not monitored yet
            for container in self.client.containers.list():
                # Only start monitoring containers that are newly added to the config.yaml, not monitored yet and not configured via labels
                if not (ctx := self._registry.get_by_id(container.id)) or \
                (ctx.monitoring_stopped_event.is_set() and not ctx.currently_configured):
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
        # TODO: maybe only get info from registry and not display which containers are not monitored?
        selected_containers, selected_swarm_services = get_configured(self.config, self.hostname)
        monitored_container_names = [c.unit_name for c in self._registry.get_actively_monitored(monitor_type=MonitorType.CONTAINER)]
        unmonitored_containers = [c for c in selected_containers if c not in monitored_container_names]
        if monitored_container_names:
            messages.append("These containers are being monitored" + prefix + separator.join(monitored_container_names))
        if unmonitored_containers:
            messages.append("These selected containers are not running" + prefix + separator.join(unmonitored_containers))
        actively_monitored_swarm = [context for context in self._registry.get_actively_monitored(monitor_type=MonitorType.SWARM)]
        unmonitored_swarm_services = [s for s in selected_swarm_services if s not in [s.config_key for s in actively_monitored_swarm]]
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
            container_start_time = container.attrs['State']['StartedAt']
            error_count, last_error_time = 0, time.time()
            too_many_errors = False

            nonlocal container_context
            stop_monitoring_event = container_context.stop_monitoring_event
            monitoring_stopped_event = container_context.monitoring_stopped_event
            unit_name = container_context.unit_name
            processor = container_context.processor
            gen = container_context.generation
            if driver in ('none', ''):
                self.logger.warning(f"Container {container.name} has LoggingDriver 'none' – no logs available.")
                stop_monitoring_event.set() 
            elif not processor:
                self.logger.error(f"Processor not found for container {unit_name}. Stopping monitoring.")
                stop_monitoring_event.set() 
            log_stream = None
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
                            if log_line_decoded and processor:
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
                    should_break = False
                    if self.shutdown_event.is_set():
                        should_break = True
                    if gen != container_context.generation:  # if there is a new thread running for this container this thread stops
                        self.logger.debug(f"{unit_name}: Stopping monitoring thread because a new thread was started for this container.")
                        should_break = True
                    elif stop_monitoring_event.is_set() or too_many_errors or not_found_error \
                    or check_container(container_start_time, error_count) is False:
                        should_break = True
                    if should_break:
                        break
                    else:
                        self.logger.info(f"{unit_name}: Log Stream stopped. Reconnecting... {'error count: ' + str(error_count) if error_count > 0 else ''}")
            self.logger.info(f"Monitoring stopped for container {unit_name}.")
            if log_stream:
                try:
                    self.logger.debug(f"Closing log stream for {unit_name} via new method")
                    log_stream.close()
                except Exception as e:
                    self.logger.debug(f"Error trying to close log stream for {unit_name}: {e}")
            container_context.log_stream = None
            container_context.not_monitored_since = datetime.now()
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
            last_seen_time = int(time.time())
            while not self.shutdown_event.is_set():
                too_many_errors = False
                container = None
                try:
                    since_ts = last_seen_time or int(time.time())
                    self.event_stream = self.client.events(
                        decode=True, 
                        filters={"event": list(MAP_CONFIG_EVENTS_TO_DOCKER_EVENTS.values())}, 
                        since=since_ts)
                    self.logger.info("Docker Event Watcher started. Watching for new containers...")
                    for event in self.event_stream:
                        if self.shutdown_event.is_set():
                            self.logger.debug("Shutdown event is set. Stopping event handler.")
                            break
                        if event.get("Type") != "container":
                            continue
                        container_id = event["Actor"]["ID"]
                        container_name = event["Actor"].get("Attributes", {}).get("name", "")
                        
                        self.logger.debug(f"Docker Event Handler: Event: {event}, Container Name: {container_name}")
                        
                        if event_time_ns := event.get("timeNano"):
                            last_seen_time = int(event_time_ns / 1_000_000_000)
                        elif event_time := event.get("time"):
                            last_seen_time = int(event_time)
                        try:
                            container = self.client.containers.get(container_id)
                        except docker.errors.NotFound:
                            self.logger.debug(f"Docker Event Handler: Container {container_id} not found.")
                            continue
                        if event.get("Action") == "start" and container:
                            if self._maybe_monitor_container(container):
                                if self.config.settings.disable_container_event_message is False:
                                    if ctx := self._registry.get_by_id(container.id):
                                        unit_name = ctx.unit_name
                                    else:
                                        unit_name = container_name
                                    # TODO: maybe add template fields
                                    send_notification(self.config, title="Loggifly", message=f"Monitoring new container: {unit_name}", hostname=self.hostname)
                 
                        # TODO: checking should_monitor and building ctx is not ideal
                        # if container and (cfg := self._should_monitor(container)): 
                        #     ctx = MonitoredContainerContext.from_container_config(cfg)
                        #     self._process_event(event, ctx)

                        elif event.get("Action") == "stop":
                            if ctx := self._registry.get_by_id(container_id):
                                self.logger.debug(f"The Container {container_name or container_id} was stopped. Stopping Monitoring now.")
                                self._stop_and_close_stream(ctx.container_id)
                       
                except docker.errors.NotFound as e:
                    self.logger.error(f"Docker Event Handler: Container {container} not found: {e}")
                except Exception as e:
                    error_count, last_error_time, too_many_errors = self._handle_error(error_count, last_error_time)
                    if error_count == 1 or self.log_level == "DEBUG":
                        self.logger.error(f"Docker Event-Handler was stopped {e}. Trying to restart it.")
                        self.logger.debug(traceback.format_exc())
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


    # def _process_event(self, event, ctx: MonitoredContainerContext):
    #     """
    #     Process a Docker event.
    #     """
    #     configured_events: List[ModelContainerEventConfig] = ctx.unit_config.events
    #     if not configured_events:
    #         return
    #     event_type = parse_event_type(event)
    #     if not event_type:
    #         return
    #     ce = next((ce for ce in configured_events if ce.event == event_type), None)
    #     if not ce:
    #         self.logger.info(f"Event {event_type} for container {ctx.unit_name} is not configured. Skipping event.")
    #         return
    #     self.logger.debug(f"Event {event_type} for container {ctx.unit_name} is configured. Processing event.")
    #     unit_modular_settings = merge_modular_settings(ctx.unit_config.model_dump(), self.config.settings.model_dump())
    #     trigger_level_config = ce.model_dump()
    #     merged_modular_settings = merge_modular_settings(trigger_level_config, unit_modular_settings)
    #     exit_code = event.get("Actor", {}).get("Attributes", {}).get("exitCode", None)
    #     notification_context = NotificationContext(
    #         notification_type=NotificationType.DOCKER_EVENT,
    #         unit_context=ctx,
    #         event=event_type,
    #         hostname=self.hostname,
    #         time=event.get("time"),
    #         exit_code=exit_code,
    #     )
    #     process_trigger(
    #         logger=self.logger,
    #         config=self.config,
    #         modular_settings=merged_modular_settings,
    #         trigger_level_config=trigger_level_config,
    #         monitor_instance=self,
    #         unit_context=ctx,
    #         notification_context=notification_context,
    #     )

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
                self._stop_and_remove_context(context)
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

    def tail_logs(self, container_id: str, lines=10) -> Optional[str]:
        """
        Tail the last n lines of logs for a specific container.
        unit_name and monitor_type are used to get the container_id from the registry.
        """
        if container := self.client.containers.get(container_id):
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
            self.logger.error(f"Container {container_id} not found. Cannot tail logs.")
            return None
        
    def container_action(self, container_name: str, action):
        """
        Perform an action on a container (start, stop, restart).
        
        Args:
            monitor_type: MonitorType.CONTAINER or MonitorType.SWARM
            unit_name: Unique unit name
            action: Action string (e.g., "restart", "stop@container_name")
            
        Returns:
            str or None: Result message describing action outcome to append to a notification title
        Raises:
            Exception: If the action fails with a specific error message.
        """        
        action_name, container_name = parse_action_target(action, container_name)
        if not action_name or not container_name:
            raise Exception(f"did not perform action. Invalid action syntax: {action}")

        try:
            container = self.client.containers.get(container_name)
            # TODO: Maybe container snapshot.is_swarm_service()
            if get_service_info(container, self.client):
                self.logger.error(f"Container {container_name} belongs to a swarm service. Cannot perform action: {action}")
                raise Exception(f"did not perform action. Container '{container_name}' belongs to a swarm service.")
            if socket.gethostname() == container.id[:12]:
                self.logger.warning("LoggiFly can not perform actions on itself. Skipping.")
                raise Exception("did not perform action. LoggiFly can not perform actions on itself.")
        except docker.errors.NotFound:
            self.logger.error(f"Container {container_name} not found. Could not perform action: {action}")
            raise Exception(f"did not perform action. Container '{container_name}' not found.")
        except Exception as e:
            self.logger.error(f"Unexpected error while trying to perform action on container {container_name}: {e}")
            raise Exception(f"did not perform action. Unexpected error: {e}")

        try:
            container_name = container.name
            container.reload()  
            self.logger.debug(f"Performing action '{action_name}' on container {container_name} with status {container.status}.")
            if action_name == Actions.STOP.value:
                if container.status != "running":
                    self.logger.info(f"not starting container {container_name}. Container {container_name} is not running.")
                    raise Exception(f"did not stop {container_name}, container is not running")
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
                    raise Exception(f"did not start {container_name}, container is already running")
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
                        raise Exception(f"Timeout while waiting for container {container_name} to start.")
                    time.sleep(1)
                self.logger.info(f"Container {container_name} has been started. Status: {container.status}")
                return f"{container_name} has been started!"
        except Exception as e:
            self.logger.error(f"Failed to {action_name} {container_name}: {e}")
            raise e


