import os
import sys
import time
import signal
import threading
import logging
import traceback
import docker
import docker.errors
from threading import Timer
from dataclasses import dataclass
import socket
from docker.tls import TLSConfig
from urllib.parse import urlparse
import urllib.request
from pydantic import ValidationError
from typing import Any, List
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from config.load_config import load_config, format_pydantic_error, ConfigLoadError
from docker_monitoring.monitor import DockerLogMonitor
from notifier import send_notification

logging.basicConfig(
    level="INFO",
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)
logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)    
logging.getLogger("docker").setLevel(logging.INFO)
logging.getLogger("watchdog").setLevel(logging.WARNING)


@dataclass
class DockerClientInfo:
    host_url: str
    client: docker.DockerClient
    tls_config: TLSConfig | None
    label: str | None
    hostname: str | None
    monitor: DockerLogMonitor | None = None

def get_title_prefix(docker_hosts: List[DockerClientInfo]) -> str:
    """ 
    In swarm mode user might want to differentiate between manager and worker nodes 
    since multiple LoggiFly instances (swarm containers) might be running on different nodes 
    sending notifications to the same endpoint.
    """
    if len(docker_hosts) == 1 and docker_hosts[0].monitor and docker_hosts[0].monitor.swarm_mode:
        return f"[{docker_hosts[0].monitor.host_identifier}] - "
    return ""

def create_handle_signal(docker_hosts: List[DockerClientInfo], config, config_observer):
    """
    Create signal handler for graceful shutdown.
    
    Args:
        monitor_instances: List of DockerLogMonitor instances to cleanup
        config: Global configuration object
        config_observer: File watcher observer for config changes
        
    Returns:
        tuple: (signal_handler_function, global_shutdown_event)
    """
    global_shutdown_event = threading.Event()   
    monitor_instances = [host_info.monitor for host_info in docker_hosts if host_info.monitor]

    def handle_signal(signum, frame):
        if not config.settings.disable_shutdown_message:
            send_notification(config=config,
                            title=get_title_prefix(docker_hosts) + "LoggiFly", 
                            message="Shutting down")
        if config_observer is not None:
            config_observer.stop()
            config_observer.join()
        threads = []
        for monitor in monitor_instances:
            monitor.shutdown_event.set()
            thread = threading.Thread(target=monitor.cleanup)
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join(timeout=2)    
        global_shutdown_event.set()

    return handle_signal, global_shutdown_event


def format_message(messages, alt_text):
    """
    Format multiple messages with separators.
    """
    message_line_break = "\n\n" + "-" * 60 + "\n\n"
    message = message_line_break.join(messages) if messages else alt_text
    message = "\n" + message
    return message


def ensure_config_template():
    """
    Download config template if it or config.yaml does not exist.
    """
    config_dir = "/config"
    config_template = os.path.join(config_dir, "config_template.yaml")
    config_file = os.path.join(config_dir, "config.yaml")
    config_url = "https://raw.githubusercontent.com/clemcer/loggifly/refs/heads/main/docs/configs/config_template.yaml"

    if os.path.isdir(config_dir):
        if not os.path.isfile(config_template) and not os.path.isfile(config_file):
            try:
                logging.info("loading config.yaml template...")
                urllib.request.urlretrieve(config_url, config_template)
            except Exception as e:
                logging.warning(f"Could not download config template from {config_url}: {e}")
    else:
        logging.debug("/config does not exist, skipping config template download.")


class ConfigHandler(FileSystemEventHandler):
    """
    Handles config.yaml changes by reloading configuration and updating all DockerLogMonitor instances.
    Ensures new keywords, settings, or other changes are applied, especially for keyword searching in line_processor.py.
    """
    
    def __init__(self, monitor_instances, config):
        """
        Initialize config change handler.
        
        Args:
            monitor_instances: List of DockerLogMonitor instances to reload
            config: Current global configuration
        """
        self.monitor_instances = monitor_instances  
        self.last_config_reload_time = 0
        self.config = config
        self.reload_timer = None
        self.debounce_seconds = 2

    def on_modified(self, event):
        """
        Handle file modification events with debounced config reload.
        """
        # Debounced reload of config.yaml if reload_config is enabled
        if self.config.settings.reload_config and not event.is_directory:
            if os.path.basename(event.src_path) == "config.yaml":
                if self.reload_timer:
                    self.reload_timer.cancel()
                self.reload_timer = Timer(self.debounce_seconds, self._trigger_reload)
                self.reload_timer.start()

    def _trigger_reload(self):
        """Execute the actual config reload after debounce period."""
        logging.info("Config change detected, reloading config...")
        try:
            new_config, _ = load_config()
        except (ValidationError, ConfigLoadError) as e:
            if isinstance(e, ValidationError):
                logging.critical(f"Config validation failed (keeping old config): {format_pydantic_error(e)}")
            else:
                logging.critical("Config loading failed (keeping old config)")
            return

        # Only update if loading and validation succeeded
        logging.getLogger().setLevel(getattr(logging, self.config.settings.log_level.upper(), logging.INFO))
        logging.info(f"Log-Level set to {self.config.settings.log_level}")
        self.config = new_config
        messages = []
        for monitor in self.monitor_instances:
            messages.append(monitor.reload_config(self.config))
        message = format_message(messages, "LoggiFly is not monitoring anything.")

        logging.info(f"Config reloaded successfully.\n{message}")
        if self.config.settings.disable_config_reload_message is False:
            send_notification(
                config=self.config,
                title="LoggiFly: The config file was reloaded",
                message=message
            )
        # Reminder: The config watcher remains active even if reload_config is set to False after reload.


def start_config_watcher(monitor_instances, config, path):
    """
    Start a watchdog observer to monitor config.yaml for changes and trigger reloads.
    
    Args:
        monitor_instances: List of DockerLogMonitor instances
        config: Global configuration object
        path: Path to watch for config file changes
        
    Returns:
        Observer: The watchdog observer instance
    """
    observer = Observer()
    observer.schedule(ConfigHandler(monitor_instances, config), path=path, recursive=False)
    observer.start()
    return observer


def check_monitor_status(docker_host_infos: List[DockerClientInfo], global_shutdown_event):
    """
    Periodically check Docker host connections and attempt reconnection if lost.
    
    Args:
        docker_hosts: Dictionary of host configurations with monitor instances
        global_shutdown_event: Event to signal global shutdown
        
    Returns:
        Thread: The monitoring thread
    """
    def check_and_reconnect():
        """Main monitoring loop for connection status."""
        while True:
            time.sleep(60)
            for host_info in docker_host_infos:
                host_url = host_info.host_url
                tls_config = host_info.tls_config
                label = host_info.label
                monitor = host_info.monitor
                assert monitor is not None
                if monitor.shutdown_event.is_set():
                    while monitor.cleanup_event.is_set():
                        time.sleep(1)
                    if global_shutdown_event.is_set():
                        return
                    new_client = None
                    try:    
                        new_client = docker.DockerClient(base_url=host_url, tls=tls_config)
                    except docker.errors.DockerException as e:
                        logging.warning(f"Could not reconnect to {host_url} ({label}): {e}")
                    except Exception as e:
                        logging.warning(f"Could not reconnect to {host_url} ({label}). Unexpected error creating Docker client: {e}")
                    if new_client:
                        logging.info(f"Successfully reconnected to {host_url} ({label})")
                        monitor.shutdown_event.clear()
                        monitor.client = new_client
                        monitor.start()
                        monitor.reload_config(None)

    thread = threading.Thread(target=check_and_reconnect, daemon=True)
    thread.start()
    return thread


def create_docker_clients() -> list[DockerClientInfo]:
    """
    Create Docker clients for all hosts specified in the DOCKER_HOST environment variable and the local Docker socket.
    Searches for TLS certificates in '/certs/{ca,cert,key}.pem' or '/certs/{host}/{ca,cert,key}.pem'.
    
    Returns:
        dict: Mapping of host to client, TLS config, and label information
    """
    def get_tls_config(hostname):
        """
        Search for TLS certificates for the given hostname.
        
        Args:
            hostname: The hostname to find certificates for
            
        Returns:
            TLSConfig or None: TLS configuration if certificates found
        """
        cert_locations = [
            (os.path.join("/certs", hostname)),   
            (os.path.join("/certs"))             
        ]

        for cert_dir in cert_locations:
            logging.debug(f"Checking TLS certs for {hostname} in {cert_dir}")
            ca = os.path.join(cert_dir, "ca.pem")
            cert = os.path.join(cert_dir, "cert.pem")
            key = os.path.join(cert_dir, "key.pem")
            
            if all(os.path.exists(f) for f in [ca, cert, key]):
                logging.debug(f"Found TLS certs for {hostname} in {cert_dir}")
                return TLSConfig(client_cert=(cert, key), ca_cert=ca, verify=True)
        return None

    # Parse DOCKER_HOST environment variable
    docker_host = os.environ.get("DOCKER_HOST", "")
    logging.debug(f"Environment variable DOCKER_HOST: {os.environ.get('DOCKER_HOST', ' - Not configured - ')}")
    tmp_hosts = [h.strip() for h in docker_host.split(",") if h.strip()]
    hosts = []
    for host in tmp_hosts:
        label = None
        if "|" in host:
            host_url, label = host.split("|", 1)
        else:
            host_url = host.strip()
        hosts.append(
            (host_url, label.strip()) if label else (host_url.strip(), None)
            )

    # Add local Docker socket if available
    if os.path.exists("/var/run/docker.sock"):
        logging.debug(f"Path to docker socket exists: True")
        if not any(h[0] == "unix:///var/run/docker.sock" for h in hosts):
            hosts.append(("unix:///var/run/docker.sock", None)) 

    logging.debug(f"Configured docker hosts to connect to: {[host for (host, _) in hosts]}")

    if len(hosts) == 0:
        logging.critical("No docker hosts configured. Please set the DOCKER_HOST environment variable or mount your docker socket.")

    # Create Docker clients for each host
    docker_hosts = []
    for host_url, label in hosts:
        logging.info(f"Trying to connect to docker client on host: {host_url}")
        parsed = urlparse(host_url)
        tls_config = None
        if parsed.scheme == "unix":
            pass  # No TLS for local socket
        elif parsed.scheme == "tcp":
            parsed_hostname = parsed.hostname
            tls_config = get_tls_config(parsed_hostname)
        try:
            if "podman" in host_url:
                # Podman workaround: set short timeout for initial ping, then increase for log streaming.
                client = docker.DockerClient(base_url=host_url, tls=tls_config, timeout=10)
                if client.ping():
                    logging.info(f"Successfully connected to Podman client on {host_url}")
                    client.close()
                    client = docker.DockerClient(base_url=host_url, tls=tls_config, timeout=300)
            else:
                client = docker.DockerClient(base_url=host_url, tls=tls_config, timeout=10)
            if label: 
                hostname = label
            else:
                try:
                    hostname = label if label else client.info()["Name"]
                except Exception as e:
                    # get hostname if docker socket is mounted
                    if parsed.scheme == "unix":
                        hostname = f"{socket.gethostname()}"
                    else: # dont use socket.gethostname() for tcp connections
                        hostname = f"{parsed.hostname}"
                    logging.warning(
                        f"Could not get hostname for {host_url}. LoggiFly will call this host '{hostname}' in notifications and logging to differentiate it from other hosts."
                        f"\nThis may occur if using a Socket Proxy that does not allow to retrieve the hostname via the docker client"
                        f"\nYou can also set a label in DOCKER_HOST as 'tcp://host:2375|label' that will be used as a hostname"
                        f"\nError details: {e}")    
            docker_hosts.append(
                DockerClientInfo(
                    host_url=host_url, 
                    client=client, 
                    tls_config=tls_config, 
                    label=label, 
                    hostname=hostname
                    )
                )
        except docker.errors.DockerException as e:
            logging.error(f"Error creating Docker client for {host_url}: {e}")
            logging.debug(f"Traceback: {traceback.format_exc()}")
            continue
        except Exception as e:
            logging.error(f"Unexpected error creating Docker client for {host_url}: {e}")
            logging.debug(f"Traceback: {traceback.format_exc()}")
            continue
        
    if len(docker_hosts) == 0:
        logging.critical("Could not connect to any docker hosts. Please check your DOCKER_HOST environment variable or mounted docker socket.")
        logging.info("Waiting 10s to prevent restart loop...")
        time.sleep(10)
        sys.exit(1)
    logging.info(
        f"Connections to Docker-Clients established for {', '.join([h.host_url for h in docker_hosts])}"
        if len(docker_hosts) > 1 else f"Connected to Docker Client on {docker_hosts[0].host_url}"
        )
    return docker_hosts


def start_loggifly():
    """
    Main entry point for LoggiFly. 
    
    Loads config, sets up Docker clients, monitoring, config watcher, and signal handlers.
    
    Returns:
        threading.Event: Global shutdown event that can be waited on
    """
    ensure_config_template()
    try:
        config, path = load_config()
    except (ValidationError, ConfigLoadError) as e:
        if isinstance(e, ValidationError):
            logging.critical(f"Config validation failed: {format_pydantic_error(e)}")
        else:
            logging.critical("Config loading failed")
        logging.info("Waiting 5s to prevent restart loop...")
        time.sleep(5)
        sys.exit(1)

    logging.getLogger().setLevel(getattr(logging, config.settings.log_level.upper(), logging.INFO))
    logging.info(f"Log-Level set to {config.settings.log_level}")
    start_messages = []
    docker_hosts = create_docker_clients()
    hostname = ""
    # Initialize monitoring for each Docker host
    for host_info in docker_hosts:
        client = host_info.client
        hostname = host_info.hostname
        host_url = host_info.host_url
        logging.info(f"Starting monitoring for {host_url} {'(' + hostname + ')' if hostname else ''}")
        monitor = DockerLogMonitor(config=config, client=client, hostname=hostname, host_url=host_url, multi_host=len(docker_hosts) > 1)
        start_messages.append(monitor.start())
        host_info.monitor = monitor

    monitor_instances = [host_info.monitor for host_info in docker_hosts]
    message = format_message(start_messages, "LoggiFly started without monitoring anything.")

    logging.info(f"LoggiFly started.\n{message}")
    if config.settings.disable_start_message is False:
        send_notification(
            config=config,
            title=get_title_prefix(docker_hosts) + "LoggiFly started",
            message=message
        )
    else:
        logging.info(f"Startup message disabled. {message}")
    
    # Start config observer to catch config.yaml changes
    if config.settings.reload_config and isinstance(path, str) and os.path.exists(path):
        config_observer = start_config_watcher(monitor_instances, config, path)
    else:
        logging.debug("Config watcher did not start: reload_config is False or config path invalid.")
        config_observer = None
    
    handle_signal, global_shutdown_event = create_handle_signal(docker_hosts, config, config_observer)
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)   

    # Start the thread that checks whether the docker hosts are still monitored and tries to reconnect if the connection is lost.
    check_monitor_status(docker_hosts, global_shutdown_event)
    return global_shutdown_event


if __name__ == "__main__":
    global_shutdown_event = start_loggifly()
    global_shutdown_event.wait()
