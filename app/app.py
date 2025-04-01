import os
import logging
import docker
import threading
import traceback
import signal
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from notifier import send_notification
from line_processor import LogProcessor
from load_config import load_config

logging.basicConfig(
     level = "INFO",
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("monitor.log", mode="w"),
        logging.StreamHandler()
    ]
)
logging.info("Loggifly started")
shutdown_event = threading.Event()
config = load_config()

def create_handle_signal(config):
    def handle_signal(signum, frame):
        if config.settings.disable_shutdown_message is False:
            send_notification(config, "Loggifly:", "The program is shutting down.")
        logging.info(f"Signal {signum} received. shutting down...")
        shutdown_event.set()
    return handle_signal

signal_handler = create_handle_signal(config)
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


def set_logging(config):
    log_level = config.settings.log_level
    logging.getLogger().handlers.clear()
    logging.basicConfig(
        level = getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("monitor.log", mode="w"),
            logging.StreamHandler()
        ]
    )
    logging.info(f"Log-Level set to {log_level}")


def restart_docker_container():
    if config.settings.disable_restart_message is False:
        send_notification(config, "Loggifly:", "Config Change detected. The program is restarting.")
    logging.info("The program is restarting.")
    client = docker.from_env()
    container_id = os.getenv("HOSTNAME")  
    container = client.containers.get(container_id)
    logging.debug(f"container_id: {container_id}, container: {container}")
    container.restart()

class ConfigHandler(FileSystemEventHandler): # Watch for changes in config.yaml. Watchdog.
    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith('config.yaml'):
            logging.debug("File has changed!")
            logging.info("Restarting container in 5s")
            restart_docker_container()


def detect_config_changes():
    logging.debug("Watching for config changes")
    path = "/app/config.yaml"  
    event_handler = ConfigHandler()
    observer = Observer()
    observer.schedule(event_handler, path=path, recursive=False)    
    observer.start()
    try:
        while not shutdown_event.is_set():
            observer.join(1)
    except Exception as e:
        logging.error(f"Error: {e}")
    finally:
        observer.stop()
        observer.join()


def monitor_container_logs(config, client, container):
    """
    I am using a buffer in case the logstream has an unfinished log line that can't be decoded correctly.
    """
    now = datetime.now()
    processor = LogProcessor(config, container, shutdown_event, timeout=5)  
    buffer = b""
    try:
        log_stream = container.logs(stream=True, follow=True, since=now)
        logging.info("Monitoring for Container started: %s", container.name)
        for chunk in log_stream:
            if shutdown_event.is_set():
                logging.debug(f"Noticed that shutdown_event.is_set in monitor_container_logs() function for {container.name}. Closing client now")
                client.close()
                break
            buffer += chunk
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                try:
                    log_line_decoded = str(line.decode("utf-8")).strip()
                except UnicodeDecodeError:
                    log_line_decoded = line.decode("utf-8", errors="replace").strip()
                    logging.warning(f"{container.name}: Error while trying to decode a log line. Used errors='replace' for line: {log_line_decoded}")
                if log_line_decoded: 
                    processor.process_line(log_line_decoded)

    except docker.errors.APIError as e:
        logging.error("Docker API-Errorer for Container %s: %s", container.name, e)
    except Exception as e:
        logging.error("Error while trying to monitor %s: %s", container.name, e)
        logging.error("Error details: %s", str(e.__class__.__name__))
        logging.debug(traceback.format_exc())
    finally:
        log_stream.close()
    logging.info("Monitoring stopped for Container: %s", container.name)


def main(config):
    """
    Creates Threads for each container to monitor their logs 
    Then docker events are being monitoring to look for new containers. 
    And a thread watching config changes is started.
    """
    threads = []
    client = docker.from_env()
    selected_containers = [ ]
    for container in config.containers:
        selected_containers.append(container)
    containers = client.containers.list()
    containers_to_monitor = [c for c in containers if c.name in selected_containers]
    containers_to_monitor_str = "\n - ".join(c.name for c in containers_to_monitor)
    logging.info(f"These containers are being monitored:\n - {containers_to_monitor_str}")
    unmonitored_containers = [c for c in selected_containers if c not in [c.name for c in containers_to_monitor]]
    if unmonitored_containers:
        unmonitored_containers_str = "\n - ".join(unmonitored_containers)
        logging.info(f"These selected Containers are not running:\n - {unmonitored_containers_str}")
    else:
        unmonitored_containers_str = ""

    if config.settings.disable_start_message is False:
        send_notification(config, "Loggifly", f"The program is running and monitoring these selected Containers:\n - {containers_to_monitor_str}\n\nThese selected Containers are not running:\n - {unmonitored_containers_str}")
    
    for container in containers_to_monitor:
        thread = threading.Thread(target=monitor_container_logs, args=(config, client, container), daemon=True)
        threads.append(thread)
        thread.start()
    if config.settings.disable_restart is False:
        thread_file_change = threading.Thread(target=detect_config_changes)
        threads.append(thread_file_change)
        thread_file_change.start()
    logging.info("Monitoring started for all selected containers. Monitoring docker events now to watch for new containers")
    for event in client.events(decode=True, filters={"event": "start"}):
        if shutdown_event.is_set():
            logging.debug(f"Noticed that shutdown_event.is_set in monitor_docker_logs() function. Closing client now")
            client.close()
            break
        id = event["Actor"]["ID"]
        container_from_event = client.containers.get(id)
        if container_from_event.name in selected_containers:
            thread = threading.Thread(target=monitor_container_logs, args=(config, client, container_from_event), daemon=True)
            threads.append(thread)
            thread.start()
            logging.info("Monitoring new container: %s", container_from_event.name)
            send_notification(config, "Loggifly", f"Monitoring new container: {container_from_event.name}")
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    set_logging(config)
    main(config)
    
