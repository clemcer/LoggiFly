import os
import sys
import time
from utils import convert_to_int

def main():
    """
    Check if the heartbeat file exists and is not too old. Called via docker healthcheck command.
    """
    heartbeat_path = os.getenv("HEARTBEAT_PATH", "/dev/shm/loggifly-heartbeat")
    interval = convert_to_int(os.getenv("HEARTBEAT_INTERVAL"), fallback_value=60, min_value=3)
    max_age = int(interval * 1.5)

    try:
        stat = os.stat(heartbeat_path)
    except FileNotFoundError:
        print(f"heartbeat file {heartbeat_path} not found", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"error accessing heartbeat file {heartbeat_path}: {e}", file=sys.stderr)
        sys.exit(1)

    age = time.time() - stat.st_mtime
    if age > max_age:
        print(f"heartbeat too old: age={int(age)}s > {max_age}s", file=sys.stderr)
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main() 