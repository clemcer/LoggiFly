import requests
import logging
import threading
from pydantic import SecretStr

logger = logging.getLogger(__name__)


class OlivetinAction:
    """
    Trigger action via Olivetin API.
    First authenticates with username/password to get a session cookie if username and password are provided.
    Then can use that cookie for subsequent action requests.
    """
    
    def __init__(self):
        """Initialize OliveTin action handler with empty authentication cache."""
        self.auth_cookies = {}
        self._locks: dict[str, threading.Lock] = {}
        self._locks_lock = threading.Lock()

    def _get_url_lock(self, url: str) -> threading.Lock:
        with self._locks_lock:
            lock = self._locks.get(url)
            if lock is None:
                lock = threading.Lock()
                self._locks[url] = lock
            return lock

    def get_auth_cookie(self, url, username, password) -> str | None:
        """
        Authenticate with OliveTin and get a session cookie.
        Checks if existing cookie is still valid before creating a new one.

        Returns:
            str or None: Session cookie if authentication successful, None otherwise
        """
        with self._get_url_lock(url):
            if (auth_cookie := self.auth_cookies.get(url)):
                if self.is_cookie_valid(url, auth_cookie):
                    return auth_cookie
                else:
                    self.auth_cookies.pop(url)
            try:
                login_url = f"{url}/api/LocalUserLogin"
                login_response = requests.post(
                    url=login_url,
                    headers={"accept": "application/json", "Content-Type": "application/json"},
                    json={"username": username, "password": password}
                )
                
                if login_response.status_code != 200:
                    logger.error(f"Olivetin login failed: {login_response.status_code} - {login_response.text}")
                    return None
                
                # Get the auth cookie
                auth_cookie = login_response.cookies.get("olivetin-sid-local")
                if not auth_cookie:
                    logger.error("Tried to login to Olivetin but did not receive an auth cookie")
                    logger.error(f"Login Response: {login_response.text}")
                    return None
                logger.info("Olivetin login successful")
                self.auth_cookies[url] = auth_cookie
                return auth_cookie
            except Exception as e:
                logger.error(f"Error getting auth cookie: {e}")
                return None

    def is_cookie_valid(self, url, auth_cookie) -> bool:
        """Check if an existing authentication cookie is still valid."""
        try:
            response = requests.get(
                url=f"{url}/api/WhoAmI",
                cookies={"olivetin-sid-local": auth_cookie}
            )
            if response.status_code != 200:
                logger.info(f"Olivetin cookie is not valid: {response.status_code} - {response.text}")
                return False
            
            return True
        except Exception as e:
            logger.error(f"Error checking if Olivetin cookie is valid: {e}")
            return False
        
    def trigger_action(self, url, action_id, arguments=None, username=None, password=None) -> dict | None:
        """Trigger an OliveTin action with optional authentication."""
        auth_cookie = None
        if username and password:
            auth_cookie = self.get_auth_cookie(url, username, password)
            if not auth_cookie:
                logger.error("Username and password are set but could not get an auth cookie. Trying to trigger action without auth cookie...")
        try:
            olivetin_request_object = {
                "actionId": action_id,
            }
            if arguments:
                olivetin_request_object["arguments"] = arguments
            action_url = f"{url}/api/StartActionAndWait"
            cookies = {"olivetin-sid-local": auth_cookie} if auth_cookie else None
            action_response = requests.post(
                url=action_url,
                cookies=cookies,
                json=olivetin_request_object
            )
            if action_response.status_code == 200:
                logger.debug("Successfully established connection to Olivetin")
            else:
                logger.error(f"Olivetin action request failed: {action_response.status_code} - {action_response.text}")
            try:
                data = action_response.json()
                logger.info(f"Action Response: {data}")
                return data
            except ValueError:
                logger.error("Invalid JSON response from Olivetin")
                return None
        except requests.RequestException as e:
            logger.error(f"Error connecting to Olivetin: {e}")
            return None


# Global instance and thread lock for singleton pattern
_olivetin_action = None


def perform_olivetin_action(
    url: str,
    username: str,
    password: str | SecretStr,
    olivetin_action_config: dict,
) -> tuple[str, str]:
    """
    Perform an OliveTin action.

    Returns:
        tuple: (notification_title, notification_message) describing the action result
    """
    if password and isinstance(password, SecretStr):
        password = password.get_secret_value()
    action_id = olivetin_action_config.get("id")
    if not action_id:
        logger.error("No action ID provided")
        return "Olivetin Action Failed", "Olivetin Action failed with no action ID"
    arguments = olivetin_action_config.get("arguments")
    global _olivetin_action
    
    if _olivetin_action is None:
        _olivetin_action = OlivetinAction()
    response = _olivetin_action.trigger_action(url, action_id, arguments, username, password)
    if not response:
        return "Olivetin Action Failed", "Olivetin Action failed with no response"
        
    # Parse response and determine success/failure
    log_entry = response.get("logEntry", {})
    action_title = log_entry.get("actionTitle", "unknown action")
    action_icon = log_entry.get("actionIcon", "")
    message = "Output:\n" + log_entry.get("output", "")
    
    if (log_entry.get("executionStarted") is True 
    and log_entry.get("executionFinished") is True 
    and log_entry.get("blocked") is False):
        logger.info(f"Olivetin Action was run successfully: {action_icon} {action_title}")
        title = f"Olivetin Action '{action_icon} {action_title}' was run successfully"
    else:
        logger.error(f"Olivetin Action failed: {action_icon} {action_title}")
        title = f"Olivetin action '{action_icon} {action_title}' failed"
    return title, message

def trigger_olivetin_action(
    settings: dict,
    action_cfg: dict,
    logger: logging.Logger,
    *,
    send_notification_cb=None,
    disable_notifications: bool | None = None,
):
    """
    Run an OliveTin action in a background thread using merged settings.

    Args:
        settings: merged settings containing olivetin_url/username/password (+ optional disable_notifications).
        action_cfg: OliveTin action dict (id, arguments).
        logger: logger instance for diagnostics.
        send_notification_cb: callable(title, message) to emit a notification (optional).
        disable_notifications: explicit override; defaults to settings["disable_notifications"].
    """
    url = (settings or {}).get("olivetin_url")
    username = (settings or {}).get("olivetin_username")
    password = (settings or {}).get("olivetin_password")
    disable = disable_notifications if disable_notifications is not None else (settings or {}).get("disable_notifications") or False

    if not url or not username or not password:
        logger.error("Could not start OliveTin action because URL, username or password is not set.")
        return None

    def _run_action():
        try:
            result = perform_olivetin_action(url, username, password, action_cfg)
        except Exception as e:
            logger.error("Olivetin action failed: %s", e)
            return
        if not result:
            return
        title, message = result
        if send_notification_cb and not disable:
            try:
                send_notification_cb(title, message)
            except Exception as e:
                logger.error("Failed to send notification for Olivetin action: %s", e)

    thread = threading.Thread(target=_run_action, daemon=True)
    thread.start()
    return thread
