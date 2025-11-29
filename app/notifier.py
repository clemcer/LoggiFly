import requests
import apprise
import tempfile
import os
import base64
import logging
from pydantic import SecretStr
import urllib.parse
from config.config_model import GlobalConfig, ContainerConfig, SwarmServiceConfig
from email.header import Header
from constants import EMOJI_PATTERN

logger = logging.getLogger(__name__)
logging.getLogger("apprise").setLevel(logging.INFO)


def emoji_to_rfc2047(match):
    """Convert the matched emoji to RFC 2047 encoding."""
    emoji = match.group(0)
    return Header(emoji, "utf-8").encode()

def replace_emojis_with_rfc2047(text):
    """Replace all emojis in a text with RFC 2047 encoded forms."""
    return EMOJI_PATTERN.sub(emoji_to_rfc2047, text)

def build_ntfy_action_header(actions: list) -> str:
    def _needs_quotes(s: str) -> bool:
        return any(ch in s for ch in [',', ';'])

    def _quote_if_needed(s: str) -> str:
        if not _needs_quotes(s):
            return s
        if "'" in s and '"' not in s:
            q = '"'
        else:
            q = "'"
        return f"{q}{s.replace(q, '\\' + q)}{q}"

    def _flatten_map(prefix: str, m: dict[str, str]) -> list[str]:
        out = []
        for k, v in m.items():
            if v is None:
                continue
            out.append(f"{prefix}.{k}={_quote_if_needed(str(v))}")
        return out

    action_list = []
    header = ""
    for idx, a in enumerate(actions, 1):
        if idx > 3:
            logging.warning(f"Ntfy Action: You can only have up to 3 actions. Only using the first 3 actions: '{actions[:3]}'.")
            break
        if a.get('action') == 'view':
            if not a.get('url') or not a.get('label'):
                logging.warning(f"Ntfy Action: url and label are required for view action. Ignoring action '{a}'.")
                continue
            parts = ["view", _quote_if_needed(a.get('label')), _quote_if_needed(a.get('url'))]
            if a.get('clear') is True:
                parts.append("clear=true")
            action_list.append(", ".join(parts))

        elif a.get('action') == 'http':
            if not a.get('url') or not a.get('label'):
                logging.warning(f"Ntfy Action: url and label are required for HTTP action. Ignoring action '{a}'.")
                continue
            parts = ["http", _quote_if_needed(a.get('label')), _quote_if_needed(a.get('url'))]
            if a.get('method') and a.get('method') != "POST":
                parts.append(f"method={_quote_if_needed(a.get('method'))}")
            if a.get('headers'):
                parts.extend(_flatten_map("headers", a.get('headers')))
            if a.get('body') is not None:
                parts.append(f"body={_quote_if_needed(a.get('body'))}")
            if a.get('clear') is True:
                parts.append("clear=true")
            action_list.append(", ".join(parts))

        elif a.get('action') == 'broadcast':
            if not a.get('label'):
                logging.warning(f"Ntfy Action: label is required for broadcast action. Ignoring action '{a}'.")
                continue
            parts = ["broadcast", _quote_if_needed(a.get('label'))]
            # Only send default intent if it differs from the default
            if a.get('intent') and a.get('intent') != "io.heckel.ntfy.USER_ACTION":
                parts.append(f"intent={_quote_if_needed(a.get('intent'))}")
            if a.get('extras'):
                parts.extend(_flatten_map("extras", a.get('extras')))
            if a.get('clear') is True:
                parts.append("clear=true")
            action_list.append(", ".join(parts))
    logger.debug(f"ACTIONS: {actions}")
    header = ";".join(action_list) if actions else ""
    return header

def get_ntfy_config(config: GlobalConfig, message_config, unit_config) -> dict:
    """
    Aggregate ntfy notification configuration from global, container, and message-specific sources.
    Precedence: message_config > unit_config > global_config.
    Handles secret values and authorization header construction.
    """
    ntfy_config = {
        "topic": None,
        "tags": None,
        "priority": None,
        "url": None,
        "token": None,
        "username": None,
        "password": None,
        "authorization": "",
        "actions": None,
        "icon": None,
        "click": None,
        "markdown": None,
        "delay": None,
    }

    global_config = config.notifications.ntfy.model_dump(exclude_none=True) if config.notifications.ntfy else {}
    unit_config_dict = unit_config.model_dump(exclude_none=True) if unit_config else {}
    message_config = message_config if message_config else {}

    # Merge configurations with precedence order
    for key in ntfy_config.keys():
        ntfy_key = "ntfy_" + key
        if message_config.get(ntfy_key) is not None:
            ntfy_config[key] = message_config.get(ntfy_key)
        elif unit_config_dict.get(ntfy_key) is not None:
            ntfy_config[key] = unit_config_dict.get(ntfy_key)
        elif global_config.get(key) is not None:
            ntfy_config[key] = global_config.get(key)

    # Extract secret values
    for key, value in ntfy_config.items():
        if value and isinstance(value, SecretStr):
            ntfy_config[key] = value.get_secret_value()

    # Build authorization header
    if ntfy_config.get("token"):
        ntfy_config["authorization"] = f"Bearer {ntfy_config['token']}"
    elif ntfy_config.get('username') and ntfy_config.get('password'):
        credentials = f"{ntfy_config['username']}:{ntfy_config['password']}"
        encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        ntfy_config["authorization"] = f"Basic {encoded_credentials}"
    return ntfy_config


def get_apprise_url(config: GlobalConfig, message_config, unit_config) -> str | None:
    """
    Retrieve the Apprise notification URL from message, container, or global config.
    Precedence: message_config > unit_config > global_config.
    Handles secret values.
    """
    apprise_url = None
    global_config = config.notifications.apprise.model_dump(exclude_none=True) if config.notifications.apprise else {}
    unit_config_dict = unit_config.model_dump(exclude_none=True) if unit_config else {}
    message_config = message_config if message_config else {}

    # Get URL with precedence order
    if message_config.get("apprise_url"):
        apprise_url = message_config.get("apprise_url")
    elif unit_config_dict.get("apprise_url"):
        apprise_url = unit_config_dict.get("apprise_url")
    elif global_config.get("url"):
        apprise_url = global_config.get("url")

    # Extract secret value if needed
    if apprise_url and isinstance(apprise_url, SecretStr):
        apprise_url = apprise_url.get_secret_value() if apprise_url else None
    return apprise_url


def get_webhook_config(config: GlobalConfig, message_config, unit_config) -> dict:
    """
    Aggregate webhook configuration from global, container, and message-specific sources.
    Precedence: message_config > unit_config > global_config.
    """
    webhook_config = {"url": None, "headers": {}}

    global_config = config.notifications.webhook.model_dump(exclude_none=True) if config.notifications.webhook else {}
    unit_config_dict = unit_config.model_dump(exclude_none=True) if unit_config else {}
    message_config = message_config if message_config else {}

    # Merge configurations with precedence order
    for key in webhook_config.keys():
        webhook_key = "webhook_" + key
        if message_config.get(webhook_key) is not None:
            webhook_config[key] = message_config.get(webhook_key)
        elif unit_config_dict.get(webhook_key) is not None:
            webhook_config[key] = unit_config_dict.get(webhook_key)
        elif global_config.get(key) is not None:
            webhook_config[key] = global_config.get(key)
    return webhook_config


def send_apprise_notification(url, message, title, attachment: dict | None = None):
    """
    Send a notification using Apprise.
    Optionally attaches a file. Message is truncated if too long.
    """
    message = ("This message had to be shortened: \n" if len(message) > 1900 else "") + message[:1900]
    file_path = None
    try:
        apobj = apprise.Apprise()
        apobj.add(url)
        if attachment and (file_content := attachment.get("content", "")):
            file_name = attachment.get("file_name", "attachment.log")
            # /dev/shm works even when the container is read_only
            file_path = None
            try:
                file_path = os.path.join("/dev/shm", file_name)
                with open(file_path, "w") as tmp_file:
                    tmp_file.write(file_content)
                    tmp_file.flush()
            except Exception:
                logger.error("Error trying to write attachment file to /dev/shm")
                try:
                    file_path = os.path.join("/tmp", file_name)
                    with open(file_path, "w") as tmp_file:
                        tmp_file.write(file_content)
                        tmp_file.flush()
                except Exception:
                    logger.error("Error trying to write attachment file to /tmp")
                    
            result = apobj.notify(
                title=title,
                body=message,
                attach=file_path if file_path and os.path.exists(file_path) else None # type: ignore
            )
        else:
            result = apobj.notify(
                title=title,
                body=message,
            )
        if result:
            logger.info("Apprise-Notification sent successfully")
        else:
            logger.error("Error trying to send apprise-notification")
    except Exception as e:
        logger.error("Error while trying to send apprise-notification: %s", e)
    finally:
        # Clean up temporary attachment file if it exists
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass


def send_ntfy_notification(ntfy_config, message, title, attachment: dict | None =None):
    """
    Send a notification via ntfy with optional file attachment.
    Handles authorization and message truncation.
    """
    message = ("This message had to be shortened: \n" if len(message) > 3900 else "") + message[:3900]
    
    title = replace_emojis_with_rfc2047(title)

    headers = {
        "Title": title.encode("latin-1", errors="ignore").decode("latin-1").strip(),
        "Tags": f"{ntfy_config['tags']}",
        "Icon": "https://raw.githubusercontent.com/clemcer/loggifly/blob/main/docs/public/icon.png",
        "Priority": f"{ntfy_config['priority']}"
    }
    if ntfy_config.get('authorization'):
        headers["Authorization"] = f"{ntfy_config.get('authorization')}"
    if ntfy_config.get('actions'):
        action_header = build_ntfy_action_header(ntfy_config.get('actions', []))
        logger.debug(f"ACTION HEADER: {action_header}")
        headers["Actions"] = action_header
    if ntfy_config.get("icon"):
        headers["Icon"] = ntfy_config.get("icon")
    if ntfy_config.get("click"):
        headers["Click"] = ntfy_config.get("click")
    if ntfy_config.get("markdown"):
        headers["Markdown"] = str(ntfy_config.get("markdown"))
    if ntfy_config.get("delay"):
        headers["Delay"] = ntfy_config.get("delay")
    try:
        if attachment and (file_content := attachment.get("content", "").encode("utf-8")):
            headers["Filename"] = attachment.get("file_name", "attachment.txt")
            # When attaching a file the message can not be passed normally.
            # So if the message is short, include it as query param, else omit it
            if len(message) < 199:
                response = requests.post(
                    f"{ntfy_config['url']}/{ntfy_config['topic']}?message={urllib.parse.quote(message)}",
                    data=file_content,
                    headers=headers
                )
            else:
                response = requests.post(
                    f"{ntfy_config['url']}/{ntfy_config['topic']}",
                    data=file_content,
                    headers=headers
                )
        else:
            response = requests.post(
                f"{ntfy_config['url']}/{ntfy_config['topic']}",
                data=message,
                headers=headers
            )
        if response.status_code == 200:
            logger.info("Ntfy-Notification sent successfully")
        else:
            logger.error("Error while trying to send ntfy-notification: %s", response.text)
    except requests.RequestException as e:
        logger.error("Error while trying to connect to ntfy: %s", e)


def send_webhook(json_data: dict, webhook_config: dict):
    """
    Send a POST request to a custom webhook with the provided JSON payload and headers.
    """
    url, headers = webhook_config.get("url", ""), webhook_config.get("headers", {})
    try:
        response = requests.post(
            url=url,
            headers=headers,
            json=json_data,
            timeout=10
        )
        if response.status_code == 200:
            logger.info(f"Webhook sent successfully.")
            # logger.debug(f"Webhook Response: {json.dumps(response.json(), indent=2)}")
        else:
            logger.error("Error while trying to send POST request to custom webhook: %s", response.text)
    except requests.RequestException as e:
        logger.error(f"Error trying to send webhook to url: {url}, headers: {headers}: %s", e)


def send_notification(config: GlobalConfig, 
                      unit_name: str, 
                      title: str, 
                      message: str,
                      message_config: dict | None = None, 
                      unit_config: ContainerConfig | SwarmServiceConfig | None = None,
                      attachment: dict | None = None,
                      hostname: str | None = None):
    """
    Dispatch a notification using ntfy, Apprise, and/or webhook based on configuration.
    Handles message formatting, file attachments, and host labeling.
    """
    message = message.replace(r"\n", "\n").strip() if message else ""
    monitor_type: str = message_config.get("monitor_type", "") if message_config else ""

    # If multiple hosts are set, prepend hostname to title
    title = f"[{hostname}] - {title}" if hostname else title

    # Send ntfy notification if configured
    ntfy_config = get_ntfy_config(config, message_config, unit_config)
    if (ntfy_config and ntfy_config.get("url") and ntfy_config.get("topic")):
        send_ntfy_notification(ntfy_config, message=message, title=title, attachment=attachment)

    # Send Apprise notification if configured
    apprise_url = get_apprise_url(config, message_config, unit_config)
    if apprise_url:
        send_apprise_notification(apprise_url, message=message, title=title, attachment=attachment)

    # Send webhook notification if configured
    webhook_config = get_webhook_config(config, message_config, unit_config)
    if (webhook_config and webhook_config.get("url")):
        keywords = message_config.get("keywords_found", None) if message_config else None
        json_data = {
            "monitor_type": monitor_type,
            "unit_name": unit_name,
            "keywords": keywords,
            "title": title,
            "message": message,
            "host": hostname
        }
        send_webhook(json_data, webhook_config)
    


