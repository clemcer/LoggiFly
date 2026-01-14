import requests
import apprise
import tempfile
import os
import base64
import logging
from pydantic import SecretStr
from utils import merge_with_precedence
import urllib.parse
from config.config_model import GlobalConfig, ContainerConfig, SwarmServiceConfig
from email.header import Header
from constants import EMOJI_PATTERN
from notification_formatter import NotificationContext

logger = logging.getLogger(__name__)
logging.getLogger("apprise").setLevel(logging.INFO)

NTFY_KEYS = {
    "url", "topic", "token", "username", "password", "tags",
    "priority", "actions", "icon", "click", "markdown", "headers"
    }
APPRISE_KEYS = {"url"}
WEBHOOK_KEYS = {"url", "headers"}

NTFY_PREFIX = "ntfy_"
APPRISE_PREFIX = "apprise_"
WEBHOOK_PREFIX = "webhook_"


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
        s = s.replace(q, '\\' + q)
        return f"{q}{s}{q}"

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

def _normalize_and_strip_prefix(d: dict, prefix: str, keys: set[str]) -> dict:
    """Accept both prefixed (ntfy_url) and bare (url) keys; strip prefix if present."""
    out = {}
    for k, v in (d or {}).items():
        base = k[len(prefix):] if k.startswith(prefix) else k
        if base in keys:
            if isinstance(v, SecretStr):
                v = v.get_secret_value()
            out[base] = v
    return out

def get_notification_config(modular_settings: dict, global_service_config: dict, prefix: str, keys: set[str]) -> dict:
    """
    Prepare a notification config with precedence: trigger > unit > global.
    Keys may be provided with or without 'prefix' prefix.
    """
    return merge_with_precedence(
        _normalize_and_strip_prefix(modular_settings, prefix, keys),
        _normalize_and_strip_prefix(global_service_config, prefix, keys),
        list_union=False,
        dict_merge=False,
    )


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
    title = title.replace("\n", " ").strip() if title else ""

    headers = {
        "Title": title.encode("latin-1", errors="ignore").decode("latin-1").strip(),
        "Icon": "https://raw.githubusercontent.com/clemcer/LoggiFly/refs/heads/main/docs/public/icon.png",
        "Priority": f"{ntfy_config.get('priority', 3)}"
    }
    if ntfy_config.get("token"):
        headers["Authorization"] = f"Bearer {ntfy_config['token']}"
    elif ntfy_config.get('username') and ntfy_config.get('password'):
        credentials = f"{ntfy_config['username']}:{ntfy_config['password']}"
        encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        headers["Authorization"] = f"Basic {encoded_credentials}"

    if ntfy_config.get('actions'):
        action_header = build_ntfy_action_header(ntfy_config.get('actions', []))
        logger.debug(f"ACTION HEADER: {action_header}")
        headers["Actions"] = action_header
    if ntfy_config.get("tags"):
        headers["Tags"] = ntfy_config.get("tags")
    if ntfy_config.get("icon"):
        headers["Icon"] = ntfy_config.get("icon")
    if ntfy_config.get("click"):
        headers["Click"] = ntfy_config.get("click")
    if ntfy_config.get("markdown"):
        headers["Markdown"] = str(ntfy_config.get("markdown"))
    if ntfy_config.get("headers"):
        headers.update(ntfy_config.get("headers"))
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
                      title: str, 
                      message: str,
                      modular_settings: dict | None = None,
                      attachment: dict | None = None,
                      notification_context: NotificationContext | None = None,
                      ):
    """
    Dispatch a notification using ntfy, Apprise, and/or webhook based on configuration.
    Handles message formatting, file attachments, and host labeling.
    """
    message = message.replace(r"\n", "\n").strip() if message else ""
    nc = config.notifications.model_dump(exclude_none=True)
    ntfy_config = get_notification_config(modular_settings or {}, nc.get("ntfy", {}), NTFY_PREFIX, NTFY_KEYS)
    apprise_url = get_notification_config(modular_settings or {}, nc.get("apprise", {}), APPRISE_PREFIX, APPRISE_KEYS).get("url")
    webhook_config = get_notification_config(modular_settings or {}, nc.get("webhook", {}), WEBHOOK_PREFIX, WEBHOOK_KEYS)

    # Send ntfy notification if configured
    if ntfy_config and ntfy_config.get("url") and ntfy_config.get("topic"):
        send_ntfy_notification(ntfy_config, message=message, title=title, attachment=attachment)

    # Send Apprise notification if configured   
    if apprise_url:
        send_apprise_notification(apprise_url, message=message, title=title, attachment=attachment)
    
    # Send webhook notification if configured
    if (webhook_config and webhook_config.get("url")):
        if notification_context:
            json_data = {
                "title": title,
                "message": message,
                "info_fields": notification_context.get_defaults() or {},
                "log_fields": {
                    "json_fields": notification_context.get_json_fields() or {},
                    "regex_fields": notification_context.get_regex_fields() or {},
                },
            }
        else:
            json_data = {
                "title": title,
                "message": message,
            }
        logger.debug(f"JSON DATA: {json_data}")
        send_webhook(json_data, webhook_config)

