from config.config_model import GlobalConfig
import logging
from typing import TYPE_CHECKING
from notification_formatter import NotificationContext, render_title, render_message
from notifier import send_notification
from services import trigger_olivetin_action
from utils import LogAttachment

if TYPE_CHECKING:
    from monitoring.base import MonitoredUnit

logger = logging.getLogger(__name__)


def process_trigger(
    logger: logging.Logger,
    config: GlobalConfig,
    modular_settings: dict,
    trigger_level_config: dict,
    monitored_unit: "MonitoredUnit",
    notification_context: NotificationContext,
):
    action_to_perform = trigger_level_config.get("action")

    # Perform action if configured and supported by this unit type
    if action_to_perform is not None and monitored_unit.supports_container_actions():
        action_result = monitored_unit.perform_container_action(
            action_to_perform,
            modular_settings.get("action_cooldown", 300),
        )
        if action_result:
            notification_context.action_string = action_to_perform
            notification_context.action_type = action_result.action_type
            notification_context.action_target = action_result.action_target
            notification_context.action_result = action_result.message
            notification_context.action_succeeded = action_result.success

    # Create log file attachment if requested
    attachment: LogAttachment | None = None
    attach_logfile = modular_settings.get("attach_logfile", False)
    attachment_lines = modular_settings.get("attachment_lines", 20) if isinstance(modular_settings.get("attachment_lines"), int) else 20
    if attach_logfile:
        if result := monitored_unit.get_log_tail(attachment_lines):
            attachment = LogAttachment(
                content=result,
                file_name=f"last_{attachment_lines}_lines_from_{monitored_unit.unit_name}.log",
            )
        else:
            logger.error(f"Could not create log attachment file for {monitored_unit.unit_name}")
    
    # Send notification if not disabled
    disable_notifications = modular_settings.get("disable_notifications", False)
    if disable_notifications:
        logger.debug(f"Not sending notification for {monitored_unit.unit_name} because notifications are disabled.")
    else:
        title = render_title(notification_context, template=modular_settings.get("title_template"))
        message = render_message(notification_context, template=modular_settings.get("message_template"))
        send_notification(config,
            title=title,
            message=message,
            modular_settings=modular_settings,
            notification_context=notification_context,
            attachment=attachment,
        )

    # Trigger OliveTin actions if configured
    olivetin_configs = trigger_level_config.get("olivetin_actions", []) or []
    for olivetin_config in olivetin_configs:
        if not olivetin_config.get("id"):
            continue
        trigger_olivetin_action(
            settings=modular_settings,
            action_cfg=olivetin_config,
            logger=logger,
            disable_notifications=disable_notifications,
            send_notification_cb=None if disable_notifications else lambda title, message: send_notification(
                config,
                title=title,
                message=message,
                notification_context=notification_context,
                attachment=attachment,
                modular_settings=modular_settings,
            )
        )
