from config.config_model import GlobalConfig
import logging
from typing import TYPE_CHECKING
from notification_formatter import NotificationContext, render_title, render_message
from notifier import send_notification
from services import trigger_olivetin_action

if TYPE_CHECKING:
    from docker_monitoring.monitor import DockerLogMonitor, MonitoredContainerContext
    from docker_monitoring.docker_helpers import ContainerActionResult

logger = logging.getLogger(__name__)

def process_trigger(
    logger: logging.Logger,
    config: GlobalConfig,
    modular_settings: dict,
    trigger_level_config: dict,
    monitor_instance: "DockerLogMonitor",
    unit_context: "MonitoredContainerContext",
    notification_context: NotificationContext,
):
    logger.debug(f"\n\nProcessing trigger for {unit_context.unit_name} with modular settings:\n{modular_settings} and trigger level config:\n{trigger_level_config}\n\n")
    action_to_perform = trigger_level_config.get("action")

    # Perform container action if configured
    if action_to_perform is not None:
        action_result = monitor_instance.perform_container_action(modular_settings, action_to_perform, unit_context.container_name)
        if action_result.is_on_cooldown:
            pass # TODO: should message for cooldown be added to notification title?
        else:
            notification_context.action_result = action_result.message
    logger.debug(f"\n\nNotification context:\n{notification_context.to_dict()}\n\n")

    # Create log file attachment if requested
    attachment = None
    attach_logfile = modular_settings.get("attach_logfile", False)
    attachment_lines = modular_settings.get("attachment_lines", 20) if isinstance(modular_settings.get("attachment_lines"), int) else 20
    if attach_logfile:
        if result := monitor_instance.tail_logs(unit_context.container_id, attachment_lines):
            attachment = {"content": result, "file_name": f"last_{attachment_lines}_lines_from_{unit_context.unit_name}.log"}
        else:
            logger.error(f"Could not create log attachment file for {unit_context.unit_name}")
    
    # Send notification if not disabled
    disable_notifications = modular_settings.get("disable_notifications", False)
    if disable_notifications:
        logger.debug(f"Not sending notification for {unit_context.unit_name} because notifications are disabled.")
    
    if not disable_notifications:
        title = render_title(notification_context, template=modular_settings.get("title_template"))
        message = render_message(notification_context, template=modular_settings.get("message_template"))
        send_notification(config,
            title=title,
            message=message,
            modular_settings=modular_settings,
            template_fields=notification_context.to_dict(),
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
                template_fields=notification_context.to_dict(),
                attachment=attachment,
                modular_settings=modular_settings,
            ),
        )
