import logging
from concurrent.futures import ThreadPoolExecutor                       
from typing import TYPE_CHECKING

from notification_formatter import NotificationContext, render_title, render_message
from notifier import send_notification
from services import trigger_olivetin_action
from utils import LogAttachment, get_env_var, convert_to_int

from config.models import GlobalConfig

if TYPE_CHECKING:
    from monitoring.base import MonitoredTarget

logger = logging.getLogger(__name__)


max_workers = convert_to_int(get_env_var("MAX_TRIGGER_WORKERS", fallback_value="8"), fallback_value=8, min_value=1)

_executor = ThreadPoolExecutor(max_workers=max_workers)


def shutdown_trigger_executor():
    _executor.shutdown(wait=False)

def process_trigger(
    logger: logging.Logger,
    config: GlobalConfig,
    trigger_context: dict,
    monitored_target: "MonitoredTarget",
    notification_context: NotificationContext,
    ):
    _executor.submit(_process_trigger, logger, config, trigger_context, monitored_target, notification_context)

def _process_trigger(
    logger: logging.Logger,
    config: GlobalConfig,
    trigger_context: dict,
    monitored_target: "MonitoredTarget",
    notification_context: NotificationContext,
):
    try:
        logger.debug(f"Processing trigger for {monitored_target.target_name} with trigger context: {trigger_context}")
        action_to_perform = trigger_context.get("container_action")

        logger.debug(f"Action to perform: {action_to_perform}. Supports container actions: {monitored_target.supports_container_actions()}")
        # Perform action if configured and supported by this target type
        if action_to_perform is not None and monitored_target.supports_container_actions():
            action_cooldown = trigger_context.get("container_action_cooldown", 300)
            action_result = monitored_target.perform_container_action(
                action_to_perform,
                action_cooldown if isinstance(action_cooldown, int) else 300,
            )
            if action_result:
                notification_context.action_string = action_to_perform
                notification_context.action_type = action_result.action_type
                notification_context.action_target = action_result.action_target
                notification_context.action_result = action_result.message
                notification_context.action_succeeded = action_result.success

        # Create log file attachment if requested
        attachment: LogAttachment | None = None
        attach_logfile = trigger_context.get("attach_logfile", False)
        attachment_lines = trigger_context.get("attachment_lines", 20) if isinstance(trigger_context.get("attachment_lines"), int) else 20
        if attach_logfile:
            if result := monitored_target.get_log_tail(attachment_lines):
                attachment = LogAttachment(
                    content=result,
                    file_name=f"last_{attachment_lines}_lines_from_{monitored_target.target_name}.log",
                )
            else:
                logger.error(f"Could not create log attachment file for {monitored_target.target_name}")

        # Send notification if not disabled
        disable_trigger_notifications = trigger_context.get("disable_trigger_notifications", False)
        if disable_trigger_notifications:
            logger.debug(f"Not sending notification for {monitored_target.target_name} because notifications are disabled.")
        else:
            title = render_title(notification_context, template=trigger_context.get("title_template"))
            message = render_message(notification_context, template=trigger_context.get("message_template"))
            send_notification(config,
                title=title,
                message=message,
                trigger_context=trigger_context,
                notification_context=notification_context,
                attachment=attachment,
            )

        # Trigger OliveTin actions if configured
        olivetin_configs = trigger_context.get("olivetin_actions", []) or []
        for olivetin_config in olivetin_configs:
            if not olivetin_config.get("id"):
                continue
            trigger_olivetin_action(
                trigger_context=trigger_context,
                action_cfg=olivetin_config,
                logger=logger,
                disable_trigger_notifications=disable_trigger_notifications,
                send_notification_cb=None if disable_trigger_notifications else lambda title, message: send_notification(
                    config,
                    title=title,
                    message=message,
                    notification_context=notification_context,
                    attachment=attachment,
                    trigger_context=trigger_context,
                )
            )
    except Exception as e:
        logger.error(f"Error processing trigger for {monitored_target.target_name}: {e}")
