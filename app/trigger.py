import json
from config.config_model import GlobalConfig, ModularSettings
import logging
import time
from typing import TYPE_CHECKING
from notification_formatter import NotificationContext, render_title, render_message
from notifier import send_notification
from services import trigger_olivetin_action
from docker_monitoring.docker_helpers import parse_action_target, cleanup_stale_action_cooldowns

if TYPE_CHECKING:
    from docker_monitoring.monitor import DockerLogMonitor, MonitoredContainerContext

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
    logger.debug(f"\n\nNotification context:\n{notification_context.to_dict()}\n\n")
    action_to_perform = trigger_level_config.get("action")
    action_result = None

    # Perform container action if configured
    if action_to_perform is not None:
        cooldown = modular_settings.get("action_cooldown", 300)
        action_name, container_target = parse_action_target(action_to_perform, unit_context.container_name)
        if not action_name or not container_target:
            return None
        cooldown_key_container = container_target
        cooldown_key_action = action_name
        last_action_lock = monitor_instance.last_action_lock
        with last_action_lock:
            cleanup_stale_action_cooldowns(monitor_instance.last_action_time_per_container)
            if cooldown_key_container not in monitor_instance.last_action_time_per_container:
                monitor_instance.last_action_time_per_container[cooldown_key_container] = {}
            cooldown_dict = monitor_instance.last_action_time_per_container[cooldown_key_container]

            last_time = cooldown_dict.get(cooldown_key_action, 0)
            if last_time < time.time() - int(cooldown):
                should_run_action = True
                cooldown_dict[cooldown_key_action] = time.time()
            else:
                should_run_action = False
                last_action_time = time.strftime("%H:%M:%S", time.localtime(cooldown_dict.get(cooldown_key_action, 0)))
                logger.info(f"Not performing action: '{action_to_perform}'. Action is on cooldown. Action was last performed at {last_action_time}. Cooldown is {cooldown} seconds.")
       
        # run action outside of lock
        if should_run_action:
            error_message = None
            try:
                action_result = monitor_instance.container_action(unit_context.container_name, action_to_perform) 
            except Exception as e:
                logger.error(f"Error while performing container action: {e}")
                error_message = str(e)
            with last_action_lock:
                if action_result or error_message:
                    cooldown_dict[cooldown_key_action] = time.time()
                else:
                    cooldown_dict[cooldown_key_action] = last_time

            notification_context.action_result = error_message or action_result

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
            hostname=monitor_instance.hostname,
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
                hostname=monitor_instance.hostname,
            ),
        )
