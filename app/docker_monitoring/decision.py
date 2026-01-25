from dataclasses import dataclass
import logging
from typing import TYPE_CHECKING, List
from enum import Enum
import fnmatch
from constants import MonitorType
from docker_monitoring.helpers import ContainerSnapshot, parse_label_config

from pydantic import ValidationError
from config.helpers import format_pydantic_error, get_pretty_yaml_config
from config.models import GlobalConfig
from config.models import (
    ContainerSourceConfig, 
    SwarmSourceConfig, 
    ContainerRule, 
    SwarmRule,
    LabelConfig,
)
from monitoring import EffectiveTargetConfig
from utils import merge_with_precedence, merge_defaults


if TYPE_CHECKING:
    from docker_monitoring.monitor import MonitoredContainerContext

logger = logging.getLogger(__name__)



def matches_glob_list(value: str, patterns: List[str] | None, case_sensitive: bool = True) -> bool:
    """Check if value matches any glob pattern in the list."""
    if patterns is None:
        return False
    for pattern in patterns:
        if case_sensitive:
            if fnmatch.fnmatch(value, pattern):
                return True
        else:
            if fnmatch.fnmatch(value.lower(), pattern.lower()):
                return True
    return False

def merge_rules(rules, overlays) -> dict:
    result = {}
    for rule in rules + overlays:
        result = merge_with_precedence(precedence=rule.model_dump(exclude_none=True), fallback=result)
    return result


@dataclass
class MonitorDecision:
    result: 'MonitorDecision.Result'
    reason: str = ""
    matched_rules: List | None = None
    matched_overlays: List | None = None
    target_config: EffectiveTargetConfig | None = None
    matched_via_labels: bool | None = False

    class Result(Enum):
        """Possible monitoring decision outcomes."""
        MONITOR = "monitor"              # Start or continue monitoring
        SKIP = "skip"                    # Explicitly excluded (via label or config)
        NOT_CONFIGURED = "not_configured"  # Not in config, monitor_all disabled
        STOP_MONITORING = "stop"         # Currently monitored but should stop (reload)

    class LabelDecision(Enum):
        """Outcome of checking loggifly.monitor label."""
        MONITOR = "monitor"
        SKIP = "skip"
        UNKNOWN = "unknown"

    @staticmethod
    def _check_label(labels: dict | None) -> 'MonitorDecision.LabelDecision':
        """Extract and check the 'loggifly.monitor' label value."""
        # return MonitorDecision.LabelDecision.UNKNOWN # TODO: implement
        if labels is None:
            return MonitorDecision.LabelDecision.UNKNOWN
        monitor_value = labels.get("loggifly.monitor", "").lower().strip()
        if not monitor_value:
            return MonitorDecision.LabelDecision.UNKNOWN
        if monitor_value == "true":
            return MonitorDecision.LabelDecision.MONITOR
        elif monitor_value == "false":
            return MonitorDecision.LabelDecision.SKIP
        return MonitorDecision.LabelDecision.UNKNOWN

    @property
    def should_monitor(self) -> bool:
        """Whether monitoring should start or continue."""
        return self.result == MonitorDecision.Result.MONITOR

    @property
    def should_stop(self) -> bool:
        """Whether existing monitoring should stop."""
        return self.result == MonitorDecision.Result.STOP_MONITORING

    @staticmethod
    def _validate_label_config(labels: dict, target_name: str) -> LabelConfig | None:
        try:
            return LabelConfig.model_validate(labels)
        except ValidationError as e:
            logging.error(f"Error validating label config for {target_name}: {format_pydantic_error(e)}")
        except Exception as e:
            logging.error(f"Unexpected error validating label config for {target_name}: {e}")
        return None


    @classmethod
    def create_target_config(
        cls,
        snapshot: ContainerSnapshot,
        label_config: dict | None,
        target_dict: dict, 
        source_config: ContainerSourceConfig | SwarmSourceConfig | None, 
        global_config: GlobalConfig, 
        ) -> EffectiveTargetConfig:

        # TODO: regarding labels: what about defaults and source keywords?
        # if snapshot.labels.get("loggifly.ignore_config", "false").lower() == "true":
        #     return EffectiveTargetConfig.model_validate(label_config)


        global_config_dict = global_config.model_dump(exclude_none=True)
        source_config_dict = source_config.model_dump(exclude_none=True) if source_config else {}

        keywords = source_config_dict.get("keywords", []) + target_dict.get("keywords", [])
        container_events = (source_config_dict.get("container_events") or []) + (target_dict.get("container_events") or[])
        defaults = (merge_defaults(
            precedence=target_dict, 
            fallback=merge_defaults(
                precedence=source_config_dict.get("defaults", {}), fallback=global_config_dict.get("defaults", {}))
                )
            )

        logger.debug(f"Created the following defaults for {snapshot.target_name}: {defaults}")
        effective = {
            "keywords": keywords,
            "container_events": container_events,
        }
        effective.update(defaults)
        if label_config:
            effective = merge_with_precedence(precedence=label_config, fallback=effective)

        effective_target_config = EffectiveTargetConfig.model_validate(effective)
        logger.debug(f"Effective target config for {snapshot.target_name}:\n{get_pretty_yaml_config(effective_target_config, top_level_key=snapshot.target_name)}")
        return effective_target_config

    @classmethod    
    def evaluate(
        cls,
        snapshot: ContainerSnapshot,
        global_config: GlobalConfig,
        hostname: str,
    ) -> 'MonitorDecision':
        """
        Decide if a container should be monitored based on labels, config, and settings.

        Decision precedence:
        1. Labels: loggifly.monitor=true/false
        2. Explicit config: containers.{name} or swarm_services.{name}
        3. Global settings: monitor_all_containers/monitor_all_swarm_services
        4. Exclusions: excluded_containers/excluded_swarm_services
        """
        if snapshot.is_swarm_service:
            return cls._evaluate_swarm(
                snapshot=snapshot,
                global_config=global_config,
                hostname=hostname,
            )
        else:
            return cls._evaluate_container(
                snapshot=snapshot,
                global_config=global_config,
                hostname=hostname,
            )

    @classmethod
    def evaluate_for_reload(
        cls,
        ctx: 'MonitoredContainerContext',
        new_config: GlobalConfig,
        hostname: str,
    ) -> 'MonitorDecision':
        """
        Decide if a currently monitored container should continue being monitored.

        Used during config reload to determine if monitoring should stop or continue
        with updated configuration.
        """
        if ctx.monitor_type == MonitorType.CONTAINER:
            return cls._evaluate_container_for_reload(
                ctx=ctx,
                new_config=new_config,
                hostname=hostname,
            )
        elif ctx.monitor_type == MonitorType.SWARM:
            return cls._evaluate_swarm_for_reload(
                ctx=ctx,
                new_config=new_config,
                hostname=hostname,
            )
        else:
            raise ValueError(f"Invalid monitor type: {ctx.monitor_type}")
            
    @staticmethod
    def _is_matched_rule(rule: ContainerRule | SwarmRule, filter_mapping: dict[str, str], hostname: str):
        """filter_mapping example: {"service_names": "my-service", "container_names": "my-container"}"""
        if not rule.enabled:
            return False
        if rule.scope and rule.scope.hosts:
            if not matches_glob_list(hostname, rule.scope.hosts):
                return False
        if rule.match.exclude:
            for k, v in filter_mapping.items():
                if pattern_list := getattr(rule.match.exclude, k, None):
                    if matches_glob_list(v, pattern_list):
                        return False
        for k, v in filter_mapping.items():
            if pattern_list := getattr(rule.match.include, k, None):
                if matches_glob_list(v, pattern_list):
                    return True
        return False

    @classmethod
    def _evaluate_swarm(
        cls,
        snapshot: ContainerSnapshot,
        global_config: GlobalConfig,
        hostname: str,
    ) -> 'MonitorDecision':
        service_name = snapshot.service_name
        stack_name = snapshot.stack_name

        assert service_name is not None, "service_name must not be None for swarm service containers"

        decision = cls.LabelDecision.UNKNOWN
        label_source = None

        # Try service labels first
        labels = {}
        if snapshot.service_labels:
            labels = snapshot.service_labels
            decision = cls._check_label(snapshot.service_labels)
            label_source = "swarm service labels"


        # Fallback to container labels if unknown
        if decision == cls.LabelDecision.UNKNOWN:
            labels = snapshot.labels
            decision = cls._check_label(labels)
            label_source = "container labels"

        if decision == cls.LabelDecision.SKIP:
            return cls(
                result=cls.Result.SKIP,
                reason="skipped via labels",
            )

        # check if excluded by host scope or never_monitor
        source_config = global_config.swarm
        if source_config:
            if source_config.scope and source_config.scope.hosts:
                if not matches_glob_list(hostname, source_config.scope.hosts):
                    return cls(
                        result=cls.Result.SKIP,
                        reason="skipped via scope",
                    )
            if source_config.never_monitor:
                if matches_glob_list(service_name, source_config.never_monitor.service_names or []):
                    return cls(
                        result=cls.Result.SKIP,
                        reason="skipped via never_monitor.service_names",
                    )
                if stack_name and matches_glob_list(stack_name, source_config.never_monitor.stack_names or []):
                    return cls(
                        result=cls.Result.SKIP,
                        reason="skipped via never_monitor.stack_names",
                    )

        # check if container should ONLY be monitored via labels (ignore config)
        label_config = None
        if decision == cls.LabelDecision.MONITOR:
            ignore_config = snapshot.labels.get("loggifly.ignore_config", "false").lower() == "true"
            parsed_labels = parse_label_config(labels)
            label_config = cls._validate_label_config(parsed_labels, service_name)
            if label_config:
                label_config = label_config.model_dump(exclude_none=True)
                if ignore_config:
                    effective_target_config = EffectiveTargetConfig.model_validate(label_config)
                    return cls(
                        result=cls.Result.MONITOR,
                        reason=f"monitored via {label_source}",
                        matched_rules=None,
                        target_config=effective_target_config,
                        matched_via_labels=True
                    )
            else:
                if ignore_config:
                    logger.error(f"Failed to validate label config for {service_name}. Since 'loggifly.ignore_config' is set to 'true' this swarm service will be skipped and the config ignored.")
                    return cls(
                        result=cls.Result.SKIP,
                        reason="skipped via 'loggifly.ignore_config' label and invalid label config",
                    )

        filter_mapping = {"service_names": service_name}
        if stack_name:
            filter_mapping["stack_names"] = stack_name
        
        # Get matching rules
        rules = []
        if global_config.swarm and global_config.swarm.rules:
            for rule in global_config.swarm.rules:
                if cls._is_matched_rule(rule, filter_mapping, hostname):
                    rules.append(rule)

        matched_rules = [rule.id for rule in rules]

        if rules:
            reason = f"monitored via {label_source} and rules ({matched_rules})" if decision == cls.LabelDecision.MONITOR else f"monitored via rules ({matched_rules})"
        else:
            if label_config:
                effective_target_config = EffectiveTargetConfig.model_validate(label_config)
                return cls(
                    result=cls.Result.MONITOR,
                    reason=f"monitored via {label_source} and no rules",
                    matched_rules=None,
                    target_config=effective_target_config,
                    matched_via_labels=True
                )
            return cls(
                result=cls.Result.NOT_CONFIGURED,
                reason="not in config and not monitored via labels"
            )

        # collect overlays
        overlays = []
        if global_config.swarm and global_config.swarm.overlays:
            for overlay in global_config.swarm.overlays:
                if cls._is_matched_rule(overlay, filter_mapping, hostname):
                    overlays.append(overlay)

        merged_rule = merge_rules(rules, overlays)
        target_config = cls.create_target_config(
            label_config=label_config,
            target_dict=merged_rule,
            source_config=global_config.swarm,
            global_config=global_config,
            snapshot=snapshot,
        )
        return cls(
            result=cls.Result.MONITOR,
            reason=reason,
            matched_rules=matched_rules,
            target_config=target_config,
            matched_via_labels=False
        )


    @classmethod
    def _evaluate_container(
        cls,
        snapshot: ContainerSnapshot,
        global_config: GlobalConfig,
        hostname: str,
    ) -> 'MonitorDecision':
        cname = snapshot.name

        # Check labels
        label_decision = cls._check_label(snapshot.labels)

        if label_decision == cls.LabelDecision.SKIP:
            return cls(
                result=cls.Result.SKIP,
                reason="skipped via labels",
            )

        # check if excluded by host scope or never_monitor
        source_config = global_config.containers
        if source_config:
            if source_config.scope and source_config.scope.hosts:
                if not matches_glob_list(hostname, source_config.scope.hosts):
                    return cls(
                        result=cls.Result.SKIP,
                        reason="skipped via scope",
                    )
            if source_config.never_monitor:
                if matches_glob_list(cname, source_config.never_monitor.container_names):
                    return cls(
                        result=cls.Result.SKIP,
                        reason="skipped via never_monitor",
                    )

        # check if container should ONLY be monitored via labels (ignore config)
        label_config = None
        if label_decision == cls.LabelDecision.MONITOR:
            ignore_config = snapshot.labels.get("loggifly.ignore_config", "false").lower() == "true"
            parsed_labels = parse_label_config(snapshot.labels)
            label_config = cls._validate_label_config(parsed_labels, cname)
            if label_config:
                logger.debug(f"Validated label config for {cname}:\n{get_pretty_yaml_config(label_config, top_level_key=cname)}")
                label_config = label_config.model_dump(exclude_none=True)
                if ignore_config:
                    effective_target_config = EffectiveTargetConfig.model_validate(label_config)
                    return cls(
                        result=cls.Result.MONITOR,
                        reason="monitored via container labels (config ignored)",
                        matched_rules=None,
                        target_config=effective_target_config,
                        matched_via_labels=True
                    )
            else:
                if ignore_config:
                    logger.error(f"Failed to validate label config for {cname}. Since 'loggifly.ignore_config' is set to 'true' this container will be skipped and the config ignored.")
                    return cls(
                        result=cls.Result.SKIP,
                        reason="skipped because of 'loggifly.ignore_config' label and invalid label config",
                    )
                logger.error(f"Failed to validate label config for {cname}.")

        # Get matching rules
        rules = []
        filter_mapping = {"container_names": cname}
        if global_config.containers and global_config.containers.rules:
            for rule in global_config.containers.rules:
                if cls._is_matched_rule(rule, filter_mapping, hostname):
                    rules.append(rule)

        matched_rules = [rule.id for rule in rules]

        if rules:
            reason = f"monitored via container labels and rules ({matched_rules})" if label_decision == cls.LabelDecision.MONITOR else f"monitored via container rules ({matched_rules})"
        else:
            if not label_config:
                return cls(
                    result=cls.Result.NOT_CONFIGURED,
                    reason="not in config and not monitored via labels"
                )
            reason = f"monitored via container labels and no rules"

        # collect overlays
        overlays = []
        if global_config.containers and global_config.containers.overlays:
            for overlay in global_config.containers.overlays:
                if cls._is_matched_rule(overlay, filter_mapping, hostname):
                    overlays.append(overlay)

        merged_rule = merge_rules(rules, overlays)
        target_config = cls.create_target_config(
            label_config=label_config,
            target_dict=merged_rule,
            source_config=global_config.containers,
            global_config=global_config,
            snapshot=snapshot,
        )
        return cls(
            result=cls.Result.MONITOR,
            reason=reason,
            matched_rules=matched_rules,
            target_config=target_config,
            matched_via_labels=False
        )
        
    @classmethod
    def _evaluate_container_for_reload(
        cls,
        ctx: 'MonitoredContainerContext',
        new_config: GlobalConfig,
        hostname: str,
    ) -> 'MonitorDecision':

        if ctx.snapshot is None:
            return cls(
                result=cls.Result.STOP_MONITORING,
                reason="no container snapshot available during reload",
            )
        decision = cls._evaluate_container(ctx.snapshot, new_config, hostname)
        if decision.should_monitor:
            return decision
        else:
            return cls(
                result=cls.Result.STOP_MONITORING,
                reason=decision.reason
            )

    @classmethod
    def _evaluate_swarm_for_reload(
        cls,
        ctx: 'MonitoredContainerContext',
        new_config: GlobalConfig,
        hostname: str,
    ) -> 'MonitorDecision':
    
        if ctx.snapshot is None:
            return cls(
                result=cls.Result.STOP_MONITORING,
                reason="no swarm service snapshot available during reload",
            )
        decision = cls._evaluate_swarm(ctx.snapshot, new_config, hostname)
        if decision.should_monitor:
            return decision
        else:
            return cls(
                result=cls.Result.STOP_MONITORING,
                reason=decision.reason
            )