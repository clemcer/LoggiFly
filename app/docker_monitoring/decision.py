from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, List
from enum import Enum
import fnmatch
import logging

from pydantic import ValidationError

from constants import MonitorType
from config.helpers import format_pydantic_error, get_pretty_yaml_config
from config.models import RootConfig
from config.models import (
    ContainerSourceConfig,
    SwarmSourceConfig,
    ContainerRule,
    SwarmRule,
    LabelConfig,
)
from docker_monitoring.helpers import ContainerSnapshot, parse_label_config
from monitoring import EffectiveTargetConfig
from utils import merge_with_precedence, merge_defaults


if TYPE_CHECKING:
    from docker_monitoring.monitor import MonitoredContainerContext

logger = logging.getLogger(__name__)


_RULE_META_FIELDS = {"id", "enabled", "match", "scope", "container_name", "service_name", "stack_name"}


class LabelDecision(Enum):
    """Outcome of checking loggifly.monitor label."""
    MONITOR = "monitor"
    SKIP = "skip"
    UNKNOWN = "unknown"


# ── Module-level helper functions ───────────────────────────────────

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


def check_label(labels: dict | None) -> LabelDecision:
    """Extract and check the 'loggifly.monitor' label value. service_labels can be None."""
    if labels is None:
        return LabelDecision.UNKNOWN
    monitor_value = labels.get("loggifly.monitor", "").lower().strip()
    if not monitor_value:
        return LabelDecision.UNKNOWN
    if monitor_value == "true":
        return LabelDecision.MONITOR
    elif monitor_value == "false":
        return LabelDecision.SKIP
    return LabelDecision.UNKNOWN


def validate_label_config(labels: dict, target_name: str) -> dict | None:
    """Validate parsed label config using LabelConfig model. Returns dict or None on failure."""
    try:
        label_config = LabelConfig.model_validate(labels)
        return label_config.model_dump(exclude_none=True) if label_config else None
    except ValidationError as e:
        logger.error(f"Error validating label config for {target_name}: {format_pydantic_error(e)}")
    except Exception as e:
        logger.error(f"Unexpected error validating label config for {target_name}: {e}")
    return None


def is_matched_rule(rule: ContainerRule | SwarmRule, filter_mapping: dict[str, str], hostname: str) -> bool:
    """Check if a rule matches the given filter values and hostname.

    filter_mapping example: {"service_names": "my-service", "container_names": "my-container"}
    """
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
        pattern_list = getattr(rule.match.include, k, None)
        if pattern_list:
            if not matches_glob_list(v, pattern_list):
                return False
    else:
        return True


def merge_rules(rules: List[ContainerRule | SwarmRule]) -> dict:
    """Merge matched rules into a single config dict. Later entries take precedence."""
    result = {}
    for ro in rules:
        result = merge_with_precedence(
            precedence=ro.model_dump(exclude_none=True, exclude=_RULE_META_FIELDS),
            fallback=result,
        )
    return result


def create_target_config(
    snapshot: ContainerSnapshot,
    validated_label_config: dict | None,
    target_dict: dict,
    source_config: ContainerSourceConfig | SwarmSourceConfig | None,
    global_config: RootConfig,
) -> EffectiveTargetConfig:
    """Build the effective target config by merging: global defaults < source defaults < rules < labels."""
    global_block_dict = global_config.global_config.model_dump(exclude_none=True)
    source_config_dict = source_config.model_dump(exclude_none=True) if source_config else {}

    keywords = (source_config_dict.get("keywords") or []) + (target_dict.get("keywords") or []) + (global_block_dict.get("keywords") or [])
    container_events = (source_config_dict.get("container_events") or []) + (target_dict.get("container_events") or [])
    defaults = merge_defaults(
        precedence=target_dict,
        fallback=merge_defaults(
            precedence=source_config_dict.get("defaults", {}),
            fallback=global_block_dict.get("defaults", {}),
        ),
    )

    effective = {
        "keywords": keywords,
        "container_events": container_events,
    }
    effective.update(defaults)
    if validated_label_config:
        effective = merge_with_precedence(precedence=validated_label_config, fallback=effective)

    effective_target_config = EffectiveTargetConfig.model_validate(effective)
    return effective_target_config


@dataclass
class MonitorDecision:
    result: 'MonitorDecision.Result'
    reason: str = ""
    matched_rules: List[str] | None = None
    target_config: EffectiveTargetConfig | None = None
    labels_applied: bool = False

    class Result(Enum):
        """Possible monitoring decision outcomes."""
        MONITOR = "monitor"
        SKIP = "skip"
        NOT_CONFIGURED = "not_configured"
        STOP_MONITORING = "stop"

    @property
    def should_monitor(self) -> bool:
        return self.result == MonitorDecision.Result.MONITOR

    @property
    def should_stop(self) -> bool:
        return self.result == MonitorDecision.Result.STOP_MONITORING

    # ── Public API ──────────────────────────────────────────────────

    @classmethod
    def evaluate(
        cls,
        snapshot: ContainerSnapshot,
        global_config: RootConfig,
        hostname: str,
    ) -> 'MonitorDecision':
        """
        Decide if a container/service should be monitored.

        Decision precedence:
          1. Labels with ignore_config (bypass everything)
          2. Label skip (loggifly.monitor=false)
          3. never_monitor (absolute exclusion)
          4. scope (host filtering)
          5. Rules (selection into monitoring)
        """
        if snapshot.is_swarm_service:
            return cls._evaluate_swarm(snapshot, global_config, hostname)
        else:
            return cls._evaluate_container(snapshot, global_config, hostname)

    @classmethod
    def evaluate_for_reload(
        cls,
        ctx: 'MonitoredContainerContext',
        new_config: RootConfig,
        hostname: str,
    ) -> 'MonitorDecision':
        """
        Decide if a currently monitored container should continue being monitored.
        Used during config reload.
        """
        if ctx.snapshot is None:
            return cls(
                result=cls.Result.STOP_MONITORING,
                reason="no snapshot available during reload",
            )
        if ctx.monitor_type == MonitorType.CONTAINER:
            decision = cls._evaluate_container(ctx.snapshot, new_config, hostname)
        elif ctx.monitor_type == MonitorType.SWARM:
            decision = cls._evaluate_swarm(ctx.snapshot, new_config, hostname)
        else:
            raise ValueError(f"Invalid monitor type: {ctx.monitor_type}")

        if decision.should_monitor:
            return decision
        return cls(result=cls.Result.STOP_MONITORING, reason=decision.reason)

    # ── Thin wrappers that prepare parameters for _evaluate_target ──

    @classmethod
    def _evaluate_container(
        cls,
        snapshot: ContainerSnapshot,
        global_config: RootConfig,
        hostname: str,
    ) -> 'MonitorDecision':
        return cls._evaluate_target(
            snapshot=snapshot,
            global_config=global_config,
            hostname=hostname,
            target_name=snapshot.name,
            source_config=global_config.containers,
            label_sources=[(snapshot.labels, "container labels")],
            filter_mapping={"container_names": snapshot.name},
            never_monitor_check=lambda nm: matches_glob_list(snapshot.name, nm.container_names),
        )

    @classmethod
    def _evaluate_swarm(
        cls,
        snapshot: ContainerSnapshot,
        global_config: RootConfig,
        hostname: str,
    ) -> 'MonitorDecision':
        service_name = snapshot.service_name
        assert service_name is not None, "service_name must not be None for swarm service containers"

        def never_monitor_check(nm) -> bool:
            if matches_glob_list(service_name, nm.service_names):
                return True
            if snapshot.stack_name and matches_glob_list(snapshot.stack_name, nm.stack_names):
                return True
            return False

        filter_mapping = {"service_names": service_name}
        if snapshot.stack_name:
            filter_mapping["stack_names"] = snapshot.stack_name

        return cls._evaluate_target(
            snapshot=snapshot,
            global_config=global_config,
            hostname=hostname,
            target_name=service_name,
            source_config=global_config.swarm,
            label_sources=[
                (snapshot.service_labels, "swarm service labels"),
                (snapshot.labels, "container labels"),
            ],
            filter_mapping=filter_mapping,
            never_monitor_check=never_monitor_check,
        )

    # ── Core decision logic (shared) ────────────────────────────────

    @classmethod
    def _evaluate_target(
        cls,
        snapshot: ContainerSnapshot,
        global_config: RootConfig,
        hostname: str,
        target_name: str,
        source_config: ContainerSourceConfig | SwarmSourceConfig | None,
        label_sources: list[tuple[dict | None, str]],
        filter_mapping: dict[str, str],
        never_monitor_check: Callable,
    ) -> 'MonitorDecision':

        # 1. Check labels (iterate sources in priority order)
        label_decision = LabelDecision.UNKNOWN
        validated_label_config = None
        label_source = None

        for labels, source_name in label_sources:
            if not labels:
                continue
            d = check_label(labels)

            if d == LabelDecision.SKIP:
                return cls(result=cls.Result.SKIP, reason=f"skipped via {source_name}")

            if d == LabelDecision.MONITOR:
                label_decision = d
                label_source = source_name
                ignore_config = labels.get("loggifly.ignore_config", "false").lower() == "true"
                parsed = parse_label_config(labels)
                validated_label_config = validate_label_config(parsed, target_name)

                if ignore_config:
                    if validated_label_config is not None:
                        return cls(
                            result=cls.Result.MONITOR,
                            reason=f"monitored via {source_name} (config ignored)",
                            target_config=EffectiveTargetConfig.model_validate(validated_label_config),
                            labels_applied=True,
                        )
                    else:
                        logger.error(
                            f"Failed to validate {source_name} config for {target_name}. "
                            f"Since 'loggifly.ignore_config' is set to 'true' this target will be skipped."
                        )
                        return cls(
                            result=cls.Result.SKIP,
                            reason="skipped via 'loggifly.ignore_config' label and invalid label config",
                        )

                if validated_label_config is None:
                    logger.error(
                        f"Failed to validate {source_name} config for {target_name}. "
                        f"Falling back to rule-based matching via regular config."
                    )
                break  # first MONITOR wins, stop checking further label sources

        # 2. never_monitor (takes precedence over label opt-in without ignore_config)
        if source_config and source_config.never_monitor:
            if never_monitor_check(source_config.never_monitor):
                return cls(result=cls.Result.SKIP, reason="skipped via never_monitor")

        # 3. Host scope
        if source_config and source_config.scope and source_config.scope.hosts:
            if not matches_glob_list(hostname, source_config.scope.hosts):
                return cls(result=cls.Result.SKIP, reason="skipped via scope")

        # 4. Find matching rules
        rules = []
        if source_config and source_config.rules:
            for rule in source_config.rules:
                if is_matched_rule(rule, filter_mapping, hostname):
                    rules.append(rule)
        matched_rule_ids = [rule.id for rule in rules]

        # 5. Determine if target should be monitored
        if rules:
            if label_decision == LabelDecision.MONITOR:
                reason = f"monitored via {label_source} and rules {tuple(matched_rule_ids)}"
            else:
                reason = f"monitored via rules {tuple(matched_rule_ids)}"
        elif validated_label_config is not None:
            reason = f"monitored via {label_source} (no rules matched)"
        else:
            return cls(
                result=cls.Result.NOT_CONFIGURED,
                reason="not in config and not monitored via labels",
            )

        # 7. Build effective config
        merged_rule = merge_rules(rules)
        target_config = create_target_config(
            snapshot=snapshot,
            validated_label_config=validated_label_config,
            target_dict=merged_rule,
            source_config=source_config,
            global_config=global_config,
        )

        return cls(
            result=cls.Result.MONITOR,
            reason=reason,
            matched_rules=matched_rule_ids,
            target_config=target_config,
            labels_applied=validated_label_config is not None,
        )
