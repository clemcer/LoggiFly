from pydantic import (
    field_validator,
    model_validator,
    Field,
    ConfigDict,
)
from typing import Literal, Optional, List, Annotated
from constants import MonitorType, SUPPORTED_CONTAINER_EVENTS
from config.models.base import (
    BaseConfigModel,
    KeywordBase,
    ModularDefaultsConfig,
    TriggerActionsBase,
    _validation_ctx,
    TriggerOnBase,
)
from config.helpers import (
    validate_container_events,
    validate_and_generate_ids,
    convert_shorthand_to_match,
)


# ================================================
# Shared between Container and Swarm
# ================================================

class ScopeConfig(BaseConfigModel):
    """Restricts a rule or source to specific Docker hosts."""
    hosts: Optional[List[str]] = Field(None, description="Restrict monitoring to specific Docker hosts by hostname.")


class ContainerEventConfig(TriggerActionsBase, TriggerOnBase):
    """Configuration for a single container lifecycle event trigger."""
    event: Literal[*SUPPORTED_CONTAINER_EVENTS] = Field(description=f"Docker container event to monitor. One of: {', '.join(event for event in SUPPORTED_CONTAINER_EVENTS)}.") # type: ignore


class ContainerEventBase(BaseConfigModel):
    """Base class providing container event monitoring support."""
    container_events: Optional[List[ContainerEventConfig]] = Field(None, description="Events to monitor on containers. Triggers when the specified Docker lifecycle event occurs.")

    @model_validator(mode="before")
    def validate_container_events(cls, data: dict) -> dict:
        if "container_events" in data and isinstance(data["container_events"], list):
            data["container_events"] = validate_container_events(data["container_events"])
        return data


class RuleBase(KeywordBase, ContainerEventBase, ModularDefaultsConfig):
    """Base class for container and Swarm monitoring rules."""
    id: Optional[str] = Field(None, description="Unique identifier for this rule. Auto-generated if not provided.")
    enabled: bool = Field(True, description="Whether this rule is active.")
    scope: Optional[ScopeConfig] = Field(None, description="Restrict this rule to specific Docker hosts.")


# ================================================
# Container Config Models
# ================================================

class ContainerMatchCriteria(BaseConfigModel):
    """Criteria for matching containers by name."""
    container_names: Annotated[List[str], Field(min_length=1)] = Field(description="List of glob patterns for container names to match (e.g. `my-container*`).")


class ContainerMatch(BaseConfigModel):
    """Inclusion and exclusion criteria for matching containers."""
    include: ContainerMatchCriteria = Field(description="Containers that must match.")
    exclude: Optional[ContainerMatchCriteria] = Field(None, description="Containers to exclude even if they match `include`.")


class ContainerRule(RuleBase):
    """A monitoring rule that applies to one or more Docker containers."""

    container_name: Optional[str] = Field(None, description="Shorthand for `match.include.container_names`. Accepts a single glob pattern for a container name (e.g. `my-container*`).")
    match: ContainerMatch = Field(description="Criteria for matching the containers this rule applies to.")

    @model_validator(mode="before")
    def convert_shorthand_to_match(cls, data: dict):
        data = convert_shorthand_to_match(data, {"container_name": "container_names"})
        return data


class ContainerSourceConfig(KeywordBase, ContainerEventBase):
    """Top-level configuration for Docker container monitoring."""

    scope: Optional[ScopeConfig] = Field(None, description="Restrict container monitoring to specific Docker hosts.")
    never_monitor: Optional[ContainerMatchCriteria] = Field(None, description="Containers that should never be monitored, regardless of other rules.")
    defaults: Optional[ModularDefaultsConfig] = Field(None, description="Default settings applied to all container rules.")
    rules: Optional[List[ContainerRule]] = Field(None, description="List of container monitoring rules.")
    overlays: Optional[List[ContainerRule]] = Field(None, description="Rules that overlay (patch) on top of matched containers without replacing existing rules.")

    @model_validator(mode="wrap")
    @classmethod
    def _inject_ctx(cls, data, handler):
        token = _validation_ctx.set({"monitor_type": MonitorType.CONTAINER})
        try:
            return handler(data)
        finally:
            _validation_ctx.reset(token)

    @model_validator(mode="before")
    def generate_ids_if_missing(cls, data: dict) -> dict:
        return validate_and_generate_ids(data, "containers")


# ================================================
# Swarm Config Models
# ================================================

class SwarmMatchCriteria(BaseConfigModel):
    """Criteria for matching Swarm services by stack or service name."""
    stack_names: Optional[Annotated[List[str], Field(min_length=1)]] = Field(None, description="List of glob patterns for Swarm stack names to match (e.g. `my-stack*`).")
    service_names: Optional[Annotated[List[str], Field(min_length=1)]] = Field(None, description="List of glob patterns for Swarm service names to match (e.g. `my-service*`).")

    @model_validator(mode="before")
    def has_at_least_one(cls, data: dict):
        if data and isinstance(data, dict):
            if not data.get("stack_names") and not data.get("service_names"):
                raise ValueError("You have to set at least one of 'stack_names' or 'service_names'.")
        return data

class SwarmMatch(BaseConfigModel):
    """Inclusion and exclusion criteria for matching Swarm services."""
    include: SwarmMatchCriteria = Field(description="Swarm services that must match.")
    exclude: Optional[SwarmMatchCriteria] = Field(None, description="Swarm services to exclude even if they match `include`.")

class SwarmRule(RuleBase):
    """A monitoring rule that applies to one or more Docker Swarm services."""

    # shorthands are converted to match
    stack_name: Optional[str] = Field(None, description="Shorthand for `match.include.stack_names`. Accepts a single glob pattern for a stack name (e.g. `my-stack*`).")
    service_name: Optional[str] = Field(None, description="Shorthand for `match.include.service_names`. Accepts a single glob pattern for a service name (e.g. `my-service*`).")

    match: SwarmMatch = Field(description="Criteria for matching the Swarm services this rule applies to.")

    @model_validator(mode="before")
    def convert_shorthand_to_match(cls, data: dict) -> dict:
        data = convert_shorthand_to_match(data, {"stack_name": "stack_names", "service_name": "service_names"})
        return data

class SwarmSourceConfig(KeywordBase, ContainerEventBase):
    """Top-level configuration for Docker Swarm service monitoring."""

    scope: Optional[ScopeConfig] = Field(None, description="Restrict Swarm monitoring to specific Docker hosts.")
    never_monitor: Optional[SwarmMatchCriteria] = Field(None, description="Swarm services that should never be monitored, regardless of other rules.")
    defaults: Optional[ModularDefaultsConfig] = Field(None, description="Default settings applied to all Swarm rules.")
    rules: Optional[List[SwarmRule]] = Field(None, description="List of Swarm service monitoring rules.")
    overlays: Optional[List[SwarmRule]] = Field(None, description="Rules that overlay (patch) on top of matched Swarm services without replacing existing rules.")

    @model_validator(mode="wrap")
    @classmethod
    def _inject_ctx(cls, data, handler):
        token = _validation_ctx.set({"monitor_type": MonitorType.SWARM})
        try:
            return handler(data)
        finally:
            _validation_ctx.reset(token)

    @model_validator(mode="before")
    def generate_ids_if_missing(cls, data: dict) -> dict:
        return validate_and_generate_ids(data, "swarm")


class LabelConfig(KeywordBase, ContainerEventBase, ModularDefaultsConfig):
    model_config = ConfigDict(extra="ignore")

    # these should not be logged as missing fields (via validator function in BaseConfigModel)
    monitor: Optional[bool] = None
    ignore_config: Optional[bool] = None

    @model_validator(mode="after")
    def unset_fields(self) -> 'LabelConfig':
        self.monitor = None
        self.ignore_config = None
        return self
