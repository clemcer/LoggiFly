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
    hosts: Optional[List[str]] = None


class ContainerEventConfig(TriggerActionsBase, TriggerOnBase):
    event: Literal[*SUPPORTED_CONTAINER_EVENTS] # type: ignore


class ContainerEventBase(BaseConfigModel):
    container_events: Optional[List[ContainerEventConfig]] = None

    @model_validator(mode="before")
    def validate_container_events(cls, data: dict) -> dict:
        if "container_events" in data and isinstance(data["container_events"], list):
            data["container_events"] = validate_container_events(data["container_events"])
        return data


class RuleBase(KeywordBase, ContainerEventBase, ModularDefaultsConfig):
    id: Optional[str] = None # auto-generated in SourceConfig class if missing
    enabled: bool = True
    scope: Optional[ScopeConfig] = None


# ================================================
# Container Config Models
# ================================================

class ContainerMatchCriteria(BaseConfigModel):
    container_names: Annotated[List[str], Field(min_length=1)]


class ContainerMatch(BaseConfigModel):
    include: ContainerMatchCriteria
    exclude: Optional[ContainerMatchCriteria] = None


class ContainerRule(RuleBase):

    container_name: Optional[str] = None # shorthand is converted to match
    match: ContainerMatch

    @model_validator(mode="before")
    def convert_shorthand_to_match(cls, data: dict):
        data = convert_shorthand_to_match(data, {"container_name": "container_names"})
        return data


class ContainerSourceConfig(KeywordBase, ContainerEventBase):

    scope: Optional[ScopeConfig] = None
    never_monitor: Optional[ContainerMatchCriteria] = None
    defaults: Optional[ModularDefaultsConfig] = None
    rules: Optional[List[ContainerRule]] = None
    overlays: Optional[List[ContainerRule]] = None

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
    stack_names: Optional[Annotated[List[str], Field(min_length=1)]] = None
    service_names: Optional[Annotated[List[str], Field(min_length=1)]] = None

    @model_validator(mode="before")
    def has_at_least_one(cls, data: dict):
        if data and isinstance(data, dict):
            if not data.get("stack_names") and not data.get("service_names"):
                raise ValueError("You have to set at least one of 'stack_names' or 'service_names'.")
        return data

class SwarmMatch(BaseConfigModel):
    include: SwarmMatchCriteria
    exclude: Optional[SwarmMatchCriteria] = None

class SwarmRule(RuleBase):

    # shorthands are converted to match
    stack_name: Optional[str] = None
    service_name: Optional[str] = None

    match: SwarmMatch

    @model_validator(mode="before")
    def convert_shorthand_to_match(cls, data: dict) -> dict:
        data = convert_shorthand_to_match(data, {"stack_name": "stack_names", "service_name": "service_names"})
        return data

class SwarmSourceConfig(KeywordBase, ContainerEventBase):

    scope: Optional[ScopeConfig] = None
    never_monitor: Optional[SwarmMatchCriteria] = None
    defaults: Optional[ModularDefaultsConfig] = None
    rules: Optional[List[SwarmRule]] = None
    overlays: Optional[List[SwarmRule]] = None

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
