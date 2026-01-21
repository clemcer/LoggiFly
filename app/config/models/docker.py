from pydantic import (
    field_validator,
    model_validator,
    Field,
)
from typing import Literal, Optional, List, ClassVar, Annotated
from constants import MonitorType, SUPPORTED_CONTAINER_EVENTS, SUPPORTED_CONTAINER_ACTIONS
from config.models.base import (
    BaseConfigModel,
    OliveTinAction,
    KeywordBase,
    ModularDefaultsConfig,
)
from config.helpers import (
    validate_and_filter_olivetin_actions,
    validate_container_events,
    generate_id_for_policies,
    convert_shorthand_to_match,
)


# ================================================
# Shared between Container and Swarm
# ================================================

class ScopeConfig(BaseConfigModel):
    hosts: Optional[List[str]] = None


class ContainerEventConfig(ModularDefaultsConfig):
    event: Literal[*SUPPORTED_CONTAINER_EVENTS] # type: ignore
    container_action: Optional[str] = None
    olivetin_actions: Optional[List[OliveTinAction]] = None

    @field_validator("container_action")
    def validate_container_action(cls, v):
        """
        Invariant check: ensures the container action is valid.
        MonitorType specific validation is done in the instantiating class that has the cls._MONITOR_TYPE variable context.
        Pre-validation in validate_container_events() should filter out invalid items before they reach here.
        """
        if v and v.split('@')[0] not in SUPPORTED_CONTAINER_ACTIONS:
            raise ValueError(f"Error in config in field 'container_events': Invalid container action ('{v}'). Must be one of {SUPPORTED_CONTAINER_ACTIONS}")
        return v    
    
    @model_validator(mode="before")
    def validate_olivetin(cls, data: dict) -> dict:
        if data and isinstance(data, dict):
            return validate_and_filter_olivetin_actions(data)
        return data


class ContainerEventBase(BaseConfigModel):
    _MONITOR_TYPE: ClassVar[MonitorType | None] = None

    container_events: Optional[List[ContainerEventConfig]] = None

    @model_validator(mode="before")
    def validate_container_events(cls, data: dict) -> dict:
        """
        Validate container events and container actions.
        container_actions are validated here because the cls._MONITOR_TYPE variable from the instantiating class is used.
        """
        assert cls._MONITOR_TYPE is not None, "Internal Error: cls._MONITOR_TYPE is not set in instantiating class"
        if "container_events" in data and isinstance(data["container_events"], list):
            data["container_events"] = validate_container_events(data["container_events"], cls._MONITOR_TYPE)
        return data


class PolicyBase(KeywordBase, ContainerEventBase, ModularDefaultsConfig):
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


class ContainerPolicy(PolicyBase):

    _MONITOR_TYPE: ClassVar[MonitorType | None] = MonitorType.CONTAINER
    
    container_name: Optional[str] = None # shorthand
    match: Optional[ContainerMatch] = None

    @model_validator(mode="before")
    def convert_shorthand_to_match(cls, data: dict):
        data = convert_shorthand_to_match(data, {"container_name": "container_names"})
        return data


class ContainerSourceConfig(KeywordBase, ContainerEventBase):

    _MONITOR_TYPE: ClassVar[MonitorType | None] = MonitorType.CONTAINER

    scope: Optional[ScopeConfig] = None
    never_monitor: Optional[ContainerMatchCriteria] = None
    defaults: Optional[ModularDefaultsConfig] = None
    policies: Optional[List[ContainerPolicy]] = None
    overlays: Optional[List[ContainerPolicy]] = None

    @model_validator(mode="before")
    def generate_ids_if_missing(cls, data: dict) -> dict:
        return generate_id_for_policies(data)


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

class SwarmPolicy(PolicyBase):

    _MONITOR_TYPE: ClassVar[MonitorType | None] = MonitorType.SWARM

    stack_name: Optional[str] = None # shorthand
    service_name: Optional[str] = None # shorthand
    match: Optional[SwarmMatch] = None

    @model_validator(mode="before")
    def convert_shorthand_to_match(cls, data: dict) -> dict:
        data = convert_shorthand_to_match(data, {"stack_name": "stack_names", "service_name": "service_names"})
        return data

class SwarmSourceConfig(KeywordBase, ContainerEventBase):

    _MONITOR_TYPE: ClassVar[MonitorType | None] = MonitorType.SWARM

    scope: Optional[ScopeConfig] = None
    never_monitor: Optional[SwarmMatchCriteria] = None
    defaults: Optional[ModularDefaultsConfig] = None
    policies: Optional[List[SwarmPolicy]] = None
    overlays: Optional[List[SwarmPolicy]] = None

    @model_validator(mode="before")
    def generate_ids_if_missing(cls, data: dict) -> dict:
        return generate_id_for_policies(data)


